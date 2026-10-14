# pg_mic: Static, Fail-Closed Function Integrity Enforcement

- **Date:** 2026-10-10
- **Status:** Approved design, pending implementation plan
- **Extension:** `pg_mic` (Mandatory Integrity Control) — renamed from `pg_biba`
- **Target:** PostgreSQL master (20devel), built/tested only against
  `~/projects/claude/pgsql/postgresql`

> **Revision note (2026-10-14, v1.0-beta3).** This spec was written for the
> static-reachability work and was approved as such. Two later adversarial
> reviews changed the architecture in ways the original text does not
> reflect; the affected sections carry inline corrections marked
> *[amended]*. In summary: (a) the function-manager hook, not
> `OAT_FUNCTION_EXECUTE`, is the authoritative runtime layer, and a function
> below HIGH is therefore never inlined (the "inlinable LOW SQL is a
> non-escape" argument in §3/§12 is moot, not relied on); (b) the subject's
> level is the higher of the outer and current user, so an owner switch
> (`SECURITY DEFINER`, `VACUUM`, replication apply) never lowers it; (c)
> rules and operators are labeled, checked objects, and `CREATE
> TRIGGER`/`POLICY`/`RULE`/`INDEX`/`STATISTICS` and every `ALTER TABLE`
> subcommand are gated both as writes to the relation and, for subjects
> above LOW, at definition time; (d) domain `DEFAULT` and extended-statistics
> expressions are in the reachable set; (e) `mic_promote_extension` skips
> members owned below the target level and labels the extension; (f)
> `mic_initialize_labels` labels by owner; (g) only HIGH subjects may own
> subscriptions. The README is the current description of behavior.

## 1. Context and Problem

`pg_mic` enforces a Biba-style mandatory integrity model with three levels
(LOW=1, MEDIUM=2, HIGH=3). A subject must not be contaminated by objects
below its level ("No Read Down"), and must not corrupt objects above it
("No Write Up"). A function is a first-class object: invoking one is a
"read"/"use" of that object, so a HIGH subject must never execute a LOW
function.

An earlier change wired enforcement onto the `OAT_FUNCTION_EXECUTE`
object-access hook and began labeling functions at creation (creator's
level). Testing the indirect-execution paths revealed that the hook-only
approach is **structurally insufficient**:

1. **Triggers are never hooked.** `src/backend/commands/trigger.c` contains
   zero calls to `InvokeFunctionExecuteHook`. A LOW trigger on a table a
   HIGH subject writes runs unchecked.
2. **Inlinable SQL functions evade the hook.** The planner inlines a simple
   `LANGUAGE sql` function before execution, so no call survives for the
   hook to see. A plpgsql CHECK was correctly denied; the same CHECK via an
   inlinable SQL function was allowed. This is a trivial, deliberate bypass.

`OAT_FUNCTION_EXECUTE` fires only from specific runtime sites (expression
eval, SRF, aggregates, window funcs, `CALL`, fastpath, RI triggers). A
mandatory model cannot rely on "wherever Postgres happens to call the
hook." We need enforcement that does not depend on the runtime hook firing.

## 2. Goals and Non-Goals

**Goals**
- A HIGH (or MEDIUM) subject can never cause a function below its level to
  execute, including via indirect, non-obvious paths: triggers, CHECK
  constraints, defaults, generated columns, index expressions/predicates,
  exclusion operators, RLS policies, domain CHECKs.
- Immunity to SQL-function inlining.
- Fail-closed: deny unless safety is proven.
- A superuser can bulk-promote all objects of a vetted extension in one
  call.
- Preserve existing behavior: create-time labeling of relations and
  functions; the existing table DML read/write checks; GUC modes.
- Build and run against every community-supported major version plus git
  master (see §13).

**Non-Goals**
- Static analysis of opaque (plpgsql/C) function bodies (infeasible).
- Confidentiality (Bell-LaPadula) — this is integrity only.
- Closing the one documented residual (see §3) — opaque function that
  internally inlines a LOW SQL function.

## 3. Design Principles

- **Subject-relative, at operation time.** A purely structural invariant
  ("a relation carries no function below its own level") is insufficient:
  a HIGH subject may legitimately *write down* into a LOW relation, which
  would still run that relation's LOW triggers/checks. Enforcement must
  compare the *subject's* level against each reachable function at the time
  the subject operates.
- **Read stored expressions, not runtime calls.** Stored node trees
  (`conbin`, `adbin`, `indexprs`, `indpred`, `polqual`, generation exprs,
  domain `conbin`) retain function OIDs even for functions that would be
  inlined at execution. Analyzing them is inlining-immune by construction.
- **Fail closed.** If an expected expression can't be read, or a collected
  function OID can't be resolved to a level, deny (subject to `biba.mode`).

### Transitivity: why nested references need no static recursion

*[amended]* The reasoning below predates the function-manager layer. Since
v1.0-beta1 a function labeled below HIGH is registered with
`needs_fmgr_hook`, which the planner refuses to inline, so a lower SQL
function is never inlined into a higher subject's query at all; nested
inlining cannot occur and the "read-only inlined LOW SQL" residual below no
longer exists. The static walk still does not recurse into function bodies,
for the reason that every nested call is a real `fmgr` invocation.

We check the functions **directly referenced** by each stored attachment
expression (§5). These reads are inlining-immune because they read the
stored node tree, which retains the referenced function's OID. We
deliberately do **not** recurse into the bodies of functions that are
themselves allowed, because nested inlining is not a meaningful integrity
escape:

- An inlinable SQL function is restricted to a single **read-only** SELECT
  expression (no data-modifying DML).
- Everything such a function does with integrity consequence is enforced by
  another layer: a table it reads becomes an RTE in the surrounding query
  and is caught by the executor table check; any non-inlined function or
  operator it invokes fires `OAT_FUNCTION_EXECUTE` at expression
  initialization and is level-checked.
- The only thing left unchecked is the *label* of a LOW SQL function whose
  body reduces entirely to exempt built-in computation — a read-only
  calculation with no integrity-relevant effect.

Opaque (plpgsql/C) functions are never inlined; any function they call is a
real invocation that fires the runtime hook, and any table they touch is
checked as a normal RTE. There is therefore no meaningful static-analysis
residual, and no need to parse SQL function bodies or walk the subject's
query pre-inlining.

## 4. Architecture

New internal module `reach.c` (name provisional) exposes one entry point:

```c
/* Deny if any function reachable from relid for the given operation
 * sits below the current subject's level. Fail-closed on anything
 * unanalyzable. Honors biba.mode (no-op/warn/error). */
void biba_check_reachable_functions(Oid relid, AclMode required_ops);
```

Invoked from two sites, because not all execution flows through the
executor, plus the retained runtime hook as a backstop:

1. **Executor path** — inside existing `biba_dml_privileges`
   (`ExecutorCheckPerms_hook`). It already iterates `rteperminfos` with each
   relation OID and `requiredPerms`; add a call to the new entry point per
   relation. Covers plain `SELECT/INSERT/UPDATE/DELETE`, before execution.
2. **Utility path** — new logic in the existing `ProcessUtility_hook` (§7
   below). Covers commands that execute attached code outside the executor.
3. **Runtime hook retained** — `OAT_FUNCTION_EXECUTE` continues to
   read-check directly-executed non-inlined functions (defense-in-depth and
   the catch for opaque nested calls).

*[amended]* The authoritative runtime layer is the function-manager hook
(`needs_fmgr_hook`/`fmgr_hook`), which sees every invocation of every
function below HIGH from every call site; `OAT_FUNCTION_EXECUTE` is the
early (expression-initialization) denial, and the static walks are the
pre-side-effect denial. The subject at every layer is the higher of the
outer and current user (`mic_get_subject_level`), so `fmgr_security_definer`
switching to a lower owner before calling the hook does not lower it.
Rules and operators are labeled at `OAT_POST_CREATE` alongside relations
and functions; `OAT_POST_CREATE` on an already-labeled object (a `CREATE OR
REPLACE`) is first checked as a write; `OAT_DROP`/`OAT_POST_ALTER` apply the
write check to every labeled class (relations incl. columns, functions,
rules, operators, types, schemas, extensions). A `planner_hook` walks each
query for user-defined operators below the subject.

No change to the label provider from prior work.

## 5. Reachable-set per operation

For a relation `R` and the operation's required-perms bits, collect and
level-check functions from these attachments (each read as a stored node
tree and walked):

| Attachment (catalog) | SELECT | INSERT | UPDATE | DELETE |
|---|:---:|:---:|:---:|:---:|
| Triggers `pg_trigger.tgfoid` (filtered by `tgtype` event) | — | INS | UPD | DEL |
| CHECK constraints `pg_constraint.conbin` (contype='c') | — | yes | yes | — |
| Column defaults `pg_attrdef.adbin` | — | yes | yes | — |
| Generated — STORED (`pg_attrdef.adbin`) | — | yes | yes | — |
| Generated — VIRTUAL | yes | yes | yes | — |
| Index expr/predicate `pg_index.indexprs`/`indpred` | yes | yes | yes | yes |
| Exclusion operators `pg_constraint.conexclop` | — | yes | yes | — |
| RLS policies `pg_policy.polqual`/`polwithcheck` | USING | WITH CHECK | both | USING |
| Domain CHECK (per-column domain type's `conbin`) | — | yes | yes | — |

Notes:
- Operation-awareness comes from the `requiredPerms` bitmap already present
  in `rteperminfos`; trigger rows are further filtered by `tgtype` event
  bits so a DELETE isn't blocked by a LOW INSERT trigger.
- **VIRTUAL generated columns** are computed on read, so they are checked on
  SELECT (and conservatively on INSERT/UPDATE for `RETURNING`/BEFORE-trigger
  read-back). **STORED** generated columns compute on write only. VIRTUAL
  generated columns exist only on PG18+, so this row compiles out on older
  majors (§13).
- **Index expr/predicate** is reachable on all operations: the planner
  evaluates IMMUTABLE index predicates while matching partial/expression
  indexes (the scratch.txt SELECT vector), and index maintenance evaluates
  them on write.
- **SELECT** therefore touches: RLS `USING`, VIRTUAL generated columns, and
  index expr/predicate. Views are covered by range-table recursion (each
  view relation gets its own RTE and its own check), not special-cased here.
- **Level rule** (reused from `biba_check_read`): built-ins (`OID < 16384`)
  are exempt; otherwise resolve label (unlabeled ⇒ LOW) and deny if
  `function_level < subject_level`. No Write Up never applies to execution.
- The subject's **directly-named** functions (e.g. `SELECT low_fn(x)`) are
  handled by a pre-inline walk of the query tree (§6), not by this table.

## 6. Expression walker and fail-closed boundaries

Each stored tree is run through PostgreSQL's `expression_tree_walker` /
`query_tree_walker` with a collector callback. The walker descends into
every child, so no sub-expression is missed; the callback extracts function
OIDs from the function-bearing node types (enumerated exhaustively in code
with an assertion comment marking the maintenance surface):

- `FuncExpr` → `funcid`
- `OpExpr` / `DistinctExpr` / `NullIfExpr` → `opfuncid` (resolve from `opno`
  via `get_opcode` if unset)
- `ScalarArrayOpExpr` → `opfuncid` (+ `hashfuncid`)
- `RowCompareExpr` → each `opno` → opcode
- `Aggref` / `WindowFunc` → the agg/window fn and its `pg_aggregate` support
  functions (trans/final/combine/serial/deserial)
- `CoerceViaIO` / `ArrayCoerceExpr` → the type's `typinput`/`typoutput`
- `CoerceToDomain` → that domain's CHECK functions
- sublinks/subqueries (RLS may contain them) → recurse via
  `query_tree_walker`, including `RTE_FUNCTION` scans

**Directly-named functions in the subject's own query** need no special
pre-inline walk: a non-inlined call fires the retained runtime hook, and an
inlinable SQL function the subject names directly is read-only with
independently-enforced effects (§3). This is deliberately simpler than an
earlier draft that walked the query tree before inlining.

**Fail-closed (hard denials):**
1. A stored expression we expect but cannot read/parse → deny.
2. A collected OID whose `pg_proc`/label cannot be resolved → deny.
3. Otherwise compare level and deny if below subject.

Under `biba.mode = permissive`, a fail-closed condition warns and allows
(see §8), which is the intended shake-out path before enabling enforcing.

## 7. Utility-path gating

New logic in `ProcessUtility_hook` maps each code-executing command to a
`(relation, operation)` and calls `biba_check_reachable_functions`, also
walking expressions carried in the parse tree:

| Command | What runs | Check |
|---|---|---|
| `COPY … FROM` | defaults, CHECK, generated, triggers, index maint. | relation as INSERT |
| `COPY … TO` | RLS, virtual generated | relation as SELECT |
| `CREATE INDEX [CONCURRENTLY]` | new index expr/predicate over rows | walk `IndexStmt` expressions |
| `REINDEX` | existing index stored expr over rows | target index `indexprs`/`indpred` |
| `TRUNCATE` | TRUNCATE-event triggers | each relation's TRUNCATE triggers |
| `ALTER TABLE` (rewrite/validate) | per-row evaluation | see below |

**`ALTER TABLE`** uses explicit subcommand enumeration rather than a
universal net (so benign subcommands aren't denied under fail-closed): the
AT codes that execute code over rows — `AT_AddColumn` with a volatile
default, `AT_CookedColumnDefault`, `AT_AddConstraint`/`AT_ValidateConstraint`,
`AT_AlterColumnType` (`USING`), `AT_SetExpression`, and identity/generated
variants — walk each one's expression and, for validation/rewrite, also run
the relation's INSERT+UPDATE attachment check.

**Scope note.** The utility path is explicit enumeration, not the
comprehensive fail-closed net the executor path is. Justification: (1) plain
DML — the overwhelming surface — is fully covered by the executor path;
(2) the runtime hook still fires for any non-inlined function these commands
execute (backstop); (3) the command/subcommand list is the documented
maintenance surface — a new PG command that executes code is a visible gap,
not a silent one. ~~Pure attachment commands (`CREATE TRIGGER`/`POLICY`/
`RULE`) are deliberately not gated: they execute nothing, and the trap they
set is caught at use-time by the executor path.~~ *[amended]* Attachment
commands are gated twice: as a **write to the relation** (`CREATE
INDEX`/`TRIGGER`/`RULE`/`POLICY`/`STATISTICS`, every `ALTER TABLE`
subcommand, `ADD COLUMN`), so that a lower owner cannot change what a
promoted relation does; and, for subjects above LOW, at **definition time**
by walking the raw expressions (`CREATE TRIGGER` function and `WHEN`,
`CREATE RULE` condition and actions, policies, domains incl. `DEFAULT`,
statistics, `CREATE TABLE`), so that a higher subject cannot define an
object in terms of lower code. `CREATE SUBSCRIPTION` and `ALTER
SUBSCRIPTION ... OWNER TO` require a HIGH subject/owner because the apply
worker bypasses the executor's permission check. `VACUUM`/`ANALYZE`/
`CLUSTER` paths also walk `pg_statistic_ext.stxexprs`.

## 8. Error/audit, modes, performance

**Error & audit** (reuses `biba_check_read`'s reporting path):
- enforcing: `ERROR` (`ERRCODE_INSUFFICIENT_PRIVILEGE`), message naming the
  reached function and *how* it was reached, e.g. `… cannot execute low
  integrity function "f" reached via CHECK constraint on "t"`.
- permissive: `WARNING`, allow.
- disabled: skip.
- `biba.debug_audit`: `LOG` each reachable-function decision with attachment
  kind, function OID, and levels.

**`biba.mode`.** The new check sits behind the same gate as all other
checks. Fail-closed "can't analyze ⇒ deny" is itself mode-sensitive: in
permissive it warns-and-allows, giving operators a rollout path.

**Performance.**
- Runs once per relation per statement at executor start, not per row.
- Fast exits before any catalog work: if `biba_mode == disabled`, or if the
  **subject is LOW** (nothing is below it, so no execution can be a
  read-down). This skips the entire cost for all unprivileged sessions;
  only MEDIUM/HIGH subjects pay.
- Prefer relcache-materialized structures (`trigdesc`, `rd_att`,
  `rd_indexprs`, constraint/RLS descriptors) over fresh scans.
- Optional per-transaction memoization (`relid → cleared`) deferred to v1.1
  unless profiling shows need.

## 9. Bulk extension promotion

New superuser-only function in `promote.c`:

```sql
biba_promote_extension(ext_name text, new_level text) RETURNS integer
```

Relabels every object belonging to the named extension to `new_level`,
returning the count relabeled. Use case: a trusted extension installed by a
low-trust user has all its functions labeled LOW; after vetting, a superuser
promotes the whole extension in one call so HIGH subjects can use it.

- **Membership:** objects with a `pg_depend` row `deptype = 'e'`
  (`DEPENDENCY_EXTENSION`), `refclassid = pg_extension`,
  `refobjid = get_extension_oid(ext_name, false)`.
- **Guards:** superuser only; validate `new_level` (low/medium/high); any
  valid target level.
- **Label-capable classes only:** functions, relations, types/domains,
  schemas, etc. are relabeled; member classes that don't support security
  labels (operators, casts, …) are skipped and reported under
  `biba.debug_audit`. The enforcement-relevant members (functions,
  relations) always support labels.
- **Direct members only** — required extensions are vetted separately (no
  implicit cascade; a future option).
- Overwrites any existing label (safe to re-run).

Documented in the README function reference and a "Vetting and promoting a
trusted extension" usage section.

## 10. Testing strategy

TDD throughout: each case's asserted output is written before the code that
makes it pass.

- **(a) `pg_regress` enforcement matrix** (enforcing mode): one case per
  attachment × operation from §5, both polarities (LOW fn + HIGH subject →
  denied; HIGH/built-in fn + HIGH subject → allowed). Covers triggers
  (INS/UPD/DEL/TRUNCATE), CHECK, defaults, STORED generated (write), VIRTUAL
  generated (read), index expr/predicate (incl. SELECT planner-fold),
  exclusion operators, RLS USING/WITH CHECK, domain CHECK.
- **(b) No-over-denial / positive cases:** superuser runs ordinary queries,
  `CREATE EXTENSION`, built-ins (`now()` trigger, `abs()` CHECK); LOW
  fast-path never denied; HIGH subject with its own HIGH helper in every
  attachment type → allowed.
- **(c) Inlining & transitivity:** inlinable `LANGUAGE sql` function via
  CHECK and via index expr, HIGH subject → denied (fails under hook-only);
  HIGH SQL function whose body inlines a LOW SQL function → denied;
  HIGH plpgsql making a non-inlined nested LOW call → denied at runtime;
  the documented residual captured as a commented `-- KNOWN LIMITATION`.
- **(d) Utility path:** `COPY FROM` with LOW default/CHECK/trigger;
  `CREATE INDEX`/`REINDEX` on a populated table with a LOW index expression;
  `ALTER TABLE ADD CONSTRAINT … CHECK` validating rows; `TRUNCATE` firing a
  LOW truncate trigger — each denied.
- **(e) TAP tests** (`PostgreSQL::Test::Cluster`): `shared_preload_libraries`
  requirement; `biba.mode` switching — enforcing denies, permissive
  warns-and-allows (including an unanalyzable attachment), disabled no-op.
- **(f) End-to-end:** the full scratch.txt confused-deputy attack asserting
  the superuser SELECT is denied and 0 bytes reach the large object.
- **(g) Version matrix:** the suite must compile and pass against every
  supported major and master. Locally this is done by building each
  `REL_N_STABLE` branch of the designated repo in its own worktree (§13) and
  running `installcheck` against each; version-specific expected-output
  files (`expected/pg_mic_N.out`) are added only where output legitimately
  differs by version.

## 11. Rename to `pg_mic`

Mechanical, pre-release (no deployed data to migrate). Touches: source file
names and `MODULE_big`/`EXTENSION` (Makefile, meson.build); control file and
`pg_mic--1.0.sql`; every `biba_*` SQL function and C symbol; the `biba.*`
GUC prefix (`MarkGUCPrefixReserved`); the `"biba"` seclabel provider tag;
views; README and docs. The Biba lineage stays in the control-file comment
and README ("a mandatory integrity model in the tradition of Biba"). Done as
its own step so the diff is reviewable.

For readability, this document uses the current `biba_*` / `biba.*` / `"biba"`
names throughout; after the rename step they become `mic_*` / `mic.*` /
`"mic"` respectively.

## 12. Limitations and non-escapes (to document in README)

- ~~**Nested inlined SQL is not an escape**~~ *[amended]* A function below
  HIGH is never inlined (it is hooked, and the planner does not inline
  hooked functions), so there is no inlined lower SQL to reason about. The
  current list of limitations and non-escapes is maintained in the README.
- The utility path (§7) covers an enumerated set of commands/subcommands; a
  new PostgreSQL command that executes code over rows would need to be added
  to that enumeration (fail-visible, not silent).
- Custom base-type I/O functions are not an attack vector (base types
  require superuser to create, so their I/O is HIGH).

## 13. Portability and multi-version support

`pg_mic` must build and pass its tests against every community-supported
major version at release time plus git master. Portability is handled with
`PG_VERSION_NUM` guards concentrated in a single compatibility header
(`pg_mic_compat.h`) so the enforcement logic stays version-agnostic.

**Load-bearing version boundaries:**

- **PG16 — permission info / hook signature.** PG16 split per-relation
  permission data out of `RangeTblEntry` into `RTEPermissionInfo` and changed
  `ExecutorCheckPerms_hook` to `bool (*)(List *rangeTabls, List *rteperminfos,
  bool abort)`. Pre-16 it is `bool (*)(List *rangeTabls, bool abort)` and
  `requiredPerms`/`relid` live on `RangeTblEntry`. The compat header provides
  one iterator yielding `(relOid, requiredPerms)` pairs regardless, and the
  hook is registered with the version-correct signature.
- **PG16 — `AclMode` width.** Widened to 64-bit; the code uses `AclMode`
  throughout and does not assume width.
- **PG18 — `PG_MODULE_MAGIC_EXT`.** The `.name`/`.version` form exists only
  on 18+. On older majors the module declares plain `PG_MODULE_MAGIC`.
- **PG18 — VIRTUAL generated columns.** `attgenerated == 'v'` and the
  read-path check (§5) are compiled only on 18+; older majors have STORED
  generated columns only.

**Other points verified as stable across the supported range:** the
`object_access_hook` and the OAT types used (`OAT_POST_CREATE`, `OAT_DROP`,
`OAT_POST_ALTER`, `OAT_TRUNCATE`, `OAT_FUNCTION_EXECUTE`),
`register_label_provider`, the security-label get/set API, `pg_policy`,
`pg_trigger`/`pg_constraint`/`pg_attrdef` layout for our purposes,
`ScalarArrayOpExpr.hashfuncid` (PG14+), and `MERGE` (PG15+, which flows
through `ExecutorCheckPerms` with combined INSERT/UPDATE/DELETE perms and so
is covered by the executor path).

**Supported floor.** Target the community-supported majors at release; the
code carries guards down to PG14 so the PG16 and PG18 boundaries are handled
uniformly. The floor is a one-line constant to adjust as versions age out.

**Build/test across versions without `/opt/src/pgsql-git`.** The designated
repo `~/projects/claude/pgsql/postgresql` already has the `REL_N_STABLE`
branches fetched. Each target version is built in its own `git worktree` off
that repo, installed to its own prefix, and the extension is built against
that prefix's `pg_config` via PGXS (`make USE_PGXS=1 PG_CONFIG=…`) and
exercised with `installcheck`. This keeps all PostgreSQL sources within the
single designated repo.
