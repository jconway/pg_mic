# pg_mic -- Biba Mandatory Integrity Model for PostgreSQL

`pg_mic` is a PostgreSQL extension that enforces a mandatory integrity model
in the tradition of Biba. The Biba model is the dual of Bell-LaPadula: it protects data
**integrity** rather than confidentiality. It prevents high-integrity subjects
from being contaminated by low-integrity data, and prevents low-integrity
subjects from corrupting high-integrity data.

## Integrity Levels

| Level  | Value | Description                        |
|--------|-------|------------------------------------|
| HIGH   | 3     | Trusted data / privileged users    |
| MEDIUM | 2     | Intermediate trust                 |
| LOW    | 1     | Untrusted data / unprivileged users|

### Subject Resolution (Users)

A role's level is:

- Superuser = HIGH
- Labeled role = label value
- Unlabeled role = LOW

The *subject* of an operation is the role on whose behalf it runs. PostgreSQL
keeps two identities: the **outer user** set by login and `SET ROLE`, and the
**current user**, which the server may switch within one operation to the
owner of a `SECURITY DEFINER` function, of a table being vacuumed or
clustered, of a materialized view being refreshed, or of a table receiving
replicated rows. Those switches are made on the outer user's behalf, so the
subject's level is the **higher of the outer and current user's levels**. An
identity switch can never lower the subject: a LOW user cannot launder code
past the checks by marking it `SECURITY DEFINER`, and `VACUUM` of a LOW table
by a superuser is still the superuser's operation. `SET ROLE` changes both
identities, so a user who deliberately lowers themselves is lowered.

An autovacuum worker has no outer subject (its session identity is the
bootstrap superuser only as an artifact of how it starts) and is judged by
the current identity alone, i.e. by each table's owner.

### Object Resolution

- System object (OID < 16384) = HIGH
- Labeled object = label value
- Unlabeled object = LOW

Tables, views, materialized views, indexes, functions, **rules** and
**operators** are labeled automatically at creation, at the creator's level.
Types, schemas and extensions carry a label only when a superuser promotes
them (see below); a label on those is consulted for `ALTER` and `DROP` only.
Sequences, large objects and other object kinds are not modeled.

System catalog reads (pg_class, pg_type, etc.) are always exempt from
enforcement so that basic SQL parsing works for all users.

## Enforcement Rules

| Rule          | Condition                    | Effect                                          |
|---------------|------------------------------|-------------------------------------------------|
| No Read Down  | `subject_level <= object_level` | HIGH users cannot read LOW objects            |
| No Write Up   | `subject_level >= object_level` | LOW users cannot write HIGH objects           |
| UPDATE        | both rules apply             | effectively requires `subject_level == object_level` |

DML mapping:

- **SELECT** -- read check
- **INSERT** -- write check
- **DELETE** -- write check
- **UPDATE** -- read + write check
- **DROP / ALTER / TRUNCATE** -- write check, on every labeled object kind
  (a LOW owner cannot rename, alter, re-define with `CREATE OR REPLACE`, or
  drop a function, rule, operator or relation that has been promoted above
  them)
- **Attaching code to a relation** -- `CREATE INDEX`, `CREATE TRIGGER`,
  `CREATE RULE`, `CREATE`/`ALTER POLICY`, `CREATE STATISTICS` and every
  `ALTER TABLE` subcommand (including `ADD COLUMN` and `ADD CONSTRAINT`)
  change what the relation does and are write checks on it, even when the
  subject owns the relation

### Function Execution and Indirect Enforcement

A function is an object like any other, so invoking one obeys No Read Down:
a HIGH subject cannot cause a function below its level to execute. This blocks
confused-deputy attacks in which a high-integrity subject is lured into running
untrusted, low-integrity code planted by a low-integrity user.

The rule covers not only functions named in the query but also **indirect,
non-obvious paths** where the server runs a function on the subject's behalf.
Three layers enforce it, from the outermost in:

1. **Function-manager hook (authoritative).** Every user-defined function
   whose label is below HIGH is registered with PostgreSQL's `needs_fmgr_hook`,
   which routes *every* invocation of it -- from the executor, from
   `trigger.c`, from event triggers, from the logical-replication apply worker,
   from the type cache (a range type's `subtype_diff`), from anything that
   calls through `fmgr` -- through an entry hook that compares the subject
   executing the call with the function's level. The hook runs after
   `fmgr_security_definer` has switched to the function's owner, which is why
   the subject is computed from the outer user as well (see "Subject
   Resolution"). The one thing the function manager never sees is code that
   is not a function: rules (below) and operators (below) are handled
   separately.
2. **Executor hook.** The object-access function-execute hook denies at
   expression-initialization time, before any row is processed.
3. **Static pre-checks.** Before a statement executes, the stored catalog
   expressions of every relation it touches -- and of every partition and
   inheritance child the statement reaches -- are walked and every function
   they name is checked. This denies before any side effect, and it is what
   makes commands that later switch to the *table owner's* identity
   (`REINDEX`, `VACUUM`, `ANALYZE`, `CLUSTER`/`REPACK`, `REFRESH MATERIALIZED
   VIEW`) answer to the invoking subject rather than to the owner.

Statically covered attachment points:

- triggers (and their `WHEN` clauses), including triggers on partitions and
  inheritance children reached through DML on the parent, and TRUNCATE
  triggers reached through partitions, inheritance children, and the `CASCADE`
  foreign-key closure
- CHECK constraints
- column defaults
- STORED and VIRTUAL generated columns
- index expressions and index predicates
- exclusion-constraint operators
- RLS `USING` / `WITH CHECK` policies
- domain CHECK constraints, including a domain nested under another domain, the
  element/subtype of an array, range, or multirange of a domain, and a domain
  reached through a field of a composite type
- a materialized view's query, on `REFRESH`
- a domain's `DEFAULT`, which an `INSERT` omitting a column of that type
  evaluates
- extended-statistics expressions, which `ANALYZE` (including the `ANALYZE`
  a bare `VACUUM` or `CLUSTER` implies) evaluates as the owner
- rules, as objects (see "Rules" below)
- user-defined operators, as objects (see "Operators" below)

Pre-checked at definition time, so a HIGH subject cannot even define an
object in terms of a lower function, or derive one from a lower relation:
`CREATE TABLE` (column defaults, CHECK/EXCLUDE constraints, generated
columns, the partition key, a column whose domain CHECKs reach a lower
function, and anything adopted via `LIKE`, `INHERITS`, `PARTITION OF`, or
`OF type`), `ALTER TABLE` (add constraint/default/index/expression, `ATTACH
PARTITION`, `INHERIT`), `CREATE TRIGGER` (function and `WHEN` clause),
`CREATE EVENT TRIGGER`, `CREATE`/`ALTER POLICY`, `CREATE`/`ALTER DOMAIN`
(CHECK and `DEFAULT`), `CREATE STATISTICS`, `CREATE RULE` (condition and
actions), and `CREATE INDEX`. Deriving from a lower relation
(`LIKE`, `INHERITS`, `PARTITION OF`, `ATTACH`, `INHERIT`) is a read of that
relation and is refused as read-down.

Built-in functions (OID < 16384) are exempt, so ordinary SQL works for all
users. The utility path covers COPY, TRUNCATE, CREATE INDEX, REINDEX (including
`REINDEX SCHEMA` and `REINDEX DATABASE`), VACUUM/ANALYZE, CLUSTER/REPACK,
REFRESH MATERIALIZED VIEW, and the ALTER TABLE validate/rewrite subcommands.

#### Rules

A rule's actions are queries that run, as extra statements, with the
privileges of whoever performs the triggering `INSERT`/`UPDATE`/`DELETE`,
while DAC on those actions is checked as the rule's *owner*. A LOW user who
can write a table but not a HIGH one could therefore plant `DO ALSO UPDATE
high_table ...` on a table a HIGH subject writes to, and have the HIGH
subject carry out the write. A rule is not a function, so the function
checks never see it. Rules are therefore labeled at creation like
functions, and before a statement runs, every rule on the relation it names
whose event matches is checked against the subject: a subject may not fire
a rule below its level. (The check runs for the original statement and for
each rule-generated statement alike, so it holds whichever the executor runs
first.) A view's `ON SELECT` rule is included, so a view re-defined by a
lower subject is refused, and a lower subject cannot `CREATE OR REPLACE` a
higher view in the first place.

#### Operators

Operators are resolved by name through `search_path`, so a LOW user can
define, say, `public.===(int, int)` -- or `public.=` -- over a *built-in*
function with the wrong semantics, and a higher subject's query may pick it
up without any lower function ever executing. Operators are therefore
labeled at creation and treated as objects: every query is walked after
rewriting and before planning (including queries inside functions, prepared
statements and plans being rebuilt), and every stored expression the static
layer examines is walked, for user-defined operators below the subject.
Sort and grouping operators always come from an operator class, which only
a superuser can create, so only direct operator applications are checked.
The usual advice about `search_path` (CVE-2018-1058) still applies: do not
place a schema writable by lower users ahead of `pg_catalog`.

#### Logical replication

The apply worker writes replicated rows through a path that bypasses the
executor's permission check, so the DML layer never sees them; functions it
runs (triggers, defaults, index expressions) are still caught by the
function-manager hook, with the subscription owner as the subject. To keep
"No Write Up" meaningful, only a HIGH subject may `CREATE SUBSCRIPTION`, and
a subscription may not be given to an owner below HIGH. Rows applied by a
subscription therefore always arrive as HIGH writes: a HIGH subscription
applying into a LOW table whose triggers or index expressions reach LOW code
fails, exactly as a superuser's `INSERT` into that table would, and the
subscription stalls until the table is fixed. Subscriptions created before
`pg_mic` was installed should be re-owned by a HIGH role.

#### SQL-function inlining

The planner never inlines a function registered with `needs_fmgr_hook`, so a
function labeled **below HIGH is never inlined**: a higher subject is simply
denied, and a same-level subject calls it as an ordinary function. A function
labeled **HIGH needs no hook** (no subject is above it) and inlines exactly as
it would without `pg_mic`. Relabeling a function invalidates every cached plan
that depends on it, so a plan built while a function was HIGH -- including one
holding an inlined copy of its body -- is rebuilt the next time it runs.

## Installation

### Requirements

`pg_mic` must be loaded via `shared_preload_libraries` because it installs
hooks at server startup.

### Build and Install

From a PostgreSQL source tree:

```sh
make -C contrib/pg_mic
make -C contrib/pg_mic install
```

Or with PGXS against an installed PostgreSQL:

```sh
cd contrib/pg_mic
USE_PGXS=1 make
USE_PGXS=1 make install
```

### Configure

Add to `postgresql.conf`:

```
shared_preload_libraries = 'pg_mic'
```

Restart PostgreSQL, then create the extension in each database:

```sql
CREATE EXTENSION pg_mic;
```

## Configuration

### GUC Variables

| GUC                | Type | Default     | Context    | Description                          |
|--------------------|------|-------------|------------|--------------------------------------|
| `mic.mode`        | enum | `enforcing` | PGC_SIGHUP | `enforcing`, `permissive`, `disabled`|
| `mic.debug_audit` | bool | `off`       | PGC_USERSET| Log all access control decisions     |

- **enforcing** -- violations are denied with an error.
- **permissive** -- violations are logged as warnings but allowed.
- **disabled** -- no checks are performed.

Change mode at runtime (takes effect after `pg_ctl reload`):

```sql
ALTER SYSTEM SET mic.mode = 'permissive';
SELECT pg_reload_conf();
```

## Usage

### Labeling Roles

Only superusers can assign integrity levels to roles:

```sql
SELECT mic_set_role_level('analyst', 'medium');
SELECT mic_set_role_level('auditor', 'high');
```

Or using the native security label syntax:

```sql
SECURITY LABEL FOR mic ON ROLE analyst IS 'medium';
```

### Labeling Tables and Functions

New tables and functions are automatically labeled at the creator's
integrity level. Because the extension's own functions are created by a
superuser during `CREATE EXTENSION`, they are labeled HIGH and remain
callable by high-integrity users. A superuser can change a table's level:

```sql
SELECT mic_promote_table('sensitive_data', 'high');
```

Or using the native syntax:

```sql
SECURITY LABEL FOR mic ON TABLE sensitive_data IS 'high';
```

### Initializing Labels

Objects that pre-date the extension carry no label and so count as LOW,
which is safe but leaves HIGH subjects unable to touch them. To label every
unlabeled user table, view, materialized view, rule, function and operator
at the level of the role that **owns** it (so a lower role's objects are
never promoted above that role):

```sql
SELECT mic_initialize_labels();   -- returns the number of objects labeled
```

### Querying Labels

```sql
-- Current session's integrity level
SELECT mic_get_session_level();

-- A role's level
SELECT mic_get_role_level('analyst');

-- A table's level
SELECT mic_get_table_level('sensitive_data');
```

### Views

| View               | Description                              |
|--------------------|------------------------------------------|
| `mic_labels`      | All labeled objects with their levels     |
| `mic_role_labels` | All roles with assigned integrity levels  |

```sql
SELECT * FROM mic_role_labels;
SELECT * FROM mic_labels;
```

### Generic Object Promotion

For objects other than tables:

```sql
SELECT mic_promote_object(class_id, object_id, 'high');
```

### Vetting and Promoting an Extension

Objects created by a subject carry that subject's level, including a function,
rule or view re-defined with `CREATE OR REPLACE` by a subject at or above its
level (which relabels it to the re-definer's level; a lower subject is
refused, since replacing is writing). Note that a *trusted* extension installed by a non-superuser is not
labeled LOW: PostgreSQL runs its script as the bootstrap superuser, so its
objects are created -- and labeled -- HIGH, and are owned by that superuser,
not by the installing user. Objects that end up LOW -- created before `pg_mic`
was installed, created by a LOW user, or demoted -- are unusable by
high-integrity subjects until a superuser vets and promotes them. For an
extension's members that can be done in one call:

```sql
SELECT mic_promote_extension('some_ext', 'high');  -- returns count of objects relabeled
```

`mic_promote_extension(ext_name text, new_level text) RETURNS integer` is
superuser-only. It relabels every labelable member (relations, functions,
operators, types, schemas) of the named extension to the given level, and
then the extension itself, and returns the number of objects relabeled.

An extension's members are owned by whoever installed it, and that owner
can make any object of their own a member with `ALTER EXTENSION ... ADD`.
A member whose owner is below the requested level is therefore **skipped,
with a warning**, so that promoting a trusted extension can never promote a
lower user's own code; the extension's label is set only when nothing was
skipped. Once the extension is labeled, `ALTER EXTENSION` (`ADD`, `DROP`,
`UPDATE`) and `DROP EXTENSION` are writes to it and are refused to lower
subjects. Vet an extension's member list before promoting it.

## Example

```sql
-- Setup
CREATE ROLE trusted_writer LOGIN;
CREATE ROLE untrusted_reader LOGIN;
SELECT mic_set_role_level('trusted_writer', 'high');
-- untrusted_reader is unlabeled, so defaults to LOW

CREATE TABLE verified_facts (id serial, fact text);
SELECT mic_promote_table('verified_facts', 'high');
GRANT ALL ON verified_facts TO trusted_writer, untrusted_reader;
GRANT USAGE ON SEQUENCE verified_facts_id_seq TO trusted_writer, untrusted_reader;

-- As trusted_writer (HIGH): can read and write HIGH table
SET ROLE trusted_writer;
INSERT INTO verified_facts (fact) VALUES ('The Earth orbits the Sun');
SELECT * FROM verified_facts;  -- works
RESET ROLE;

-- As untrusted_reader (LOW): can read HIGH table, cannot write it
SET ROLE untrusted_reader;
SELECT * FROM verified_facts;  -- works (No Read Down: LOW <= HIGH)
INSERT INTO verified_facts (fact) VALUES ('fake news');  -- ERROR (No Write Up: LOW < HIGH)
RESET ROLE;
```

## SQL Function Reference

| Function | Returns | Description |
|----------|---------|-------------|
| `mic_get_session_level()` | text | Current user's integrity level |
| `mic_get_role_level(role_name text)` | text | Named role's integrity level |
| `mic_get_table_level(table_name text)` | text | Named table's integrity level |
| `mic_set_role_level(role_name text, level text)` | void | Set a role's level (superuser only) |
| `mic_promote_table(table_name text, new_level text)` | void | Set a table's level (superuser only) |
| `mic_promote_object(class_id oid, object_id oid, new_level text)` | void | Set any object's level (superuser only) |
| `mic_promote_extension(ext_name text, new_level text)` | integer | Relabel every labelable member of an extension; returns count (superuser only) |
| `mic_initialize_labels()` | integer | Label unlabeled user relations, rules, functions and operators at their owner's level; returns count (superuser only) |

## Supported Versions

PostgreSQL 14 through master. Validated on 14, 15, 16, 17, 18, 19, and
master -- the regression suite on all seven, and the TAP suite (including the
two-node logical-replication test) on every branch built with
`--enable-tap-tests`; the stable branches are tested with `--enable-cassert`.
Version differences are handled with guards in `pg_mic_compat.h`.

## Limitations and Non-Escapes

- **A function below HIGH is never inlined** (see "SQL-function inlining"
  above), so inlining cannot make a lower-level function's call vanish from
  the function manager's view.
- **Commands that run as the table owner are checked against the invoking
  subject.** `VACUUM`, `ANALYZE`, `CLUSTER`/`REPACK`, `REINDEX`, and `REFRESH
  MATERIALIZED VIEW` switch to the owner's identity before evaluating index,
  statistics, or view code. PostgreSQL does this precisely so that code runs
  with the owner's privileges, but it still runs in the invoking session, so a
  HIGH subject is denied these commands on a relation whose stored code
  reaches a lower-level function. Autovacuum is a system process, not a
  session, and is not affected; it runs as the owner. A superuser-owned table
  can therefore never be analyzed by autovacuum if a lower function is reached
  from its indexes or statistics -- which is why attaching one is refused.
- **`SECURITY DEFINER` runs as a HIGH subject when its owner is HIGH.** A
  HIGH-owned `SECURITY DEFINER` function called by a LOW user executes as a
  HIGH subject (the higher of the two identities), so inside it a read of a
  LOW table is denied. This is the price of the rule that an identity switch
  never lowers the subject; write such functions to read only data at their
  own level.
- **A HIGH function is trusted with whatever it is handed.** The checks
  decide whether a subject may *run* a function, not what arguments it gets.
  A HIGH trigger or event-trigger function attached by a lower user (where
  DAC allows it) runs on that user's rows and `TG_ARGV`, and a HIGH function
  called by a lower user receives that user's arguments. Write HIGH code
  defensively; the model does not taint data flowing *into* it.
- **Labels travel with `pg_dump`.** Security labels are dumped and restored,
  but `pg_dump`/`pg_restore --no-security-labels` strips them, after which
  every restored object is LOW (unusable by HIGH subjects until relabeled)
  and every restored role is LOW. Never restore a labeled database with that
  option into a database whose roles are already labeled.
- **Relabel visibility.** A function demotion invalidates cached plans
  everywhere, but a `FmgrInfo` a session has already cached outside the plan
  cache (the type cache's copy of a range type's `subtype_diff`, for instance)
  keeps its pre-demotion, unhooked state for that session's lifetime.
- **Custom base-type I/O functions are not an attack vector.** Creating a base
  type requires superuser, so its I/O functions are HIGH.
- **VIRTUAL generated columns** cannot reference user-defined functions in
  PostgreSQL (the server rejects them), so that read-path vector is moot in
  practice; a defensive check remains.
- **RLS enforcement is conservative (over-approximate).** Every policy on an
  RLS-enabled relation is checked; BYPASSRLS, FORCE ROW LEVEL SECURITY,
  per-policy command (`polcmd`), and per-policy role applicability are not
  modeled. A subject that would actually bypass a policy may still be denied if
  the policy references a lower-integrity function (fail-closed).
- **The utility path covers an enumerated set** of commands/subcommands. A new
  PostgreSQL command that executes code over rows would need to be added to
  that enumeration.
- **REINDEX SYSTEM** has nothing to check: it rebuilds only system catalogs,
  whose indexes are all system objects (OID below the threshold) and therefore
  exempt.
- **Partition trees are expanded for every statement above LOW.** The static
  layer takes an `AccessShareLock` on every partition and inheritance child a
  statement can reach, even when the executor would lock only the partitions
  it routes into. A LOW subject reading skips the expansion entirely.
- **Not modeled.** Sequences (`nextval`/`setval`), large objects, and DAC
  changes (`GRANT`, `COMMENT`) carry no integrity semantics here. Schema and
  type labels (set only by promotion) govern `ALTER`/`DROP` of those objects,
  not use of them.

## Running Tests

```sh
# Requires a running server with shared_preload_libraries = 'pg_mic'
make -C contrib/pg_mic installcheck
```
