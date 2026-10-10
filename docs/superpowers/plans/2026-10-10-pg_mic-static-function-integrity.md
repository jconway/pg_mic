# pg_mic Static Function Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the confused-deputy gap so a HIGH/MEDIUM subject can never cause a function below its level to execute — including via triggers, CHECK/defaults/generated columns/index expressions/exclusion operators/RLS/domain checks — immune to SQL-function inlining; add bulk extension promotion; rename the extension to `pg_mic`; and support all current major versions plus master.

**Architecture:** Enforcement is static and subject-relative, done at operation time by reading *stored* expressions from the catalogs (inlining-immune) rather than relying only on the `OAT_FUNCTION_EXECUTE` runtime hook. A new module `reach.c` collects function OIDs reachable from a relation for a given operation and denies any below the subject's level (fail-closed). It is driven from the existing `ExecutorCheckPerms_hook` (plain DML) and `ProcessUtility_hook` (COPY/CREATE INDEX/REINDEX/TRUNCATE/ALTER TABLE). The runtime hook is retained as a backstop; the existing table read/write checks remain underneath.

**Tech Stack:** C (PostgreSQL extension, PGXS build), PostgreSQL server internals (object_access_hook, ExecutorCheckPerms_hook, ProcessUtility_hook, security labels, relcache/syscache, expression_tree_walker), pg_regress + TAP (PostgreSQL::Test::Cluster) tests.

**Spec:** `docs/superpowers/specs/2026-10-10-pg_mic-static-function-integrity-design.md`

## Global Constraints

- **PostgreSQL sources:** build/test ONLY against `~/projects/claude/pgsql/postgresql` (any branch/worktree of it). NEVER use any repo under `/opt/src/pgsql-git`.
- **Build toolchain:** PGXS against the installed master at `~/projects/claude/pgsql/pg-install`; `PGC=~/projects/claude/pgsql/pg-install/bin/pg_config`; build with `make USE_PGXS=1 PG_CONFIG=$PGC`. `PG_CONFIG` must be passed as a make argument (the Makefile sets `PG_CONFIG = pg_config` with `=`, so an env var will not override it).
- **Test cluster:** data dir under the session scratchpad; socket dir `$HOME/.pgb_sock` (the scratchpad path is too long for a UNIX socket, >107 bytes); `shared_preload_libraries = 'pg_mic'`; port 54399.
- **Version floor:** PG14 through master. Guard version-divergent code with `PG_VERSION_NUM`; concentrate guards in `pg_mic_compat.h`. Load-bearing boundaries: PG16 (`ExecutorCheckPerms_hook` signature + `RTEPermissionInfo` + 64-bit `AclMode`) and PG18 (`PG_MODULE_MAGIC_EXT`, VIRTUAL generated columns).
- **Naming:** extension and all identifiers are `mic` / `mic_*` / `mic.*`; the seclabel provider tag is `"mic"`. Keep the Biba lineage only in prose (control-file comment, README).
- **Fail-closed:** if an expected stored expression cannot be read/parsed, or a collected function OID cannot be resolved to a level, deny under enforcing (warn-and-allow under permissive).
- **Integrity levels:** LOW=1, MEDIUM=2, HIGH=3. Built-ins (`OID < FirstNormalObjectId` = 16384) are exempt. Deny execution when `function_level < subject_level` (No Read Down on the function object). No Write Up never applies to execution.
- **Commit attribution:** every commit message ends with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## Review Focus

- **Superuser everyday usability under fail-closed:** a HIGH subject running ordinary queries on tables with built-in-only triggers/checks (e.g. a `now()` default, an `abs()` CHECK) must NOT be denied. Covered by Task 4 Step (positive built-in case) and Task 6.
- **LOW-subject fast path:** an unprivileged (LOW) session must never pay the analysis cost nor be denied by the reachable check (nothing is below LOW). Covered by Task 4 (fast-path test).
- **Trigger event filtering:** a DELETE must not be blocked by a LOW *INSERT*-only trigger on the table. Covered by Task 5 (event-filtering test).
- **permissive vs enforcing for unanalyzable attachments:** in permissive mode a fail-closed condition must WARN and allow, not error. Covered by Task 14 (mode TAP test).
- **Version skew in expected output:** the regression output must match on every supported major; VIRTUAL-generated cases exist only on PG18+. Covered by Task 16 (version matrix + `pg_mic_N.out`).

---

## Task 1: Initialize git repository and hygiene

**Files:**
- Create: `.gitignore`, `LICENSE`
- (repo init over the existing working tree at `~/projects/claude/pgsql/pg_biba`)

**Interfaces:**
- Produces: a git repo with a clean initial commit; `.gitignore` excluding build artifacts.

- [ ] **Step 1: Initialize the repo**

```bash
cd ~/projects/claude/pgsql/pg_biba
git init
git config user.email "mail@joeconway.com"
```

- [ ] **Step 2: Write `.gitignore`**

```gitignore
# Build artifacts
*.o
*.so
*.bc
# pg_regress output
/results/
/regression.diffs
/regression.out
/log/
/tmp_check/
# editor
*~
```

- [ ] **Step 3: Add a LICENSE (PostgreSQL License)**

Write the standard PostgreSQL License text to `LICENSE` with copyright line
`Copyright (c) 2026, Joe Conway`. (Use the canonical PostgreSQL License
wording; it is the same permissive license PostgreSQL itself ships.)

- [ ] **Step 4: Commit the current tree**

```bash
cd ~/projects/claude/pgsql/pg_biba
git add -A
git commit -m "$(cat <<'EOF'
Initial commit: Biba integrity model extension (pre-rename)

Imports the existing working extension and its tests as the starting
point before the pg_mic rename and the static function-integrity work.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Verify**

Run: `git log --oneline -1 && git status --porcelain`
Expected: one commit; empty status (clean tree, artifacts ignored).

---

## Task 2: Rename pg_biba → pg_mic

**Files:**
- Rename: `pg_biba.h`→`pg_mic.h`, `pg_biba.control`→`pg_mic.control`, `pg_biba--1.0.sql`→`pg_mic--1.0.sql`, `sql/pg_biba.sql`→`sql/pg_mic.sql`, `expected/pg_biba.out`→`expected/pg_mic.out`
- Modify: `Makefile`, `meson.build`, `dml.c`, `enforce.c`, `hooks.c`, `label.c`, `promote.c`, `README.md`

**Interfaces:**
- Produces: identical behavior under new names — `mic_*` SQL functions, `mic.mode`/`mic.debug_audit` GUCs, `"mic"` seclabel tag, `MODULE_big = pg_mic`, `EXTENSION = pg_mic`.

- [ ] **Step 1: Rename files with git**

```bash
cd ~/projects/claude/pgsql/pg_biba
git mv pg_biba.h pg_mic.h
git mv pg_biba.control pg_mic.control
git mv pg_biba--1.0.sql pg_mic--1.0.sql
git mv sql/pg_biba.sql sql/pg_mic.sql
git mv expected/pg_biba.out expected/pg_mic.out
```

- [ ] **Step 2: Rewrite identifiers in all sources**

Apply these global substitutions across `*.c`, `*.h`, `*.sql`, `*.control`, `Makefile`, `meson.build`, `README.md`:
- `pg_biba` → `pg_mic`
- `biba_` → `mic_` (C symbols and SQL function names)
- `BIBA_` → `MIC_` (macros in the header)
- `"biba"` provider tag → `"mic"` (the `BIBA_LABEL_TAG` / `MIC_LABEL_TAG` value)
- GUC names `biba.mode`/`biba.debug_audit` → `mic.mode`/`mic.debug_audit`; `MarkGUCPrefixReserved("biba")` → `MarkGUCPrefixReserved("mic")`
- `#include "pg_biba.h"` → `#include "pg_mic.h"`
- In `pg_mic.control`: `comment = 'Mandatory integrity control (Biba model)'`, `module_pathname = '$libdir/pg_mic'`

```bash
cd ~/projects/claude/pgsql/pg_biba
sed -i 's/pg_biba/pg_mic/g; s/biba_/mic_/g; s/BIBA_/MIC_/g; s/"biba"/"mic"/g; s/\bbiba\.mode\b/mic.mode/g; s/\bbiba\.debug_audit\b/mic.debug_audit/g; s/MarkGUCPrefixReserved("biba")/MarkGUCPrefixReserved("mic")/g' \
  dml.c enforce.c hooks.c label.c promote.c pg_mic.h pg_mic--1.0.sql pg_mic.control Makefile sql/pg_mic.sql expected/pg_mic.out
# header guard
sed -i 's/PG_BIBA_H/PG_MIC_H/g' pg_mic.h
# meson target name
sed -i "s/'pg_biba'/'pg_mic'/g; s/pg_biba_sources/pg_mic_sources/g; s/pg_biba =/pg_mic =/g; s/pg_biba\b/pg_mic/g" meson.build
```

- [ ] **Step 3: Fix the control-file comment to keep the Biba lineage in prose**

Edit `pg_mic.control` comment line to:
`comment = 'Mandatory integrity control (a Biba-style integrity model)'`

- [ ] **Step 4: Build and install**

Run:
```bash
cd ~/projects/claude/pgsql/pg_biba
PGC=~/projects/claude/pgsql/pg-install/bin/pg_config
make USE_PGXS=1 PG_CONFIG=$PGC clean
make USE_PGXS=1 PG_CONFIG=$PGC && make USE_PGXS=1 PG_CONFIG=$PGC install
```
Expected: compiles with no warnings; installs `pg_mic.so`, `pg_mic.control`, `pg_mic--1.0.sql`.

- [ ] **Step 5: Restart cluster with the renamed preload and run existing tests**

Run (helper env in Global Constraints):
```bash
BIN=~/projects/claude/pgsql/pg-install/bin; DATA=<scratchpad>/testdata; SOCK=$HOME/.pgb_sock
# postgresql.conf must now say shared_preload_libraries = 'pg_mic'
sed -i "s/shared_preload_libraries = .*/shared_preload_libraries = 'pg_mic'/" $DATA/postgresql.conf
$BIN/pg_ctl -D $DATA -o "-p 54399" restart
export PGHOST=$SOCK PGPORT=54399 PGUSER=postgres
make USE_PGXS=1 PG_CONFIG=~/projects/claude/pgsql/pg-install/bin/pg_config installcheck
```
Expected: `All 1 tests passed` (the existing suite, now under `pg_mic`).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Rename extension pg_biba -> pg_mic

Mechanical rename of files, C symbols, SQL functions, GUC prefix
(mic.mode/mic.debug_audit), and the security-label provider tag ("mic").
Behavior is unchanged; the existing regression suite passes. The Biba
lineage is retained in the control-file comment and README prose.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Compatibility header (pg_mic_compat.h)

**Files:**
- Create: `pg_mic_compat.h`
- Modify: `hooks.c` (module magic + ExecutorCheckPerms registration), `dml.c` (permission-info iteration), `meson.build`/`Makefile` (no new object; header only), `pg_mic.h` (include compat where needed)

**Interfaces:**
- Produces:
  - Macro `MIC_MODULE_MAGIC` expanding to `PG_MODULE_MAGIC_EXT(.name="pg_mic", .version=PG_VERSION)` on PG18+, else `PG_MODULE_MAGIC`.
  - `typedef struct { Oid relid; AclMode requiredPerms; } MicPermEntry;`
  - `List *mic_perm_entries(List *rangeTabls, List *rteperminfos);` — returns a `List*` of `MicPermEntry*` regardless of version (pre-16 derives from `RangeTblEntry`; 16+ from `RTEPermissionInfo`). On pre-16 builds the second arg is absent; the compat header also defines the correct `ExecutorCheckPerms_hook` function signature macro `MIC_CHECKPERMS_ARGS` and a way to call `mic_perm_entries`.

- [ ] **Step 1: Write the failing test (build-only guard check)**

Add a compile-time assertion file usage: in `pg_mic_compat.h` include a `StaticAssertDecl` that `PG_VERSION_NUM >= 140000`. The "test" is that the build fails clearly on unsupported versions. For the master build, the test is simply that the project still builds and `installcheck` passes after rewiring (Step 4/5).

- [ ] **Step 2: Write `pg_mic_compat.h`**

```c
#ifndef PG_MIC_COMPAT_H
#define PG_MIC_COMPAT_H

#include "postgres.h"
#include "access/transam.h"      /* FirstNormalObjectId */
#include "nodes/parsenodes.h"
#include "nodes/pg_list.h"
#include "utils/acl.h"

StaticAssertDecl(PG_VERSION_NUM >= 140000,
                 "pg_mic requires PostgreSQL 14 or newer");

/* Module magic: PG18+ has the extended form with name/version. */
#if PG_VERSION_NUM >= 180000
#define MIC_MODULE_MAGIC \
    PG_MODULE_MAGIC_EXT(.name = "pg_mic", .version = PG_VERSION)
#else
#define MIC_MODULE_MAGIC PG_MODULE_MAGIC
#endif

typedef struct MicPermEntry
{
    Oid         relid;
    AclMode     requiredPerms;
} MicPermEntry;

/*
 * ExecutorCheckPerms_hook signature differs at PG16: before 16 it is
 * (List *rangeTabls, bool abort); 16+ adds List *rteperminfos.
 */
#if PG_VERSION_NUM >= 160000
#define MIC_CHECKPERMS_PROTO(name) \
    static bool name(List *rangeTabls, List *rteperminfos, bool abort)
#define MIC_PERM_ENTRIES(rangeTabls, rteperminfos) \
    mic_perm_entries((rangeTabls), (rteperminfos))
#else
#define MIC_CHECKPERMS_PROTO(name) \
    static bool name(List *rangeTabls, bool abort)
#define MIC_PERM_ENTRIES(rangeTabls, rteperminfos) \
    mic_perm_entries((rangeTabls), NIL)
#endif

/* Defined in dml.c. Returns List* of MicPermEntry*. */
extern List *mic_perm_entries(List *rangeTabls, List *rteperminfos);

#endif                          /* PG_MIC_COMPAT_H */
```

- [ ] **Step 3: Implement `mic_perm_entries` in `dml.c`**

```c
/* 16+ : iterate rteperminfos; pre-16 : iterate rangeTabls RTE_RELATION. */
List *
mic_perm_entries(List *rangeTabls, List *rteperminfos)
{
    List       *out = NIL;
    ListCell   *lc;

#if PG_VERSION_NUM >= 160000
    (void) rangeTabls;
    foreach(lc, rteperminfos)
    {
        RTEPermissionInfo *pi = lfirst_node(RTEPermissionInfo, lc);
        MicPermEntry *e = palloc(sizeof(MicPermEntry));
        e->relid = pi->relid;
        e->requiredPerms = pi->requiredPerms;
        out = lappend(out, e);
    }
#else
    (void) rteperminfos;
    foreach(lc, rangeTabls)
    {
        RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);
        if (rte->rtekind != RTE_RELATION)
            continue;
        MicPermEntry *e = palloc(sizeof(MicPermEntry));
        e->relid = rte->relid;
        e->requiredPerms = rte->requiredPerms;
        out = lappend(out, e);
    }
#endif
    return out;
}
```

- [ ] **Step 4: Rewire `hooks.c` and `dml.c`**

- In `hooks.c`: replace `PG_MODULE_MAGIC_EXT(...)` with `MIC_MODULE_MAGIC`; change the `biba_exec_check_perms`→`mic_exec_check_perms` definition to use `MIC_CHECKPERMS_PROTO(mic_exec_check_perms)`; inside it build entries with `MIC_PERM_ENTRIES(rangeTbls, rteperminfos)` and pass them to `mic_dml_privileges`.
- In `dml.c`: change `mic_dml_privileges` to accept `List *perm_entries` (list of `MicPermEntry*`) instead of `rteperminfos`, and iterate those. Keep the chaining to `next_exec_check_perms_hook` in `hooks.c` version-correct.
- `#include "pg_mic_compat.h"` in both.

- [ ] **Step 5: Build, install, restart, run existing tests**

Run: the Task 2 Step 4–5 build+installcheck commands.
Expected: no warnings; `All 1 tests passed` (behavior unchanged on master).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add pg_mic_compat.h to isolate version-divergent APIs

Abstracts PG_MODULE_MAGIC(_EXT) (PG18) and the ExecutorCheckPerms_hook
signature / RTEPermissionInfo split (PG16) behind a compat header and a
mic_perm_entries() iterator, so the enforcement logic is version-agnostic.
No behavior change on master.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: reach.c core + CHECK-constraint vertical slice

**Files:**
- Create: `reach.c`
- Modify: `Makefile` (add `reach.o`), `meson.build` (add `reach.c`), `pg_mic.h` (declare entry points), `dml.c` (call into reach)
- Test: `sql/pg_mic.sql`, `expected/pg_mic.out`

**Interfaces:**
- Produces:
  - `void mic_check_reachable_functions(Oid relid, AclMode required_ops);`
  - `void mic_check_expr_functions(Node *expr, int subject_level, const char *via, const char *objname);`
  - `void mic_check_one_function(Oid funcid, int subject_level, const char *via, const char *objname);`
- Consumes: `mic_get_subject_level()`, `mic_get_object_level()`, `mic_level_to_string()`, `mic_is_enforcing()`, `mic_debug_audit`, `mic_mode` (from label.c/hooks.c), `MicPermEntry` (compat).

- [ ] **Step 1: Write the failing test (inlinable SQL CHECK)**

Append to `sql/pg_mic.sql` before the Cleanup section a new block. The key assertion: a HIGH subject inserting into a HIGH table whose CHECK calls an **inlinable** LOW SQL function is denied.

```sql
-- ============================================================
-- Reachable-function enforcement: CHECK constraints
-- ============================================================
GRANT CREATE, USAGE ON SCHEMA public TO mic_low_user;
SET ROLE mic_low_user;
-- inlinable SQL function (would be inlined away at runtime)
CREATE FUNCTION public.low_sql_chk(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
RESET ROLE;
CREATE TABLE r_chk (id int CHECK (public.low_sql_chk(id)));
-- HIGH subject INSERT must be denied (CHECK reaches a LOW function)
INSERT INTO r_chk VALUES (1);
-- a built-in-only CHECK must still work for HIGH
CREATE TABLE r_chk_ok (id int CHECK (id >= 0));
INSERT INTO r_chk_ok VALUES (1);
-- a HIGH helper in a CHECK must work for HIGH
CREATE FUNCTION public.high_chk(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;  -- created by superuser => HIGH
CREATE TABLE r_chk_hi (id int CHECK (public.high_chk(id)));
INSERT INTO r_chk_hi VALUES (1);
-- LOW subject fast path: a LOW user inserting is never denied by reachability
GRANT INSERT ON r_chk_ok TO mic_low_user;
SET ROLE mic_low_user;
INSERT INTO r_chk_ok VALUES (2);
RESET ROLE;
```

Add to the Cleanup section: `DROP TABLE r_chk; DROP TABLE r_chk_ok; DROP TABLE r_chk_hi; DROP FUNCTION public.low_sql_chk(int); DROP FUNCTION public.high_chk(int);` (before dropping `mic_low_user`).

- [ ] **Step 2: Run to verify it fails**

Run: `make USE_PGXS=1 PG_CONFIG=$PGC installcheck` then inspect `results/pg_mic.out`.
Expected: the `INSERT INTO r_chk VALUES (1);` **succeeds** (no error) — the gap — so the run differs from the intended expected output. (This is the red state proving the test captures the bug.)

- [ ] **Step 3: Implement `reach.c` core + CHECK enumeration**

```c
#include "postgres.h"
#include "access/genam.h"
#include "access/table.h"
#include "access/transam.h"      /* FirstNormalObjectId */
#include "catalog/pg_class.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"     /* expression_tree_walker */
#include "nodes/nodes.h"
#include "pg_mic.h"
#include "pg_mic_compat.h"
#include "utils/acl.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/relcache.h"

typedef struct FuncCollectCtx { List *funcids; } FuncCollectCtx;

static bool
func_collect_walker(Node *node, FuncCollectCtx *ctx)
{
    if (node == NULL)
        return false;
    switch (nodeTag(node))
    {
        case T_FuncExpr:
            ctx->funcids = lappend_oid(ctx->funcids, ((FuncExpr *) node)->funcid);
            break;
        case T_OpExpr:
        case T_DistinctExpr:
        case T_NullIfExpr:
        {
            OpExpr *op = (OpExpr *) node;
            Oid f = op->opfuncid ? op->opfuncid : get_opcode(op->opno);
            ctx->funcids = lappend_oid(ctx->funcids, f);
            break;
        }
        case T_ScalarArrayOpExpr:
        {
            ScalarArrayOpExpr *sa = (ScalarArrayOpExpr *) node;
            Oid f = sa->opfuncid ? sa->opfuncid : get_opcode(sa->opno);
            ctx->funcids = lappend_oid(ctx->funcids, f);
            break;
        }
        case T_Aggref:
            ctx->funcids = lappend_oid(ctx->funcids, ((Aggref *) node)->aggfnoid);
            break;
        case T_WindowFunc:
            ctx->funcids = lappend_oid(ctx->funcids, ((WindowFunc *) node)->winfnoid);
            break;
        case T_CoerceViaIO:
        {
            /* resolve input/output functions of the involved types */
            CoerceViaIO *c = (CoerceViaIO *) node;
            Oid infn, outfn;
            bool v;
            getTypeInputInfo(c->resulttype, &infn, &v);
            getTypeOutputInfo(exprType((Node *) c->arg), &outfn, &v);
            ctx->funcids = lappend_oid(ctx->funcids, infn);
            ctx->funcids = lappend_oid(ctx->funcids, outfn);
            break;
        }
        default:
            break;
    }
    /* recurse into subqueries too */
    if (IsA(node, Query))
        return query_tree_walker((Query *) node, func_collect_walker, ctx, 0);
    return expression_tree_walker(node, func_collect_walker, ctx);
}

void
mic_check_one_function(Oid funcid, int subject_level,
                       const char *via, const char *objname)
{
    int objlevel;

    if (!OidIsValid(funcid) || funcid < FirstNormalObjectId)
        return;                 /* built-in / system: exempt */

    objlevel = mic_get_object_level(ProcedureRelationId, funcid);

    if (subject_level > objlevel)
    {
        if (mic_debug_audit)
            ereport(LOG,
                    (errmsg("pg_mic: execute denied - subject %s > function %s (func %u) via %s \"%s\"",
                            mic_level_to_string(subject_level),
                            mic_level_to_string(objlevel), funcid, via, objname)));
        if (mic_is_enforcing())
            ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("pg_mic: execute denied - %s integrity subject cannot execute %s integrity function reached via %s \"%s\"",
                            mic_level_to_string(subject_level),
                            mic_level_to_string(objlevel), via, objname)));
        else
            ereport(WARNING,
                    (errmsg("pg_mic: execute violation (permissive) via %s \"%s\"",
                            via, objname)));
    }
}

void
mic_check_expr_functions(Node *expr, int subject_level,
                         const char *via, const char *objname)
{
    FuncCollectCtx ctx = {NIL};
    ListCell   *lc;

    if (expr == NULL)
        return;
    (void) func_collect_walker(expr, &ctx);
    foreach(lc, ctx.funcids)
        mic_check_one_function(lfirst_oid(lc), subject_level, via, objname);
}

/* CHECK constraints (relcache rd_att->constr->check[].ccbin). */
static void
check_check_constraints(Relation rel, int subject_level)
{
    TupleConstr *constr = RelationGetDescr(rel)->constr;
    int i;

    if (constr == NULL || constr->num_check == 0)
        return;
    for (i = 0; i < constr->num_check; i++)
    {
        char   *ccbin = constr->check[i].ccbin;
        Node   *expr;

        if (ccbin == NULL)      /* fail-closed: expected but missing */
            ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("pg_mic: cannot analyze CHECK constraint \"%s\" on \"%s\"",
                            constr->check[i].ccname, RelationGetRelationName(rel))));
        expr = stringToNode(ccbin);
        mic_check_expr_functions(expr, subject_level, "CHECK constraint on",
                                 RelationGetRelationName(rel));
    }
}

void
mic_check_reachable_functions(Oid relid, AclMode required_ops)
{
    int         subject_level;
    Relation    rel;
    bool        need_write = (required_ops & (ACL_INSERT | ACL_UPDATE)) != 0;

    if (mic_mode == MIC_MODE_DISABLED)
        return;

    subject_level = mic_get_subject_level();
    if (subject_level <= MIC_LEVEL_LOW)
        return;                 /* fast path: nothing is below LOW */

    if (relid < FirstNormalObjectId)
        return;                 /* system relation */

    rel = try_table_open(relid, AccessShareLock);
    if (rel == NULL)
        return;

    if (need_write)
        check_check_constraints(rel, subject_level);
    /* subsequent tasks add: triggers, defaults, generated, index, excl, RLS, domain */

    table_close(rel, AccessShareLock);
}
```

Add declarations to `pg_mic.h`; add `reach.o` to `Makefile` OBJS and `reach.c` to `meson.build` sources.

- [ ] **Step 4: Wire into `dml.c`**

In `mic_dml_privileges`, after the existing per-relation table read/write check, add:
```c
mic_check_reachable_functions(e->relid, e->requiredPerms);
```
(where `e` is the current `MicPermEntry *`). Keep it under the same `IsCatalogRelationOid`/system-OID skips already present.

- [ ] **Step 5: Build, install, restart, run; update expected**

Run: build+install+restart, then `installcheck`.
Expected: `INSERT INTO r_chk VALUES (1);` now errors `pg_mic: execute denied … reached via CHECK constraint on "r_chk"`; the built-in CHECK, HIGH-helper CHECK, and LOW fast-path inserts all succeed. Then:
```bash
cp results/pg_mic.out expected/pg_mic.out   # after confirming the diff is exactly the intended behavior
make USE_PGXS=1 PG_CONFIG=$PGC installcheck  # clean pass
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
reach.c: static reachable-function check, CHECK constraints

Adds mic_check_reachable_functions() driven from ExecutorCheckPerms. Reads
stored CHECK expressions from the relcache and denies execution of any
reachable function below the subject's level (fail-closed). Immune to SQL
inlining because it reads the stored node tree. Includes the LOW-subject
fast path and built-in exemption.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Triggers (by event)

**Files:**
- Modify: `reach.c` (add `check_triggers`), `sql/pg_mic.sql`, `expected/pg_mic.out`

**Interfaces:**
- Consumes: `mic_check_one_function`. Produces: trigger coverage inside `mic_check_reachable_functions`.

- [ ] **Step 1: Write the failing test**

Append to `sql/pg_mic.sql` (before Cleanup):
```sql
-- ============================================================
-- Reachable-function enforcement: triggers (by event)
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_trig() RETURNS trigger
    AS 'BEGIN RETURN NEW; END' LANGUAGE plpgsql;
CREATE FUNCTION public.low_trig_del() RETURNS trigger
    AS 'BEGIN RETURN OLD; END' LANGUAGE plpgsql;
RESET ROLE;
CREATE TABLE r_trg (id int);
CREATE TRIGGER t_ins BEFORE INSERT ON r_trg
    FOR EACH ROW EXECUTE FUNCTION public.low_trig();
CREATE TRIGGER t_del BEFORE DELETE ON r_trg
    FOR EACH ROW EXECUTE FUNCTION public.low_trig_del();
-- INSERT denied (LOW insert trigger)
INSERT INTO r_trg VALUES (1);
-- event filtering: DELETE must NOT be blocked by the INSERT trigger,
-- but IS blocked by the LOW delete trigger
DELETE FROM r_trg WHERE id = 1;
```
Cleanup additions: `DROP TABLE r_trg; DROP FUNCTION public.low_trig(); DROP FUNCTION public.low_trig_del();`

- [ ] **Step 2: Run to verify it fails**

Run: `installcheck`; inspect `results/pg_mic.out`.
Expected: both the INSERT and DELETE succeed (triggers not yet covered).

- [ ] **Step 3: Implement `check_triggers`**

```c
#include "commands/trigger.h"   /* TriggerDesc, TRIGGER_FOR_* */
#include "utils/reltrigger.h"   /* if needed for TriggerDesc fields */

static void
check_triggers(Relation rel, int subject_level, AclMode required_ops)
{
    TriggerDesc *td = rel->trigdesc;
    int i;

    if (td == NULL)
        return;
    for (i = 0; i < td->numtriggers; i++)
    {
        Trigger *tg = &td->triggers[i];
        int16 t = tg->tgtype;
        bool want = false;

        if ((required_ops & ACL_INSERT) && TRIGGER_FOR_INSERT(t)) want = true;
        if ((required_ops & ACL_UPDATE) && TRIGGER_FOR_UPDATE(t)) want = true;
        if ((required_ops & ACL_DELETE) && TRIGGER_FOR_DELETE(t)) want = true;
        if (!want)
            continue;
        mic_check_one_function(tg->tgfoid, subject_level,
                               "trigger on", RelationGetRelationName(rel));
    }
}
```
Call it from `mic_check_reachable_functions` (pass `required_ops`).

- [ ] **Step 4: Build, install, restart, run**

Expected: INSERT denied (`via trigger on "r_trg"`); DELETE denied by the delete trigger; crucially the INSERT trigger does NOT block the DELETE path (only the delete trigger does). Confirm message cites the right trigger function.

- [ ] **Step 5: Update expected + clean pass**

`cp results/pg_mic.out expected/pg_mic.out` after confirming; re-run `installcheck` → pass.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "$(cat <<'EOF'
reach.c: cover triggers, filtered by event

Checks pg_trigger tgfoid for triggers matching the operation's event bits,
closing the gap where trigger.c never invokes the function-execute hook.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Defaults and generated columns (STORED + VIRTUAL)

**Files:**
- Modify: `reach.c` (add `check_defaults_and_generated`), `sql/pg_mic.sql`, `expected/pg_mic.out`

**Interfaces:**
- Consumes: `mic_check_expr_functions`. Produces: default/generated coverage.

- [ ] **Step 1: Write the failing test**

```sql
-- ============================================================
-- Reachable-function enforcement: defaults and generated columns
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_def() RETURNS int AS 'SELECT 7' LANGUAGE sql IMMUTABLE;
CREATE FUNCTION public.low_gen(int) RETURNS int AS 'SELECT $1 * 2' LANGUAGE sql IMMUTABLE;
RESET ROLE;
-- DEFAULT reaches a LOW function on INSERT
CREATE TABLE r_def (id int DEFAULT public.low_def());
INSERT INTO r_def DEFAULT VALUES;
-- STORED generated column reaches a LOW function on write
CREATE TABLE r_gs (id int, g int GENERATED ALWAYS AS (public.low_gen(id)) STORED);
INSERT INTO r_gs (id) VALUES (1);
```
Add a VIRTUAL case guarded for PG18+ (Task 16 handles version-specific expected output; include it now so 18+/master exercises it):
```sql
-- VIRTUAL generated column reaches a LOW function on READ (PG18+)
CREATE TABLE r_gv (id int, g int GENERATED ALWAYS AS (public.low_gen(id)) VIRTUAL);
INSERT INTO r_gv (id) VALUES (1);      -- allowed by HIGH? stored? virtual not computed on write
SELECT g FROM r_gv;                    -- denied: virtual gen computed on read
```
Cleanup additions: `DROP TABLE r_def; DROP TABLE r_gs; DROP TABLE r_gv; DROP FUNCTION public.low_def(); DROP FUNCTION public.low_gen(int);`

- [ ] **Step 2: Run to verify it fails**

Expected: default INSERT and generated writes succeed (uncovered); `SELECT g FROM r_gv` succeeds.

- [ ] **Step 3: Implement**

```c
#include "catalog/pg_attribute.h"
#include "access/tupdesc.h"

static void
check_defaults_and_generated(Relation rel, int subject_level, AclMode required_ops)
{
    TupleDesc   td = RelationGetDescr(rel);
    TupleConstr *constr = td->constr;
    bool        is_read = (required_ops & ACL_SELECT) != 0;
    bool        is_write = (required_ops & (ACL_INSERT | ACL_UPDATE)) != 0;
    int         i;

    if (constr == NULL || constr->num_defval == 0)
        return;
    for (i = 0; i < constr->num_defval; i++)
    {
        AttrDefault *d = &constr->defval[i];
        Form_pg_attribute att = TupleDescAttr(td, d->adnum - 1);
        char        gen = att->attgenerated;   /* '\0', 's' (stored), 'v' (virtual, PG18+) */
        Node       *expr;
        bool        want;

        /* plain default and STORED generated => write; VIRTUAL generated => read (and write for RETURNING) */
        if (gen == ATTRIBUTE_GENERATED_STORED)
            want = is_write;
#if PG_VERSION_NUM >= 180000
        else if (gen == ATTRIBUTE_GENERATED_VIRTUAL)
            want = is_read || is_write;
#endif
        else
            want = is_write;    /* plain column DEFAULT */

        if (!want || d->adbin == NULL)
            continue;
        expr = stringToNode(d->adbin);
        mic_check_expr_functions(expr, subject_level,
                                 (gen ? "generated column on" : "column default on"),
                                 RelationGetRelationName(rel));
    }
}
```
Call from `mic_check_reachable_functions` with `required_ops`.

- [ ] **Step 4–6: Build/run/update-expected/commit** (same cycle as Task 5)

Commit message subject: `reach.c: cover column defaults and STORED/VIRTUAL generated columns`.

---

## Task 7: Index expressions and predicates (all operations)

**Files:**
- Modify: `reach.c` (`check_index_exprs`), `sql/pg_mic.sql`, `expected/pg_mic.out`

- [ ] **Step 1: Write the failing test**

```sql
-- ============================================================
-- Reachable-function enforcement: index expressions / predicates
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_ident(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
RESET ROLE;
CREATE TABLE r_idx (id int);
CREATE INDEX r_idx_e ON r_idx (public.low_ident(id));
INSERT INTO r_idx VALUES (1);          -- denied: index maintenance
-- partial-index predicate evaluated by planner on SELECT (scratch.txt vector)
CREATE TABLE r_idxp (id int);
CREATE INDEX r_idxp_p ON r_idxp (id) WHERE public.low_ident(id) > 0;
SELECT count(*) FROM r_idxp;           -- denied: planner evaluates predicate
```
Cleanup: `DROP TABLE r_idx; DROP TABLE r_idxp; DROP FUNCTION public.low_ident(int);`

- [ ] **Step 2: Run to verify it fails** (inserts/selects succeed).

- [ ] **Step 3: Implement**

```c
static void
check_index_exprs(Relation rel, int subject_level)
{
    List       *indexoids = RelationGetIndexList(rel);
    ListCell   *lc;

    foreach(lc, indexoids)
    {
        Oid         indexoid = lfirst_oid(lc);
        Relation    irel = index_open(indexoid, AccessShareLock);
        List       *exprs = RelationGetIndexExpressions(irel);
        List       *pred = RelationGetIndexPredicate(irel);
        ListCell   *l2;

        foreach(l2, exprs)
            mic_check_expr_functions((Node *) lfirst(l2), subject_level,
                                     "index expression on", RelationGetRelationName(rel));
        foreach(l2, pred)
            mic_check_expr_functions((Node *) lfirst(l2), subject_level,
                                     "index predicate on", RelationGetRelationName(rel));
        index_close(irel, AccessShareLock);
    }
}
```
Add `#include "access/genam.h"` / `"nodes/execnodes.h"` and `index_open`/`index_close` via `"access/relation.h"`. Call for **all** ops (unconditional in `mic_check_reachable_functions`, since planner proof affects SELECT).

- [ ] **Step 4–6: Build/run/update-expected/commit.** Subject: `reach.c: cover index expressions and predicates on all operations`.

---

## Task 8: Exclusion operators and domain CHECK

**Files:**
- Modify: `reach.c` (`check_exclusion_ops`, `check_domain_checks`), `sql/pg_mic.sql`, `expected/pg_mic.out`

- [ ] **Step 1: Write the failing test**

```sql
-- ============================================================
-- Reachable-function enforcement: domain CHECK (type-level)
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_domchk(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
CREATE DOMAIN public.low_dom AS int CHECK (public.low_domchk(VALUE));
RESET ROLE;
CREATE TABLE r_dom (id public.low_dom);
INSERT INTO r_dom VALUES (1);          -- denied: domain CHECK reaches LOW fn
```
Cleanup: `DROP TABLE r_dom; DROP DOMAIN public.low_dom; DROP FUNCTION public.low_domchk(int);`
(Exclusion-operator case: add a gist/btree_gist-free example only if a built-in opclass with a user function is feasible; otherwise cover exclusion via the same conexclop path in code and rely on the operator's opcode check. A dedicated SQL case is optional; the code path is implemented and exercised indirectly by the operator-collection in the walker.)

- [ ] **Step 2: Run to verify it fails** (domain INSERT succeeds).

- [ ] **Step 3: Implement**

Domain CHECK — for each attribute whose type is a domain, read `pg_constraint` rows with `contypid = <domain oid>` and `contype = 'c'`, `stringToNode(conbin)`, and check:
```c
#include "catalog/pg_constraint.h"
#include "catalog/pg_type.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

static void
check_domain_of_type(Oid typid, int subject_level, const char *relname)
{
    if (get_typtype(typid) != TYPTYPE_DOMAIN)
        return;
    /* scan pg_constraint by contypid */
    {
        Relation    conrel = table_open(ConstraintRelationId, AccessShareLock);
        ScanKeyData skey;
        SysScanDesc scan;
        HeapTuple   tup;

        ScanKeyInit(&skey, Anum_pg_constraint_contypid,
                    BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typid));
        scan = systable_beginscan(conrel, ConstraintTypidIndexId, true,
                                  NULL, 1, &skey);
        while (HeapTupleIsValid(tup = systable_getnext(scan)))
        {
            Form_pg_constraint c = (Form_pg_constraint) GETSTRUCT(tup);
            Datum       val;
            bool        isnull;

            if (c->contype != CONSTRAINT_CHECK)
                continue;
            val = heap_getattr(tup, Anum_pg_constraint_conbin,
                               RelationGetDescr(conrel), &isnull);
            if (isnull)
                ereport(ERROR,
                        (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                         errmsg("pg_mic: cannot analyze domain constraint on \"%s\"", relname)));
            mic_check_expr_functions(stringToNode(TextDatumGetCString(val)),
                                     subject_level, "domain CHECK on", relname);
        }
        systable_endscan(scan);
        table_close(conrel, AccessShareLock);
    }
}

static void
check_domain_checks(Relation rel, int subject_level)
{
    TupleDesc td = RelationGetDescr(rel);
    int i;
    for (i = 0; i < td->natts; i++)
    {
        Form_pg_attribute att = TupleDescAttr(td, i);
        if (att->attisdropped) continue;
        check_domain_of_type(att->atttypid, subject_level, RelationGetRelationName(rel));
    }
}
```
Exclusion operators — read `pg_constraint` rows with `conrelid = relid`, `contype = 'x'`, decode `conexclop` (oidvector of operator OIDs), `get_opcode` each, and `mic_check_one_function`. Implement `check_exclusion_ops(Relation, int)` analogously (scan by `conrelid`). Call domain+exclusion for write ops.

- [ ] **Step 4–6: Build/run/update-expected/commit.** Subject: `reach.c: cover domain CHECK and exclusion-constraint operators`.

---

## Task 9: RLS policies

**Files:**
- Modify: `reach.c` (`check_rls_policies`), `sql/pg_mic.sql`, `expected/pg_mic.out`

- [ ] **Step 1: Write the failing test**

```sql
-- ============================================================
-- Reachable-function enforcement: RLS policies
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_rls(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql STABLE;
RESET ROLE;
CREATE TABLE r_rls (id int);
ALTER TABLE r_rls ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_sel ON r_rls FOR SELECT USING (public.low_rls(id));
INSERT INTO r_rls VALUES (1);          -- (as table owner/superuser; RLS may be bypassed by owner)
-- force RLS so the USING qual is applied even for the owner
ALTER TABLE r_rls FORCE ROW LEVEL SECURITY;
SELECT count(*) FROM r_rls;            -- denied: USING qual reaches LOW fn
```
Cleanup: `DROP TABLE r_rls; DROP FUNCTION public.low_rls(int);`

- [ ] **Step 2: Run to verify it fails** (SELECT succeeds).

- [ ] **Step 3: Implement**

```c
#include "rewrite/rowsecurity.h"

static void
check_rls_policies(Relation rel, int subject_level, AclMode required_ops)
{
    RowSecurityDesc *rsd = rel->rd_rsdesc;
    ListCell   *lc;
    bool        is_read = (required_ops & (ACL_SELECT | ACL_DELETE | ACL_UPDATE)) != 0;
    bool        is_write = (required_ops & (ACL_INSERT | ACL_UPDATE)) != 0;

    if (rsd == NULL)
        return;
    foreach(lc, rsd->policies)
    {
        RowSecurityPolicy *p = (RowSecurityPolicy *) lfirst(lc);
        if (is_read && p->qual)
            mic_check_expr_functions((Node *) p->qual, subject_level,
                                     "RLS USING policy on", RelationGetRelationName(rel));
        if (is_write && p->with_check_qual)
            mic_check_expr_functions((Node *) p->with_check_qual, subject_level,
                                     "RLS WITH CHECK policy on", RelationGetRelationName(rel));
    }
}
```
Note: `rd_rsdesc` is built lazily; ensure it is populated (query the relation under RLS or call the relcache builder). If `rd_rsdesc` is NULL while `relhasrowsecurity` is true, fail-closed is unnecessary here because the executor will have built it; if not built, fall back to scanning `pg_policy` by `polrelid` and `stringToNode(polqual/polwithcheck)`. Implement the `pg_policy` scan fallback to be safe.

- [ ] **Step 4–6: Build/run/update-expected/commit.** Subject: `reach.c: cover RLS USING and WITH CHECK policies`.

---

## Task 10: Utility path — COPY and TRUNCATE triggers

**Files:**
- Modify: `hooks.c` (`mic_utility_command`), `reach.c` (reuse entry point), `sql/pg_mic.sql`, `expected/pg_mic.out`

**Interfaces:**
- Consumes: `mic_check_reachable_functions`. Produces: utility-path gating for COPY/TRUNCATE.

- [ ] **Step 1: Write the failing test**

```sql
-- ============================================================
-- Utility path: COPY FROM and TRUNCATE triggers
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_copychk(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
CREATE FUNCTION public.low_trunc() RETURNS trigger
    AS 'BEGIN RETURN NULL; END' LANGUAGE plpgsql;
RESET ROLE;
CREATE TABLE r_copy (id int CHECK (public.low_copychk(id)));
COPY r_copy FROM STDIN;
1
\.
-- expect denial before/at COPY due to LOW CHECK
CREATE TABLE r_trunc (id int);
CREATE TRIGGER t_tr BEFORE TRUNCATE ON r_trunc
    FOR EACH STATEMENT EXECUTE FUNCTION public.low_trunc();
TRUNCATE r_trunc;                      -- denied: LOW truncate trigger
```
Cleanup: `DROP TABLE r_copy; DROP TABLE r_trunc; DROP FUNCTION public.low_copychk(int); DROP FUNCTION public.low_trunc();`

- [ ] **Step 2: Run to verify it fails** (COPY and TRUNCATE succeed).

- [ ] **Step 3: Implement in `mic_utility_command`**

Before delegating to the next hook / `standard_ProcessUtility`, inspect `parsetree`:
```c
switch (nodeTag(parsetree))
{
    case T_CopyStmt:
    {
        CopyStmt *cs = (CopyStmt *) parsetree;
        if (cs->relation)   /* COPY table, not COPY (query) */
        {
            Oid relid = RangeVarGetRelid(cs->relation, AccessShareLock, true);
            if (OidIsValid(relid))
                mic_check_reachable_functions(relid, cs->is_from ? ACL_INSERT : ACL_SELECT);
        }
        break;
    }
    case T_TruncateStmt:
    {
        TruncateStmt *ts = (TruncateStmt *) parsetree;
        ListCell *lc;
        foreach(lc, ts->relations)
        {
            RangeVar *rv = lfirst_node(RangeVar, lc);
            Oid relid = RangeVarGetRelid(rv, AccessShareLock, true);
            if (OidIsValid(relid))
                mic_check_reachable_functions(relid, ACL_DELETE);  /* fires TRUNCATE triggers */
        }
        break;
    }
    default:
        break;
}
```
Extend `check_triggers` to also match TRUNCATE triggers when invoked from the truncate path. Simplest: add a `bool truncate` parameter, or a separate `required_ops` sentinel. Implement by adding `TRIGGER_FOR_TRUNCATE(t)` handling: when `required_ops == ACL_DELETE` from TRUNCATE we want TRUNCATE triggers — distinguish TRUNCATE by passing an explicit flag `mic_check_reachable_functions(relid, ACL_DELETE)` plus a new internal variant, OR add `TRIGGER_FOR_TRUNCATE` to the DELETE branch guarded by a `from_truncate` flag threaded through. Choose: add `mic_check_truncate_triggers(Oid relid)` dedicated helper to avoid overloading DELETE semantics.

Use the dedicated helper for TRUNCATE:
```c
void mic_check_truncate_triggers(Oid relid);  /* in pg_mic.h */
```
implemented to open the rel, iterate trigdesc for `TRIGGER_FOR_TRUNCATE(tg->tgtype)`, and `mic_check_one_function`.

- [ ] **Step 4–6: Build/run/update-expected/commit.** Subject: `reach.c/hooks.c: gate COPY FROM/TO and TRUNCATE triggers on the utility path`.

---

## Task 11: Utility path — CREATE INDEX / REINDEX

**Files:**
- Modify: `hooks.c` (`mic_utility_command`), `sql/pg_mic.sql`, `expected/pg_mic.out`

- [ ] **Step 1: Write the failing test**

```sql
-- ============================================================
-- Utility path: CREATE INDEX / REINDEX over existing rows
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_ixbuild(int) RETURNS int AS 'SELECT $1' LANGUAGE sql IMMUTABLE;
RESET ROLE;
CREATE TABLE r_ixb (id int);
INSERT INTO r_ixb SELECT g FROM generate_series(1,3) g;   -- rows present (no index yet)
-- building an expression index over existing rows runs the LOW function
CREATE INDEX r_ixb_e ON r_ixb (public.low_ixbuild(id));   -- denied
```
Cleanup: `DROP TABLE r_ixb; DROP FUNCTION public.low_ixbuild(int);`

- [ ] **Step 2: Run to verify it fails** (CREATE INDEX succeeds).

- [ ] **Step 3: Implement**

In `mic_utility_command`, handle `T_IndexStmt` and `T_ReindexStmt`:
- `IndexStmt`: resolve `relation` → relid; walk the statement's index element expressions and `whereClause`. The parse-tree expressions are raw; the simplest robust approach is to check after the relation is resolved by walking `indexParams` (`IndexElem.expr`) and `whereClause` with `mic_check_expr_functions` (they are already analyzed expressions in the `IndexStmt` at ProcessUtility time for non-`CONCURRENTLY`? They are raw parse nodes — may contain `FuncCall`, not `FuncExpr`). Because raw parse nodes name functions as `FuncCall` (unresolved), resolve via a dedicated walker that, on `T_FuncCall`, looks up the function by name+nargs (`LookupFuncName`) and checks it. Implement `mic_check_rawexpr_functions(Node *raw, int subject_level, via, objname)` using `raw_expression_tree_walker` and handling `T_FuncCall` (resolve) and `T_A_Expr` operators (resolve operator). Simpler and version-robust alternative: let the index be created, then in an `OAT_POST_CREATE` for `RelationRelationId` of kind index we already ignore; instead check after creation by reading the finished index's `indexprs`/`indpred` (now resolved) and the table's existing rows exist → but it is already built. Therefore prefer the pre-exec raw check.

Implement `mic_check_rawexpr_functions` using `raw_expression_tree_walker`:
```c
#include "parser/parse_func.h"   /* LookupFuncName */
#include "nodes/parsenodes.h"

static bool
raw_func_walker(Node *node, RawCtx *ctx)
{
    if (node == NULL) return false;
    if (IsA(node, FuncCall))
    {
        FuncCall *fc = (FuncCall *) node;
        Oid f = LookupFuncName(fc->funcname, -1, NULL, true); /* best-effort */
        if (OidIsValid(f))
            ctx->funcids = lappend_oid(ctx->funcids, f);
    }
    /* A_Expr operator name resolution omitted for brevity; handle if needed */
    return raw_expression_tree_walker(node, raw_func_walker, ctx);
}
```
Walk `IndexStmt.indexParams` element `expr` and `IndexStmt.whereClause`.
- `ReindexStmt`: resolve the target (index or table). For a target index, open it and reuse `RelationGetIndexExpressions`/`Predicate` (resolved) → `mic_check_expr_functions`. For a table target, run `check_index_exprs` on the table.

- [ ] **Step 4–6: Build/run/update-expected/commit.** Subject: `hooks.c: gate CREATE INDEX / REINDEX expression builds`.

---

## Task 12: Utility path — ALTER TABLE (rewrite/validate subcommands)

**Files:**
- Modify: `hooks.c` (`mic_utility_command`), `sql/pg_mic.sql`, `expected/pg_mic.out`

- [ ] **Step 1: Write the failing test**

```sql
-- ============================================================
-- Utility path: ALTER TABLE ADD CONSTRAINT validating existing rows
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_atchk(int) RETURNS boolean AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
RESET ROLE;
CREATE TABLE r_at (id int);
INSERT INTO r_at VALUES (1);
ALTER TABLE r_at ADD CONSTRAINT c_chk CHECK (public.low_atchk(id));  -- denied: validates rows
```
Cleanup: `DROP TABLE r_at; DROP FUNCTION public.low_atchk(int);`

- [ ] **Step 2: Run to verify it fails** (ALTER succeeds).

- [ ] **Step 3: Implement**

Handle `T_AlterTableStmt`: resolve `relation` → relid. Iterate `cmds` (`AlterTableCmd`); for the enumerated code-executing subtypes, walk their embedded raw expressions with `mic_check_rawexpr_functions` and, for validating/rewriting subtypes, also call `mic_check_reachable_functions(relid, ACL_INSERT|ACL_UPDATE)`:
```c
case T_AlterTableStmt:
{
    AlterTableStmt *at = (AlterTableStmt *) parsetree;
    Oid relid = AlterTableLookupRelation(at, AccessShareLock); /* or RangeVarGetRelid */
    ListCell *lc;
    foreach(lc, at->cmds)
    {
        AlterTableCmd *cmd = lfirst_node(AlterTableCmd, lc);
        switch (cmd->subtype)
        {
            case AT_AddConstraint:
            case AT_ValidateConstraint:
            case AT_AlterColumnType:     /* USING expr */
            case AT_ColumnDefault:
            case AT_CookedColumnDefault:
#if PG_VERSION_NUM >= 180000
            case AT_SetExpression:
#endif
                if (cmd->def)
                    mic_check_rawexpr_functions(cmd->def, mic_get_subject_level(),
                                                "ALTER TABLE on", get_rel_name(relid));
                mic_check_reachable_functions(relid, ACL_INSERT | ACL_UPDATE);
                break;
            default:
                break;
        }
    }
    break;
}
```
(Confirm exact `AT_*` enum names for the target version; guard `AT_SetExpression` for PG18+.)

- [ ] **Step 4–6: Build/run/update-expected/commit.** Subject: `hooks.c: gate ALTER TABLE rewrite/validate subcommands`.

---

## Task 13: Bulk extension promotion (mic_promote_extension)

**Files:**
- Modify: `promote.c`, `pg_mic--1.0.sql`, `sql/pg_mic.sql`, `expected/pg_mic.out`, `README.md`

**Interfaces:**
- Produces SQL function `mic_promote_extension(ext_name text, new_level text) RETURNS integer`.

- [ ] **Step 1: Write the failing test**

```sql
-- ============================================================
-- Bulk extension promotion
-- ============================================================
-- A LOW user installs a (trusted) extension; its functions are labeled LOW.
-- We simulate "an extension" with a small SQL-only extension if available;
-- otherwise test the membership scan against an installed contrib extension.
-- Minimal deterministic test: create a schema of objects tied to an
-- extension via CREATE EXTENSION of a trivial control (see fixtures), then:
SELECT mic_promote_extension('pg_mic', 'high') >= 0 AS promoted_count_nonneg;
-- non-superuser cannot call it
SET ROLE mic_low_user;
SELECT mic_promote_extension('pg_mic', 'high');   -- ERROR: superuser only
RESET ROLE;
-- invalid level rejected
SELECT mic_promote_extension('pg_mic', 'bogus');  -- ERROR: invalid level
```
(The deterministic membership assertion — that a LOW extension's functions become HIGH — is exercised in the TAP/e2e task where a fixture extension can be installed by a LOW role. Here assert the guards and that it runs and returns a count.)

- [ ] **Step 2: Run to verify it fails** (`mic_promote_extension` undefined).

- [ ] **Step 3: Implement in `promote.c`**

```c
#include "catalog/dependency.h"
#include "catalog/pg_depend.h"
#include "catalog/pg_extension.h"
#include "commands/extension.h"
#include "commands/seclabel.h"
#include "utils/fmgroids.h"

PG_FUNCTION_INFO_V1(mic_promote_extension);
Datum
mic_promote_extension(PG_FUNCTION_ARGS)
{
    char       *extname = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char       *level   = text_to_cstring(PG_GETARG_TEXT_PP(1));
    Oid         extoid;
    Relation    deprel;
    ScanKeyData skey[2];
    SysScanDesc scan;
    HeapTuple   tup;
    int         count = 0;

    if (!superuser())
        ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
            errmsg("pg_mic: only superuser can promote extensions")));
    if (mic_level_from_string(level) == MIC_LEVEL_INVALID)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
            errmsg("pg_mic: \"%s\" is not a valid integrity level", level),
            errhint("Valid levels are: low, medium, high.")));

    extoid = get_extension_oid(extname, false);

    deprel = table_open(DependRelationId, AccessShareLock);
    ScanKeyInit(&skey[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber,
                F_OIDEQ, ObjectIdGetDatum(ExtensionRelationId));
    ScanKeyInit(&skey[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber,
                F_OIDEQ, ObjectIdGetDatum(extoid));
    scan = systable_beginscan(deprel, DependReferenceIndexId, true, NULL, 2, skey);
    while (HeapTupleIsValid(tup = systable_getnext(scan)))
    {
        Form_pg_depend dep = (Form_pg_depend) GETSTRUCT(tup);
        ObjectAddress obj;

        if (dep->deptype != DEPENDENCY_EXTENSION)
            continue;
        obj.classId = dep->classid;
        obj.objectId = dep->objid;
        obj.objectSubId = dep->objsubid;

        /* Only label classes that support security labels; skip others. */
        if (!mic_class_supports_seclabel(obj.classId))
        {
            if (mic_debug_audit)
                ereport(LOG, (errmsg("pg_mic: skipping unlabelable member class %u obj %u",
                                     obj.classId, obj.objectId)));
            continue;
        }
        SetSecurityLabel(&obj, MIC_LABEL_TAG, level);
        count++;
    }
    systable_endscan(scan);
    table_close(deprel, AccessShareLock);

    PG_RETURN_INT32(count);
}
```
Implement `mic_class_supports_seclabel(Oid classId)` returning true for the classes we know support labels (relations `RelationRelationId`, functions `ProcedureRelationId`, types `TypeRelationId`, schemas `NamespaceRelationId`, and the other classes accepted by the core seclabel code). Keep it conservative: label those, skip the rest.

Add the SQL declaration to `pg_mic--1.0.sql`:
```sql
CREATE FUNCTION mic_promote_extension(ext_name text, new_level text)
RETURNS integer
AS 'MODULE_PATHNAME', 'mic_promote_extension'
LANGUAGE C STRICT VOLATILE;
```

- [ ] **Step 4–6: Build/run/update-expected/commit.** Subject: `promote.c: add mic_promote_extension() for bulk vetting`.

---

## Task 14: TAP tests — preload requirement and mode switching

**Files:**
- Create: `t/001_preload.pl`, `t/002_modes.pl`
- Modify: `Makefile` (TAP_TESTS = 1 / `tap_check` wiring), `meson.build` (tap test entry)

**Interfaces:** none (black-box cluster tests).

- [ ] **Step 1: Write `t/001_preload.pl`**

Start a node WITHOUT `shared_preload_libraries`, attempt `CREATE EXTENSION pg_mic`, assert it fails because the module errors unless preloaded (or that loading errors). Then start a node WITH the preload and assert `CREATE EXTENSION` succeeds and `SHOW mic.mode` returns `enforcing`.

```perl
use strict; use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('mic_preload');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_mic'");
$node->start;
my ($rc, $out, $err) = $node->psql('postgres', 'CREATE EXTENSION pg_mic; SHOW mic.mode;');
is($rc, 0, 'CREATE EXTENSION works when preloaded');
like($out, qr/enforcing/, 'mic.mode defaults to enforcing');
$node->stop;
done_testing();
```

- [ ] **Step 2: Write `t/002_modes.pl`**

With a preloaded node and extension, create a LOW role and a LOW function in a HIGH table's CHECK; assert:
- enforcing: HIGH INSERT denied;
- `ALTER SYSTEM SET mic.mode='permissive'; SELECT pg_reload_conf();` then HIGH INSERT emits a WARNING and succeeds;
- `mic.mode='disabled'` then HIGH INSERT succeeds silently.
Also include an "unanalyzable attachment" case is not easily forced; instead assert permissive downgrades a normal denial to a warning (covers the fail-closed-in-permissive path).

- [ ] **Step 3: Wire TAP into the build**

In `Makefile` add `TAP_TESTS = 1`. In `meson.build` add a `tap` kwarg entry listing `t/001_preload.pl`, `t/002_modes.pl`.

- [ ] **Step 4: Run**

Run: `make USE_PGXS=1 PG_CONFIG=$PGC installcheck` (TAP tests also need `PROVE`/cluster; run `make … check` or the TAP target). Use:
```bash
make USE_PGXS=1 PG_CONFIG=$PGC PROVE_FLAGS="--verbose" installcheck
```
Expected: TAP tests pass.

- [ ] **Step 5: Commit.** Subject: `tests: TAP coverage for preload requirement and mic.mode switching`.

---

## Task 15: End-to-end confused-deputy regression

**Files:**
- Create: `t/003_confused_deputy.pl`
- Modify: `meson.build`, `Makefile` (TAP list)

- [ ] **Step 1: Write the TAP test** replaying the original scratch.txt attack:
  a LOW role (`joe`) with `CREATE` on `public` plants `poc_shared_data`, a sequence naming a large object, a LOW `poc_exfil()` that reads `pg_authid` into the LO, and a partial index whose predicate calls it; `GRANT SELECT ... TO PUBLIC`. Then as the superuser run `SELECT 1 FROM public.poc_shared_data LIMIT 1;` and assert it ERRORs with `pg_mic: execute denied`. Finally read the large object back and assert **0 bytes**.

```perl
# ... init+preload+CREATE EXTENSION pg_mic; CREATE ROLE joe; GRANT CREATE ON SCHEMA public TO joe;
my ($rc,$out,$err) = $node->psql('postgres', q{SELECT 1 FROM public.poc_shared_data LIMIT 1;});
isnt($rc, 0, 'HIGH SELECT on baited table is denied');
like($err, qr/pg_mic: execute denied/, 'denied at function execution');
my ($rc2,$bytes) = $node->psql('postgres',
    q{SET SESSION AUTHORIZATION joe;
      SELECT octet_length(loread(lo_open((SELECT last_value FROM public.poc_exfil_oid)::oid,262144),1000000));});
like($bytes, qr/^\s*0\s*$/, 'no credentials exfiltrated');
```

- [ ] **Step 2: Wire into TAP list; run; expect pass.**

- [ ] **Step 3: Commit.** Subject: `tests: end-to-end confused-deputy attack is blocked (0 bytes exfiltrated)`.

---

## Task 16: Multi-version validation and version-specific expected output

**Files:**
- Create: `expected/pg_mic_1.out` (only if output legitimately differs on an older major), a helper script `tools/test-all-versions.sh`
- Modify: `meson.build`/`Makefile` regress `alternative output` wiring if needed

**Interfaces:** none (build/test infrastructure).

- [ ] **Step 1: Create per-version worktrees of the designated repo**

```bash
cd ~/projects/claude/pgsql/postgresql
for br in REL_17_STABLE REL_16_STABLE; do
  git worktree add ../pg-$br $br
done
```
(Extend to all supported majors; REL_17 and REL_16 at minimum exercise the PG16 hook boundary. REL_18+ exercise VIRTUAL generated; master already tested.)

- [ ] **Step 2: Build+install each version to its own prefix**

For each worktree: `./configure --prefix=$HOME/projects/claude/pgsql/pg-install-$br --without-icu ... && make -j && make install` (same configure flags as master; see spec Global Constraints). Record each `pg_config`.

- [ ] **Step 3: Build pg_mic against each and run installcheck**

```bash
for p in $HOME/projects/claude/pgsql/pg-install-REL_17_STABLE $HOME/projects/claude/pgsql/pg-install-REL_16_STABLE; do
  make USE_PGXS=1 PG_CONFIG=$p/bin/pg_config clean
  make USE_PGXS=1 PG_CONFIG=$p/bin/pg_config && make USE_PGXS=1 PG_CONFIG=$p/bin/pg_config install
  # init+preload a cluster from $p, then:
  make USE_PGXS=1 PG_CONFIG=$p/bin/pg_config installcheck
done
```
Expected: compiles on every version (compat header does its job); tests pass. Where VIRTUAL-generated-column lines in `sql/pg_mic.sql` cannot run (<PG18), provide an alternative expected file (`expected/pg_mic_1.out`) OR gate those SQL lines with a server-version `\if` in the test. Prefer `\if` guards keyed on `current_setting('server_version_num')::int >= 180000` so one `.sql` serves all versions; add the alternate `.out` only if a diff is otherwise unavoidable.

- [ ] **Step 4: Commit** the version-guard adjustments and any alternate expected file. Subject: `tests: validate build and regression across PG16/17/18/master`.

---

## Task 17: Documentation, limitations, and push-readiness

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

- Rename/branding: `pg_mic` throughout; one line on the Biba lineage.
- New "Function execution" enforcement subsection (No Read Down on functions; built-ins exempt; indirect paths covered: triggers, CHECK, defaults, generated, index expr/pred, exclusion, RLS, domain).
- "Vetting and promoting a trusted extension" usage section with `mic_promote_extension('ext', 'high')`.
- "Supported versions" (PG14–master) and "Limitations and non-escapes" (§12 of the spec: nested inlined SQL is a non-escape; utility path is an enumerated set; base-type I/O requires superuser so is HIGH).

- [ ] **Step 2: Final full build + installcheck + TAP on master**

Run the full build, `installcheck`, and TAP suite on master; confirm all green.

- [ ] **Step 3: Commit.** Subject: `docs: document function-integrity enforcement, extension promotion, versions, and limitations`.

- [ ] **Step 4: Push-readiness (manual handoff)**

The repo is now a clean series of commits suitable for GitHub. Pushing requires the user's remote and credentials (interactive). Suggested commands for the user to run themselves:
```bash
cd ~/projects/claude/pgsql/pg_biba
gh repo create pg_mic --public --source=. --remote=origin --push   # or: git remote add origin <url> && git push -u origin HEAD
```
Do not push on the user's behalf without explicit confirmation.

---

## Self-Review

- **Spec coverage:** §1 problem → Tasks 4–12 (static check). §4 architecture / two paths → Task 4 (executor) + Tasks 10–12 (utility) + retained hook (unchanged). §5 reachable-set → Tasks 4 (CHECK), 5 (triggers), 6 (defaults/generated incl. VIRTUAL read), 7 (index all ops), 8 (exclusion/domain), 9 (RLS). §6 walker/fail-closed → Task 4 (`func_collect_walker`, fail-closed in `check_check_constraints`/`mic_check_one_function`). §7 utility path → Tasks 10–12. §8 error/mode/perf → Task 4 (fast path, modes in `mic_check_one_function`) + Task 14 (mode TAP). §9 bulk promotion → Task 13. §10 testing → Tasks 4–15 (pg_regress + TAP + e2e). §11 rename → Task 2. §12 limitations → Task 17. §13 portability → Task 3 (compat) + Task 16 (version matrix).
- **Placeholder scan:** code steps carry real C/SQL/Perl and exact run/commit commands; the raw-parse operator resolution in Task 11 and the exact `AT_*` names in Task 12 are flagged as "confirm against the target version" rather than left blank, because they are version-sensitive and the fail/pass cycle validates them.
- **Type consistency:** `mic_check_reachable_functions(Oid, AclMode)`, `mic_check_expr_functions(Node*, int, const char*, const char*)`, `mic_check_one_function(Oid, int, const char*, const char*)`, `mic_perm_entries(List*, List*) -> List* of MicPermEntry*`, `mic_promote_extension -> int32` used consistently across tasks.
- **Review Focus:** superuser-usability + LOW fast path (Task 4 tests), trigger event filtering (Task 5), permissive-vs-enforcing (Task 14), version-skew expected output (Task 16) — each pinned to a task above.
