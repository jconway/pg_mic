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

- Superuser = HIGH
- Labeled role = label value
- Unlabeled role = LOW

### Object Resolution (Tables, etc.)

- System object (OID < 16384) = HIGH
- Labeled object = label value
- Unlabeled object = LOW

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
- **DROP / ALTER / TRUNCATE** -- write check

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
   executing the call, in whatever identity the call actually runs, with the
   function's level. There is no call site this layer does not see.
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

Pre-checked at definition time, so a HIGH subject cannot even define an
object in terms of a lower function, or derive one from a lower relation:
`CREATE TABLE` (column defaults, CHECK/EXCLUDE constraints, generated
columns, the partition key, a column whose domain CHECKs reach a lower
function, and anything adopted via `LIKE`, `INHERITS`, `PARTITION OF`, or
`OF type`), `ALTER TABLE` (add constraint/default/index/expression, `ATTACH
PARTITION`, `INHERIT`), `CREATE TRIGGER` (function and `WHEN` clause),
`CREATE EVENT TRIGGER`, `CREATE`/`ALTER POLICY`, `CREATE`/`ALTER DOMAIN`,
`CREATE STATISTICS`, and `CREATE INDEX`. Deriving from a lower relation
(`LIKE`, `INHERITS`, `PARTITION OF`, `ATTACH`, `INHERIT`) is a read of that
relation and is refused as read-down.

Built-in functions (OID < 16384) are exempt, so ordinary SQL works for all
users. The utility path covers COPY, TRUNCATE, CREATE INDEX, REINDEX (including
`REINDEX SCHEMA` and `REINDEX DATABASE`), VACUUM/ANALYZE, CLUSTER/REPACK,
REFRESH MATERIALIZED VIEW, and the ALTER TABLE validate/rewrite subcommands.

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

To label all existing unlabeled user tables at the caller's level:

```sql
SELECT mic_initialize_labels();
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

Objects created by a subject carry that subject's level, including a function
re-defined with `CREATE OR REPLACE` (which relabels it to the re-definer's
level). Note that a *trusted* extension installed by a non-superuser is not
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
superuser-only. It relabels every labelable member belonging to the named extension to
the given level and returns the number of objects relabeled.

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
| `mic_initialize_labels()` | void | Label all unlabeled user tables (superuser only) |

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

## Running Tests

```sh
# Requires a running server with shared_preload_libraries = 'pg_mic'
make -C contrib/pg_mic installcheck
```
