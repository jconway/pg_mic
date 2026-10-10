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
These are enforced **statically**, by reading the stored catalog expressions of
every relation the statement touches, so the check is **immune to SQL-function
inlining** (the planner may inline a function and make it vanish from the plan;
the catalog expression still names it). A runtime function-execution hook is
retained as a backstop.

Covered attachment points:

- triggers (including TRUNCATE triggers)
- CHECK constraints
- column defaults
- STORED and VIRTUAL generated columns
- index expressions and index predicates
- exclusion-constraint operators
- RLS `USING` / `WITH CHECK` policies
- domain CHECK constraints

Built-in functions (OID < 16384) are exempt, so ordinary SQL works for all
users. Enforcement is driven from both the executor (DML) and ProcessUtility
(COPY, TRUNCATE, CREATE INDEX / REINDEX, and ALTER TABLE validate/rewrite
subcommands), since those utility commands run catalog-stored code over rows
without going through the normal executor checks.

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

### Vetting and Promoting a Trusted Extension

An extension installed by a low-trust user has its objects (functions, tables,
...) labeled LOW, so high-integrity users cannot use it. After reviewing the
extension, a superuser can promote everything it owns in one call:

```sql
SELECT mic_promote_extension('some_ext', 'high');  -- returns count of objects relabeled
```

`mic_promote_extension(ext_name text, new_level text) RETURNS integer` is
superuser-only. It relabels every object belonging to the named extension to
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
| `mic_promote_extension(ext_name text, new_level text)` | integer | Relabel all objects of an extension; returns count (superuser only) |
| `mic_initialize_labels()` | void | Label all unlabeled user tables (superuser only) |

## Supported Versions

PostgreSQL 14 through master. Currently validated on 15, 16, 17, and master;
version differences are handled with guards in `pg_mic_compat.h`.

## Limitations and Non-Escapes

- **Nested inlined SQL is NOT an escape.** A LOW SQL function reached only by
  inlining inside an allowed function is read-only, and any table access or
  non-inlined call it performs is independently enforced (executor table check
  / runtime hook). No static body recursion is done or needed.
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
- **Not followed:** nested domains (a domain over a domain); arrays/ranges of
  domains; TRUNCATE triggers on partitions, inheritance children, or
  CASCADE-reached foreign-key tables; REINDEX SCHEMA / DATABASE / SYSTEM.

## Running Tests

```sh
# Requires a running server with shared_preload_libraries = 'pg_mic'
make -C contrib/pg_mic installcheck
```
