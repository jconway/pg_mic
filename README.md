# pg_biba -- Biba Mandatory Integrity Model for PostgreSQL

`pg_biba` is a PostgreSQL extension that enforces the Biba mandatory integrity
model. The Biba model is the dual of Bell-LaPadula: it protects data
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

Operation mapping:

- **Function execution** -- read check. A function is an object like any
  other, so invoking one obeys No Read Down: a HIGH subject cannot execute
  a LOW-integrity function. This blocks confused-deputy attacks in which a
  high-integrity subject is lured into running untrusted, low-integrity
  code (for example a function planted in an index predicate or trigger by
  a low-integrity user). Built-in functions (OID < 16384) are exempt, so
  ordinary SQL continues to work for all users.

## Installation

### Requirements

`pg_biba` must be loaded via `shared_preload_libraries` because it installs
hooks at server startup.

### Build and Install

From a PostgreSQL source tree:

```sh
make -C contrib/pg_biba
make -C contrib/pg_biba install
```

Or with PGXS against an installed PostgreSQL:

```sh
cd contrib/pg_biba
USE_PGXS=1 make
USE_PGXS=1 make install
```

### Configure

Add to `postgresql.conf`:

```
shared_preload_libraries = 'pg_biba'
```

Restart PostgreSQL, then create the extension in each database:

```sql
CREATE EXTENSION pg_biba;
```

## Configuration

### GUC Variables

| GUC                | Type | Default     | Context    | Description                          |
|--------------------|------|-------------|------------|--------------------------------------|
| `biba.mode`        | enum | `enforcing` | PGC_SIGHUP | `enforcing`, `permissive`, `disabled`|
| `biba.debug_audit` | bool | `off`       | PGC_USERSET| Log all access control decisions     |

- **enforcing** -- violations are denied with an error.
- **permissive** -- violations are logged as warnings but allowed.
- **disabled** -- no checks are performed.

Change mode at runtime (takes effect after `pg_ctl reload`):

```sql
ALTER SYSTEM SET biba.mode = 'permissive';
SELECT pg_reload_conf();
```

## Usage

### Labeling Roles

Only superusers can assign integrity levels to roles:

```sql
SELECT biba_set_role_level('analyst', 'medium');
SELECT biba_set_role_level('auditor', 'high');
```

Or using the native security label syntax:

```sql
SECURITY LABEL FOR biba ON ROLE analyst IS 'medium';
```

### Labeling Tables and Functions

New tables and functions are automatically labeled at the creator's
integrity level. Because the extension's own functions are created by a
superuser during `CREATE EXTENSION`, they are labeled HIGH and remain
callable by high-integrity users. A superuser can change a table's level:

```sql
SELECT biba_promote_table('sensitive_data', 'high');
```

Or using the native syntax:

```sql
SECURITY LABEL FOR biba ON TABLE sensitive_data IS 'high';
```

### Initializing Labels

To label all existing unlabeled user tables at the caller's level:

```sql
SELECT biba_initialize_labels();
```

### Querying Labels

```sql
-- Current session's integrity level
SELECT biba_get_session_level();

-- A role's level
SELECT biba_get_role_level('analyst');

-- A table's level
SELECT biba_get_table_level('sensitive_data');
```

### Views

| View               | Description                              |
|--------------------|------------------------------------------|
| `biba_labels`      | All labeled objects with their levels     |
| `biba_role_labels` | All roles with assigned integrity levels  |

```sql
SELECT * FROM biba_role_labels;
SELECT * FROM biba_labels;
```

### Generic Object Promotion

For objects other than tables:

```sql
SELECT biba_promote_object(class_id, object_id, 'high');
```

## Example

```sql
-- Setup
CREATE ROLE trusted_writer LOGIN;
CREATE ROLE untrusted_reader LOGIN;
SELECT biba_set_role_level('trusted_writer', 'high');
-- untrusted_reader is unlabeled, so defaults to LOW

CREATE TABLE verified_facts (id serial, fact text);
SELECT biba_promote_table('verified_facts', 'high');
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
| `biba_get_session_level()` | text | Current user's integrity level |
| `biba_get_role_level(role_name text)` | text | Named role's integrity level |
| `biba_get_table_level(table_name text)` | text | Named table's integrity level |
| `biba_set_role_level(role_name text, level text)` | void | Set a role's level (superuser only) |
| `biba_promote_table(table_name text, new_level text)` | void | Set a table's level (superuser only) |
| `biba_promote_object(class_id oid, object_id oid, new_level text)` | void | Set any object's level (superuser only) |
| `biba_initialize_labels()` | void | Label all unlabeled user tables (superuser only) |

## Running Tests

```sh
# Requires a running server with shared_preload_libraries = 'pg_biba'
make -C contrib/pg_biba installcheck
```
