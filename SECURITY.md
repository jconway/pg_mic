# Security Policy

`pg_mic` is a mandatory integrity control extension. Its entire purpose is
that a higher-integrity subject can never execute lower-integrity code or
read lower-integrity data through any path. Any way to make that happen --
however indirect, and even if it requires an unusual object configuration --
is a vulnerability in `pg_mic`, not an edge case.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v1.0-beta1` and later on `main` | yes |
| PostgreSQL 14 through 19, and `master` | yes |

Beta releases receive fixes on `main`; there are no maintenance branches yet.

## Reporting a vulnerability

Please **do not open a public issue** for anything that could be a bypass.
Use GitHub's private vulnerability reporting instead:

**Security tab -> Report a vulnerability** at
https://github.com/jconway/pg_mic/security/advisories/new

A good report includes the PostgreSQL major version, the `mic.mode` setting,
the labels of the roles and objects involved, and the sequence of SQL
statements that leads to a higher-level subject executing (or reading)
something below its level. A reproduction as a `pg_regress` or TAP test in
the style of `sql/pg_mic.sql` or `t/` is ideal but not required.

You can expect an acknowledgement within a few days and a fix or a
documented limitation, with credit if you want it, before any public
disclosure. Draft advisories stay private until the fix is published.

## Out of scope

- Behavior with `mic.mode = 'permissive'` or `'disabled'`: those modes
  intentionally do not enforce.
- Anything a superuser does *as* a lower-level role after `SET ROLE`: the
  subject has deliberately lowered its own level.
- Properties PostgreSQL itself does not promise (for example, code that a
  table owner attached to a table running under that owner's identity during
  `autovacuum`). If you believe you have found a defect in PostgreSQL rather
  than in `pg_mic`, report it to <security@postgresql.org>.
