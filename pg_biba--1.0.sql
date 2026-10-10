/* contrib/pg_biba/pg_biba--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_biba" to load this file. \quit

-- Introspection functions

CREATE FUNCTION biba_get_session_level()
RETURNS text
AS 'MODULE_PATHNAME', 'biba_get_session_level'
LANGUAGE C STRICT STABLE;

CREATE FUNCTION biba_get_role_level(role_name text)
RETURNS text
AS 'MODULE_PATHNAME', 'biba_get_role_level'
LANGUAGE C STRICT STABLE;

CREATE FUNCTION biba_get_table_level(table_name text)
RETURNS text
AS 'MODULE_PATHNAME', 'biba_get_table_level'
LANGUAGE C STRICT STABLE;

-- Administration functions (superuser only)

CREATE FUNCTION biba_set_role_level(role_name text, level text)
RETURNS void
AS 'MODULE_PATHNAME', 'biba_set_role_level'
LANGUAGE C STRICT VOLATILE;

CREATE FUNCTION biba_promote_table(table_name text, new_level text)
RETURNS void
AS 'MODULE_PATHNAME', 'biba_promote_table'
LANGUAGE C STRICT VOLATILE;

CREATE FUNCTION biba_promote_object(class_id oid, object_id oid, new_level text)
RETURNS void
AS 'MODULE_PATHNAME', 'biba_promote_object'
LANGUAGE C STRICT VOLATILE;

CREATE FUNCTION biba_initialize_labels()
RETURNS void
AS 'MODULE_PATHNAME', 'biba_initialize_labels'
LANGUAGE C STRICT VOLATILE;

-- Views

CREATE VIEW biba_labels AS
SELECT
    s.objoid,
    s.classoid,
    s.objsubid,
    s.label AS integrity_level,
    CASE s.classoid
        WHEN 'pg_catalog.pg_class'::regclass THEN 'table'
        WHEN 'pg_catalog.pg_proc'::regclass THEN 'function'
        WHEN 'pg_catalog.pg_namespace'::regclass THEN 'schema'
        ELSE s.classoid::regclass::text
    END AS object_type,
    CASE s.classoid
        WHEN 'pg_catalog.pg_class'::regclass THEN s.objoid::regclass::text
        WHEN 'pg_catalog.pg_proc'::regclass THEN s.objoid::regprocedure::text
        WHEN 'pg_catalog.pg_namespace'::regclass THEN s.objoid::regnamespace::text
        ELSE s.objoid::text
    END AS object_name
FROM pg_seclabel s
WHERE s.provider = 'biba';

CREATE VIEW biba_role_labels AS
SELECT
    s.objoid AS role_oid,
    r.rolname AS role_name,
    s.label AS integrity_level
FROM pg_shseclabel s
JOIN pg_authid r ON r.oid = s.objoid
WHERE s.provider = 'biba'
  AND s.classoid = 'pg_catalog.pg_authid'::regclass;
