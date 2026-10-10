-- pg_mic regression tests
-- Requires: shared_preload_libraries = 'pg_mic'

CREATE EXTENSION pg_mic;

-- Check session level (superuser = high)
SELECT mic_get_session_level();

-- Create test roles
CREATE ROLE mic_high_user LOGIN;
CREATE ROLE mic_medium_user LOGIN;
CREATE ROLE mic_low_user LOGIN;

-- Set role levels
SELECT mic_set_role_level('mic_high_user', 'high');
SELECT mic_set_role_level('mic_medium_user', 'medium');
SELECT mic_set_role_level('mic_low_user', 'low');

-- Verify role levels
SELECT mic_get_role_level('mic_high_user');
SELECT mic_get_role_level('mic_medium_user');
SELECT mic_get_role_level('mic_low_user');

-- Create test tables at various levels
CREATE TABLE mic_test_high (id int, data text);
CREATE TABLE mic_test_medium (id int, data text);
CREATE TABLE mic_test_low (id int, data text);

-- Label tables
SELECT mic_promote_table('mic_test_high', 'high');
SELECT mic_promote_table('mic_test_medium', 'medium');
SELECT mic_promote_table('mic_test_low', 'low');

-- Verify table levels
SELECT mic_get_table_level('mic_test_high');
SELECT mic_get_table_level('mic_test_medium');
SELECT mic_get_table_level('mic_test_low');

-- Insert test data (as superuser = HIGH)
INSERT INTO mic_test_high VALUES (1, 'high data');
INSERT INTO mic_test_medium VALUES (1, 'medium data');
INSERT INTO mic_test_low VALUES (1, 'low data');

-- Grant access to test roles
GRANT ALL ON mic_test_high TO mic_high_user, mic_medium_user, mic_low_user;
GRANT ALL ON mic_test_medium TO mic_high_user, mic_medium_user, mic_low_user;
GRANT ALL ON mic_test_low TO mic_high_user, mic_medium_user, mic_low_user;

-- ============================================================
-- Test as HIGH user
-- ============================================================
SET ROLE mic_high_user;
SELECT mic_get_session_level();

-- HIGH can read HIGH (same level)
SELECT * FROM mic_test_high;

-- HIGH cannot read MEDIUM (No Read Down)
SELECT * FROM mic_test_medium;

-- HIGH cannot read LOW (No Read Down)
SELECT * FROM mic_test_low;

-- HIGH can write HIGH (same level)
INSERT INTO mic_test_high VALUES (2, 'high insert');

-- HIGH cannot write MEDIUM (we are higher, but No Write Up doesn't block this;
-- however we also need read for the table check, which blocks it? No:
-- INSERT is write-only. HIGH >= MEDIUM so write is OK)
-- Actually: No Write Up means subject >= object. HIGH(3) >= MEDIUM(2) so write OK.
INSERT INTO mic_test_medium VALUES (2, 'high writes medium');

-- HIGH can write LOW
INSERT INTO mic_test_low VALUES (2, 'high writes low');

RESET ROLE;

-- ============================================================
-- Test as LOW user
-- ============================================================
SET ROLE mic_low_user;
SELECT mic_get_session_level();

-- LOW can read LOW (same level)
SELECT * FROM mic_test_low;

-- LOW can read MEDIUM (No Read Down: subject(1) <= object(2), OK)
SELECT * FROM mic_test_medium;

-- LOW can read HIGH (No Read Down: subject(1) <= object(3), OK)
SELECT * FROM mic_test_high;

-- LOW can write LOW (same level)
INSERT INTO mic_test_low VALUES (3, 'low insert');

-- LOW cannot write MEDIUM (No Write Up: subject(1) < object(2))
INSERT INTO mic_test_medium VALUES (3, 'low writes medium');

-- LOW cannot write HIGH (No Write Up: subject(1) < object(3))
INSERT INTO mic_test_high VALUES (3, 'low writes high');

-- LOW cannot UPDATE HIGH (requires both read and write, fails write)
UPDATE mic_test_high SET data = 'tampered' WHERE id = 1;

-- LOW cannot DELETE HIGH
DELETE FROM mic_test_high WHERE id = 1;

RESET ROLE;

-- ============================================================
-- Test as MEDIUM user
-- ============================================================
SET ROLE mic_medium_user;
SELECT mic_get_session_level();

-- MEDIUM can read MEDIUM
SELECT * FROM mic_test_medium;

-- MEDIUM can read HIGH (subject(2) <= object(3))
SELECT * FROM mic_test_high;

-- MEDIUM cannot read LOW (subject(2) > object(1))
SELECT * FROM mic_test_low;

-- MEDIUM can write MEDIUM
INSERT INTO mic_test_medium VALUES (4, 'medium insert');

-- MEDIUM can write LOW (subject(2) >= object(1))
INSERT INTO mic_test_low VALUES (4, 'medium writes low');

-- MEDIUM cannot write HIGH (subject(2) < object(3))
INSERT INTO mic_test_high VALUES (4, 'medium writes high');

RESET ROLE;

-- ============================================================
-- Test SECURITY LABEL syntax
-- ============================================================
SECURITY LABEL FOR mic ON TABLE mic_test_low IS 'medium';
SELECT mic_get_table_level('mic_test_low');

-- Invalid label should fail
SECURITY LABEL FOR mic ON TABLE mic_test_low IS 'invalid';

-- Restore
SECURITY LABEL FOR mic ON TABLE mic_test_low IS 'low';

-- ============================================================
-- Test permissive mode
-- ============================================================
-- Switch to permissive mode (need to reload for PGC_SIGHUP, so just
-- test that the GUC exists)
SHOW mic.mode;
SHOW mic.debug_audit;

-- ============================================================
-- Test mic_promote_object (generic)
-- ============================================================
SELECT mic_promote_object('pg_catalog.pg_class'::regclass::oid,
                           'mic_test_low'::regclass::oid,
                           'high');
SELECT mic_get_table_level('mic_test_low');

-- Restore
SELECT mic_promote_table('mic_test_low', 'low');

-- ============================================================
-- Test views
-- ============================================================
SELECT count(*) >= 0 AS has_labels FROM mic_labels;
SELECT count(*) >= 0 AS has_role_labels FROM mic_role_labels;

-- ============================================================
-- Non-superuser cannot set labels
-- ============================================================
SET ROLE mic_low_user;
SELECT mic_set_role_level('mic_low_user', 'high');
SELECT mic_promote_table('mic_test_low', 'high');
RESET ROLE;

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
-- HIGH subject UPDATE must also be denied
UPDATE r_chk SET id = 2;
-- LOW subject fast path: LOW user, LOW table, CHECK calls LOW function
SET ROLE mic_low_user;
CREATE TABLE r_chk_low (id int CHECK (public.low_sql_chk(id)));
INSERT INTO r_chk_low VALUES (1);
RESET ROLE;
-- MEDIUM subject must be denied for a LOW function in a CHECK
GRANT CREATE, USAGE ON SCHEMA public TO mic_medium_user;
SET ROLE mic_medium_user;
CREATE TABLE r_chk_med (id int CHECK (public.low_sql_chk(id)));
INSERT INTO r_chk_med VALUES (1);
RESET ROLE;

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

-- event filtering proof: table with ONLY a LOW insert trigger; a HIGH
-- DELETE must SUCCEED (insert trigger not consulted for DELETE)
SET ROLE mic_low_user;
CREATE FUNCTION public.low_trig_ins_only() RETURNS trigger
    AS 'BEGIN RETURN NEW; END' LANGUAGE plpgsql;
RESET ROLE;
CREATE TABLE r_trg_insonly (id int);
CREATE TRIGGER t_ins_only BEFORE INSERT ON r_trg_insonly
    FOR EACH ROW EXECUTE FUNCTION public.low_trig_ins_only();
DELETE FROM r_trg_insonly WHERE id = 0;

-- ============================================================
-- Reachable-function enforcement: defaults and generated columns
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_def() RETURNS int AS 'BEGIN RETURN 7; END' LANGUAGE plpgsql VOLATILE;
CREATE FUNCTION public.low_gen(int) RETURNS int AS 'SELECT $1 * 2' LANGUAGE sql IMMUTABLE;
RESET ROLE;
-- DEFAULT reaches a LOW function on INSERT
CREATE TABLE r_def (id int DEFAULT public.low_def());
INSERT INTO r_def DEFAULT VALUES;
-- STORED generated column reaches a LOW function on write
CREATE TABLE r_gs (id int, g int GENERATED ALWAYS AS (public.low_gen(id)) STORED);
INSERT INTO r_gs (id) VALUES (1);
-- VIRTUAL generated columns exist only on PG18+; silent no-op elsewhere
SELECT current_setting('server_version_num')::int >= 180000 AS pg18plus \gset
\if :pg18plus
-- (PG18 rejects user-defined functions in VIRTUAL expressions, so only a
-- built-in expression is possible; it must remain usable by a HIGH subject)
CREATE TABLE r_gv (id int, g int GENERATED ALWAYS AS (id * 2) VIRTUAL);
INSERT INTO r_gv (id) VALUES (1);
SELECT g FROM r_gv;
DROP TABLE r_gv;
\endif

-- ============================================================
-- Cleanup
-- ============================================================
DROP TABLE r_def;
DROP TABLE r_gs;
DROP FUNCTION public.low_def();
DROP FUNCTION public.low_gen(int);
DROP TABLE r_trg;
DROP TABLE r_trg_insonly;
DROP FUNCTION public.low_trig_ins_only();
DROP FUNCTION public.low_trig();
DROP FUNCTION public.low_trig_del();
DROP TABLE r_chk;
DROP TABLE r_chk_ok;
DROP TABLE r_chk_hi;
DROP TABLE r_chk_low;
DROP TABLE r_chk_med;
DROP FUNCTION public.low_sql_chk(int);
DROP FUNCTION public.high_chk(int);
DROP TABLE mic_test_high;
DROP TABLE mic_test_medium;
DROP TABLE mic_test_low;
REVOKE CREATE, USAGE ON SCHEMA public FROM mic_low_user;
REVOKE CREATE, USAGE ON SCHEMA public FROM mic_medium_user;
DROP ROLE mic_high_user;
DROP ROLE mic_medium_user;
DROP ROLE mic_low_user;
