-- pg_biba regression tests
-- Requires: shared_preload_libraries = 'pg_biba'

CREATE EXTENSION pg_biba;

-- Check session level (superuser = high)
SELECT biba_get_session_level();

-- Create test roles
CREATE ROLE biba_high_user LOGIN;
CREATE ROLE biba_medium_user LOGIN;
CREATE ROLE biba_low_user LOGIN;

-- Set role levels
SELECT biba_set_role_level('biba_high_user', 'high');
SELECT biba_set_role_level('biba_medium_user', 'medium');
SELECT biba_set_role_level('biba_low_user', 'low');

-- Verify role levels
SELECT biba_get_role_level('biba_high_user');
SELECT biba_get_role_level('biba_medium_user');
SELECT biba_get_role_level('biba_low_user');

-- Create test tables at various levels
CREATE TABLE biba_test_high (id int, data text);
CREATE TABLE biba_test_medium (id int, data text);
CREATE TABLE biba_test_low (id int, data text);

-- Label tables
SELECT biba_promote_table('biba_test_high', 'high');
SELECT biba_promote_table('biba_test_medium', 'medium');
SELECT biba_promote_table('biba_test_low', 'low');

-- Verify table levels
SELECT biba_get_table_level('biba_test_high');
SELECT biba_get_table_level('biba_test_medium');
SELECT biba_get_table_level('biba_test_low');

-- Insert test data (as superuser = HIGH)
INSERT INTO biba_test_high VALUES (1, 'high data');
INSERT INTO biba_test_medium VALUES (1, 'medium data');
INSERT INTO biba_test_low VALUES (1, 'low data');

-- Grant access to test roles
GRANT ALL ON biba_test_high TO biba_high_user, biba_medium_user, biba_low_user;
GRANT ALL ON biba_test_medium TO biba_high_user, biba_medium_user, biba_low_user;
GRANT ALL ON biba_test_low TO biba_high_user, biba_medium_user, biba_low_user;

-- ============================================================
-- Test as HIGH user
-- ============================================================
SET ROLE biba_high_user;
SELECT biba_get_session_level();

-- HIGH can read HIGH (same level)
SELECT * FROM biba_test_high;

-- HIGH cannot read MEDIUM (No Read Down)
SELECT * FROM biba_test_medium;

-- HIGH cannot read LOW (No Read Down)
SELECT * FROM biba_test_low;

-- HIGH can write HIGH (same level)
INSERT INTO biba_test_high VALUES (2, 'high insert');

-- HIGH cannot write MEDIUM (we are higher, but No Write Up doesn't block this;
-- however we also need read for the table check, which blocks it? No:
-- INSERT is write-only. HIGH >= MEDIUM so write is OK)
-- Actually: No Write Up means subject >= object. HIGH(3) >= MEDIUM(2) so write OK.
INSERT INTO biba_test_medium VALUES (2, 'high writes medium');

-- HIGH can write LOW
INSERT INTO biba_test_low VALUES (2, 'high writes low');

RESET ROLE;

-- ============================================================
-- Test as LOW user
-- ============================================================
SET ROLE biba_low_user;
SELECT biba_get_session_level();

-- LOW can read LOW (same level)
SELECT * FROM biba_test_low;

-- LOW can read MEDIUM (No Read Down: subject(1) <= object(2), OK)
SELECT * FROM biba_test_medium;

-- LOW can read HIGH (No Read Down: subject(1) <= object(3), OK)
SELECT * FROM biba_test_high;

-- LOW can write LOW (same level)
INSERT INTO biba_test_low VALUES (3, 'low insert');

-- LOW cannot write MEDIUM (No Write Up: subject(1) < object(2))
INSERT INTO biba_test_medium VALUES (3, 'low writes medium');

-- LOW cannot write HIGH (No Write Up: subject(1) < object(3))
INSERT INTO biba_test_high VALUES (3, 'low writes high');

-- LOW cannot UPDATE HIGH (requires both read and write, fails write)
UPDATE biba_test_high SET data = 'tampered' WHERE id = 1;

-- LOW cannot DELETE HIGH
DELETE FROM biba_test_high WHERE id = 1;

RESET ROLE;

-- ============================================================
-- Test as MEDIUM user
-- ============================================================
SET ROLE biba_medium_user;
SELECT biba_get_session_level();

-- MEDIUM can read MEDIUM
SELECT * FROM biba_test_medium;

-- MEDIUM can read HIGH (subject(2) <= object(3))
SELECT * FROM biba_test_high;

-- MEDIUM cannot read LOW (subject(2) > object(1))
SELECT * FROM biba_test_low;

-- MEDIUM can write MEDIUM
INSERT INTO biba_test_medium VALUES (4, 'medium insert');

-- MEDIUM can write LOW (subject(2) >= object(1))
INSERT INTO biba_test_low VALUES (4, 'medium writes low');

-- MEDIUM cannot write HIGH (subject(2) < object(3))
INSERT INTO biba_test_high VALUES (4, 'medium writes high');

RESET ROLE;

-- ============================================================
-- Test SECURITY LABEL syntax
-- ============================================================
SECURITY LABEL FOR biba ON TABLE biba_test_low IS 'medium';
SELECT biba_get_table_level('biba_test_low');

-- Invalid label should fail
SECURITY LABEL FOR biba ON TABLE biba_test_low IS 'invalid';

-- Restore
SECURITY LABEL FOR biba ON TABLE biba_test_low IS 'low';

-- ============================================================
-- Test permissive mode
-- ============================================================
-- Switch to permissive mode (need to reload for PGC_SIGHUP, so just
-- test that the GUC exists)
SHOW biba.mode;
SHOW biba.debug_audit;

-- ============================================================
-- Test biba_promote_object (generic)
-- ============================================================
SELECT biba_promote_object('pg_catalog.pg_class'::regclass::oid,
                           'biba_test_low'::regclass::oid,
                           'high');
SELECT biba_get_table_level('biba_test_low');

-- Restore
SELECT biba_promote_table('biba_test_low', 'low');

-- ============================================================
-- Test views
-- ============================================================
SELECT count(*) >= 0 AS has_labels FROM biba_labels;
SELECT count(*) >= 0 AS has_role_labels FROM biba_role_labels;

-- ============================================================
-- Non-superuser cannot set labels
-- ============================================================
SET ROLE biba_low_user;
SELECT biba_set_role_level('biba_low_user', 'high');
SELECT biba_promote_table('biba_test_low', 'high');
RESET ROLE;

-- ============================================================
-- Cleanup
-- ============================================================
DROP TABLE biba_test_high;
DROP TABLE biba_test_medium;
DROP TABLE biba_test_low;
DROP ROLE biba_high_user;
DROP ROLE biba_medium_user;
DROP ROLE biba_low_user;
