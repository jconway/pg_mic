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
-- a HIGH subject may not even define a table in terms of a LOW function
CREATE TABLE r_chk (id int CHECK (public.low_sql_chk(id)));   -- denied at CREATE TABLE
-- so wire a HIGH function in, then demote it: the stored CHECK now reaches
-- a LOW function (the realistic "trusted helper turned out bad" case)
CREATE FUNCTION public.high_chk(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;  -- created by superuser => HIGH
CREATE TABLE r_chk (id int CHECK (public.high_chk(id)));
INSERT INTO r_chk VALUES (1);          -- allowed: HIGH helper
SELECT mic_promote_object('pg_catalog.pg_proc'::regclass::oid,
                          'public.high_chk(int)'::regprocedure::oid, 'low');
-- HIGH subject INSERT must be denied (CHECK reaches a LOW function)
INSERT INTO r_chk VALUES (1);
-- a built-in-only CHECK must still work for HIGH
CREATE TABLE r_chk_ok (id int CHECK (id >= 0));
INSERT INTO r_chk_ok VALUES (1);
-- a HIGH helper in a CHECK must work for HIGH
CREATE FUNCTION public.high_chk2(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
CREATE TABLE r_chk_hi (id int CHECK (public.high_chk2(id)));
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
CREATE TABLE r_chk_med (id int CHECK (public.low_sql_chk(id)));   -- denied at CREATE TABLE (MEDIUM > LOW)
RESET ROLE;
SET ROLE mic_low_user;
CREATE TABLE r_chk_med (id int CHECK (public.low_sql_chk(id)));
GRANT INSERT ON r_chk_med TO mic_medium_user;
RESET ROLE;
SET ROLE mic_medium_user;
INSERT INTO r_chk_med VALUES (1);      -- denied: write-down is fine, the LOW CHECK code is not
RESET ROLE;

-- ============================================================
-- Reachable-function enforcement: triggers (by event)
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_trig() RETURNS trigger
    AS 'BEGIN RETURN NEW; END' LANGUAGE plpgsql;
CREATE FUNCTION public.low_trig_del() RETURNS trigger
    AS 'BEGIN RETURN OLD; END' LANGUAGE plpgsql;
-- (the LOW user owns the table and plants the triggers; the HIGH subject's
-- writes into the LOW table are write-down, which Biba permits -- the LOW
-- trigger code is what must not run)
CREATE TABLE r_trg (id int);
CREATE TRIGGER t_ins BEFORE INSERT ON r_trg
    FOR EACH ROW EXECUTE FUNCTION public.low_trig();
CREATE TRIGGER t_del BEFORE DELETE ON r_trg
    FOR EACH ROW EXECUTE FUNCTION public.low_trig_del();
RESET ROLE;
-- a HIGH subject may not wire a LOW function into a table at all
CREATE TABLE r_trg_hi (id int);
CREATE TRIGGER t_hi BEFORE INSERT ON r_trg_hi
    FOR EACH ROW EXECUTE FUNCTION public.low_trig();    -- denied at CREATE TRIGGER
-- INSERT denied (LOW insert trigger)
INSERT INTO r_trg VALUES (1);
-- event filtering: DELETE must NOT be blocked by the INSERT trigger,
-- but IS blocked by the LOW delete trigger
DELETE FROM r_trg;

-- event filtering proof: table with ONLY a LOW insert trigger; a HIGH
-- DELETE must SUCCEED (insert trigger not consulted for DELETE)
SET ROLE mic_low_user;
CREATE FUNCTION public.low_trig_ins_only() RETURNS trigger
    AS 'BEGIN RETURN NEW; END' LANGUAGE plpgsql;
CREATE TABLE r_trg_insonly (id int);
CREATE TRIGGER t_ins_only BEFORE INSERT ON r_trg_insonly
    FOR EACH ROW EXECUTE FUNCTION public.low_trig_ins_only();
RESET ROLE;
DELETE FROM r_trg_insonly;

-- triggers on partitions and inheritance children fire for DML on the
-- parent, which is all the statement names
SET ROLE mic_low_user;
CREATE TABLE r_trg_par (id int) PARTITION BY RANGE (id);
CREATE TABLE r_trg_par_p1 PARTITION OF r_trg_par FOR VALUES FROM (0) TO (100);
CREATE TRIGGER t_p1 BEFORE INSERT ON r_trg_par_p1
    FOR EACH ROW EXECUTE FUNCTION public.low_trig();
CREATE TABLE r_trg_inh (id int);
CREATE TABLE r_trg_inh_c (id int) INHERITS (r_trg_inh);
CREATE TRIGGER t_c BEFORE DELETE ON r_trg_inh_c
    FOR EACH ROW EXECUTE FUNCTION public.low_trig_del();
RESET ROLE;
INSERT INTO r_trg_par VALUES (1);      -- denied: routed into partition with LOW trigger
COPY r_trg_par FROM STDIN;
2
\.
DELETE FROM r_trg_inh;                 -- denied: child's LOW delete trigger
DELETE FROM ONLY r_trg_inh;            -- allowed: ONLY does not reach the child
-- the WHEN clause of a trigger runs even before its function does
SET ROLE mic_low_user;
CREATE FUNCTION public.low_when(int) RETURNS boolean
    AS 'BEGIN RETURN true; END' LANGUAGE plpgsql;
RESET ROLE;
CREATE FUNCTION public.high_noop_trig() RETURNS trigger
    AS 'BEGIN RETURN NEW; END' LANGUAGE plpgsql;
CREATE TABLE r_trg_when (id int);
CREATE TRIGGER t_when BEFORE INSERT ON r_trg_when
    FOR EACH ROW WHEN (public.low_when(NEW.id)) EXECUTE FUNCTION public.high_noop_trig();  -- denied at CREATE TRIGGER

-- ============================================================
-- Reachable-function enforcement: defaults and generated columns
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_def() RETURNS int AS 'BEGIN RETURN 7; END' LANGUAGE plpgsql VOLATILE;
CREATE FUNCTION public.low_gen(int) RETURNS int AS 'SELECT $1 * 2' LANGUAGE sql IMMUTABLE;
-- (defined by the LOW user; the HIGH subject's INSERT is write-down, and it
-- is the LOW default / generation code that must not run)
CREATE TABLE r_def (id int DEFAULT public.low_def());
CREATE TABLE r_gs (id int, g int GENERATED ALWAYS AS (public.low_gen(id)) STORED);
RESET ROLE;
-- DEFAULT reaches a LOW function on INSERT
INSERT INTO r_def DEFAULT VALUES;
-- STORED generated column reaches a LOW function on write
INSERT INTO r_gs (id) VALUES (1);
-- VIRTUAL generated columns exist only on PG18+; silent no-op elsewhere
SELECT current_setting('server_version_num')::int >= 180000 AS pg18plus \gset
\if :pg18plus
-- (PG18 rejects user-defined functions in VIRTUAL expressions, so only a
-- built-in expression is possible; it must remain usable by a HIGH subject)
CREATE TABLE r_gv (id int, g int GENERATED ALWAYS AS (id * 2) VIRTUAL);
INSERT INTO r_gv (id) VALUES (1);
SELECT g FROM r_gv \gset
DROP TABLE r_gv;
\endif

-- ============================================================
-- Reachable-function enforcement: index expressions / predicates
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_ident(int) RETURNS int AS 'BEGIN RETURN $1; END' LANGUAGE plpgsql IMMUTABLE;
RESET ROLE;
-- (CREATE INDEX with a LOW function is itself denied for a HIGH subject, so a
-- LOW subject builds the table and index, then HIGH writes to it)
SET ROLE mic_low_user;
CREATE TABLE r_idx (id int);
CREATE INDEX r_idx_e ON r_idx (public.low_ident(id));
GRANT ALL ON r_idx TO PUBLIC;
RESET ROLE;
INSERT INTO r_idx VALUES (1);          -- denied: index maintenance
-- partial-index predicate evaluated by planner on SELECT (scratch.txt vector)
-- (index creation itself evaluates the predicate and is denied for a LOW
-- function, so build the index with a HIGH function, then demote it)
CREATE FUNCTION public.high_ident(int) RETURNS int AS 'BEGIN RETURN $1; END' LANGUAGE plpgsql IMMUTABLE;
CREATE TABLE r_idxp (id int);
CREATE INDEX r_idxp_p ON r_idxp (id) WHERE public.high_ident(id) > 0;
SELECT count(*) FROM r_idxp;           -- allowed: predicate function is HIGH
SELECT mic_promote_object('pg_catalog.pg_proc'::regclass::oid,
                          'public.high_ident(int)'::regprocedure::oid, 'low');
SELECT count(*) FROM r_idxp;           -- denied: planner evaluates predicate

-- ============================================================
-- Reachable-function enforcement: domain CHECK (type-level)
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_domchk(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
CREATE DOMAIN public.low_dom AS int CHECK (public.low_domchk(VALUE));
CREATE TABLE r_dom (id public.low_dom);
RESET ROLE;
INSERT INTO r_dom VALUES (1);          -- denied: domain CHECK reaches LOW fn

-- ============================================================
-- Reachable-function enforcement: cast to domain inside an expression
-- (T_CoerceToDomain; the column type is plain int, not the domain)
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_domchk2(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
CREATE DOMAIN public.low_dom2 AS int CHECK (public.low_domchk2(VALUE));
CREATE TABLE r_domcast (x int CHECK ((x::public.low_dom2) >= 0));
RESET ROLE;
INSERT INTO r_domcast VALUES (1);      -- denied: cast-to-domain CHECK reaches LOW fn

-- ============================================================
-- Reachable-function enforcement: nested / array / range of domain
-- (the LOW CHECK lives on a domain reached only by unwrapping the
-- column type through a domain, an array, or a range)
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_ndchk(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
-- domain over a domain: the CHECK is on the inner domain
CREATE DOMAIN public.low_inner AS int CHECK (public.low_ndchk(VALUE));
CREATE DOMAIN public.low_outer AS public.low_inner;
-- array of a domain
CREATE DOMAIN public.low_elem AS int CHECK (public.low_ndchk(VALUE));
-- range over a domain
CREATE DOMAIN public.low_rsub AS int CHECK (public.low_ndchk(VALUE));
CREATE TYPE public.low_rng AS RANGE (subtype = public.low_rsub);
-- composite type with a domain field
CREATE TYPE public.low_comp AS (a public.low_elem);
CREATE TABLE r_nd (v public.low_outer);
CREATE TABLE r_ad (v public.low_elem[]);
CREATE TABLE r_rd (v public.low_rng);
CREATE TABLE r_cd (v public.low_comp);
RESET ROLE;
INSERT INTO r_nd VALUES (1);           -- denied: nested domain CHECK reaches LOW fn
INSERT INTO r_ad VALUES ('{1}');       -- denied: array element domain CHECK reaches LOW fn
INSERT INTO r_rd VALUES ('[1,2]');     -- denied: range subtype domain CHECK reaches LOW fn
INSERT INTO r_cd VALUES (ROW(1));      -- denied: composite field domain CHECK reaches LOW fn

-- ============================================================
-- Reachable-function enforcement: RLS policies
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_rls(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql STABLE;
RESET ROLE;
CREATE TABLE r_rls (id int);
ALTER TABLE r_rls ENABLE ROW LEVEL SECURITY;
-- a HIGH subject may not define a policy in terms of a LOW function ...
CREATE POLICY p_sel ON r_rls FOR SELECT USING (public.low_rls(id));   -- denied at CREATE POLICY
-- ... so the policies use a HIGH helper that is demoted afterwards
CREATE FUNCTION public.high_rls(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql STABLE;
CREATE POLICY p_sel ON r_rls FOR SELECT USING (public.high_rls(id));
INSERT INTO r_rls VALUES (1);
ALTER TABLE r_rls FORCE ROW LEVEL SECURITY;
-- primary rd_rsdesc path: non-superuser HIGH subject genuinely subject to RLS
CREATE ROLE mic_rls_high LOGIN;
SELECT mic_set_role_level('mic_rls_high', 'high');
CREATE TABLE r_rls_pri (id int);
INSERT INTO r_rls_pri VALUES (1);
ALTER TABLE r_rls_pri ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_pri ON r_rls_pri FOR ALL TO mic_rls_high
    USING (public.high_rls(id)) WITH CHECK (public.high_rls(id));
GRANT SELECT, INSERT ON r_rls_pri TO mic_rls_high;
SELECT mic_promote_object('pg_catalog.pg_proc'::regclass::oid,
                          'public.high_rls(int)'::regprocedure::oid, 'low');
SELECT count(*) FROM r_rls;            -- denied: USING qual reaches LOW fn
SET ROLE mic_rls_high;
SELECT count(*) FROM r_rls_pri;        -- denied: USING policy reaches LOW fn
INSERT INTO r_rls_pri VALUES (2);      -- denied: WITH CHECK policy reaches LOW fn
RESET ROLE;
CREATE TABLE r_rls_ok (id int);
ALTER TABLE r_rls_ok ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_ok ON r_rls_ok FOR ALL TO mic_rls_high
    USING (id >= 0) WITH CHECK (id >= 0);
GRANT SELECT, INSERT ON r_rls_ok TO mic_rls_high;
SET ROLE mic_rls_high;
SELECT count(*) FROM r_rls_ok;         -- allowed: built-in policy
INSERT INTO r_rls_ok VALUES (1);       -- allowed
RESET ROLE;

-- ============================================================
-- Utility path: COPY FROM and TRUNCATE triggers
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_copychk(int) RETURNS boolean
    AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
CREATE FUNCTION public.low_trunc() RETURNS trigger
    AS 'BEGIN RETURN NULL; END' LANGUAGE plpgsql;
CREATE TABLE r_copy (id int CHECK (public.low_copychk(id)));
RESET ROLE;
COPY r_copy FROM STDIN;
1
\.
-- (LOW-owned tables with LOW-planted TRUNCATE triggers; TRUNCATE by the HIGH
-- subject is write-down and otherwise permitted)
SET ROLE mic_low_user;
CREATE TABLE r_trunc (id int);
CREATE TRIGGER t_tr BEFORE TRUNCATE ON r_trunc
    FOR EACH STATEMENT EXECUTE FUNCTION public.low_trunc();
RESET ROLE;
TRUNCATE r_trunc;                      -- denied: LOW truncate trigger

-- TRUNCATE reaches triggers on partitions, inheritance children, and
-- CASCADE-referencing tables -- none named in the statement
SET ROLE mic_low_user;
CREATE FUNCTION public.low_trunc2() RETURNS trigger
    AS 'BEGIN RETURN NULL; END' LANGUAGE plpgsql;
-- partition: trigger on the partition, TRUNCATE the partitioned parent
CREATE TABLE r_tpar (id int) PARTITION BY RANGE (id);
CREATE TABLE r_tpar_p1 PARTITION OF r_tpar FOR VALUES FROM (0) TO (100);
CREATE TRIGGER t_tp BEFORE TRUNCATE ON r_tpar_p1
    FOR EACH STATEMENT EXECUTE FUNCTION public.low_trunc2();
-- inheritance child: trigger on the child, TRUNCATE the parent
CREATE TABLE r_tparent (id int);
CREATE TABLE r_tchild (id int) INHERITS (r_tparent);
CREATE TRIGGER t_tc BEFORE TRUNCATE ON r_tchild
    FOR EACH STATEMENT EXECUTE FUNCTION public.low_trunc2();
-- CASCADE: the FK-referencing table carries the LOW truncate trigger
CREATE TABLE r_tref (id int PRIMARY KEY);
CREATE TABLE r_tdep (id int REFERENCES r_tref(id));
CREATE TRIGGER t_td BEFORE TRUNCATE ON r_tdep
    FOR EACH STATEMENT EXECUTE FUNCTION public.low_trunc2();
RESET ROLE;
TRUNCATE r_tpar;                       -- denied: partition's LOW truncate trigger
TRUNCATE r_tparent;                    -- denied: child's LOW truncate trigger
TRUNCATE ONLY r_tparent;               -- allowed: ONLY does not reach the child
TRUNCATE r_tref CASCADE;               -- denied: FK-cascade reaches r_tdep's LOW trigger

-- ============================================================
-- Utility path: CREATE INDEX / REINDEX over existing rows
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_ixbuild(int) RETURNS int AS
  $$ BEGIN RETURN $1; END $$ LANGUAGE plpgsql IMMUTABLE;
RESET ROLE;
CREATE TABLE r_ixb (id int);
INSERT INTO r_ixb SELECT g FROM generate_series(1,3) g;
CREATE INDEX r_ixb_e ON r_ixb (public.low_ixbuild(id));              -- denied
CREATE INDEX r_ixb_p ON r_ixb (id) WHERE public.low_ixbuild(id) > 0; -- denied
-- built-in overloaded function must not be over-denied for a HIGH subject
CREATE TABLE r_idx_builtin (t text);
INSERT INTO r_idx_builtin VALUES ('aB');
CREATE INDEX r_idx_builtin_e ON r_idx_builtin (lower(t));            -- allowed
-- REINDEX: a LOW subject builds a LOW expression index (allowed), then a
-- HIGH subject reindexes it
SET ROLE mic_low_user;
CREATE FUNCTION public.ixr_fn(int) RETURNS int AS
  $$ BEGIN RETURN $1; END $$ LANGUAGE plpgsql IMMUTABLE;
CREATE TABLE r_ixr (id int);
INSERT INTO r_ixr SELECT g FROM generate_series(1,3) g;
CREATE INDEX r_ixr_e ON r_ixr (public.ixr_fn(id));                   -- allowed (LOW)
RESET ROLE;
REINDEX INDEX r_ixr_e;                                               -- denied
REINDEX TABLE r_ixr;                                                 -- denied
-- REINDEX SCHEMA expands to every relation in the schema (REINDEX DATABASE
-- uses the same path with no namespace filter; REINDEX SYSTEM hits only
-- exempt catalogs).  Isolate in a dedicated schema for a deterministic result.
CREATE SCHEMA mic_rx;
GRANT USAGE, CREATE ON SCHEMA mic_rx TO mic_low_user;
SET ROLE mic_low_user;
CREATE FUNCTION mic_rx.low_sixbuild(int) RETURNS int AS
  $$ BEGIN RETURN $1; END $$ LANGUAGE plpgsql IMMUTABLE;
CREATE TABLE mic_rx.r_sidx (id int);
INSERT INTO mic_rx.r_sidx SELECT g FROM generate_series(1,3) g;
CREATE INDEX r_sidx_e ON mic_rx.r_sidx (mic_rx.low_sixbuild(id));    -- allowed (LOW)
RESET ROLE;
REINDEX SCHEMA mic_rx;                 -- denied: schema holds a LOW expression index

-- ============================================================
-- Utility path: ALTER TABLE ADD CONSTRAINT validating existing rows
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_atchk(int) RETURNS boolean AS 'SELECT $1 >= 0' LANGUAGE sql IMMUTABLE;
RESET ROLE;
CREATE TABLE r_at (id int);
INSERT INTO r_at VALUES (1);
ALTER TABLE r_at ADD CONSTRAINT c_chk CHECK (public.low_atchk(id));  -- denied: validates rows
ALTER TABLE r_at ADD CONSTRAINT c_ok CHECK (id >= 0);  -- allowed: built-in only
ALTER TABLE r_at ALTER COLUMN id SET DEFAULT public.low_atchk(1)::int::int + 0;  -- denied: bare raw default walked
-- unresolvable name: plain parse error, not a pg_mic error (terse: the
-- optional HINT on "function does not exist" varies across major versions)
\set VERBOSITY terse
ALTER TABLE r_at ALTER COLUMN id SET DEFAULT public.nosuchfn(1);
\set VERBOSITY default

-- ============================================================
-- Definition-time refusal: a HIGH subject cannot define an object in terms
-- of a LOW function, nor derive one from a LOW relation
-- ============================================================
SET ROLE mic_low_user;
CREATE FUNCTION public.low_defn(int) RETURNS int
    AS 'BEGIN RETURN $1; END' LANGUAGE plpgsql IMMUTABLE;
CREATE FUNCTION public.low_defn_chk(int) RETURNS boolean
    AS 'BEGIN RETURN true; END' LANGUAGE plpgsql IMMUTABLE;
CREATE DOMAIN public.low_defn_dom AS int CHECK (public.low_defn_chk(VALUE));
CREATE TABLE r_defn_src (id int DEFAULT public.low_defn(1));
CREATE TABLE r_defn_par (id int) PARTITION BY RANGE (id);
CREATE TABLE r_defn_orphan (id int);
RESET ROLE;
CREATE TABLE r_defn (id int DEFAULT public.low_defn(1));                   -- denied: default
CREATE TABLE r_defn (id int CHECK (public.low_defn_chk(id)));              -- denied: column CHECK
CREATE TABLE r_defn (id int, CHECK (public.low_defn_chk(id)));             -- denied: table CHECK
CREATE TABLE r_defn (id int, g int GENERATED ALWAYS AS (public.low_defn(id)) STORED);  -- denied: generated
CREATE TABLE r_defn (id public.low_defn_dom);                              -- denied: LOW-checked domain column
CREATE TABLE r_defn (id int) PARTITION BY RANGE (public.low_defn(id));     -- denied: partition key
CREATE TABLE r_defn (LIKE r_defn_src INCLUDING DEFAULTS);                  -- denied: LIKE a LOW relation
CREATE TABLE r_defn (id int) INHERITS (r_defn_src);                        -- denied: INHERITS a LOW parent
CREATE TABLE r_defn PARTITION OF r_defn_par FOR VALUES FROM (0) TO (10);   -- denied: PARTITION OF a LOW parent
CREATE TABLE r_defn (id int);                                              -- allowed: nothing LOW involved
ALTER TABLE r_defn INHERIT r_defn_src;                                     -- denied: INHERIT a LOW parent
CREATE TABLE r_defn_hipar (id int) PARTITION BY RANGE (id);
ALTER TABLE r_defn_hipar ATTACH PARTITION r_defn_orphan FOR VALUES FROM (0) TO (10);  -- denied: ATTACH a LOW relation
CREATE DOMAIN public.hi_defn_dom AS int CHECK (public.low_defn_chk(VALUE));          -- denied: CREATE DOMAIN
CREATE DOMAIN public.hi_defn_dom AS int;
ALTER DOMAIN public.hi_defn_dom ADD CHECK (public.low_defn_chk(VALUE));             -- denied: ALTER DOMAIN

-- ============================================================
-- Function-manager backstop: call sites the executor never sees
-- ============================================================
-- event trigger: a HIGH subject may not attach a LOW function ...
SET ROLE mic_low_user;
CREATE FUNCTION public.low_evt() RETURNS event_trigger
    AS 'BEGIN END' LANGUAGE plpgsql;
RESET ROLE;
CREATE EVENT TRIGGER mic_evt ON ddl_command_end EXECUTE FUNCTION public.low_evt();  -- denied
-- ... and an event trigger whose function is demoted afterwards is denied
-- when it fires (event_trigger.c calls the function manager directly)
CREATE FUNCTION public.high_evt() RETURNS event_trigger
    AS 'BEGIN END' LANGUAGE plpgsql;
CREATE EVENT TRIGGER mic_evt ON ddl_command_end EXECUTE FUNCTION public.high_evt();
CREATE TABLE r_evt_ok (id int);        -- allowed: HIGH event trigger function
SELECT mic_promote_object('pg_catalog.pg_proc'::regclass::oid,
                          'public.high_evt()'::regprocedure::oid, 'low');
CREATE TABLE r_evt_bad (id int);       -- denied: event trigger function is now LOW
DROP EVENT TRIGGER mic_evt;

-- range subtype_diff: reached only through the type cache (GiST penalty,
-- selectivity estimation), never through an executor expression
SET ROLE mic_low_user;
CREATE FUNCTION public.low_diff(a int, b int) RETURNS float8
    AS 'BEGIN RETURN (a - b)::float8; END' LANGUAGE plpgsql IMMUTABLE;
CREATE TYPE public.low_drng AS RANGE (subtype = int, subtype_diff = public.low_diff);
RESET ROLE;
CREATE TABLE r_rng (r public.low_drng);
CREATE INDEX r_rng_gist ON r_rng USING gist (r);
INSERT INTO r_rng
  SELECT format('[%s,%s)', g, g + 5)::public.low_drng
    FROM generate_series(1, 300) g;    -- denied: GiST penalty calls the LOW subtype_diff

-- maintenance commands switch to the table owner's identity before running
-- index / statistics / view code; like REINDEX they are checked against the
-- invoking subject first
SET ROLE mic_low_user;
CREATE FUNCTION public.low_mix(int) RETURNS int
    AS 'BEGIN RETURN $1; END' LANGUAGE plpgsql IMMUTABLE;
CREATE TABLE r_maint (id int);
INSERT INTO r_maint VALUES (1);
CREATE INDEX r_maint_ix ON r_maint (public.low_mix(id));
CREATE FUNCTION public.low_mvf() RETURNS int
    AS 'BEGIN RETURN 1; END' LANGUAGE plpgsql;
CREATE MATERIALIZED VIEW r_mv AS SELECT public.low_mvf() AS v;
RESET ROLE;
VACUUM r_maint;                        -- denied
ANALYZE r_maint;                       -- denied
VACUUM FULL r_maint;                   -- denied
CLUSTER r_maint USING r_maint_ix;      -- denied
REFRESH MATERIALIZED VIEW r_mv;        -- denied: LOW function in the view query
-- statistics expressions run at every ANALYZE, autovacuum's included
CREATE TABLE r_stat (id int);
CREATE STATISTICS r_stat_x ON (public.low_mix(id)) FROM r_stat;   -- denied

-- a cached plan is invalidated when a function is demoted: the first
-- EXECUTE inlines the HIGH SQL function, the second must see it as LOW
CREATE FUNCTION public.high_sqlf(int) RETURNS int
    AS 'SELECT $1 + 1' LANGUAGE sql IMMUTABLE;
PREPARE mic_pp AS SELECT public.high_sqlf(1);
EXECUTE mic_pp;                        -- allowed (and inlined)
SELECT mic_promote_object('pg_catalog.pg_proc'::regclass::oid,
                          'public.high_sqlf(int)'::regprocedure::oid, 'low');
EXECUTE mic_pp;                        -- denied: plan rebuilt, function now LOW
DEALLOCATE mic_pp;

-- ============================================================
-- Bulk extension promotion
-- ============================================================
BEGIN;
SELECT mic_promote_extension('pg_mic', 'high') >= 0 AS promoted_count_nonneg;
ROLLBACK;
-- membership: demote one member to LOW, bulk-promote, verify it is HIGH again
BEGIN;
SELECT mic_promote_object('pg_catalog.pg_proc'::regclass::oid,
                          'mic_get_session_level'::regproc::oid, 'low');
SELECT integrity_level AS before_promote FROM mic_labels
  WHERE classoid = 'pg_catalog.pg_proc'::regclass
    AND objoid = 'mic_get_session_level'::regproc::oid;
SELECT mic_promote_extension('pg_mic', 'high') > 0 AS promoted_some;
SELECT integrity_level AS after_promote FROM mic_labels
  WHERE classoid = 'pg_catalog.pg_proc'::regclass
    AND objoid = 'mic_get_session_level'::regproc::oid;
ROLLBACK;
SET ROLE mic_low_user;
SELECT mic_promote_extension('pg_mic', 'high');   -- ERROR: superuser only
RESET ROLE;
SELECT mic_promote_extension('pg_mic', 'bogus');  -- ERROR: invalid level

-- Cleanup
DROP DOMAIN public.hi_defn_dom;
DROP TABLE r_defn_hipar;
DROP TABLE r_defn;
DROP TABLE r_defn_orphan;
DROP TABLE r_defn_par;
DROP TABLE r_defn_src;
DROP DOMAIN public.low_defn_dom;
DROP FUNCTION public.low_defn_chk(int);
DROP FUNCTION public.low_defn(int);
DROP FUNCTION public.high_sqlf(int);
DROP TABLE r_stat;
DROP MATERIALIZED VIEW r_mv;
DROP FUNCTION public.low_mvf();
DROP TABLE r_maint;
DROP FUNCTION public.low_mix(int);
DROP TABLE r_rng;
DROP TYPE public.low_drng;
DROP FUNCTION public.low_diff(int, int);
DROP TABLE r_evt_ok;
DROP FUNCTION public.high_evt();
DROP FUNCTION public.low_evt();
DROP TABLE r_at;
DROP FUNCTION public.low_atchk(int);
-- ============================================================
DROP TABLE r_ixb;
DROP TABLE r_idx_builtin;
DROP TABLE r_ixr;
DROP SCHEMA mic_rx CASCADE;
DROP FUNCTION public.low_ixbuild(int);
DROP FUNCTION public.ixr_fn(int);
DROP TABLE r_copy;
DROP TABLE r_trunc;
DROP TABLE r_tpar;
DROP TABLE r_tparent CASCADE;
DROP TABLE r_tdep;
DROP TABLE r_tref;
DROP FUNCTION public.low_copychk(int);
DROP FUNCTION public.low_trunc();
DROP FUNCTION public.low_trunc2();
DROP TABLE r_rls_ok;
DROP TABLE r_rls_pri;
DROP ROLE mic_rls_high;
DROP TABLE r_rls;
DROP FUNCTION public.low_rls(int);
DROP FUNCTION public.high_rls(int);
DROP TABLE r_domcast;
DROP DOMAIN public.low_dom2;
DROP FUNCTION public.low_domchk2(int);
DROP TABLE r_dom;
DROP DOMAIN public.low_dom;
DROP FUNCTION public.low_domchk(int);
DROP TABLE r_cd;
DROP TABLE r_rd;
DROP TABLE r_ad;
DROP TABLE r_nd;
DROP TYPE public.low_comp;
DROP TYPE public.low_rng;
DROP DOMAIN public.low_rsub;
DROP DOMAIN public.low_elem;
DROP DOMAIN public.low_outer;
DROP DOMAIN public.low_inner;
DROP FUNCTION public.low_ndchk(int);
DROP TABLE r_idx;
DROP TABLE r_idxp;
DROP FUNCTION public.low_ident(int);
DROP FUNCTION public.high_ident(int);
DROP TABLE r_def;
DROP TABLE r_gs;
DROP FUNCTION public.low_def();
DROP FUNCTION public.low_gen(int);
DROP TABLE r_trg;
DROP TABLE r_trg_hi;
DROP TABLE r_trg_par;
DROP TABLE r_trg_inh CASCADE;
DROP TABLE r_trg_when;
DROP FUNCTION public.high_noop_trig();
DROP FUNCTION public.low_when(int);
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
DROP FUNCTION public.high_chk2(int);
DROP TABLE mic_test_high;
DROP TABLE mic_test_medium;
DROP TABLE mic_test_low;
REVOKE CREATE, USAGE ON SCHEMA public FROM mic_low_user;
REVOKE CREATE, USAGE ON SCHEMA public FROM mic_medium_user;
DROP ROLE mic_high_user;
DROP ROLE mic_medium_user;
DROP ROLE mic_low_user;
