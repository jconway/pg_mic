# Logical replication apply never goes through ExecutorCheckPerms and
# trigger.c never consults the function-execute object-access hook, so a LOW
# trigger on a subscribed table would run inside the apply worker under the
# subscription owner's identity (always, before PG16; with run_as_owner on
# PG16+).  The function-manager hook must deny it there.
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $pub = PostgreSQL::Test::Cluster->new('mic_pub');
$pub->init(allows_streaming => 'logical');
$pub->start;

my $sub = PostgreSQL::Test::Cluster->new('mic_sub');
$sub->init;
$sub->append_conf('postgresql.conf', q{
shared_preload_libraries = 'pg_mic'
wal_retrieve_retry_interval = 500ms
});
$sub->start;

$pub->safe_psql('postgres', q{
	CREATE TABLE public.rep (id int PRIMARY KEY);
	CREATE PUBLICATION pub_rep FOR TABLE public.rep;
});

# LOW user owns the subscribed table and plants an ALWAYS trigger on it
$sub->safe_psql('postgres', q{
	CREATE EXTENSION pg_mic;
	CREATE ROLE lo LOGIN;
	CREATE SCHEMA lo AUTHORIZATION lo;
	GRANT CREATE ON SCHEMA public TO lo;
	SET ROLE lo;
	CREATE TABLE lo.evil_log (usr text);
	CREATE FUNCTION lo.trg() RETURNS trigger LANGUAGE plpgsql AS $f$
	BEGIN
		INSERT INTO lo.evil_log VALUES (current_user);
		RETURN NEW;
	END $f$;
	CREATE TABLE public.rep (id int PRIMARY KEY);
	CREATE TRIGGER t_rep BEFORE INSERT ON public.rep
		FOR EACH ROW EXECUTE FUNCTION lo.trg();
	ALTER TABLE public.rep ENABLE ALWAYS TRIGGER t_rep;
});

# subscription owned by the superuser; apply runs as that owner
my $opts = 'copy_data = false';
# run_as_owner exists from PG16 (and is the only behavior before it); the
# pg_version accessor itself is missing from PG14's compatibility shim
$opts .= ', run_as_owner = true'
  if $sub->can('pg_version') && $sub->pg_version >= 16;
my $connstr = $pub->connstr . ' dbname=postgres';
$sub->safe_psql('postgres',
	"CREATE SUBSCRIPTION sub_rep CONNECTION '$connstr' PUBLICATION pub_rep WITH ($opts)");

$pub->safe_psql('postgres', 'INSERT INTO public.rep VALUES (1)');

# the apply worker must be denied, repeatedly, and never apply the row
my $deadline = time() + 60;
my $denied = 0;
while (time() < $deadline)
{
	my $log = slurp_file($sub->logfile);
	if ($log =~ /pg_mic: execute denied .* function "trg"/)
	{
		$denied = 1;
		last;
	}
	sleep 1;
}
ok($denied, 'apply worker denied executing the LOW trigger function');

my $applied = $sub->safe_psql('postgres',
	'SET ROLE lo; SELECT count(*) FROM public.rep');
is($applied, '0', 'row was not applied while enforcing');
my $ran = $sub->safe_psql('postgres',
	'SET ROLE lo; SELECT count(*) FROM lo.evil_log');
is($ran, '0', 'LOW trigger body never ran while enforcing');

# control: with enforcement off, the same apply succeeds and the LOW trigger
# runs as the HIGH subscription owner -- the escape the hook closes
$sub->safe_psql('postgres', q{
	ALTER SYSTEM SET mic.mode = 'disabled';
	SELECT pg_reload_conf();
});
$deadline = time() + 60;
while (time() < $deadline)
{
	last if $sub->safe_psql('postgres',
		'SET ROLE lo; SELECT count(*) FROM public.rep') eq '1';
	sleep 1;
}
is($sub->safe_psql('postgres', 'SET ROLE lo; SELECT count(*) FROM public.rep'),
	'1', 'control: row applied with enforcement disabled');
my $who = $sub->safe_psql('postgres',
	'SET ROLE lo; SELECT DISTINCT usr FROM lo.evil_log');
isnt($who, 'lo', 'control: LOW trigger ran as the subscription owner, not as lo');
isnt($who, '', 'control: LOW trigger body ran');

$sub->safe_psql('postgres', 'DROP SUBSCRIPTION sub_rep');
$sub->stop;
$pub->stop;
done_testing();
