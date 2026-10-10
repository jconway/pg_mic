# End-to-end replay of the "confused deputy" credential-exfiltration attack:
# a LOW user plants a LOW function in a partial index predicate; a HIGH
# subject (superuser) touching the table would run it.  pg_mic must block
# the HIGH subject so that zero bytes are exfiltrated.
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('mic_deputy');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_mic'");
$node->start;

$node->safe_psql('postgres', q{
	CREATE EXTENSION pg_mic;
	CREATE ROLE joe LOGIN;
	GRANT CREATE, USAGE ON SCHEMA public TO joe;
});

# attacker setup, as joe (unlabeled => LOW)
$node->safe_psql('postgres', q{
	SET ROLE joe;
	CREATE TABLE public.poc_shared_data
		(id serial PRIMARY KEY, category text, value numeric);
	INSERT INTO public.poc_shared_data (category, value)
		SELECT 'c' || (g % 5), g FROM generate_series(1, 100) g;
	CREATE SEQUENCE public.poc_exfil_oid;
	SELECT setval('public.poc_exfil_oid', lo_create(0)::bigint);
	CREATE FUNCTION public.poc_exfil(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS $f$
	DECLARE
		fd int;
		payload text;
	BEGIN
		BEGIN
			SELECT string_agg(rolname || ':' || coalesce(rolpassword, 'NO_PASSWORD'), E'\n')
				INTO payload FROM pg_authid;
			fd := lo_open((SELECT last_value FROM public.poc_exfil_oid)::oid, 131072);
			PERFORM lowrite(fd, convert_to(payload, 'UTF8'));
			PERFORM lo_close(fd);
		EXCEPTION WHEN insufficient_privilege THEN
			NULL;
		END;
		RETURN 1;
	END $f$;
	CREATE INDEX poc_trap_idx ON public.poc_shared_data (id)
		WHERE public.poc_exfil(0) IS NOT NULL;
	GRANT SELECT ON public.poc_shared_data TO PUBLIC;
});

# victim: HIGH superuser touches the table
my ($rc, $out, $err) = $node->psql('postgres',
	q{SELECT 1 FROM public.poc_shared_data LIMIT 1;});
isnt($rc, 0, 'HIGH subject touching LOW-trapped table fails');
like($err, qr/pg_mic: .*denied/, 'denied by pg_mic');

# nothing exfiltrated
my $len = $node->safe_psql('postgres', q{
	SET ROLE joe;
	SELECT octet_length(loread(lo_open((SELECT last_value FROM public.poc_exfil_oid)::oid, 262144), 1000000));
});
$len =~ s/^\s+|\s+$//g;
$len = (split /\n/, $len)[-1];
is($len, '0', 'zero bytes exfiltrated');

done_testing();
