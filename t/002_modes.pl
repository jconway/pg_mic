# Verify mic.mode switching: enforcing denies, permissive warns+allows,
# disabled is a silent no-op.
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('mic_modes');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_mic'");
$node->start;

$node->safe_psql('postgres', q{
	CREATE EXTENSION pg_mic;
	CREATE ROLE mic_low LOGIN;
	SELECT mic_set_role_level('mic_low', 'low');
	CREATE TABLE hi (id int);
	SELECT mic_promote_table('hi', 'high');
	GRANT ALL ON hi TO mic_low;
});

sub set_mode
{
	my ($mode) = @_;
	$node->safe_psql('postgres',
		"ALTER SYSTEM SET mic.mode = '$mode'; SELECT pg_reload_conf();");
	# a fresh session picks the new value up once the postmaster reloads
	my $ok = 0;
	for (1 .. 100)
	{
		if ($node->safe_psql('postgres', 'SHOW mic.mode;') eq $mode)
		{
			$ok = 1;
			last;
		}
		select(undef, undef, undef, 0.1);
	}
	ok($ok, "mic.mode is now $mode");
}

sub low_insert
{
	return $node->psql('postgres',
		q{SET ROLE mic_low; INSERT INTO hi VALUES (1);});
}

# enforcing
my ($rc, $out, $err) = low_insert();
isnt($rc, 0, 'enforcing: LOW write to HIGH table fails');
like($err, qr/pg_mic: write denied/, 'enforcing: denial message');

# permissive
set_mode('permissive');
($rc, $out, $err) = low_insert();
is($rc, 0, 'permissive: write succeeds');
like($err, qr/WARNING:.*pg_mic: write violation \(permissive\)/,
	'permissive: violation is warned');
is($node->safe_psql('postgres', 'SELECT count(*) FROM hi'), '1',
	'permissive: row was written');

# disabled
set_mode('disabled');
($rc, $out, $err) = low_insert();
is($rc, 0, 'disabled: write succeeds');
unlike($err, qr/pg_mic/, 'disabled: no pg_mic output');
is($node->safe_psql('postgres', 'SELECT count(*) FROM hi'), '2',
	'disabled: row was written');

# back to enforcing
set_mode('enforcing');
($rc, $out, $err) = low_insert();
isnt($rc, 0, 're-enforcing: write denied again');

$node->stop;
done_testing();
