# Verify pg_mic's shared_preload_libraries requirement.
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Without preload: loading the module must fail.
my $bare = PostgreSQL::Test::Cluster->new('mic_nopreload');
$bare->init;
$bare->start;
my ($rc, $out, $err) = $bare->psql('postgres', q{LOAD 'pg_mic';});
isnt($rc, 0, 'LOAD fails when not preloaded');
like($err, qr/pg_mic must be loaded via "shared_preload_libraries"/,
	'error mentions shared_preload_libraries');
$bare->stop;

# With preload: everything works and the default mode is enforcing.
my $node = PostgreSQL::Test::Cluster->new('mic_preload');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_mic'");
$node->start;
($rc, $out, $err) = $node->psql('postgres', 'CREATE EXTENSION pg_mic;');
is($rc, 0, 'CREATE EXTENSION works when preloaded');
is($node->safe_psql('postgres', 'SHOW mic.mode;'), 'enforcing',
	'mic.mode defaults to enforcing');
$node->stop;

done_testing();
