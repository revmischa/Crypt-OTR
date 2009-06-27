use Test::More qw/no_plan/;
BEGIN { use_ok('Crypt::OTR') };

use threads;
use threads::shared;

my ($alice, $bob) = (init(), init());





sub init () {
    my $alice = 

