use Test::More qw/no_plan/;
BEGIN { use_ok('Crypt::OTR') };

use threads;
use threads::shared;

use strict;
use warnings;

my $otr_mutex : shared;
my $finished : shared = 0;
my %e;
my $established : shared;
$established = share(%e);

my $alice_buf = [];
my $bob_buf = [];

my $u1 = "alice";
my $u2 = "bob";

Crypt::OTR->init;


ok(test_multithreading(), "multithreading");


sub sync (&) {
    my $code = shift;
    lock $otr_mutex;
    $code->();
}

sub test_multithreading {
    my $alice_thread = async {
        my $alice = test_init($u1, $alice_buf);
        
        sync(sub {
            $alice->establish($u2);
        });

        sleep 1;

        my $msg = shift @$alice_buf;
        ok($msg, "Injected OTR setup message");
        my $resp = $alice->decrypt($u2, $msg);

        sync(sub {
            ok($established->{$u2}, "Connection with $u2 established");
        });
    };

    my $bob_thread = async {
        my $bob = test_init($u2, $bob_buf);
        
        sync(sub {
            $bob->establish($u1);
        });

        select undef, undef, undef, 1.2;

        my $msg = shift @$bob_buf;
        ok($msg, "Injected OTR setup message");
        my $resp = $bob->decrypt($u1, $msg);
        sync(sub {
            $bob->encrypt($u1, "message two");
        });

        sync(sub {
            ok($established->{$u1}, "Connection with $u1 established");
        });
    };

    $_->join foreach ($alice_thread, $bob_thread);

    return 1;
}


sub test_init {
    my ($user, $dest) = @_;

    my $otr = new Crypt::OTR(
                             account_name     => $user,
                             protocol_name    => "crypt-otr-test",
                             max_message_size => 2000, 
                             );

    my $inject = sub {
        my ($account_name, $protocol, $dest_account, $message) = @_;
        push @$dest, $message;
    };

    my $unverified = sub {
        my ($otr, $other_user) = @_;
        print "Unverified conversation started with $other_user\n";

        $established->{$user} = 1;
    };

    my $otr_system_message = sub {
        warn "OTR system says: @_\n";
    };

    $otr->set_callback('inject' => $inject);
    $otr->set_callback('otr_message' => $otr_system_message);
    #$otr->set_callback('connect' => \&otr_connect);
    $otr->set_callback('unverified' => $unverified);

    return $otr;
}

