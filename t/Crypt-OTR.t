use Test::More qw/no_plan/;
BEGIN { use_ok('Crypt::OTR') };

use threads;
use threads::shared;

use strict;
use warnings;

my $otr_mutex : shared;
my $finished : shared = 0;

my $alice_buf = [];
my $bob_buf = [];

my $u1 = "alice";
my $u2 = "bob";

my ($alice, $bob) = (init($u1, $alice_buf), init($u2, $bob_buf));
ok(test_multithreading(), "multithreading");


sub sync (&) {
    my $code = shift;
    lock $otr_mutex;
    $code->();
}

sub test_multithreading {
    my $alice_thread = async {
        sync(sub {
            $alice->establish($u2);
        });

        sleep 1;
        warn "\nalice buf: @$alice_buf\n";
    };

    my $bob_thread = async {
        sync(sub {
            $bob->establish($u1);
        });

        sleep 2;
        warn "\nbob buf: @$bob_buf\n";
    };

    $_->join foreach ($alice_thread, $bob_thread);

    return 1;
}


sub init {
    my ($user, $dest) = @_;

    my $otr = new Crypt::OTR(
                             account_name     => $user,
                             protocol_name    => "crypt-otr-test",
                             max_message_size => 16, 
                             );

    my $inject = sub {
        warn "\ninject\n";
        my ($self, $account_name, $protocol, $dest_account, $message) = @_;
        push @$dest, $message;
    };

    my $unverified = sub {
        warn "\n\nunverified\n\n";
        my ($otr, $other_user) = @_;
        print "Unverified conversation started with $other_user\n";
    };

    $otr->set_callback('inject' => $inject);
    #$otr->set_callback('otr_message' => \&otr_system_message);
    #$otr->set_callback('connect' => \&otr_connect);
    $otr->set_callback('unverified' => $unverified);

    return $otr;
}

