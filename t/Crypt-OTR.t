use threads;
use threads::shared;

use Test::More tests => 19;
BEGIN { use_ok('Crypt::OTR') };

use strict;
use warnings;

my $otr_mutex : shared;
my $finished : shared = 0;
my %e;
my $established : shared;
$established = share(%e);

my $alice_buf = [];
my $bob_buf = [];

share( @$alice_buf );
share( @$bob_buf );

my $bob_info_buf = [];

share( @$bob_info_buf );

my $u1 = "alice";
my $u2 = "bob";

my $m1 = "Hello $u1, this is $u2";
my $m2 = "Hello $u2, this is $u1";

# socialist millionaires protocol (shared secret verification)
my $secret = "Rosebud";
my $question = "Which movie";

my %connected :shared = (
	$u1 => 0,
	$u2 => 0,
	);

my %disconnected :shared = (
	$u1 => 0,
	$u2 => 0,
	);

my %secured :shared = (
	$u1 => 0,
	$u2 => 0,
	);

my %smp_request :shared = (
	$u1 => 0,
	$u2 => 0,
	);

Crypt::OTR->init;
ok(test_multithreading(), "multithreading");

# ensure only one thread at a time is doing something
# this is to ensure there are no issues when using Crypt::OTR
# with multiple threads. hopefully this is not needed, so it's
# disabled for now.
sub sync (&) {
    my $code = shift;
#    lock $otr_mutex;
    $code->();
}

sub test_multithreading {
    my $alice_thread = async {
        my $alice = test_init($u1, $bob_buf);
        
        sync(sub {
            $alice->establish($u2);
        });

		my $con = 0;

		while( $con == 0 ){
			sleep 1;

			my $msg;
			{
				lock( @$alice_buf );
				$msg = shift @$alice_buf;
			}

			if( $msg ){
				my $resp = $alice->decrypt($u2, $msg);
			}
			{
				lock( %connected );
				$con = $connected{ $u2 }
			}
		}

        sync(sub {
            ok($established->{$u2}, "Connection with $u2 established");
        });
		
		# Encrypt a message and send it to Bob
		{
			my $enc_msg = $alice->encrypt($u2, $m1);
			lock( @$bob_buf );
			push @$bob_buf, $enc_msg;
		}
		
		# Decrypt messages from Bob
		{
			my $rec_msg;
			my $dec_msg;

			until( $dec_msg )
			{
				{
					lock( @$alice_buf );
					$rec_msg = shift @$alice_buf;
					$dec_msg = $alice->decrypt($u2, $rec_msg);
				}
				sleep 1;
			}

			ok( $dec_msg eq $m2, "Send: $m2 = Decrypted: $dec_msg");
		}

		sleep 2;

		# Secure the connection using SMP
		{
			my $sec_con;
			$alice->start_smp($u2, $secret);

			until( $sec_con )
			{
				my $msg;
				{
					lock( @$alice_buf );
					$msg = shift @$alice_buf;
				}

				if( $msg ){
					my $resp = $alice->decrypt($u2, $msg);
					if ($resp){
						print "resp: $resp\n";
					}
				}

				{
                    pass("Secured connection with SMP");
					lock( %secured );
					$sec_con = $secured{ $u2 };
				}

				sleep 1;
			}
		}

		# Disconnect
		sleep 2;				
		{
			$alice->finish($u2);

			my $dis;
			until( $dis )
			{
				{
					lock( %disconnected );
					$dis = $disconnected{ $u2 };
				}
			}

			ok( $dis, "Disconnected from $u2" );
		}

    };

    my $bob_thread = async {
        my $bob = test_init($u2, $alice_buf);
        
        # establish
        {
            sync(sub {
                $bob->establish($u1);
            });

            select undef, undef, undef, 1.2;

			my $con = 0;

			while( $con == 0 ){
				sleep 1;

				my $msg;
				{
					lock( @$bob_buf );
					$msg = shift @$bob_buf;
				}

				if( $msg ){
					my $resp = $bob->decrypt($u1, $msg);
				}

				{
					lock( %connected );
					$con = $connected{ $u1 };
				}

			}

            sync(sub {
                ok($established->{$u1}, "Connection with $u1 established");
            });
        }
        
		# Encrypt a message and send it to Alice
		{
			my $enc_msg = $bob->encrypt($u1, $m2);
			lock( @$alice_buf );
			push @$alice_buf, $enc_msg;
		}

		# Decrypt messages from Alice
		{
			my $rec_msg;
			my $dec_msg;

			until( $dec_msg )
			{
				{
					lock( @$bob_buf );
					$rec_msg = shift @$bob_buf;
					$dec_msg = $bob->decrypt($u1, $rec_msg);
				}
				sleep 1;
			}

			ok( $dec_msg eq $m1, "Send: $m1 = Decrypted: $dec_msg");
		}

		sleep 2;
		
		# Monitor for SMP until the conversation is secure
		{
			my $sec_con;
			
			until( $sec_con )
			{
				my $msg;
				{
					lock( @$bob_buf );
					$msg = shift @$bob_buf;
				}
				
				if( $msg )
				{
					my $resp = $bob->decrypt($u1, $msg);
					if($resp){
						print "resp $resp\n";
					}
				}

				my $smp_req;
				{
					lock( %smp_request );
					$smp_req = $smp_request{ $u1 };
				}

                # takes a few steps to finish SMP
				if( $smp_req )
				{
					$bob->continue_smp($u1, $secret);
					lock( %smp_request );
					$smp_request{ $u1 } = 0;
				}
								
				{
					lock( %secured );
					$sec_con = $secured{ $u1 };
				}

				sleep 1;
			}
		}

		# Disconnect
		sleep 2;
		{
			$bob->finish($u1);

			my $dis;
			until( $dis )
			{
				{
					lock( %disconnected );
					$dis = $disconnected{ $u1 };
				}
			}

			ok( $dis, "Disconnected from $u1" );
		}

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

    # callback to inject an encrypted message (add to recipient's buffer)
    my $inject = sub {
        my ( $ptr, $account_name, $protocol, $dest_account, $message) = @_;

		lock( @$dest );
        push @$dest, $message;
    };

    # got a message from the OTR system (e.g. "Heartbeat received from alice")
	my $send_system_message = sub {
		my( $ptr, $account_name, $protocol, $dest_account, $message) = @_;
		
		if( $dest_account eq $u2 ){
			lock( @$bob_buf );
			push @$bob_buf, $message;
		}

		if( $dest_account eq $u1 ){
			lock( @$alice_buf );
			push @$alice_buf, $message;
		}
	};

	# created an unverified connection
	my $unverified_cb = sub {
		my($ptr, $username) = @_;

		pass("Unverified connection started with $username");
		lock( %connected );
		$connected{ $username } = 1;
        $established->{$username} = 1;
	};

    # created a verified connection, not tested yet
    # TODO: add tests for fingerprint verification
	my $secured_cb = sub {
		my($ptr, $username) = @_;
		
		pass("Secure connection established with $username");
		lock(%secured);
		$secured{ $username } = 1;
	};
	

    #### self-explanatory OTR callbacks below
	my $disconnected_cb = sub {
		my( $ptr, $username ) = @_;

		#print "Disconnected\n";

		lock( %disconnected );
		$disconnected{ $username } = 1;
	};
	my $error_cb = sub {
		my($ptr, $accountname, $protocol, $username, $title, $primary, $secondary) = @_;
		
		print "Error! -- $accountname -- $protocol -- $username -- $title -- $primary -- $secondary\n";
	};
	my $warning_cb = sub {
		my($ptr, $accountname, $protocol, $username, $title, $primary, $secondary) = @_;
		
		print "Warning! -- $accountname -- $protocol -- $username -- $title -- $primary -- $secondary\n";
	};
	my $info_cb = sub {
		my($ptr, $accountname, $protocol, $username, $title, $primary, $secondary) = @_;
		
		#print "Info -- $accountname -- $protocol -- $username -- $title -- $primary -- $secondary\n";

		if( $accountname eq $u2 ){
			lock( @$bob_info_buf );
			push @$bob_info_buf, $primary;
		}
	};
	
	my $new_fingerprint_cb = sub {
		my( $ptr, $accountname, $protocol, $username, $fingerprint) = @_;
		
		pass("New fingerprint for $username = $fingerprint");
	};

	my $still_connected_cb = sub {
		my( $ptr, $username ) = @_;
		
		#print "Still connected with $username\n";
	};

    # socialist millionares protocol, where one party creates a shared
    # secret and the other party must generate the same secret
	my $smp_request_cb = sub {
		my( $ptr, $protocol, $username, $question ) = @_;
		
		if( $question ){
            # this is never reached?
			print "Question asked: $question\n";
		}
		
		pass("$username requesting SMP shared secret");

		lock( %smp_request );
		$smp_request{ $username } = 1;
	};

    # install callbacks
    $otr->set_callback('inject' => $inject);
    $otr->set_callback('otr_message' => $send_system_message);

    $otr->set_callback('secured' => $secured_cb);
    $otr->set_callback('unverified' => $unverified_cb);
	$otr->set_callback('disconnect' => $disconnected_cb);
	$otr->set_callback('still_connected' => $still_connected_cb);

	$otr->set_callback('error' => $error_cb);
	$otr->set_callback('warning' => $warning_cb);
	$otr->set_callback('info' => $info_cb);
	$otr->set_callback('smp_request' => $smp_request_cb);
	
	$otr->set_callback('new_fingerprint' => $new_fingerprint_cb);

    return $otr;
}

