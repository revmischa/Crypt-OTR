package Crypt::OTR;

use 5.010000;
use strict;
use warnings;
use Carp qw/croak/;

use AutoLoader;

our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Crypt::OTR::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Crypt::OTR', $VERSION);

#########################

=head1 NAME

Crypt::OTR - Off-The-Record encryption library for secure instant messaging applications

=head1 SYNOPSIS

    use Crypt::OTR;
    
    # call near the beginning of your program, should only be one per process
    Crypt::OTR->init(
        account_name     => "alice",            # name of account associated with this keypair
        protocol_name    => "my_protocol_name", # e.g. 'AIM'
        max_message_size => 1024,               # how much to fragment
    );

    # create OTR object, set up callbacks
    my $otr = new Crypt::OTR();
    $otr->set_callback('inject' => \&otr_inject);
    $otr->set_callback('otr_message' => \&otr_system_message);
    $otr->set_callback('connect' => \&otr_connect);
    $otr->set_callback('unverified' => \&otr_unverified);

    # create a context for user "bob"
    $otr->establish("bob");  # calls otr_inject($account_name, $protocol, $dest_account, $message)

    # send a message to bob
    my $plaintext = "hello, bob! this is a message from alice";
    if (my $ciphertext = $otr->encrypt("bob", $plaintext)) {
        $my_app->send_message_to_user("bob", $ciphertext);
    } else {
        warn "Your message was not sent - no encrypted conversation is established\n";
    }

    # called from bob's end
    if (my $plaintext = $otr->decrypt("alice", $ciphertext)) {
        print "alice: $plaintext\n";
    } else {
        warn "We received an encrypted message from alice but were unable to decrypt it\n";
    }

    # done with chats
    $otr->finish("bob");
    
    # CALLBACKS 
    #  (if writing a multithreaded application you will
    #   probably want to lock a mutex when sending/receiving)

    # called when OTR is ready to send a message after massaging it.
    # this method should transmit $message over a socket or somesuch
    sub otr_inject {
        my ($self, $account_name, $protocol, $dest_account, $message) = @_;
        $my_app->send_message_to_user($dest_account, $message);
    }

    # called to display an OTR control message for a particular user or protocol
    sub otr_system_message {
        my ($self, $account_name, $protocol, $other_user, $otr_message) = @_;
        warn "OTR says: $otr_message\n";
        return 1;
    }

    # called when a verified conversation is established with $from_account
    sub connect {
        my ($self, $from_account) = @_;
        print "Started verified conversation with $from_account\n";
    }

    # called when an unverified conversation is established with $from_account
    sub unverified {
        my ($self, $from_account) = @_;
        print "Started unverified conversation with $from_account\n";
    }


=head1 DESCRIPTION

Perl wrapper around libotr2 - see http://www.cypherpunks.ca/otr/README-libotr-3.2.0.txt

=head1 EXPORT

None by default.

=head1 METHODS

=over 4


=item init(%opts)

This method sets up OTR and initializes the global OTR context. It is probably unsafe to call this more than once

Options:
 'account_name'     => name of the account in your application
 'protocol_name'    => string identifying your application
 'max_message_size' => how many bytes messages should be fragmented into

=cut

sub init {
    my ($class, %opts) = @_;

    crypt_otr_init();

    my $account_name = delete $opts{account_name} || 'crypt_otr_user';
    my $protocol_name = delete $opts{protocol_name} || 'crypt_otr';
    my $max_message_size = delete $opts{max_message_size};

    crypt_otr_set_accountname($account_name)
        if defined $account_name;

    crypt_otr_set_protocol($protocol_name)
        if defined $protocol_name;

    crypt_otr_set_max_message_size($max_message_size)
        if defined $max_message_size;
}


=item new()

Simple constructor.

=cut

sub new {
    my ($class, %opts) = @_;

    my $self = {
    };

    return bless $self, $class;
}


=item set_callback($event, \&callback)

Set a callback to be called when various events happen:

  inject: Called when establishing a connection, or sending a fragmented message. This should send your message over whatever communication channel your application is using.

  otr_message: Called when OTR wants to display a notification. Return 1 if the message has been displayed, return 0 if you want OTR to display the message inline.

  connect: Called when a verified conversation is established

  unverified: called when an unverified conversation is established

=cut

sub set_callback {
    my ($self, $action, $cb) = @_;

    # wrap in method call
    my $wrapped_cb = sub {
        $cb->($self, @_);
    };

    my $callback_map = {
        'inject' => \&crypt_otr_set_inject_cb,
        'otr_message' => \&crypt_otr_set_system_message_cb,
        'connect' => \&crypt_otr_set_connect_cb,
        'unverified' => \&crypt_otr_set_unverified_cb,
    };

    my $cb_method = $callback_map->{$action}
    or croak "unknown callback $action";

    $cb_method->($cb);
}


=item establish($user_name)

Attemps to begin an OTR-encrypted conversation with $user_name. This will call the inject callback with a message containing an OTR connection attempt.

=cut

sub establish {
    my ($self, $user_name) = @_;

    croak "No user_name specified to establish()" unless $user_name;
    return crypt_otr_establish($user_name);
}


=item encrypt($user_name, $plaintext)

Encrypts $plaintext for $user_name. Returns undef unless an encrypted message has been generated, in which case it returns that.

=cut

sub encrypt {
    my ($self, $user_name, $plaintext) = @_;

    return crypt_otr_process_sending($user_name, $plaintext);
}


=item decrypt($user_name, $ciphertext)

Decrypt a message from $user_name, returns plaintext if successful, otherwise undef

=cut

sub decrypt {
    my ($self, $user_name, $ciphertext) = @_;

    return crypt_otr_process_receiving($user_name, $ciphertext);
}


=item finish($user_name)

Ends an encrypted conversation, no new messages from $user_name will
be able to be decrypted

=cut

sub finish {
    my ($self, $user_name) = @_;

    return crypt_otr_disconnect($user_name);
}

=back

=head1 SEE ALSO

http://www.cypherpunks.ca/otr

=head1 TODO

- Data directory configuration

- More informational callbacks

- Socialist Millionaire Protocol (verify key fingerprints)

=head1 AUTHOR

Patrick Tierney, E<lt>patrick.l.tierney@gmail.comE<gt>
Mischa Spiegelmock, E<lt>mspiegelmock@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Patrick Tierney, Mischa Spiegelmock

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself, either Perl version 5.8.8 or, at your option, any later version of Perl 5 you may have available.

=cut


1;
__END__
