

/////////////////////////////////////////
//  CRYPT-OTR PERL FUNCTIONS
////////////////////////////////////////


/* crypt_otr_init
 * Call OTRL_INIT
 * Create a private key if there is not one already
 * Store values of accountname (your name), the protocol
 */

//int crypt_otr_init( SV* sv_accountname, SV* sv_protocolname, SV* sv_max_message_size )
int crypt_otr_init(  )
{		
	OTRL_INIT;
}

CryptOTRUserState crypt_otr_create_user( char* in_root )
{
	char* root = in_root;
	char* temp_keyfile;
	char* temp_fingerprintfile;
	
	char* temp_key_name = PRIVKEY_FILE_NAME;
	char* temp_fpr_name = STORE_FILE_NAME;
	
	CryptOTRUserState crypt_state = crypt_otr_create_new_userstate();

	crypt_state->root = in_root;
	
	crypt_state->otrl_state = otrl_userstate_create();	
	printf( "userstate ptr = %i\n", crypt_state->otrl_state );
				
	root = expand_filename( crypt_state->root );
	
	temp_keyfile = malloc( (strlen(root) + strlen( PRIVKEY_FILE_NAME ) + 1)*sizeof(char) ); // +1 for the \0

	temp_fingerprintfile =  malloc( (strlen(root) + strlen( STORE_FILE_NAME ) + 1)*sizeof(char) ); // +1 for the \0 
		
	sprintf( temp_keyfile, "%s%s", root, temp_key_name );
	sprintf( temp_fingerprintfile, "%s%s", root, temp_fpr_name );
				
	crypt_state->keyfile = temp_keyfile;
	crypt_state->fprfile = temp_fingerprintfile;

	printf( "Saved keyfile %s\n", crypt_state->keyfile );

	//free( temp_keyfile );
	//free( temp_fingerprintfile );
	
	printf( "Made State = %i\n", crypt_state );

	
	return crypt_state;
}


void crypt_otr_establish( CryptOTRUserState in_state, char* in_account, char* in_proto, int in_max, char* in_username )
{		
	printf( "Got State = %i\n", in_state );
		
	if( otrl_privkey_read( in_state->otrl_state, in_state->keyfile ) ) {
		printf( "Could not read OTR key from %s\n", in_state->keyfile);
		crypt_otr_create_privkey( in_state, in_account, in_proto );
	}
	else {
		printf( "Loaded private key file from %s\n", in_state->keyfile );
	}
	

	crypt_otr_startstop(in_state, in_account, in_proto, in_username, 1 );
}


void crypt_otr_disconnect( CryptOTRUserState in_state, char* in_account, char* in_proto, int in_max, char* in_username )
{
	crypt_otr_startstop(in_state, in_account, in_proto, in_username, 0 );
}


SV* crypt_otr_process_sending( CryptOTRUserState crypt_state, char* in_account, char* in_proto, int in_max, char* who, char* sv_message )
{
	char* newmessage = NULL;
	char* message = strdup( sv_message );
	OtrlUserState userstate = crypt_state->otrl_state;
	const char* accountname = in_account;
	const char* protocol = in_proto;
	char* username = who;
	int err;
	
	printf( "crypt_otr_process_sending enrcypting %s\n%s\n%s\n%i\n", 
		   message, accountname, username, userstate );
	
	if( !who || !message )
		return sv_2mortal( newSVpv( newmessage, 0 ));
	
	err = otrl_message_sending( userstate, &otr_ops, NULL, 
						   accountname, protocol, username, 
						   message, NULL, &newmessage, NULL, NULL);

	puts( "done sending" );
	
	if( err && newmessage == NULL ) {
		/* Be *sure* not to send out plaintext */
		char* ourm = strdup( "" );
		free( message ); // This may cause bugs, I don't know how perl allocates memory, though it's probably with strdup
		message = ourm;
	} else if ( newmessage ) {
		/* Fragment the message if necessary, and send all but the last
		 * fragment over the network.  The client will send the last
		 * fragment for us. */
		ConnContext* context = otrl_context_find( userstate, username, accountname, 
										  protocol, 0, NULL, NULL, NULL );
		free( message );
		message = NULL;
		err = otrl_message_fragment_and_send(&otr_ops, NULL, context,
									  newmessage, OTRL_FRAGMENT_SEND_ALL_BUT_LAST, message);
		otrl_message_free(newmessage);
	}
	
	printf( "Finished otrl_sending\n" );
	printf( "Returning message:\n%s\n", message );

	SV* temp_return = sv_2mortal( newSVpv( message, 0 ));		 
		
	return temp_return;
}


/*
 * returns whether a otr_message was received
 * sets *message to NULL, when it was an internal otr message
 */
SV*  crypt_otr_process_receiving( CryptOTRUserState crypt_state, char* in_accountname, char* in_protocol, int in_max, char* who, char* sv_message )
{
	char* message = strdup( sv_message  );
	//char* message = message_ptr;
	char* message_out = NULL;
    	char* newmessage = NULL;
	OtrlTLV* tlvs = NULL;
	OtrlTLV* tlv = NULL;
	OtrlUserState userstate = crypt_state->otrl_state;
	char* username = who;
	int res;
	const char* accountname = in_accountname;
	const char* protocol = in_protocol;
	ConnContext* context;
	NextExpectedSMP nextMsg;

	if( !who || !message )
		return sv_2mortal( newSVpv( newmessage, 0 ));

	//printf( "crypt_otr_process_receiving start\n" );
	//printf( "who: %s\nmsg:\n%s\n", who, message );

	res = otrl_message_receiving( userstate, &otr_ops, crypt_state, 
							accountname, protocol, username, message,
							&newmessage, &tlvs, NULL, NULL );

	if( newmessage ) {
		char* ourm = malloc( strlen( newmessage ) + 1 );
		if( ourm ) {
			strcpy( ourm, newmessage );
		}
		otrl_message_free( newmessage );
		free( message ); // this may cause problems, if perl doesn't use malloc, or tries cleaning up the pointer itself
		message = ourm;
	}

	tlv = otrl_tlv_find( tlvs, OTRL_TLV_DISCONNECTED );
	if( tlv ) {
		/* Notify the user that the other side disconnected */
		crypt_otr_handle_disconnection( username );
	}

	/* Keep track of our current progress in the Socialist Millionaires'
	 * Protocol. */
	context = otrl_context_find( userstate, username, accountname, protocol, 0, NULL, NULL, NULL );
	if( context ) {
		nextMsg = context->smstate->nextExpected;

		if( context->smstate->sm_prog_state == OTRL_SMP_PROG_CHEATED ) {
			crypt_otr_abort_smp( context );
			context->smstate->nextExpected = OTRL_SMP_EXPECT1;
			context->smstate->sm_prog_state = OTRL_SMP_PROG_OK;
		} else {
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1Q);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT1)
					crypt_otr_abort_smp(context);
				else {
					char *question = (char *)tlv->data;
					char *eoq = memchr(question, '\0', tlv->len);
					if (eoq) {
						crypt_otr_ask_socialist_millionaires_q(context, question);
					}
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT1)
					crypt_otr_abort_smp(context);
				else {
					crypt_otr_ask_socialist_millionaires(context);
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP2);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT2)
					crypt_otr_abort_smp(context);
				else {
					context->smstate->nextExpected = OTRL_SMP_EXPECT4;
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP3);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT3)
					crypt_otr_abort_smp(context);
				else {
					crypt_otr_completed_smp( context );
					context->smstate->nextExpected = OTRL_SMP_EXPECT1;
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP4);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT4)
					crypt_otr_abort_smp(context);
				else {
					crypt_otr_completed_smp( context );
					context->smstate->nextExpected = OTRL_SMP_EXPECT1;
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP_ABORT);
			if (tlv) {				
				context->smstate->nextExpected = OTRL_SMP_EXPECT1;
			}
		}
	}

	otrl_tlv_free(tlvs);

	/* If we're supposed to ignore this incoming message (because it's a
	 * protocol message), set it to NULL, so that other plugins that
	 * catch receiving-im-msg don't return 0, and cause it to be
	 * displayed anyway. */
	if (res) {
		free(message);
		message = NULL;
	}
			
	//printf( "crypt_otr_process_receiving end\n" );
	//printf( "who: %s\nmsg:\n%s\n", who, message );	
			
	SV* temp_return = sv_2mortal( newSVpv( message, 0 ));
	
	return temp_return;
	//return sv_2mortal( newSVpv( message, 0 ));		
}



void crypt_otr_cleanup( CryptOTRUserState crypt_state ){

	free( crypt_state->keyfile );
	free( crypt_state->fprfile );
	free( crypt_state );

}
