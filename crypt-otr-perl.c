#include <gcrypt.h>

/////////////////////////////////////////
//  CRYPT-OTR PERL FUNCTIONS
////////////////////////////////////////


int crypt_otr_init(  )
{		
	OTRL_INIT;
	// This works without this line, and the pidgin OTR plugin doesn't use it
	//otrl_sm_init();
}

CryptOTRUserState crypt_otr_create_user( char* in_root, char* account_name, char* protocol )
{
	char* root = in_root;
	char* temp_keyfile;
	char* temp_fingerprintfile;
	CryptOTRUserState crypt_state = crypt_otr_create_new_userstate();

	crypt_state->root = strdup( in_root );
	crypt_state->otrl_state = otrl_userstate_create();	
	
	temp_keyfile = malloc( (strlen(in_root) + 
					    strlen(PRIVKEY_FILE_NAME) +
					    strlen(account_name) +
					    strlen(protocol) +
					    2 + 1)*sizeof(char) ); // +1 for the \0

	temp_fingerprintfile =  malloc( (strlen(in_root) + 
							   strlen(STORE_FILE_NAME) +
							   strlen(account_name) +
							   strlen(protocol) + 
							   2 + 1)*sizeof(char) ); // +1 for the \0 
		
	sprintf( temp_keyfile, "%s%s-%s-%s", in_root, PRIVKEY_FILE_NAME, account_name, protocol);
	sprintf( temp_fingerprintfile, "%s%s-%s-%s", in_root, STORE_FILE_NAME, account_name, protocol);
				
	crypt_state->keyfile = temp_keyfile;
	crypt_state->fprfile = temp_fingerprintfile;
	
	return crypt_state;
}

// load private key from file, or create new one
// (this may block for several minutes while generating a key)
void crypt_otr_load_privkey( CryptOTRUserState in_state, char* in_account, char* in_proto, int in_max ) {
  if (in_state->privkey_loaded)
    return;

  in_state->privkey_loaded = 1;

  gcry_error_t res = otrl_privkey_read( in_state->otrl_state, in_state->keyfile );

  if( res ) {
    printf( "Could not read OTR key from %s\n", in_state->keyfile);
    crypt_otr_create_privkey( in_state, in_account, in_proto );
  }
  else {
    printf( "Loaded private key file from %s\n", in_state->keyfile );
  }
}

void crypt_otr_establish( CryptOTRUserState in_state, char* in_account, char* in_proto, int in_max, 
					 char* in_username ) {		
  
  crypt_otr_load_privkey( in_state, in_account, in_proto, in_max );
  crypt_otr_startstop(in_state, in_account, in_proto, in_username, 1 );
}


void crypt_otr_disconnect( CryptOTRUserState in_state, char* in_account, char* in_proto, int in_max, 
					  char* in_username )
{
	crypt_otr_startstop(in_state, in_account, in_proto, in_username, 0 );
}


SV* crypt_otr_process_sending( CryptOTRUserState crypt_state, char* in_account, char* in_proto, int in_max, 
						 char* who, char* sv_message )
{
	char* newmessage = NULL;
	char* message = strdup( sv_message );
	OtrlUserState userstate = crypt_state->otrl_state;
	const char* accountname = in_account;
	const char* protocol = in_proto;
	char* username = who;
	int err;
		
	if( !who || !message )
		return newSVpv( newmessage, 0);

	err = otrl_message_sending( userstate, &otr_ops, crypt_state, 
						   accountname, protocol, username, 
						   message, NULL, &newmessage, NULL, NULL);

	if( err && (newmessage == NULL) ) {
		/* Be *sure* not to send out plaintext */
		//puts( "Oops, message not encrypted" );
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
		err = otrl_message_fragment_and_send(&otr_ops, crypt_state, context,
									  newmessage, OTRL_FRAGMENT_SEND_ALL_BUT_LAST, &message);

		otrl_message_free(newmessage);
	}
		
	return newSVpv( message, 0 );
}

/*
 * returns whether a otr_message was received
 * sets *message to NULL, when it was an internal otr message
 */
SV*  crypt_otr_process_receiving( CryptOTRUserState crypt_state, char* in_accountname, char* in_protocol, int in_max, 
						    char* who, char* sv_message )
{
	char* message = strdup( sv_message  );
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
		return newSVpv( newmessage, 0);

	res = otrl_message_receiving( userstate, &otr_ops, crypt_state, 
							accountname, protocol, username, message,
							&newmessage, &tlvs, NULL, NULL );

	if( newmessage ) {
		char* ourm = malloc( strlen( newmessage ) + 1 );
		if( ourm ) {
			strcpy( ourm, newmessage );
		}
		otrl_message_free( newmessage );
		free( message );
		message = ourm;
	}

	tlv = otrl_tlv_find( tlvs, OTRL_TLV_DISCONNECTED );
	if( tlv ) {
		/* Notify the user that the other side disconnected */
		crypt_otr_handle_disconnection(crypt_state, username );
	}

	/* Keep track of our current progress in the Socialist Millionaires'
	 * Protocol. */
	context = otrl_context_find( userstate, username, 
						    accountname, protocol, 0, NULL, NULL, NULL );

	if( context ) {
		nextMsg = context->smstate->nextExpected;

		if( context->smstate->sm_prog_state == OTRL_SMP_PROG_CHEATED ) {
			crypt_otr_abort_smp_context( crypt_state, context );
			context->smstate->nextExpected = OTRL_SMP_EXPECT1;
			context->smstate->sm_prog_state = OTRL_SMP_PROG_OK;
		} else {
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1Q);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT1)
					crypt_otr_abort_smp_context( crypt_state, context);
				else {
					char *question = (char *)tlv->data;
					char *eoq = memchr(question, '\0', tlv->len);
					if (eoq) {
						crypt_otr_ask_socialist_millionaires(crypt_state, in_accountname, in_protocol,
													  context, question, 1);
					}
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT1)
					crypt_otr_abort_smp_context(crypt_state, context);
				else {
					crypt_otr_ask_socialist_millionaires(crypt_state, in_accountname, in_protocol,
												  context, NULL, 1 );
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP2);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT2)
					crypt_otr_abort_smp_context(crypt_state, context);
				else {
					crypt_otr_notify_socialist_millionaires_statis( crypt_state, in_accountname, in_protocol,
														   context, 2 );
					context->smstate->nextExpected = OTRL_SMP_EXPECT4;
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP3);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT3)
					crypt_otr_abort_smp_context(crypt_state, context);
				else {
					crypt_otr_notify_socialist_millionaires_statis( crypt_state, in_accountname, in_protocol, 
														   context, 3 );
					context->smstate->nextExpected = OTRL_SMP_EXPECT1;
				}
			}
			tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP4);
			if (tlv) {
				if (nextMsg != OTRL_SMP_EXPECT4)
					crypt_otr_abort_smp_context(crypt_state, context);
				else {
					crypt_otr_notify_socialist_millionaires_statis( crypt_state, in_accountname, in_protocol,
														   context, 3 );
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

	return newSVpv( message, 0 );
}

/* Start the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret, and optionally a question to pass to
 * the buddy. */
void crypt_otr_start_smp( CryptOTRUserState crypt_state, char* in_accountname, char* in_protocol, int in_max,
					 char* who, char* secret )
{
	ConnContext* ctx = crypt_otr_get_context( crypt_state, in_accountname, in_protocol, who );

	otrl_message_initiate_smp(crypt_state->otrl_state, &otr_ops, crypt_state,
						 ctx, secret, strlen(secret) );
}


/* Start the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret, and optionally a question to pass to
 * the buddy. */
void crypt_otr_start_smp_q( CryptOTRUserState crypt_state, char* in_accountname, char* in_protocol, int in_max,
					 char* who, char* secret, char* question )
{
	ConnContext* ctx = crypt_otr_get_context( crypt_state, in_accountname, in_protocol, who );

	otrl_message_initiate_smp_q(crypt_state->otrl_state, &otr_ops, crypt_state,
						   ctx, question, secret, strlen(secret));
}

/* Continue the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret (ie finish step 2). */
void crypt_otr_continue_smp( CryptOTRUserState crypt_state, char* in_accountname, char* in_protocol, int in_max,
					    char* who, const unsigned char *secret )
{
	ConnContext* ctx = crypt_otr_get_context( crypt_state, in_accountname, in_protocol, who );

	otrl_message_respond_smp(crypt_state->otrl_state, &otr_ops, crypt_state,
						ctx, secret, strlen(secret) );
}

/* Abort the SMP protocol.  Used when malformed or unexpected messages
 * are received. */
void crypt_otr_abort_smp( CryptOTRUserState crypt_state, char* in_accountname, char* in_protocol, int in_max,
					 char* who )
{
	ConnContext* ctx = crypt_otr_get_context( crypt_state, in_accountname, in_protocol, who );

	otrl_message_abort_smp(crypt_state->otrl_state, &otr_ops, crypt_state, ctx);
}


///// Accessors
SV* crypt_otr_get_keyfile( CryptOTRUserState in_state ) { return newSVpv( in_state->keyfile, 0 ); }
SV* crypt_otr_get_fprfile( CryptOTRUserState in_state ) { return newSVpv( in_state->fprfile, 0 ); }

OtrlPrivKey* crypt_otr_get_privkey( CryptOTRUserState in_state, char *account, char *proto, int maxsize ) {
  crypt_otr_load_privkey( in_state, account, proto, maxsize );  // try to ensure a privkey is loaded
  return otrl_privkey_find( in_state->otrl_state, account, proto );
}

char* crypt_otr_get_pubkey_data( CryptOTRUserState in_state, char *account, char *proto, int maxsize ) {
  OtrlPrivKey* privkey = crypt_otr_get_privkey(in_state, account, proto, maxsize);
  return privkey->pubkey_data;
}
size_t crypt_otr_get_pubkey_size( CryptOTRUserState in_state, char *account, char *proto, int maxsize ) {
  OtrlPrivKey* privkey = crypt_otr_get_privkey(in_state, account, proto, maxsize);
  return privkey->pubkey_datalen;
}
unsigned short crypt_otr_get_pubkey_type( CryptOTRUserState in_state, char *account, char *proto, int maxsize ) {
  OtrlPrivKey* privkey = crypt_otr_get_privkey(in_state, account, proto, maxsize);
  return privkey->pubkey_type;
}

///// Signing
// would be nice to make this take a scalarref instead of a char*
SV* crypt_otr_sign( CryptOTRUserState in_state, char *account, char *proto, int maxsize, char *msghash ) {
  OtrlPrivKey *privkey = crypt_otr_get_privkey( in_state, account, proto, maxsize );
  if (! privkey) {
    perror("Could not find privkey\n");
    return NULL;
  }

  unsigned char *sig;
  size_t siglen;

  otrl_privkey_sign(&sig, &siglen, privkey, msghash, strlen(msghash));

  // copy result, make SV
  SV *sig_sv = newSVpvn(sig, siglen);

  // we are responsible for freeing the signature
  free(sig);

  return sig_sv;
}

SV* crypt_otr_get_pubkey_str( CryptOTRUserState in_state, char *account, char *proto, int maxsize ) {
  OtrlPrivKey *privkey = crypt_otr_get_privkey( in_state, account, proto, maxsize );
  SV *privkey_sv = newSVpvn(privkey->pubkey_data, privkey->pubkey_datalen);
  return privkey_sv;
}

unsigned int crypt_otr_verify( unsigned char *msghash, unsigned char *sig, unsigned char *pubkey_data,
                               size_t pubkey_length, unsigned short pubkey_type) {

  // create s-expression object representing the public key
  gcry_sexp_t pubkey;

  gcry_sexp_new(&pubkey, pubkey_data, pubkey_length, 1);

  gcry_error_t err = otrl_privkey_verify( sig, strlen(sig), pubkey_type, pubkey_data, msghash, strlen(msghash) );

  gcry_sexp_release(pubkey);

  return err;
}

void crypt_otr_cleanup( CryptOTRUserState crypt_state ){
  if (crypt_state->inject_cb)
    SvREFCNT_dec(crypt_state->inject_cb);
  if (crypt_state->system_message_cb)
    SvREFCNT_dec(crypt_state->system_message_cb);
  if (crypt_state->connected_cb)
    SvREFCNT_dec(crypt_state->connected_cb);
  if (crypt_state->unverified_cb)
    SvREFCNT_dec(crypt_state->unverified_cb);
  if (crypt_state->disconnected_cb)
    SvREFCNT_dec(crypt_state->disconnected_cb);
  if (crypt_state->stillconnected_cb)
    SvREFCNT_dec(crypt_state->stillconnected_cb);
  if (crypt_state->error_cb)
    SvREFCNT_dec(crypt_state->error_cb);
  if (crypt_state->warning_cb)
    SvREFCNT_dec(crypt_state->warning_cb);
  if (crypt_state->info_cb)
    SvREFCNT_dec(crypt_state->info_cb);
  if (crypt_state->new_fpr_cb)
    SvREFCNT_dec(crypt_state->new_fpr_cb);
  if (crypt_state->smp_request_cb)
    SvREFCNT_dec(crypt_state->smp_request_cb);

  if (crypt_state->root)
    free( crypt_state->root );

  if (crypt_state->otrl_state)
    otrl_userstate_free( crypt_state->otrl_state );

  free( crypt_state->keyfile );
  free( crypt_state->fprfile );
  free( crypt_state );
}
