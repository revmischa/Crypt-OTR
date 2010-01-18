/* An attempt to use perl's threadsafe storage for static data failed */ 
/* This is how you could implement threading */

/*
OtrlUserState crypt_otr_get_userstate() { return MY_CXT.userstate; }
char* crypt_otr_get_keyfile() { return MY_CXT.keyfile; }
char* crypt_otr_get_fprfile() { return MY_CXT.fprfile; }
char* crypt_otr_get_accountname() { return MY_CXT.accountname; }
char* crypt_otr_get_protocol() { return MY_CXT.protocol; }
int crypt_otr_get_max_message_size() { return MY_CXT.max_message_size; }

char* crypt_otr_get_inject_cb() { return MY_CXT.inject_cb; }
char* crypt_otr_get_display_cb() { return MY_CXT.display_cb; }
char* crypt_otr_get_error_cb() { return MY_CXT.error_cb; }
char* crypt_otr_get_warning_cb() { return MY_CXT.warning_cb; }
char* crypt_otr_get_info_cb() { return MY_CXT.info_cb; }


void crypt_otr_set_userstate( OtrlUserState userstate ) { MY_CXT.userstate = userstate; }
void crypt_otr_set_keyfile( char* keyfile ) { MY_CXT.keyfile = keyfile; }
void crypt_otr_set_fprfile( char* fprfile ) { MY_CXT.fprfile = fprfile; }
void crypt_otr_set_accountname( char* accountname ) { MY_CXT.accountname = accountname; }
void crypt_otr_set_protocol( char* protocol ) { MY_CXT.protocol = protocol; }
void crypt_otr_set_max_message_size ( int max_size ) { MY_CXT.max_message_size = max_size; }
*/




/*
OtrlUserState crypt_otr_userstate;
char* crypt_otr_root;
char* crypt_otr_keyfile;
char* crypt_otr_fprfile;
char* crypt_otr_accountname;
char* crypt_otr_protocol;
unsigned int crypt_otr_max_size;

CV* crypt_otr_inject_cb;
CV* crypt_otr_system_message_cb;
CV* crypt_otr_connected_cb;
CV* crypt_otr_unverified_cb;
CV* crypt_otr_disconnected_cb;
CV* crypt_otr_stillconnected_cb;
CV* crypt_otr_error_cb;
CV* crypt_otr_warning_cb;
CV* crypt_otr_info_cb;
CV* crypt_otr_new_fpr_cb;
*/
/*
OtrlUserState crypt_otr_get_userstate() { return crypt_otr_userstate; }
char* crypt_otr_get_keyfile() { return crypt_otr_keyfile; }
char* crypt_otr_get_fprfile() { return crypt_otr_fprfile; }
char* crypt_otr_get_root() { return crypt_otr_root; }
char* crypt_otr_get_accountname() { return crypt_otr_accountname; }
char* crypt_otr_get_protocol() { return crypt_otr_protocol; }
unsigned int crypt_otr_get_max_message_size() { return crypt_otr_max_size; }

CV* crypt_otr_get_inject_cb() { return  crypt_otr_inject_cb; }
CV* crypt_otr_get_system_message_cb() { return crypt_otr_system_message_cb; }
CV* crypt_otr_get_connected_cb() { return crypt_otr_connected_cb; }
CV* crypt_otr_get_unverified_cb() { return crypt_otr_unverified_cb; }
CV* crypt_otr_get_disconnected_cb() { return crypt_otr_disconnected_cb; }
CV* crypt_otr_get_stillconnected_cb() { return crypt_otr_stillconnected_cb; }
CV* crypt_otr_get_error_cb() { return crypt_otr_error_cb; }
CV* crypt_otr_get_warning_cb() { return crypt_otr_warning_cb; }
CV* crypt_otr_get_info_cb() { return crypt_otr_info_cb; }
CV* crypt_otr_get_new_fpr_cb() { return crypt_otr_new_fpr_cb; }

*/ 

//void crypt_otr_set_userstate( OtrlUserState in_userstate ) { crypt_otr_userstate = in_userstate; }
//void crypt_otr_set_keyfile	( CryptOTRUserState in_state, char* in_keyfile ) 	{ in_state->keyfile = in_keyfile; }
//void crypt_otr_set_fprfile	( CryptOTRUserState in_state, char* in_fprfile ) 	{ in_state->fprfile = in_fprfile; }
//void crypt_otr_set_root		( CryptOTRUserState in_state, char* in_root ) 	{ in_state->root = in_root; }
//void crypt_otr_set_max_message_size ( CryptOTRUserState in_state, int in_max_size ) { in_state->max_size = in_max_size; }



// accessors
char* crypt_otr_get_keyfile( CryptOTRUserState in_state ) { return in_state->keyfile; }
char* crypt_otr_get_fprfile( CryptOTRUserState in_state ) { return in_state->fprfile; }



// Callback setters
#define CRYPT_OTR_INSTALL_CALLBACK(userstate_cb, perl_cb) SvREFCNT_inc(perl_cb); userstate_cb = perl_cb;

void crypt_otr_set_inject_cb( CryptOTRUserState in_state, CV* in_inject_cb ){ CRYPT_OTR_INSTALL_CALLBACK( in_state->inject_cb, in_inject_cb ); }
void crypt_otr_set_system_message_cb( CryptOTRUserState in_state, CV* in_sys_mes_cb ){ CRYPT_OTR_INSTALL_CALLBACK(in_state->system_message_cb, in_sys_mes_cb); }
void crypt_otr_set_connected_cb( CryptOTRUserState in_state, CV* in_connected_cb ){ CRYPT_OTR_INSTALL_CALLBACK( in_state->connected_cb, in_connected_cb); }
void crypt_otr_set_unverified_cb( CryptOTRUserState in_state, CV* in_unver_cb ) { CRYPT_OTR_INSTALL_CALLBACK( in_state->unverified_cb, in_unver_cb); }
void crypt_otr_set_disconnected_cb( CryptOTRUserState in_state, CV* in_disconnected_cb ){ CRYPT_OTR_INSTALL_CALLBACK( in_state->disconnected_cb, in_disconnected_cb); }
void crypt_otr_set_stillconnected_cb( CryptOTRUserState in_state, CV* in_still_cb ) { CRYPT_OTR_INSTALL_CALLBACK( in_state->stillconnected_cb, in_still_cb); }
void crypt_otr_set_error_cb( CryptOTRUserState in_state, CV* in_error_cb ) { CRYPT_OTR_INSTALL_CALLBACK( in_state->error_cb, in_error_cb); }
void crypt_otr_set_warning_cb( CryptOTRUserState in_state, CV* in_warning_cb ) { CRYPT_OTR_INSTALL_CALLBACK( in_state->warning_cb, in_warning_cb); }
void crypt_otr_set_info_cb( CryptOTRUserState in_state, CV* in_info_cb ) { CRYPT_OTR_INSTALL_CALLBACK( in_state->info_cb, in_info_cb); }
void crypt_otr_set_new_fpr_cb( CryptOTRUserState in_state, CV* in_fpr_cb ) { CRYPT_OTR_INSTALL_CALLBACK( in_state->new_fpr_cb, in_fpr_cb); }
void crypt_otr_set_smp_request_cb( CryptOTRUserState in_state, CV* in_smp ) { CRYPT_OTR_INSTALL_CALLBACK( in_state->smp_request_cb, in_smp); } 
