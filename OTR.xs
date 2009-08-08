#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "crypt-otr.h"

#include "ppport.h"


/* Global Data */

#define MY_CXT_KEY "Crypt::OTR::_guts" XS_VERSION

typedef struct {
    /* Put Global Data in here */
    OtrlUserState userstate;		/* you can access this elsewhere as MY_CXT.userstate */
	char* keyfile;
	char* fprfile;
	char* accountname; /* This is YOUR id.  OTR convention is that *username* is THEM */
	char* protocol;
	int* max_message_size;
	char* inject_cb; /* From this callback you get an encrypted version of your original message (sort of) */
	char* display_cb; 
	char* connected_cb; /* This callback is called when a context transitions to ENCRYPTED */
	char* disconnected_cb; /* This callback is called when a context transitions to PLAINTEXT */ 
	char* error_cb;
	char* warning_cb;
	char* info_cb;
	char* new_fpr_cb;
} my_cxt_t;

START_MY_CXT

#include "const-c.inc"

MODULE = Crypt::OTR		PACKAGE = Crypt::OTR		

INCLUDE: const-xs.inc

BOOT:
{
    MY_CXT_INIT;
    /* If any of the fields in the my_cxt_t struct need
     * to be initialised, do it here.
     */
	
	MY_CXT.userstate = NULL;
	MY_CXT.keyfile = NULL;
	MY_CXT.fprfile = NULL;
	MY_CXT.accountname = NULL;
	MY_CXT.protocol = NULL;
	MY_CXT.max_message_size = 2343; /* AIM. */
	
	MY_CXT.inject_cb = NULL;
	MY_CXT.display_cb = NULL;
	MY_CXT.connected_cb = NULL;
	MY_CXT.disconnected_cb = NULL;
	MY_CXT.error_cb = NULL;
	MY_CXT.warning_cb = NULL;
	MY_CXT.info_cb = NULL;
	MY_CXT.new_fpr_cb = NULL;
}


void
crypt_otr_init( )

void
crypt_otr_cleanup(  IN CryptOTRUserState perl_state )

CryptOTRUserState 
crypt_otr_create_user( IN char* perl_root, IN char* perl_account, IN char* perl_proto  )
	OUTPUT:
		RETVAL

void 
crypt_otr_establish( IN CryptOTRUserState perl_state, IN char* perl_account, IN char* perl_proto, IN int perl_max, IN char* perl_username )

void
crypt_otr_disconnect( IN CryptOTRUserState perl_state, IN char* perl_account, IN char* perl_proto, IN int perl_max, IN char* perl_username )

SV*
crypt_otr_process_sending( IN CryptOTRUserState perl_state, IN char* perl_account, IN char* perl_proto, IN int perl_max, IN char* perl_username, IN char* perl_message )	
	OUTPUT:
		RETVAL

SV* 
crypt_otr_process_receiving( IN CryptOTRUserState perl_state, IN char* perl_account, IN char* perl_proto, IN int perl_max, IN char* perl_who, IN char* perl_message )
	OUTPUT:
		RETVAL

void 
crypt_otr_set_inject_cb( IN CryptOTRUserState perl_state, IN CV* perl_set )

void 
crypt_otr_set_system_message_cb( IN CryptOTRUserState perl_state, IN CV* perl_set )

void 
crypt_otr_set_connected_cb( IN CryptOTRUserState perl_state, IN CV* perl_set )

void 
crypt_otr_set_unverified_cb( IN CryptOTRUserState perl_state, IN CV* perl_set )

void 
crypt_otr_set_stillconnected_cb( IN CryptOTRUserState perl_state, IN CV* perl_set )

void 
crypt_otr_set_disconnected_cb( IN CryptOTRUserState perl_state, IN CV* perl_set )

void 
crypt_otr_set_error_cb( IN CryptOTRUserState perl_state, IN CV* perl_set ) 

void 
crypt_otr_set_warning_cb( IN CryptOTRUserState perl_state, IN CV* perl_set )

void 
crypt_otr_set_info_cb( IN CryptOTRUserState perl_state, IN CV* perl_set )

void 
crypt_otr_set_new_fpr_cb( IN CryptOTRUserState perl_state, IN CV* perl_set ) 




