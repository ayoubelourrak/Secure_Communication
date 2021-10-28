#include "client_utils.h"
#include "client_global.h"

//ver is AUTH_CLNT_SRV or AUTH_CLNT_CLNT
//return -1 if error, 0 otherwise
int authentication(int id_sock, uint8_t ver);

//return -1 in case of error, 0 otherwise
int authentication_receiver(int id_sock);
