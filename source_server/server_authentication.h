#include "server_utils.h"
#include "server_global.h"

//handle authentication with client
//return user_id of the client, -1  in case of errors
int authentication_client(string pwd_for_keys);
