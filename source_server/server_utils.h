#include "server_global.h"

//  prologue for granting mutual exclusion
//  return -1 in case of errors, 0 otherwise
int sem_prologue(sem_t* sem_id);

 //epilogue for granting mutual exclusion
 //return -1 in case of errors, 0 otherwise
int sem_epilogue(sem_t* sem_id);


// test socket of communication in the user data store
//return return -1 in case the user is offline, -2 in case of errors, the socket_id otherwise
int get_socket_from_id(int user_id);

//return int 0 if busy, 1 if free, -1 on error
int test_busy_user(int user_id);


// return 1 on succes, -1 on error
int set_busy_user(int user_id, int busy);


//return return -1 in case of errors, 0 otherwise
int set_user_socket(string username, int socket);


user_info* copy_user_store();


//initialize content of user datastore
//return 0 in case of errors, 1 otherwise
int init_user_info(user_info* user_status);


int get_id_from_username(string username);


//return username or empty string in case of errors
string get_username_from_id(size_t id);

//Removes traces of other execution
void pre_cleanup();


//Send message to the message queue of the to_user_id
//return 0 in case of success, otherwise
int relay_write(uint to_user_id, message_info msg);

//read from message queue of user_id
//return -1 if no message has been read otherwise return the bytes copied
int relay_read(int user_id, message_info& msg, bool blocking);


//handles SIG_ALARM, every REQUEST_CONTROL_TIME the client controls for a chat request
void signal_handler(int sig);


//perform authenticad encryption and then send operation
//pt is pointer of plaintext without sequence number
//return 1 in case of success, 0 otherwise
int secure_send(int c_socket_id, uchar* pt, uint pt_len);

//decipher it and return the plaintext in the correspodent parameter and controls the sequence number
//return int plaintext length or -1 if error
int secure_recv(int c_socket_id, unsigned char** plaintext);
