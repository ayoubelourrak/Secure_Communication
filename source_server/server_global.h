#ifndef HEADER_GUARD_SERVER
#define HEADER_GUARD_SERVER
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <limits.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <errno.h>
#include <fcntl.h>
#include "../constant.h"
#include "../util.h"
#include "../secure.h"

using namespace std;
using uchar = unsigned char;
typedef void (*sighandler_t)(int);



struct user_info{
    int socket_id; //if socket_id is equal to -1 then the user isn't connected
    string username;
    int busy = 0;
};

struct message_info{
    long type;
    char buffer[RELAY_MSG_SIZE];
};



extern int client_id;
extern int c_socket_id;
extern message_info relay_msg;

//Parameters of connection
extern const char *srv_ip;
extern const int srv_port;
extern void* server_privk;

extern uchar* session_key;
extern uint32_t session_key_len;

//Handling mutual exclusion for accessing the user datastore
extern const char* sem_user_store;
extern const char* message_queue;

void* create_shared_memory(ssize_t size);

extern void* shared_mem;
int secure_send(int c_socket_id, uchar* pt, uint pt_len);
int secure_recv(int c_socket_id, unsigned char** plaintext);

extern uint32_t rcv_counter;
extern uint32_t snd_counter;

#endif
