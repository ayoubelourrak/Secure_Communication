#ifndef HEADER_GUARD
#define HEADER_GUARD

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <climits>
#include <limits>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sstream>
#include "../constant.h"
#include "../util.h"
#include "../secure.h"
using namespace std;


extern bool in_chat;
extern bool error;

extern string actual_user;
extern int actual_user_id;

extern string peer_username;
extern int peer_id;

extern int id_sock;

extern unsigned char* sess_key_client_server;
extern uint32_t sess_key_client_server_len;

extern unsigned char* sess_key_client_client;
extern uint32_t sess_key_client_client_len;

extern unsigned char* peer_pub_key;

extern unsigned char* server_cert;

extern uint32_t rcv_counter;
extern uint32_t snd_counter;
extern uint32_t rcv_counter_client_client;
extern uint32_t snd_counter_client_client;


struct msg_command
{
    uint8_t opcode;
    int user_id;
};

struct message_info
{
    uint8_t opcode;
    uint16_t user_id_recipient;
    uint16_t length;
    unsigned char* payload;
};

struct user
{
    int user_id;
    unsigned char* username;
    size_t username_size;
    user* next;
};

extern user* users;

#endif
