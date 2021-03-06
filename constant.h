#ifndef FUNCTIONS_CONSTANTS_INCLUDED
#define FUNCTIONS_CONSTANTS_INCLUDED

//ERROR
#define GEN_ERR             0x00
#define CONN_ERR            0x01
#define SEND_ERR            0x02
#define REC_ERR             0x03
#define MALLOC_ERR          0x04
#define SOCK_ERR            0x05
#define BIND_ERR            0x06
#define LISTEN_ERR          0x07
#define CLOSE_ERR           0x08
#define FORK_ERR            0x09
#define INT_OW_ERR          0x0A
#define SEM_OPEN_ERR        0x0B
#define SEM_WAIT_ERR        0x0C
#define SEM_POST_ERR        0x0D
#define SEM_CLOSE_ERR       0x0E
#define MMAP_ERR            0x0F
#define SRV_INTERNAL_ERR    0x10
#define AUTHENTICATION_ERR  0x11
#define MSG_ERR             0x12

//COMMMAD CODE
#define NOT_VALID_CMD   0x01
#define EXIT_CMD        0x02
#define ONLINE_CMD      0x03
#define CHAT_CMD        0x04
#define HELP_CMD        0x05
#define CHAT_POS        0x06
#define CHAT_NEG        0x07
#define STOP_CMD       0x08
#define CHAT_RESPONSE   0x09
#define AUTH            0x0A
#define USRID           0x0B


#define MAX_USERNAME_SIZE   16


#define SOCKET_QUEUE 15
#define REGISTERED_USERS 4
#define BUFFER_MAX  10000
#define REQUEST_CONTROL_TIME 30 // seconds
#define RELAY_CONTROL_TIME 2 //seconds
#define RELAY_MSG_SIZE 11000
#define NONCE_SIZE 2
#define AUTH_CLNT_SRV 1
#define AUTH_CLNT_CLNT 2
#define MAX_SEQ_NUM 0xFFFFFFFF


#define AUTH_ENCRYPT_DEFAULT EVP_aes_256_gcm()
#define DIGEST_DEFAULT EVP_sha256()
#define IV_DEFAULT EVP_CIPHER_iv_length(AUTH_ENCRYPT_DEFAULT) // 12
#define TAG_DEFAULT 16
#define PUBKEY_DEFAULT 2048
#define PUBKEY_DEFAULT_SER 451

#endif
