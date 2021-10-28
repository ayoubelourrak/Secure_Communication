#include "client_global.h"

//help command
void help();

//return uint8_t opcode
uint8_t string_to_command(string cmd);

//return the username or empty in case of error
string id_to_username(int user_id, user* users);

//return 0 in case of success
int chat(struct msg_command* msg_send, user* users);

void free_list_users(struct user* users);

//return number of users online, or -1 in case of error
int get_online_users(unsigned char* plaintext, uint32_t pt_len);

//return 0 in case of success, -1 otherwise.
int print_users(user* users);

//get plaintext
//return Return plaintext len or -1 in case of error
int plaintext_from_client(unsigned char* ciphertext, uint32_t msg_lenght, unsigned char** plaintext);

//return plaintext length or -1 in case of error
int secure_recv(int socket, unsigned char** plaintext);

//return The length of sending_msg, 0 if error(s)
int message_to_client(unsigned char* pt, uint32_t pt_len, unsigned char** sending_msg);

//return 0 in case of error, 1 otherwise
int secure_send(int c_socket_id, uchar* pt, int pt_len);

//return -1 in case of error
int command_send(int id_sock, msg_command* cmd_send);

//return -1 in case of error, 0 otherwise
int send_message(int id_sock, message_info* msg_to_send);

//return int -1 id error, 0 otherwise
int receive_message(int id_sock, string& msg, unsigned char* msg_rcvd, uint32_t msg_rcvd_len);

//return 0 in case of success, -1 otherwise
int get_self_id(int socket);

//return 0 in case of success, -1 otherwise
int negative_rsp(int id_sock, int neg_user);
