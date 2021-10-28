#include "server_global.h"
#include "server_utils.h"
#include "server_authentication.h"

///////////////////// GLOBAL VARIABLES ///////////////////
int client_id;
int c_socket_id;
message_info relay_msg;

//Parameters of connection
const char *srv_ip = "127.0.0.1";
const int srv_port = 4242;
void* server_privk;

uchar* session_key;
uint32_t session_key_len;

//Handling mutual exclusion for accessing the user datastore
const char* sem_user_store = "/user_store";
const char* message_queue = "/user_message_queue";


//Shared memory for storing data of users
void* shared_mem = create_shared_memory(sizeof(user_info)*REGISTERED_USERS);

void* create_shared_memory(ssize_t size){
    int protection = PROT_READ | PROT_WRITE; //Processes can read/write the contents of the memory
    int visibility = MAP_SHARED | MAP_ANONYMOUS; //Memory pages are shared across processes
    return mmap(NULL, size, protection, visibility, -1, 0);
}


//Handle the response to the client for the !online command
//return 0 in case of success, -1 otherwise
int get_users_online(int c_socket_id, uchar* plaintext)
{
    if(c_socket_id < 0 || plaintext == nullptr){
        log("Invalid input parameters");
        return -1;
        }

    int ret;
    uint reply_offset = 0;
    unsigned char online_cmd = ONLINE_CMD;
    user_info* user_datastore_copy = copy_user_store();

    //Need to calculate how much space to allocate and send (limited users and username sizes in this context, can't overflow those values)
    int total_space_to_allocate = 9;
    int online_users = 0; //also num_pairs

    for(int i=0; i<REGISTERED_USERS; i++){
        if(user_datastore_copy[i].socket_id != -1){
            total_space_to_allocate += user_datastore_copy[i].username.length() + 8;
            online_users++;
            }
        }

    //Copy various fields in the reply msg
    uchar* reply_send = (uchar*)malloc(total_space_to_allocate);
    if(!reply_send){
        errorHandler(MALLOC_ERR);
        }
    uint32_t online_users_to_send = htonl(online_users);

    //Copy OPCODE and NUM_PAIRS
    memcpy(reply_send+reply_offset, (void*)&online_cmd, sizeof(uchar));
    reply_offset += sizeof(uchar);
    memcpy(reply_send+reply_offset, (void*)&online_users_to_send, sizeof(int));
    reply_offset += sizeof(int);

    for(int i=0; i<REGISTERED_USERS; i++){
        //Copy ID, USERNAME_LENGTH and USERNAME for online users
        if(user_datastore_copy[i].socket_id != -1){
            int curr_username_length = user_datastore_copy[i].username.length();
            uint32_t i_to_send = htonl(i);
            uint32_t curr_username_length_to_send = htonl(curr_username_length);

            memcpy(reply_send + reply_offset, (void*)&i_to_send, sizeof(int));
            reply_offset += sizeof(int);
            memcpy(reply_send + reply_offset, (void*)&curr_username_length_to_send, sizeof(int));
            reply_offset += sizeof(int);
            memcpy(reply_send + reply_offset, (void*)user_datastore_copy[i].username.c_str(), curr_username_length);
            reply_offset += curr_username_length;
            }
        }

    ret = secure_send(c_socket_id, (uchar*)reply_send, reply_offset);
    if(ret == 0){
        safe_free(reply_send, total_space_to_allocate);
        safe_free((uchar*)user_datastore_copy, REGISTERED_USERS*sizeof(user_info));
        errorHandler(SEND_ERR);
        return -1;
        }

    safe_free(reply_send, total_space_to_allocate);
    safe_free((uchar*)user_datastore_copy, REGISTERED_USERS*sizeof(user_info));
    return 0;
}



//Handle the response to the client for the !chat command
//return 0 in case of success, -1 in case of error
int handle_chat_request(int c_socket_id, int client_id, message_info& relay_msg, uchar* plaintext, uint plain_len)
{
    if(c_socket_id < 0 || client_id < 0 || client_id >= REGISTERED_USERS || plaintext == nullptr){
        log("Invalid input parameters");
        return -1;
        }
    if(!set_busy_user(client_id, 1)){
        log("ERROR: setting user busy\n");
        return -1;
        }
    if(plain_len != 9){
        log("ERROR on length of plaintext");
        return -1;
        }

    uint offset_plaintext = 5; //From where data is good to read
    uint offset_relay = 0;
    int ret;

    int peer_id_net;
    memcpy(&peer_id_net,(const void*)(plaintext + offset_plaintext),sizeof(int));
    offset_plaintext += sizeof(int);
    int peer_id = ntohl(peer_id_net);

    if(peer_id < 0 || peer_id >= REGISTERED_USERS){
        log("ERROR: invalid value");
        return -1;
        }

    unsigned char chat_cmd = CHAT_CMD;
    string client_username = get_username_from_id(client_id);
    if(client_username.empty()){
        log("ERROR on get_username_from_id");
        return -1;
        }

    int client_username_length = client_username.length();
    uint32_t client_username_length_net = htonl(client_username_length);
    uint32_t client_id_net = htonl(client_id);
    const char* username = client_username.c_str();

    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&chat_cmd, 1);
    offset_relay += sizeof(uchar);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&client_id_net, sizeof(int));
    offset_relay += sizeof(int);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&client_username_length_net, sizeof(int));
    offset_relay += sizeof(int);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)username, client_username_length);
    offset_relay += client_username_length;

    string client_pubkey_path = "certification/" + client_username + "_pubkey.pem";

    FILE* client_pubkey_file = fopen(client_pubkey_path.c_str(), "rb");
    if(!client_pubkey_file){
        log("Unable to open pubkey of client");
        return -1;
        }
    uchar* pubkey_client_ser;
    int pubkey_client_ser_len = serialize_pubkey_from_file(client_pubkey_file, &pubkey_client_ser);

    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)pubkey_client_ser, pubkey_client_ser_len);
    offset_relay += pubkey_client_ser_len;



    //Handle case user is offline
    if(get_socket_from_id(peer_id) == -1 || !test_busy_user(peer_id)){
        uchar chat_cmd = CHAT_NEG;
        offset_relay = 0;
        memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&chat_cmd, 1);
        offset_relay += sizeof(uchar);
        memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&peer_id_net, sizeof(int));
        offset_relay += sizeof(int);
        relay_write(client_id, relay_msg);
        return 0;
        }

    relay_write(peer_id, relay_msg);

    //Wait for response to the own named message queue (blocking)
    relay_read(client_id, relay_msg, true);
    memcpy((void*)(relay_msg.buffer + 1), (void*)&peer_id, sizeof(int));

    uint8_t opcode = relay_msg.buffer[0];

    int final_response_len;
    if(opcode == CHAT_NEG){
        final_response_len = 5;
        }
    else{
        final_response_len = 5 + PUBKEY_DEFAULT_SER;
        }

    // Send reply of the peer to the client
    ret = secure_send(c_socket_id, (uchar*)relay_msg.buffer, final_response_len);
    if(ret == 0){
        errorHandler(SEND_ERR);
        return -1;
        }
    if(!set_busy_user(client_id, 0)){
        log("ERROR: setting user busy while e ending requesting to chat \n");
        return -1;
        }

    return 0;
}


//return -1 in case of errors, 0 in case of success
int chat_response(uchar* plaintext, uint8_t opcode, uint plain_len)
{
    if(plaintext == nullptr){
        log("ERROR invalid parameters");
        return -1;
        }

    if(plain_len != 9){
        log("INVALID plain_len");
        return -1;
        }

    if(opcode == CHAT_POS)
        log("\n\n*** CHAT_POS ***\n");
    else if(opcode == CHAT_NEG)
        log("\n\n*** CHAT_NEG ***\n");
    else if(opcode == STOP_CMD)
        log("\n\n*** STOP_CMD ***\n");
    else{
        log("invalid opcode on chat_response");
        return -1;
        }


    uint offset_plaintext = 5;
    uint offset_relay = 0;
    int peer_id_net = *(int*)(plaintext + offset_plaintext);
    offset_plaintext += sizeof(int);

    int peer_id = ntohl(peer_id_net);
    if(peer_id < 0 || peer_id >= REGISTERED_USERS){
        log("INVALID peer_id on chat_response");
        return -1;
        }

    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&opcode, sizeof(uchar));
    offset_relay += sizeof(uchar);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&peer_id_net, sizeof(int));
    offset_relay += sizeof(int);

    if(opcode == CHAT_POS){

        string client_username = get_username_from_id(client_id);
        if(client_username.empty()){
            log("ERROR on get_username_from_id");
            return -1;
            }

        string client_pubkey_path = "certification/" + client_username + "_pubkey.pem";

        FILE* client_pubkey_file = fopen(client_pubkey_path.c_str(), "rb");
        if(!client_pubkey_file){
            log("Unable to open pubkey of client");
            return -1;
            }

        //Adding pubkey
        uchar* pubkey_client_ser;
        int pubkey_client_ser_len = serialize_pubkey_from_file(client_pubkey_file, &pubkey_client_ser);

        memcpy((void*)(relay_msg.buffer + offset_relay), (void*)pubkey_client_ser, PUBKEY_DEFAULT_SER);
        offset_relay += pubkey_client_ser_len;
        }

    relay_write(peer_id, relay_msg);
    return 0;
}

//return -1 in case of errors, 0 instead
int handle_auth_and_msg(uchar* plaintext, uint8_t opcode, int plaintext_len)
{
    if(opcode == AUTH)
        log("\n *** AUTH (" + to_string(opcode) + ") ***\n");
    else if(opcode == CHAT_RESPONSE)
        log("\n *** CHAT_RESPONSE ***\n");
    else{
        log("invalid opcode");
        return -1;
        }

    if(plaintext_len < 5 || plaintext_len > RELAY_MSG_SIZE || plaintext == nullptr){
        log("INVALID plaintext_len on handle_auth_and_msg");
        return -1;
        }

    uint offset_plaintext = 5;
    uint offset_relay = 0;
    int plain_len_no_seq = plaintext_len - 4;
    int peer_id_net = *(int*)(plaintext + offset_plaintext);
    offset_plaintext += sizeof(int);
    int peer_id = ntohl(peer_id_net);

    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&opcode, sizeof(uint8_t));
    offset_relay += sizeof(uint8_t);

    //Add length of msg in between
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&plain_len_no_seq, sizeof(int));
    offset_relay += sizeof(int);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)(plaintext + 5), plaintext_len - 5);
    offset_relay += (plaintext_len - 5);

    //Control if user is offline
    if(get_socket_from_id(peer_id) == -1){
        uchar chat_cmd = STOP_CMD;
        offset_relay = 0;
        memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&chat_cmd, 1);
        offset_relay += sizeof(uchar);
        memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&peer_id_net, sizeof(int));
        offset_relay += sizeof(int);
        relay_write(client_id, relay_msg);
        return 0;
        }

    return relay_write(peer_id, relay_msg);
}



int main(){

    //Create shared memory for mantaining info about users
    int ret=system("sudo sysctl -w kernel.msgmni=16384 kernel.msgmax=120000 kernel.msgmnb=600000");

    if(ret<0){
        log("failed to initialize kernel variables for message queue");
        return 0;
        }

    pre_cleanup();

    if(shared_mem == MAP_FAILED){
        log("MMAP failed");
        return 0;
    }

    user_info user_status[REGISTERED_USERS];
    ret = init_user_info(user_status);
    if(ret == 0){
        log("ERROR on init_user_info");
        return 0;
        }
    memcpy(shared_mem, user_status, sizeof(user_info)*REGISTERED_USERS);

    int listen_socket;                   //socket indexes
    struct sockaddr_in srv_addr, cl_addr;   //address informations
    pid_t pid;
    string password_for_keys;
    uchar msg_opcode;                        //where is received the opcode of the message
    uchar* plaintext;                       //buffer to store the plaintext
    int plain_len;


    cout << "Enter the password that will be used for reading the keys: ";
    FILE* server_key = fopen("certification/Server_privkey.pem", "rb");
    server_privk=read_privkey(server_key, NULL);
    if(!server_privk){
        cerr << "Wrong password";
        exit(1);
        }

    //Preparation of ip address struct
    memset(&srv_addr, 0, sizeof(srv_addr));
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket == -1){
        log("ERROR on listen socket");
        return 0;
        }

    //For avoiding annoying address already in use error
    int option = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    //Configuration of server address
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    if(-1 == inet_pton(AF_INET, srv_ip, &srv_addr.sin_addr)){
        log("ERROR on inet_pton: ");
        perror(strerror(errno));
        return 0;
        }

    if (-1 == bind(listen_socket, (struct sockaddr *)&srv_addr, sizeof(srv_addr))){
        log("ERROR on bind: ");
        perror(strerror(errno));
        return 0;
        }

    if (-1 == listen(listen_socket, SOCKET_QUEUE)){
        log("ERROR on listen: ");
        perror(strerror(errno));
        return 0;
        }

    unsigned int len = sizeof(cl_addr);
    log("Waiting...");

    while (true){
        c_socket_id = accept(listen_socket, (struct sockaddr *)&cl_addr, &len);
        if(c_socket_id == -1){
            log("ERROR on accept");
            return 0;
            }

        pid = fork();

        if (pid == 0){
            close(listen_socket);
            log("Connection with a client");

            //Manage authentication
            client_id = authentication_client(password_for_keys);
            if(client_id == -1){
                errorHandler(AUTHENTICATION_ERR);
                log("Errore di autenticazione");
                return -1;
                }
            string client_username = get_username_from_id(client_id);
            if(client_username.empty()){
                log("ERROR on get_username_from_id");
                return -1;
            }

            log("--- AUTHENTICATION COMPLETED WITH user: " + client_username);
            if(SIG_ERR == signal(SIGALRM, signal_handler)){
                log("ERROR on signal");
                safe_free(session_key, session_key_len);
                set_user_socket(get_username_from_id(client_id), -1);
                close(c_socket_id);
                return 0;
                }

            alarm(RELAY_CONTROL_TIME);

            while (true){

                plain_len = secure_recv(c_socket_id, &plaintext);

                if(plain_len <= 4){
                    log("ERROR on secure_recv");
                    safe_free(session_key, session_key_len);
                    set_user_socket(get_username_from_id(client_id), -1);
                    close(c_socket_id);
                    return -1;
                    }
                msg_opcode = *(uchar*)(plaintext+4); //plaintext has at least 5 bytes of memory allocated

                switch (msg_opcode){
                    case ONLINE_CMD:
                        if(-1 == get_users_online(c_socket_id, plaintext)) {
                            log("Error on get_users_online");
                            safe_free(session_key, session_key_len);
                            set_user_socket(get_username_from_id(client_id), -1);
                            close(c_socket_id);
                            return 0;
                            }
                        break;

                    case CHAT_CMD:
                        if(-1 == handle_chat_request(c_socket_id, client_id, relay_msg, plaintext, plain_len)) {
                            log("Error on handle_chat_request");
                            safe_free(session_key, session_key_len);
                            set_user_socket(get_username_from_id(client_id), -1);
                            close(c_socket_id);
                            return 0;
                            }
                        break;

                    case CHAT_NEG:
                    case CHAT_POS:
                    case STOP_CMD:
                        if(-1 == chat_response(plaintext, msg_opcode, plain_len)){
                            log("Error on chat_response");
                            safe_free(session_key, session_key_len);
                            set_user_socket(get_username_from_id(client_id), -1);
                            close(c_socket_id);
                            return 0;
                        }
                        break;
                    case CHAT_RESPONSE:
                    case AUTH:
                        ret = handle_auth_and_msg(plaintext, msg_opcode, plain_len);
                        if(ret<0) {
                            log("Error on handle_msg");
                            safe_free(session_key, session_key_len);
                            set_user_socket(get_username_from_id(client_id), -1);
                            close(c_socket_id);
                            return 0;
                        }
                        break;
                    case EXIT_CMD:
                        safe_free(session_key, session_key_len);
                        set_user_socket(get_username_from_id(client_id), -1);
                        close(c_socket_id);
                        exit(0);
                    default:
                        log("\n\n-------------Commando non valido-----------\n\n");
                        break;
                    }

                }
            }
        else if (pid == -1){
            log("ERROR on fork");
            return 0;
        }
        close(c_socket_id);
    }
}
