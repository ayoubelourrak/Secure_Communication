#include "client_global.h"
#include "client_utils.h"
#include "client_authentication.h"

bool in_chat = false;
bool error = false;
string actual_user;
int actual_user_id;
string peer_username;
int peer_id;
int id_sock;

unsigned char* sess_key_client_server = NULL;
uint32_t sess_key_client_server_len = 0;

unsigned char* sess_key_client_client = NULL;
uint32_t sess_key_client_client_len = 0;

unsigned char* peer_pub_key = NULL;

unsigned char* server_cert = NULL;

uint32_t rcv_counter=0;
uint32_t snd_counter=0;
uint32_t rcv_counter_client_client = 0;
uint32_t snd_counter_client_client = 0;

user* users = NULL;

void welcome()
{
    cout << " ----------------------------------------------------------------------- \n";
    cout << "                           SECURE MESSAGING SERVICE \n\n";
    cout << "   Write !help   \n";
    cout << "-------------------------------------------------------------------------\n";
}


//return 1 on success, 0 otherwise
int request_chat(unsigned char* plaintext, uint32_t pt_len)
{
    if(plaintext==NULL){return 0;}

    int ret;
    uint8_t opcode = NOT_VALID_CMD;
    uint8_t response;
    int id_other;
    unsigned char* counterpart;
    uint size_username;
    char response_user = 'a';
    unsigned char* resp_buffer = NULL;
    size_t resp_buffer_size = 0;
    uint32_t bytes_read = 5; // opcode and seq_num

    // Reading peer id
    memcpy(&id_other, (plaintext + bytes_read), sizeof(int));
    bytes_read += sizeof(int);

    // Read username_len
    memcpy(&size_username, plaintext+bytes_read, sizeof(int));
    bytes_read += sizeof(int);
    size_username = ntohl(size_username);
    if(size_username>MAX_USERNAME_SIZE){
        cerr << " Username too huge \n";
        return 0;
        }

    // Read username peer
    counterpart = (unsigned char*)malloc(size_username+1);
    if(!counterpart){
        cout << " error malloc\n";
        return 0;
        }

    if(bytes_read + size_username > pt_len){
        cerr << " Errore in reading \n";
        return 0;
        }
    memcpy(counterpart, plaintext+bytes_read, size_username);
    bytes_read += size_username;
    counterpart[size_username] = '\0';

    // Read sender pubkey
    // Public key of an old peer
    if(peer_pub_key!=NULL){
        free(peer_pub_key);
        peer_pub_key = NULL;
        }
    peer_pub_key = (unsigned char*)malloc(PUBKEY_DEFAULT_SER);
    if(!peer_pub_key){return 0;}

    memcpy(peer_pub_key, plaintext+bytes_read, PUBKEY_DEFAULT_SER);
    bytes_read += PUBKEY_DEFAULT_SER;
    if(peer_pub_key==NULL){return 0;}

    if(in_chat){
        // negative response
        free(counterpart);
        ret = negative_rsp(id_sock, id_other);
        if(ret==-1){return 0;}
        return 1;
        }

    in_chat = true;
    peer_id = ntohl(id_other);

    cout << "\n----------------------------------------------------------\n";
    cout << "Do you accept chat request from" << counterpart << "(user id " << peer_id << ") ? (y/n)\n";

    while(response_user!='y' && response_user!='n') {
        cin >> response_user;
        if(cin.fail()){
            cin.clear();
        }
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        if(response_user=='y'){
            response = CHAT_POS;
            }
        else if (response_user=='n'){
            response = CHAT_NEG;
            }
        else{
            cout << "  write y or n\n";
            }
    }

    resp_buffer_size = sizeof(uint8_t)+sizeof(int);
    resp_buffer = (unsigned char*)malloc(resp_buffer_size);
    if(!resp_buffer){return 0;}

    memcpy((void*)resp_buffer, (void*)&response, sizeof(uint8_t));
    memcpy((void*)(resp_buffer+1), (void*)&id_other, sizeof(int));

    ret = secure_send(id_sock, resp_buffer, resp_buffer_size);
    if(ret==-1){
        free(resp_buffer);
        return 0;
        }
    free(resp_buffer);

    if(response==CHAT_NEG){
        cout << " Chat refused \n";
        in_chat = false;
        return 1;
        }

    peer_username = (char*)counterpart;
    free(counterpart);
    peer_id = ntohl(id_other);


    cout << "Waiting authentication ... \n";
    if(response==CHAT_POS){
        ret = authentication_receiver(id_sock);
        if(ret==-1){
            cout << " Authentication with " << peer_username <<" failed \n";
            return 0;
            }
        }
    else{
        cerr << " unspecified error \n";
        return 0;
        }

    // Clean stdin
    cin.clear();
    fflush(stdin);
    cout << "\n ------------------------------------------------------------------\n";
    cout << "                             CHAT  " <<  peer_username << endl;
    cout << " Only the command !stop works\n";
    cout << " ------------------------------------------------------------------- \n\n" << endl;
    return 1;
}

/*
return
    -1 for error,
    1 if no answer from the server,
    2 if answer from the server,
    3 !exit
*/
int handle_command(string userInput)
{
    int ret;
    struct msg_command cmd_send;
    cmd_send.opcode = NOT_VALID_CMD;
    cmd_send.user_id = -1;

    struct message_info a_msg_send;
    a_msg_send.opcode = CHAT_RESPONSE;
    a_msg_send.payload = NULL;
    a_msg_send.length = 0;
    bool no_server=false;
    if(!in_chat || (in_chat==true && userInput.compare("!stop")==0)) {

        uint8_t code_command = string_to_command(userInput);

        switch (code_command){
            case CHAT_CMD:
                ret = chat(&cmd_send,users);
                if(ret<0) {
                    cout << " error retry with !online\n";
                    no_server=true;
                    }
                break;

            case ONLINE_CMD:
                cmd_send.opcode = ONLINE_CMD;
                break;

            case HELP_CMD:
                no_server = true;
                help();
                break;

            case EXIT_CMD:
                cmd_send.opcode = EXIT_CMD;
                break;

            case STOP_CMD:
                if(in_chat){
                    cmd_send.opcode = STOP_CMD;
                    in_chat = false;
                    }
                else{
                    no_server = true;
                    cout << "You aren't chatting \n";
                    }
                break;

            case NOT_VALID_CMD:
                no_server = true;
                cout << "Invalid Command\n";
                break;

            default:
                no_server = true;
                cout << "Invalid Command\n";
                break;
            }
        }
    else {
        a_msg_send.opcode = CHAT_RESPONSE;
        a_msg_send.length = userInput.size()+1;
        a_msg_send.payload = (unsigned char*)malloc(a_msg_send.length);
        if(!a_msg_send.payload) {
            error = true;
            errorHandler(MALLOC_ERR);
            return -1;
            }
        strncpy((char*)a_msg_send.payload, userInput.c_str(), a_msg_send.length);
        }

    if(no_server){return 1;}

    if(in_chat && cmd_send.opcode!=STOP_CMD) {
        ret = send_message(id_sock, &a_msg_send);
        if(ret!=0){
            error = true;
            errorHandler(SEND_ERR);
            return -1;
            }
        return 1;
        }
    else {
        // Send the command to server
        ret = command_send(id_sock, &cmd_send);
        if(ret!=0){
            error = true;
            errorHandler(SEND_ERR);
            return -1;
            }

        if(cmd_send.opcode==STOP_CMD){
            cout << " \t\t    ------- Exit Chat -------\n\n";
            return 1;
            }
        if(cmd_send.opcode==EXIT_CMD){
            return 3;
            }
        }
    return 2;
}

/**
 *  Handler of the messages received from the server
 *
 *   id_sock
 *  return return -1 in case of error, 0 otherwise
 */
int handle_msg_server(int id_sock)
{
    if(id_sock<0){return -1;}

    int ret;
    uint8_t opcode;
    int counterpart_id;

    unsigned char* plaintext = NULL;
    int pt_len = secure_recv(id_sock, &plaintext);
    if(pt_len==-1){return -1;}

    memcpy(&opcode, plaintext+sizeof(uint32_t), sizeof(uint8_t));

    switch (opcode){
        case ONLINE_CMD:{
            ret = get_online_users(plaintext, pt_len);
            if(ret == 0){
                cout << " Nobody is online \n";
                }
            else if (ret==-1){
                error = true;
                errorHandler(GEN_ERR);
                free(plaintext);
                return -1;
                }
            else if(print_users(users)!=0){
                error = true;
                errorHandler(GEN_ERR);
                free(plaintext);
                return -1;
                }
            break;
            }
        case CHAT_POS:
        {
            memcpy(&counterpart_id, plaintext+5, sizeof(int)); // opcode and seq_num
            if(peer_username.empty()){
                cout << " Peer username is empty \n";
                error = true;
                errorHandler(GEN_ERR);
                free(plaintext);
                return -1;
                }

            if(peer_id!=counterpart_id) {
                cout << " Error with the requested user id\n";
                break;
                }

            if(peer_pub_key!=NULL){
                free(peer_pub_key); // old public key peer
                peer_pub_key = NULL;
                }

            peer_pub_key = (unsigned char*)malloc(PUBKEY_DEFAULT_SER);
            if(!peer_pub_key){
                errorHandler(MALLOC_ERR);
                free(plaintext);
                return -1;
                }
            memcpy(peer_pub_key, plaintext + 5 + sizeof(int), PUBKEY_DEFAULT_SER);
            if(peer_pub_key==NULL){
                cerr << " Error peer public key \n";
                free(plaintext);
                return -1;
                }

            ret = authentication(id_sock, AUTH_CLNT_CLNT);
            if(ret!=0){
                cout << " Authentication with " << peer_username << " failed \n";
                free(plaintext);
                return -1;
                }
            in_chat = true;
            cout << "SUCCESS AUTHENTICATION WITH " << peer_username << endl;
            cout << "\n ------------------------------------------------------------------ \n";
            cout << "                             CHAT  "<<  peer_username << endl;
            cout << " Only command !stop works\n";
            cout << " -------------------------------------------------------------------- \n\n";
            }
        break;

        case CHAT_NEG:
            cout << " The user has refused the request \n";
            break;

        case CHAT_RESPONSE:
            {
            string message;
            ret = receive_message(id_sock, message, plaintext, pt_len);
            if(ret!=0) {
                error = true;
                perror("chat response");
                errorHandler(REC_ERR);
                free(plaintext);
                return -1;
                }

            if(peer_username.empty()){
                error = true;
                errorHandler(GEN_ERR);
                free(plaintext);
                return -1;
                }
            cout << peer_username << " -> " << message << endl;
            }
        break;

        case CHAT_CMD:
            ret = request_chat(plaintext, pt_len);
            if(ret<=0) {
                error = true;
                perror("chat command");
                errorHandler(REC_ERR);
                free(plaintext);
                return -1;
                }
        break;

        case STOP_CMD:
            in_chat = false;
            free(peer_pub_key);
            peer_pub_key = NULL;
            snd_counter_client_client=0;
            rcv_counter_client_client=0;
            cout << " -----------  " << peer_username << " ended the chat -------\n\n";
            break;

        default:{
            error = true;
            errorHandler(SRV_INTERNAL_ERR);
            free(plaintext);
            return -1;
            }
        break;
        }

    return 1;
}

int main(int argc, char* argv[])
{
    string userInput;
    fd_set list_fd;
    int ret;
    bool server_need = false;

    struct message_info a_msg_send;
    a_msg_send.opcode = CHAT_RESPONSE;
    a_msg_send.payload = NULL;
    a_msg_send.length = 0;

    struct msg_command cmd_send;
    cmd_send.opcode = NOT_VALID_CMD;
    cmd_send.user_id = -1;

    struct sockaddr_in srv_addr;
    const char* srv_ip = "127.0.0.1";
    const int srv_port = 4242;

    id_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(id_sock<0){
        error = true;
        errorHandler(CONN_ERR);
        goto end;
        }
    // Initialization for server address
    if(!memset(&srv_addr, 0, sizeof(srv_addr))){
        error = true;
        errorHandler(GEN_ERR);
        goto end;
    }
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    ret = inet_pton(AF_INET, srv_ip, &srv_addr.sin_addr);
    if(ret<=0){
        error = true;
        errorHandler(CONN_ERR);
        goto end;
    }
    // Socket connection
    ret = connect(id_sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if(ret < 0){
        error = true;
        errorHandler(CONN_ERR);
        goto end;
    }

    // Welcome page
    welcome();

    // Authentication phase
    ret = authentication(id_sock, AUTH_CLNT_SRV);
    if(ret<0) {
        error = true;
        errorHandler(AUTHENTICATION_ERR);
        goto end;
        }
    cout << "--- AUTHENTICATION SUCCESS --- \n";
    cout << "WELCOME " << actual_user << "\n\n";

    while(true) {
        // list_fd must be initialized after each use of the select
        FD_ZERO(&list_fd);
        FD_SET(fileno(stdin), &list_fd);
        FD_SET(id_sock, &list_fd);

        int descr_num = 0;
        int descr_max = (fileno(stdin)>=id_sock)?fileno(stdin):id_sock;
        descr_max++;
        descr_num = select(descr_max, &list_fd, NULL, NULL, NULL);

        switch(descr_num){
            case 0:
                printf("SELECT RETURN 0\n");
                break;
            case -1:
                perror("select");
                break;
            default:
                if (FD_ISSET(fileno(stdin), &list_fd)!=0) {
                    fseek(stdin,0,SEEK_END);
                    getline(cin, userInput);
                    if(!server_need){
                        ret = handle_command(userInput);
                        if(ret<0){
                            error = true;
                            errorHandler(GEN_ERR);
                            goto end;
                            }
                        }
                    if(ret==2){server_need=true;}
                    if(ret==3){goto end;}
                }
                if (FD_ISSET(id_sock, &list_fd)!=0) {
                    // Something arrived on the socket
                    ret = handle_msg_server(id_sock);
                    if(ret<0){
                        error = true;
                        perror("recv");
                        errorHandler(GEN_ERR);
                        goto end;
                        }
                    if(ret!=2){server_need=false;}
                    }
            }
        }

end:
    if(a_msg_send.payload){free(a_msg_send.payload);}
    if(peer_pub_key){free(peer_pub_key);}
    if(sess_key_client_client){safe_free(sess_key_client_client, sess_key_client_client_len);}
    if(server_cert){free(server_cert);}
    if(sess_key_client_server){safe_free(sess_key_client_server, sess_key_client_server_len);}

    if(users){free_list_users(users);}
    close(id_sock);

    if(error) {
        cout << " Termination forced \n" << endl;
        exit(-1);
        }
    else {
        cout << "\n ARRIVEDERCI!!!\n";
        return 0;
        }
}
