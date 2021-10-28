#include "client_utils.h"

void help()
{
    cout << "\n-------------------------HELP-----------------------------\n";
    cout <<  "   !online : command for seeing who is online.\n";
    cout << "    !chat : command for chatting with someone who is online.\n";
    cout << "   !exit : command for closing the application.\n";
    cout << "   --------------------------------------------------------------\n";
}


uint8_t string_to_command(string cmd)
{
    if(cmd.compare("!help")==0) {return HELP_CMD;}
    else if(cmd.compare("!online")==0) {return ONLINE_CMD;}
    else if(cmd.compare("!chat")==0) {return CHAT_CMD;}
    else if(cmd.compare("!exit")==0) {return EXIT_CMD;}
    else if(cmd.compare("!stop")==0) {return STOP_CMD;}
    else {return NOT_VALID_CMD;}
}


string id_to_username(int user_id, user* users)
{
    if(users==NULL) {
        cout << "users is NULL" << endl;
        return string();
        }

    struct user* appo = users;

    while(appo!=NULL) {
        if(appo->user_id==user_id) {
            string username ((char*)(appo->username));
            return username;
            }
        appo = appo->next;
        }

    return string();
}


int chat(struct msg_command* msg_send, user* users)
{
    if(users==NULL || msg_send==NULL){return -1;}

    msg_send->opcode = CHAT_CMD;

    cout << "\n------------------------------------------------------------\n";
    cout << "what is the user_id of who you want to chat?\n->";
    cin >> msg_send->user_id;

    if(cin.fail()){
        cin.clear();
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return -1;
        }

    cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if(msg_send->user_id == actual_user_id){
        cout << "you can't select yourself" << endl;
        return -1;
        }

    if(msg_send->user_id < 0){
        cout << " User_id not valid " << endl;
        return -1;
        }

    cout << "Waiting response and authentication ...\n";

    peer_id = msg_send->user_id;
    peer_username = id_to_username(peer_id, users);
    if(peer_username.empty()){return -1;}

    return 0;
}


void free_list_users(struct user* users)
{
    if(users==NULL){return;}

    struct user* appo = users;
    struct user* next_appo = NULL;

    while(appo!=NULL) {
        next_appo = appo->next;
        free(appo->username);
        free(appo);
        appo = next_appo;
        }
}


int get_online_users(unsigned char* plaintext, uint32_t pt_len)
{
    if(plaintext == NULL){return -1;}

    if(users != NULL){
        free_list_users(users);
        users = NULL;
        }

    uint32_t num;
    int ret;
    uint32_t bytes_read = 5; // opcode and seq number

    //users
    memcpy(&num, plaintext+bytes_read, sizeof(uint32_t));
    bytes_read += sizeof(uint32_t);
    num = ntohl(num);


    if(num == 0){return 0;}
    if(num > REGISTERED_USERS){return -1;}

    struct user* current = NULL;
    struct user* appo = NULL;

    for(int i = 0; i<num; i++) {
        int username_size;
        appo = (struct user*)malloc(sizeof(user));
        if(!appo) {
            errorHandler(MALLOC_ERR);
            free_list_users(users);
            users = NULL;
            return -1;
            }

        appo->username = NULL;
        appo->user_id = -1;
        appo->next = NULL;
        appo->username_size = 0;

        memcpy(&(appo->user_id), plaintext+bytes_read, sizeof(int));
        bytes_read += sizeof(int);

        appo->user_id = ntohl(appo->user_id);


        memcpy(&username_size, plaintext+bytes_read, sizeof(int));
        bytes_read += sizeof(int);

        username_size = ntohl(username_size);
        appo->username_size = username_size;
        if(username_size>MAX_USERNAME_SIZE) {
            free(appo);
            free_list_users(users);
            users = NULL;
            return -1;
            }

        appo->username = (unsigned char*)malloc(username_size+1);
        if(!appo->username){
            errorHandler(MALLOC_ERR);
            free(appo);
            free_list_users(users);
            users = NULL;
            return -1;
            }

        if(bytes_read+username_size>pt_len){
            cerr << " Error in reading plaintext " << endl;
            free(appo);
            free_list_users(users);
            users = NULL;
            return -1;
            }

        memcpy(appo->username, plaintext+bytes_read, username_size);
        bytes_read += username_size;
        appo->username[username_size] = '\0';

        if(i==0){users = appo;}
        else{current->next = appo;}
        current = appo;
        }

    return num;
}



int print_users(user* users)
{
    if(users==NULL) {
        cout << " no users \n";
        return -1;
        }

    struct user* appo = users;
    cout << "\n------- USERS -------- \n";
    cout << "  ID \t Username\n";
    while(appo!=NULL) {
        cout << "  " << appo->user_id << " \t " << appo->username << endl;
        appo = appo->next;
    }
    cout << "------------------- \n";
    return 0;
}


int plaintext_from_client(unsigned char* ciphertext, uint32_t msg_lenght, unsigned char** plaintext)
{
    if(ciphertext==NULL){return -1;}

    uint32_t header_len = sizeof(uint32_t) + IV_DEFAULT + TAG_DEFAULT;
    uint32_t read = 9; //seq number, opcode and len
    uint32_t ct_len;
    uint32_t pt_len;

    unsigned char* header = (unsigned char*)malloc(header_len);
    if(!header){
        cerr << " Error malloc\n";
        return -1;
        }

    memcpy(header, ciphertext+read, header_len);
    read += header_len;

    unsigned char* iv = (unsigned char*)malloc(IV_DEFAULT);
    if(!iv){
        cerr << " Error malloc\n";
        free(header);
        return -1;
        }

    unsigned char* tag = (unsigned char*)malloc(TAG_DEFAULT);
    if(!tag){
        cerr << " Error malloc\n";
        free(header);
        free(iv);
        return -1;
        }

    // Open header
    memcpy((void*)&ct_len, header, sizeof(uint32_t));
    ct_len = ntohl(ct_len);

    memcpy(iv, header+sizeof(uint32_t), IV_DEFAULT);
    memcpy(tag, header+sizeof(uint32_t) + IV_DEFAULT, TAG_DEFAULT);

    unsigned char* aad = (unsigned char*)malloc(sizeof(uint32_t));
    if(!aad){
        cerr << " Error malloc \n";
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        return -1;
        }
    memcpy(aad, header, sizeof(uint32_t));

    if(sess_key_client_client==NULL){
        cerr << " Null key " << endl;
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        free(aad);
        return -1;
        }

    unsigned char* cypher_msg = (unsigned char*)malloc(ct_len);
    if(!cypher_msg){
        cerr << " Error  malloc \n";
        free(aad);
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }

    memcpy(cypher_msg, ciphertext+read, ct_len);

    pt_len = auth_enc_decrypt(cypher_msg, ct_len, aad, sizeof(uint32_t), sess_key_client_client, tag, iv, plaintext);
    if(pt_len == 0 || pt_len!=ct_len){
        cerr << " Decryption error\n";
        free(ciphertext);
        free(*plaintext);
        free(header);
        free(tag);
        free(iv);
        return -1;
        }
    free(ciphertext);
    free(header);
    free(tag);
    free(iv);

    // check seq number
    uint32_t seq_num = ntohl(*(uint32_t*) (*plaintext));

    if(seq_num<rcv_counter_client_client){
        cerr << " Error seq num " << endl;
        safe_free(*plaintext,pt_len);
        return -1;
        }

    if(seq_num==MAX_SEQ_NUM){
        cerr << " Error: you have reached the maximum number of message in this session\n";
        safe_free(*plaintext,pt_len);
        return -1;
    }
    rcv_counter_client_client=seq_num+1;

    uint32_t message_len = pt_len - sizeof(uint32_t);
    unsigned char* risp = (unsigned char*)malloc(message_len);
    if(!risp){return -1;}

    memcpy(risp, ((*plaintext)+sizeof(uint32_t)), message_len);
    safe_free((*plaintext), pt_len);
    *plaintext = risp;

    return message_len;
}


int secure_recv(int socket, unsigned char** plaintext)
{
    if(id_sock<0){return -1;}

    uint32_t header_len = sizeof(uint32_t) + IV_DEFAULT + TAG_DEFAULT;
    uint32_t ct_len;
    unsigned char* ciphertext = NULL;
    uint32_t pt_len;
    int ret;

    unsigned char* header = (unsigned char*)malloc(header_len);
    if(!header){
        cerr << " Error malloc\n";
        return -1;
        }
    unsigned char* iv = (unsigned char*)malloc(IV_DEFAULT);
    if(!iv){
        cerr << " Error malloc \n";
        free(header);
        return -1;
        }
    unsigned char* tag = (unsigned char*)malloc(TAG_DEFAULT);
    if(!tag){
        cerr << " Error malloc\n";
        free(header);
        free(iv);
        return -1;
        }

    // Receive Header
    ret = recv(id_sock, (void*)header, header_len, 0);
    if(ret <= 0 || ret != header_len){
        cerr << " Error header rcv" << ret << endl;
        BIO_dump_fp(stdout, (const char*)header, header_len);
        free(header);
        free(tag);
        free(iv);
        return -1;
        }
    memcpy((void*)&ct_len, header, sizeof(uint32_t));

    memcpy(iv, header+sizeof(uint32_t), IV_DEFAULT);
    memcpy(tag, header+sizeof(uint32_t)+IV_DEFAULT, TAG_DEFAULT);

    unsigned char* aad = (unsigned char*)malloc(sizeof(uint32_t));
    if(!aad){
        cerr << " Error malloc \n";
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        return -1;
        }
    memcpy(aad, header, sizeof(uint32_t));

    // Receive ciphertext
    ct_len = ntohl(ct_len);
    ciphertext = (unsigned char*)malloc(ct_len);
    if(!ciphertext){
        cerr << " Error malloc\n";
        free(header);
        free(tag);
        free(iv);
        return -1;
        }

    ret = recv(id_sock, (void*)ciphertext, ct_len, 0);
    if(ret <= 0){
        cerr << " Error AAD rcv \n";
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }

    // Decryption
    pt_len = auth_enc_decrypt(ciphertext, ct_len, aad, sizeof(uint32_t), sess_key_client_server, tag, iv, plaintext);
    if(pt_len == 0 || pt_len!=ct_len){
        cerr << " Error decryption \n";
        free(ciphertext);
        free(*plaintext);
        free(header);
        free(tag);
        free(iv);
        return -1;
        }
    free(ciphertext);
    free(header);
    free(tag);
    free(iv);

    uint32_t seq_num = ntohl(*(uint32_t*) (*plaintext));

    if(seq_num<rcv_counter){
        cerr << " Error wrong seq num\n";
        free(plaintext);
        return -1;
        }
    if(seq_num==MAX_SEQ_NUM){
        cerr << " Error: you have reached the maximum number of message in this session\n";
        safe_free(*plaintext,pt_len);
        return -1;
        }

    rcv_counter=seq_num+1;

    return pt_len;
}


int message_to_client(unsigned char* pt, uint32_t pt_len, unsigned char** sending_msg)
{
    if(pt==NULL){return -1;}

    uchar *tag, *iv, *ct, *aad;
    uint aad_len;

    uint32_t header_len = sizeof(uint32_t) + IV_DEFAULT + TAG_DEFAULT;

    // adding seq_num
    uint32_t counter_n = htonl(snd_counter_client_client);

    if(pt_len>UINT32_MAX-sizeof(uint32_t)){
        cerr << " num too big\n";
        return -1;
        }

    uchar* pt_seq = (uchar*)malloc(pt_len+sizeof(uint32_t));
    if(!pt_seq){
        safe_free(pt, pt_len);
        return 0;
        }

    memcpy(pt_seq, &counter_n, sizeof(uint32_t));
    memcpy(pt_seq+sizeof(uint32_t), pt, pt_len);
    pt=pt_seq;
    pt_len+=sizeof(uint32_t);

    int aad_ct_len_net = htonl(pt_len);
    if(sess_key_client_client==NULL){
        cerr << " Null key \n";
        return 0;
        }

    uint ct_len = auth_enc_encrypt(pt, pt_len, (uchar*)&aad_ct_len_net, sizeof(uint), sess_key_client_client, &tag, &iv, &ct);
    if(ct_len == 0){
        cerr << "auth_enc_encrypt failed\n";
        safe_free(pt, pt_len);
        free(iv);
        free(tag);
        free(ct);
        free(pt_seq);
        return 0;
        }

    if(ct_len > UINT_MAX - header_len){
        cerr << " Integer overflow \n";
        safe_free(pt, pt_len);
        free(iv);
        free(tag);
        free(ct);
        free(pt_seq);
        return 0;
        }

    uint sending_msg_len = ct_len + header_len;
    uint bytes_copied = 0;

    *sending_msg = (uchar*)malloc(sending_msg_len);
    if(!(*sending_msg)){
        errorHandler(MALLOC_ERR);
        safe_free(pt, pt_len);
        free(iv);
        free(tag);
        free(ct);
        free(pt_seq);
        return 0;
    }

    memcpy((*sending_msg) + bytes_copied, &aad_ct_len_net, sizeof(uint32_t));
    bytes_copied += sizeof(uint32_t);
    memcpy((*sending_msg) + bytes_copied, iv, IV_DEFAULT);
    bytes_copied += IV_DEFAULT;
    memcpy((*sending_msg) + bytes_copied, tag, TAG_DEFAULT);
    bytes_copied += TAG_DEFAULT;
    memcpy((*sending_msg) + bytes_copied, ct, ct_len);
    bytes_copied += ct_len;

    if(bytes_copied!=sending_msg_len){
        cerr << " Warning " << bytes_copied << " != " << sending_msg_len << endl;
        }

    safe_free(pt, pt_len);
    free(iv);
    free(tag);
    free(ct);

    if(snd_counter_client_client==UINT32_MAX){return 0;}
    snd_counter_client_client++;

    return bytes_copied;
}


int secure_send(int c_socket_id, uchar* pt, int pt_len)
{
    if(c_socket_id<0){return 0;}
    if(pt==NULL){return 0;}

    int ret;
    uchar *tag, *iv, *ct, *aad;
    uint aad_len;
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT;

    // adding seq_num
    uint32_t counter_n=htonl(snd_counter);
    uchar* pt_seq = (uchar*)malloc(pt_len+sizeof(uint32_t));
    if(!pt_seq){
        safe_free(pt, pt_len);
        return 0;
        }

    memcpy(pt_seq , &counter_n, sizeof(uint32_t));
    memcpy(pt_seq + sizeof(uint32_t), pt, pt_len);
    pt = pt_seq;
    pt_len += sizeof(uint32_t);

    int aad_ct_len_net = htonl(pt_len); //GCM ciphertext == plaintext
    if(sess_key_client_server==NULL){
        cerr << " Null key \n";
        return 0;
        }

    uint ct_len = auth_enc_encrypt(pt, pt_len, (uchar*)&aad_ct_len_net, sizeof(uint), sess_key_client_server, &tag, &iv, &ct);
    if(ct_len == 0){
        cerr << "auth_enc_encrypt failed\n";
        free(iv);
        free(tag);
        free(ct);
        return 0;
        }

    if(ct_len > UINT_MAX - header_len){
        cerr << " Integer overflow \n";
        safe_free(pt, pt_len);
        free(iv);
        free(tag);
        free(ct);
        return 0;
        }

    uint sending_msg_len = ct_len + header_len;
    uint bytes_copied = 0;
    uchar* sending_msg = (uchar*)malloc(sending_msg_len);
    if(!sending_msg){
        errorHandler(MALLOC_ERR);
        free(iv);
        free(tag);
        free(ct);
        safe_free(pt, pt_len);
        return 0;
        }

    memcpy(sending_msg + bytes_copied, &aad_ct_len_net, sizeof(uint));
    bytes_copied += sizeof(uint);
    memcpy(sending_msg + bytes_copied, iv, IV_DEFAULT);
    bytes_copied += IV_DEFAULT;
    memcpy(sending_msg + bytes_copied, tag, TAG_DEFAULT);
    bytes_copied += TAG_DEFAULT;
    memcpy(sending_msg + bytes_copied, ct, ct_len);
    bytes_copied += ct_len;

    safe_free(pt, pt_len);

    ret = send(c_socket_id, sending_msg, sending_msg_len, 0);
    if(ret <= 0 || ret != sending_msg_len){
        errorHandler(SEND_ERR);
        free(iv);
        free(tag);
        free(ct);
        safe_free(sending_msg, sending_msg_len);
        return 0;
        }

    if(snd_counter==UINT32_MAX){
        errorHandler(SEND_ERR);
        free(iv);
        free(tag);
        free(ct);
        safe_free(sending_msg, sending_msg_len);
        return 0;
        }

    snd_counter++;

    safe_free(sending_msg, sending_msg_len);

    free(iv);
    free(tag);
    free(ct);
    return 1;
}


int command_send(int id_sock, msg_command* cmd_send)
{
    if(id_sock<0){return -1;}
    if(cmd_send==NULL){return -1;}

    uint32_t net_id;
    unsigned char* pt = NULL;
    uint32_t pt_len = (cmd_send->opcode==CHAT_CMD || cmd_send->opcode==STOP_CMD)? sizeof(uint8_t)+sizeof(uint32_t) : sizeof(uint8_t);
    pt = (unsigned char*)malloc(pt_len);

    if(!pt){return -1;}

    memcpy(pt, &(cmd_send->opcode), sizeof(uint8_t));
    int stop=0;

    if(cmd_send->opcode==CHAT_CMD || cmd_send->opcode==STOP_CMD) {

        if(cmd_send->opcode==STOP_CMD){
            cmd_send->user_id = peer_id;
            stop=1;
            }

        net_id = htonl(cmd_send->user_id);
        memcpy(pt+sizeof(uint8_t), &net_id, sizeof(uint32_t));
        }

    int ret = secure_send(id_sock, pt, pt_len);
    if(ret==0){
        safe_free(pt, pt_len);
        return -1;
        }

    safe_free(pt, pt_len);
    if(stop){
        snd_counter_client_client=0;
        rcv_counter_client_client=0;
        }

    return 0;
}


int send_message(int id_sock, message_info* msg_to_send)
{
    if(id_sock<0){return -1;}
    if(msg_to_send==NULL){return -1;}

    unsigned char* intern_msg = NULL; // nonce for client + msg for client
    uint32_t intern_msg_len = message_to_client(msg_to_send->payload, msg_to_send->length, &intern_msg);

    if(intern_msg_len==0){return -1;}
    if(intern_msg_len>UINT32_MAX-(sizeof(uint8_t)+sizeof(uint32_t))){
        cerr << " Integer Overflow \n";
        return -1;
        }

    uint32_t message_len = intern_msg_len + sizeof(uint8_t) + sizeof(uint32_t);
    unsigned char* msg = (unsigned char*)malloc(message_len);
    if(!msg){
        safe_free(intern_msg, intern_msg_len);
        return -1;
        }

    int alloc_bytes = 0;

    uint32_t net_peer_id = htonl(peer_id);
    memcpy((void*)msg, &(msg_to_send->opcode), sizeof(uint8_t));
    alloc_bytes += sizeof(uint8_t);
    memcpy((void*)(msg+alloc_bytes), &(net_peer_id), sizeof(uint32_t));
    alloc_bytes += sizeof(uint32_t);
    memcpy((void*)(msg+alloc_bytes), intern_msg, intern_msg_len);
    alloc_bytes += intern_msg_len;

    if(alloc_bytes!=message_len){
        cout << " WARNING\n";
        }

    int ret = secure_send(id_sock, msg, message_len);
    if(ret==0){
        cerr << " secure_send failed " << endl;
        safe_free(intern_msg, intern_msg_len);
        safe_free(msg, message_len);
        return -1;
        }

    safe_free(intern_msg, intern_msg_len);
    safe_free(msg, message_len);

    return 0;
}


int receive_message(int id_sock, string& msg, unsigned char* msg_rcvd, uint32_t msg_rcvd_len)
{
    if(id_sock<0){return -1;}
    if(msg_rcvd==NULL){return -1;}

    unsigned char* pt = NULL;
    uint32_t pt_len = plaintext_from_client(msg_rcvd, msg_rcvd_len, &pt);
    if(pt_len<=0){
        return -1;
        }
    msg = (string)((char*)pt);
    return 0;
}


int get_self_id(int socket)
{
    if(id_sock<0){return -1;}

    unsigned char* plaintext = NULL;
    int pt_len = secure_recv(id_sock, &plaintext);
    if(pt_len==-1){return -1;}

    // check opcode
    uint8_t opcode;
    memcpy(&opcode, plaintext+4, sizeof(uint8_t));

    if(opcode!=USRID){
        cerr << "wrong opcode \n";
        free(plaintext);
        return -1;
    }

    int actual_user_id_net;
    memcpy(&actual_user_id_net, plaintext + sizeof(uint32_t) + 1, sizeof(uint32_t));
    actual_user_id = ntohl(actual_user_id_net);
    return 0;
}


int negative_rsp(int id_sock, int neg_user)
{
    if(id_sock<0){return -1;}
    if(ntohl(neg_user)<0 || ntohl(neg_user)>REGISTERED_USERS){return -1;}

    uint32_t resp_buffer_size = sizeof(uint8_t)+sizeof(int);
    unsigned char* resp_buffer = (unsigned char*)malloc(resp_buffer_size);
    if(!resp_buffer){return -1;}

    uint8_t response = CHAT_NEG;
    memcpy(resp_buffer, (void*)&response, sizeof(uint8_t));
    memcpy(resp_buffer + 1, (void*)&neg_user, sizeof(int));

    int ret = secure_send(id_sock, resp_buffer, resp_buffer_size);
    if(ret==-1){
        free(resp_buffer);
        return -1;
        }

    free(resp_buffer);
    return 0;
}
