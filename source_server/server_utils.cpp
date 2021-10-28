#include "server_utils.h"

int sem_prologue(sem_t* sem_id)
{
    log("sem_prologue");

    if(sem_id == nullptr){
        log("sem_prologue: sem_id null");
        return -1;
        }

    if(sem_id == SEM_FAILED){
        log("SEM_FAILED");
        return -1;
        }

    if(-1 == sem_wait(sem_id)){
        log("ERROR on sem_wait");
        return -1;
    }

    return 0;
}


int sem_epilogue(sem_t* sem_id)
{
    log("sem_epilogue");

    if(sem_id == nullptr){
        log("sem_epilogue: sem_id null");
        return -1;
        }

    if(-1 == sem_post(sem_id)){
        log("ERROR on sem_exit");
        return -1;
        }

    if(-1 == sem_close(sem_id)){
        log("ERROR on sem_close");
        return -1;
    }

    return 0;
}


int get_socket_from_id(int user_id)
{
    if(user_id < 0 || user_id >= REGISTERED_USERS){
        log("ERROR: user_id not valid");
        return -2;
        }

    sem_t* sem_id= sem_open(sem_user_store, O_CREAT, 0600, 1);
    if(-1 == sem_prologue(sem_id)){
        log("ERROR on sem_prologue");
        return -2;
        }

    user_info* user_status = (user_info*)shared_mem;
    int socket_id = user_status[user_id].socket_id;

    if(-1 == sem_epilogue(sem_id)){
        log("ERROR on sem_epilogue");
        return -2;
    }

    return socket_id;
}


int test_busy_user(int user_id)
{
    if(user_id < 0 || user_id >= REGISTERED_USERS){
        log("ERROR: user_id not valid");
        return -1;
        }

    sem_t* sem_id = sem_open(sem_user_store, O_CREAT, 0600, 1);
    if(-1 == sem_prologue(sem_id)){
        log("ERROR on sem_prologue");
        return -1;
        }

    user_info* user_status = (user_info*)shared_mem;
    int ret = user_status[user_id].busy;
    if(-1 == sem_epilogue(sem_id)){
        log("ERROR on sem_epilogue");
        return -1;
        }

    return (!ret);
}


int set_busy_user(int user_id, int busy)
{
    if(user_id < 0 || user_id >= REGISTERED_USERS){
        log("ERROR: user_id not valid");
        return -1;
        }

    sem_t* sem_id = sem_open(sem_user_store, O_CREAT, 0600, 1);
    if(-1 == sem_prologue(sem_id)){
        log("ERROR on sem_prologue");
        return -1;
        }

    user_info* user_status = (user_info*)shared_mem;
    user_status[user_id].busy = busy;
    if(-1 == sem_epilogue(sem_id)){
        log("ERROR on sem_epilogue");
        return -1;
        }

    return 1;
}



int set_user_socket(string username, int socket)
{
    if(socket < -1){ //the user will be offline
        log("SOCKET fd invalid");
        return -1;
        }

    sem_t* sem_id = sem_open(sem_user_store, O_CREAT, 0600, 1);
    if(-1 == sem_prologue(sem_id)){
        log("ERROR on sem_prologue");
        return -1;
        }

    user_info* user_status = (user_info*)shared_mem;
    int found = 0;
    for(int i=0; i<REGISTERED_USERS; i++){
        if(user_status[i].username.compare(username) == 0){
            user_status[i].socket_id = socket;
            if(socket==-1){
                log("\n\n------ logout client " +username+" --------\n\n");
                }
            log("Set socket of " + username);
            found = 1;
            break;
            }
        }

    if(-1 == sem_epilogue(sem_id)){
        log("ERROR on sem_epilogue");
        return -1;
        }

    return found;
}


user_info* copy_user_store()
{
    sem_t* sem_id = sem_open(sem_user_store, O_CREAT, 0600, 1);
    if(-1 == sem_prologue(sem_id)){
        log("ERROR on sem_prologue");
        return nullptr;
        }

    //Obtain a copy of the user datastore
    user_info* user_status = (user_info*)malloc(REGISTERED_USERS*sizeof(user_info));
    if(!user_status){
        log("ERROR on malloc");
        return nullptr;
        }

    memcpy(user_status, shared_mem, REGISTERED_USERS*sizeof(user_info));

    if(-1 == sem_epilogue(sem_id)){
        log("ERROR on sem_epilogue");
        return nullptr;
        }

    return user_status;
}



int init_user_info(user_info* user_status)
{
    if(user_status == nullptr){
        return 0;
        }

    vector<string> usernames {"alice", "bob", "carol", "david"};
    for(int i=0; i < REGISTERED_USERS; i++){
        user_status[i].username = usernames[i];
        user_status[i].socket_id = -1;
        }

    return 1;
}


int get_id_from_username(string username)
{
    if(username.empty()){
        log("INVALID username");
        return -1;
        }

    sem_t* sem_id = sem_open(sem_user_store, O_CREAT, 0600, 1);
    if(-1 == sem_prologue(sem_id)){
        log("ERROR on sem_prologue");
        return -1;
        }

    int ret = -1;
    user_info* user_status = (user_info*)shared_mem;
    for(int i=0; i<REGISTERED_USERS; i++){
        if(user_status[i].username.compare(username) == 0){
            log("Found username " + username + " in the datastore with user_id " + to_string(i));
            ret = i;
            break;
            }
        }

    if(-1 == sem_epilogue(sem_id)){
        log("ERROR on sem_epilogue");
        return -1;
        }

    return ret;
}



string get_username_from_id(size_t id)
{
    if(id >= REGISTERED_USERS){
        log(" ERROR: user_id not present");
        errorHandler(GEN_ERR);
        }

    sem_t* sem_id = sem_open(sem_user_store, O_CREAT, 0600, 1);
    if(-1 == sem_prologue(sem_id)){
        log("ERROR on sem_prologue");
        return string();
        }

    user_info* user_status = (user_info*)shared_mem;
    string username = user_status[id].username;
    if(-1 == sem_epilogue(sem_id)){
        log("ERROR on sem_epilogue");
        return string();
        }

    return username;
}


void pre_cleanup()
{
    sem_unlink(sem_user_store); //Remove traces of usage for older execution
    key_t key = ftok(message_queue, 65);
    int msgid = msgget(key, 0666 | IPC_CREAT);
    msgctl(msgid, IPC_RMID, NULL);
    msgid = msgget(key, 0666 | IPC_CREAT);

    //add space to buffer
    struct msqid_ds buffer;
    msgctl(msgid, IPC_STAT, &buffer);
    buffer.msg_qbytes = 600000;
    int ret = msgctl(msgid, IPC_SET, &buffer);
    msgctl(msgid, IPC_STAT, &buffer);
    log("Message queue size: " + to_string(buffer.msg_qbytes));
}



int relay_write(uint to_user_id, message_info msg)
{
    if(to_user_id >= REGISTERED_USERS){return -1;}

    msg.type = to_user_id + 1;

    key_t key = ftok(message_queue, 65);
    log("Key of ftok returned is " + to_string(key));

    int msgid = msgget(key, 0666 | IPC_CREAT);
    log("msgid is " + to_string(msgid));

    return msgsnd(msgid, &msg, sizeof(message_info), 0);
}


int relay_read(int user_id, message_info& msg, bool blocking)
{
    uint time_residue;
    if(user_id >= REGISTERED_USERS || user_id < 0){return -1;}

    if(blocking){
        time_residue = alarm(0);
        }

    int ret = -1;

    //Read from the message queue
    key_t key = ftok(message_queue, 65);
    log("Key of ftok returned is " + to_string(key));

    int msgid = msgget(key, 0666 | IPC_CREAT);
    log("msgid is " + to_string(msgid));

    ret = msgrcv(msgid, &msg, sizeof(msg), user_id+1, (blocking? 0: IPC_NOWAIT));
    if(ret == -1){
        log("read nothing");
        }

    if(blocking){
        if(time_residue > 0){
            alarm(time_residue);
            }
        else{
            alarm(RELAY_CONTROL_TIME);
            }
        }
    return ret;
}


void signal_handler(int sig)
{
    int ret;
    uint8_t opcode;
    int bytes_copied = relay_read(client_id, relay_msg, false);
    uint message_len;

    if(bytes_copied > 0){
        opcode = relay_msg.buffer[0];

        if(opcode == CHAT_CMD) {
            uint username_length, username_length_net;

            memcpy(&username_length_net, (void*)(relay_msg.buffer + 5), sizeof(int));
            username_length = ntohl(username_length_net);


            if(username_length > UINT_MAX - 9 - PUBKEY_DEFAULT_SER){
                log("ERROR: unsigned wrap");
                return;
                }

            message_len = 9 + username_length + PUBKEY_DEFAULT_SER;

            // Send reply of the peer to the client
            ret = secure_send(c_socket_id, (uchar*)relay_msg.buffer, message_len);
            if(ret == 0){
                log("ERROR on secure_send");
                close(c_socket_id);
                exit(1);
                }
            }

        else if(opcode == AUTH || opcode == CHAT_RESPONSE){

            memcpy(&message_len, relay_msg.buffer + 1, sizeof(int)); //Added len field
            if(message_len < 1){
                log("ERROR: message_len < 1");
                close(c_socket_id);
                exit(1);
                }

            uchar* sending_msg = (uchar*)malloc(message_len);
            if(!sending_msg){
                log("ERROR on malloc");
                close(c_socket_id);
                exit(1);
                }

            sending_msg[0] = opcode;
            memcpy(sending_msg + 1, relay_msg.buffer + 5, message_len - 1);

            ret = secure_send(c_socket_id, (uchar*)sending_msg, message_len);
            if(ret == 0){
                log("ERROR on secure_send");
                close(c_socket_id);
                free(sending_msg);
                exit(1);
                }
            free(sending_msg);
            }
        else if(opcode == STOP_CMD || opcode == CHAT_NEG){
            message_len = 5;
            // Send reply of the peer to the client
            ret = secure_send(c_socket_id, (uchar*)relay_msg.buffer, message_len);
            if(ret == 0){
                log("ERROR on secure_send");
                close(c_socket_id);
                exit(1);
                }
            }
        else {
            log("OPCODE not recognized (" + to_string(opcode) + ")");
            }
    }

    alarm(RELAY_CONTROL_TIME);
    return;
}


uint32_t snd_counter=0;

int secure_send(int c_socket_id, uchar* pt, uint pt_len)
{
    if(pt_len < 0 || c_socket_id < 0){
        log("ERROR parameters not valid");
        return 0;
        }

    int ret;
    uchar *tag, *iv, *ct, *aad;
    uint aad_len;
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT;

    // adding sequence number
    uint32_t counter_n = htonl(snd_counter);
    if(pt_len > UINT_MAX - sizeof(uint32_t)){
        log("ERROR: unsigned wrap");
        return 0;
        }

    uchar* pt_seq = (uchar*)malloc(pt_len+sizeof(uint32_t));
    memcpy(pt_seq , &counter_n, sizeof(uint32_t));
    memcpy(pt_seq+ sizeof(uint32_t), pt, pt_len);
    pt=pt_seq;
    pt_len+=sizeof(uint32_t);

    uint aad_ct_len_net = htonl(pt_len); //we use GCM ciphertext == plaintext
    uint ct_len = auth_enc_encrypt(pt, pt_len, (uchar*)&aad_ct_len_net, sizeof(uint), session_key, &tag, &iv, &ct);
    if(ct_len == 0){
        log("auth_enc_encrypt failed");
        return 0;
        }
    if(ct_len > UINT_MAX - header_len){
        log("ERROR: unsigned wrap");
        return 0;
        }

    uint sending_msg_len = ct_len + header_len, bytes_copied = 0;
    uchar* sending_msg = (uchar*)malloc(sending_msg_len);
    if(!sending_msg){return 0;}

    memcpy(sending_msg + bytes_copied, &aad_ct_len_net, sizeof(uint));
    bytes_copied += sizeof(uint);

    memcpy(sending_msg + bytes_copied, iv, IV_DEFAULT);
    bytes_copied += IV_DEFAULT;

    memcpy(sending_msg + bytes_copied, tag, TAG_DEFAULT);
    bytes_copied += TAG_DEFAULT;

    memcpy(sending_msg + bytes_copied, ct, ct_len);
    bytes_copied += sizeof(uint);

    // Controllo encr/decr
    unsigned char* pt_test = NULL;
    int pt_len_test = auth_enc_decrypt(ct, ct_len, (uchar*)&aad_ct_len_net, sizeof(uint32_t), session_key, tag, iv, &pt_test);
    if(pt_len_test == 0){
        log("auth_enc_decrypt failed");
        return 0;
        }

    safe_free(pt, pt_len);

    ret = send(c_socket_id, sending_msg, sending_msg_len, 0);
    if(ret <= 0 || ret != sending_msg_len){
        errorHandler(SEND_ERR);
        safe_free(sending_msg, sending_msg_len);
        return 0;
        }

    snd_counter++;
    if(snd_counter == 0){
        log("ERROR: unsigned wrap");
        return 0;
        }

    safe_free(sending_msg, sending_msg_len);
    return 1;
}


uint32_t rcv_counter=0;

int secure_recv(int c_socket_id, unsigned char** plaintext)
{
    uint32_t header_len = sizeof(uint32_t) + IV_DEFAULT + TAG_DEFAULT;
    uint32_t ct_len;
    unsigned char* ciphertext = NULL;
    uint32_t pt_len;
    int ret;

    unsigned char* header = (unsigned char*)malloc(header_len);
    if(!header){
        cerr << " Error in malloc" << endl;
        return -1;
        }

    unsigned char* iv = (unsigned char*)malloc(IV_DEFAULT);
    if(!iv){
        cerr << " Error in malloc" << endl;
        safe_free(header, header_len);
        return -1;
        }

    unsigned char* tag = (unsigned char*)malloc(TAG_DEFAULT);
    if(!tag){
        cerr << "Error in malloc" << endl;
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        return -1;
    }

    ret = recv(c_socket_id, (void*)header, header_len, 0);
    if(ret <= 0 || ret != header_len){
        cerr << " Error in reception of header" << ret << endl;
        close(c_socket_id);
        BIO_dump_fp(stdout, (const char*)header, header_len);
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        return -1;
        }

    // Open header
    memcpy((void*)&ct_len, header, sizeof(uint32_t));

    memcpy(iv, header+sizeof(uint32_t), IV_DEFAULT);

    memcpy(tag, header+sizeof(uint32_t)+IV_DEFAULT, TAG_DEFAULT);

    unsigned char* aad = (unsigned char*)malloc(sizeof(uint32_t));
    if(!aad){
        cerr << " Error in malloc " << endl;
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        return -1;
        }

    memcpy(aad, header, sizeof(uint32_t));

    // Receive ciphertext
    ct_len = ntohl(ct_len);
    ciphertext = (unsigned char*)malloc(ct_len);
    if(!ciphertext){
        cerr << " Error in malloc" << endl;
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        safe_free(aad, sizeof(uint32_t));
        return -1;
        }

    ret = recv(c_socket_id, (void*)ciphertext, ct_len, 0);
    if(ret <= 0){
        cerr << " Error in reception of aad" << endl;
        safe_free(ciphertext, ct_len);
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        safe_free(aad, sizeof(uint32_t));
        return -1;
    }

    pt_len = auth_enc_decrypt(ciphertext, ct_len, aad, sizeof(uint32_t), session_key, tag, iv, plaintext);
    if(pt_len == 0 || pt_len!=ct_len){
        cerr << " Error during decryption " << endl;
        safe_free(*plaintext, pt_len);
        safe_free(ciphertext, ct_len);
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        safe_free(aad, sizeof(uint32_t));
        return -1;
        }

    safe_free(ciphertext, ct_len);
    safe_free(tag, TAG_DEFAULT);
    safe_free(header, header_len);
    safe_free(iv, IV_DEFAULT);
    safe_free(aad, sizeof(uint32_t));

    // check seq_num
    uint32_t seq_num = ntohl(*(uint32_t*) (*plaintext));
    if(seq_num<rcv_counter){
        cerr << " Error: wrong seq_num " << endl;
        safe_free(*plaintext, pt_len);
        return -1;
        }

    rcv_counter = seq_num + 1;
    if(rcv_counter == 0){
        log("ERROR: unsigned wrap");
        return -1;
        }

    return pt_len;
}
