#include "client_authentication.h"

int authentication(int id_sock, uint8_t ver)
{
    if(id_sock<0){return -1;}

    // if ver is AUTH_CLNT_CLNT  then we use server for indicating the other client
    if(ver!=AUTH_CLNT_CLNT && ver!=AUTH_CLNT_SRV){return -1;}

    bool big_username = false;
    unsigned char* nonce = NULL;         // nonce R
    unsigned char* server_nonce = NULL;  // nonce R2
    uint32_t username_size;
    uint32_t net_username_size;
    uint16_t allocating_size;
    size_t msg_bytes_written;
    int ret;
    int peer_id_net = htonl(peer_id);
    unsigned char* name = NULL;
    unsigned char* msg_auth_1 = NULL;

    unsigned char* msg2_pt = NULL;
    uint32_t msg2_pt_len = 0;

    int dh_pub_srv_key_size;
    unsigned char* dh_server_pubkey = NULL;

    uint32_t len_signature;
    uint32_t len_signed_msg;
    unsigned char* signed_msg = NULL;
    unsigned char* signature = NULL;

    uint32_t cert_len;
    unsigned char* server_cert = NULL;

    // get username
    if(ver==AUTH_CLNT_SRV){
        do{
            if(big_username){
                cout << " The username is too big! \n";
                }
            cout << "Insert username \n -> ";
            cin >> actual_user;
            if(cin.fail()){
                cin.clear();
                cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                return -1;
                }
            cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            if(actual_user.size()+1>MAX_USERNAME_SIZE){big_username = true;}

            }while(big_username);
        }

    /*************************************************************
     * M1 - Send R,username to the server
     *************************************************************/
    // Nonce Generation
    nonce = (unsigned char*)malloc(NONCE_SIZE);
    if(!nonce){return -1;}
    gen_random(NONCE_SIZE, nonce);

    //creating username
    if(ver==AUTH_CLNT_SRV){
        username_size = actual_user.size()+1;
        name = (unsigned char*)malloc(username_size);
        if(!name){
            free(nonce);
            return -1;
            }
        net_username_size = htonl(username_size);
        strncpy((char*)name, actual_user.c_str(), username_size);
        name[username_size-1] = '\0';
        }

    // Composition of the message: OPCODE, R, USERNAME_SIZE, USERNAME
    allocating_size = (ver==AUTH_CLNT_SRV) ? (NONCE_SIZE+sizeof(uint32_t)+username_size) : (sizeof(uint8_t) + NONCE_SIZE + sizeof(int));
    msg_auth_1 = (unsigned char*)malloc(allocating_size);
    if(!msg_auth_1){
        free(name);
        free(nonce);
        return -1;
        }

    if(ver==AUTH_CLNT_SRV){
        memcpy(msg_auth_1, nonce, NONCE_SIZE);
        msg_bytes_written = NONCE_SIZE;
        memcpy(msg_auth_1+msg_bytes_written, &net_username_size, sizeof(uint32_t));
        msg_bytes_written += sizeof(uint32_t);
        memcpy(msg_auth_1+msg_bytes_written, name, username_size);
        msg_bytes_written += username_size;
        }

    else if(ver==AUTH_CLNT_CLNT){
        uint8_t op = AUTH;
        memcpy(msg_auth_1, (void*)&op, sizeof(uint8_t));
        msg_bytes_written = sizeof(uint8_t);
        memcpy(msg_auth_1+msg_bytes_written, (void*)&peer_id_net, sizeof(int));
        msg_bytes_written += sizeof(int);
        memcpy(msg_auth_1+msg_bytes_written, nonce, NONCE_SIZE);
        msg_bytes_written += NONCE_SIZE;
    }

    // Send message to server
    if(ver==AUTH_CLNT_SRV){
        ret = send(id_sock, (void*)msg_auth_1, msg_bytes_written, 0);
        if(ret<=0 || ret != msg_bytes_written){
            free(msg_auth_1);
            free(name);
            free(nonce);
            return -1;
            }
        free(name);
        }
    else if(ver==AUTH_CLNT_CLNT){
        secure_send(id_sock, msg_auth_1, allocating_size);
        }

    safe_free(msg_auth_1, allocating_size);

    /*************************************************************
     * M2 - Wait for message from the server
     *************************************************************/
    // wait for nonce
    if(ver==AUTH_CLNT_CLNT){
        uint8_t op_appo;
        uint32_t read_appo;
        do{
            msg2_pt_len = secure_recv(id_sock, &msg2_pt);
            if(msg2_pt_len==-1){return -1;}

            read_appo = sizeof(uint32_t); // seq_num read
            memcpy(&op_appo, msg2_pt+read_appo, sizeof(uint8_t));
            read_appo += sizeof(uint8_t);

            if(op_appo==CHAT_CMD){
                // automatic refuse
                int rejected_user;
                memcpy(&rejected_user, msg2_pt+read_appo, sizeof(uint32_t));
                ret = negative_rsp(id_sock, rejected_user);
                if(ret==-1){
                    free(nonce);
                    return -1;
                    }
                }
            else if(op_appo!=AUTH){
                free(nonce);
                return -1;
                }
            }while(op_appo!=AUTH);
        }

    uint32_t read_from_msg2 = sizeof(uint32_t) + sizeof(uint8_t); // adding seq_num and opcode

    server_nonce = (unsigned char*)malloc(NONCE_SIZE);
    if(!server_nonce){
        free(nonce);
        return -1;
        }

    if(ver==AUTH_CLNT_SRV){
        ret = recv(id_sock, (void*)server_nonce, NONCE_SIZE, 0);
        if(ret <= 0){
            free(server_nonce);
            free(nonce);
            return -1;
            }
        }
    else if(ver==AUTH_CLNT_CLNT){
        read_from_msg2 += sizeof(int); // skipping user_id
        memcpy(server_nonce, msg2_pt + read_from_msg2, NONCE_SIZE);
        read_from_msg2 += NONCE_SIZE;
        }

    // Read len of the DH server pub key
    if(ver==AUTH_CLNT_SRV){
        ret = recv(id_sock, (void*)&dh_pub_srv_key_size, sizeof(int), 0);
        if(ret <= 0){
            free(server_nonce);
            free(nonce);
            return -1;
            }
        }
    else if(ver==AUTH_CLNT_CLNT){
        memcpy(&dh_pub_srv_key_size, msg2_pt+read_from_msg2, sizeof(int));
        read_from_msg2 += sizeof(int);
        }
    dh_pub_srv_key_size = ntohl(dh_pub_srv_key_size);

    // Read DH server pub key
    dh_server_pubkey = (unsigned char*)malloc(dh_pub_srv_key_size);
    if(!dh_server_pubkey){
        free(server_nonce);
        free(nonce);
        }

    if(ver==AUTH_CLNT_SRV){
        ret = recv(id_sock, (void*)dh_server_pubkey, dh_pub_srv_key_size, 0);
        if(ret <= 0 || ret != dh_pub_srv_key_size){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            return -1;
            }
        }
    else if(ver==AUTH_CLNT_CLNT){
        if(read_from_msg2 + dh_pub_srv_key_size > msg2_pt_len){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            return -1;
            }
        memcpy(dh_server_pubkey, msg2_pt+read_from_msg2, dh_pub_srv_key_size);
        read_from_msg2 += dh_pub_srv_key_size;
        }

    // Read len_signature
    if(ver==AUTH_CLNT_SRV){
        ret = recv(id_sock, (void*)&len_signature, sizeof(uint32_t), 0);
        if(ret <= 0 || ret!=sizeof(uint32_t)){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            return -1;
            }
        }
    else if(ver==AUTH_CLNT_CLNT){
        memcpy(&len_signature, msg2_pt+read_from_msg2, sizeof(uint32_t));
        read_from_msg2 += sizeof(uint32_t);
        }
    len_signature = ntohl(len_signature);


    // Read signature
    signature = (unsigned char*)malloc(len_signature);
    if(!signature){
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        return -1;
        }

    if(ver==AUTH_CLNT_SRV){
        ret = recv(id_sock, (void*)signature, len_signature, 0);
        if(ret <= 0 || ret!=len_signature){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signature);
            return -1;
            }
        }
    else if(ver==AUTH_CLNT_CLNT){
        if(read_from_msg2 + len_signature > msg2_pt_len){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            return -1;
            }
        memcpy(signature, msg2_pt+read_from_msg2, len_signature);
        read_from_msg2 += len_signature;
        }

    //certificate
    if(ver==AUTH_CLNT_SRV){
        ret = recv(id_sock, (void*)&cert_len, sizeof(uint32_t), 0);
        if(ret <= 0 || ret!=sizeof(uint32_t)){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signature);
            return -1;
            }
        cert_len = ntohl(cert_len);

        server_cert = (unsigned char*)malloc(cert_len);
        if(!server_cert){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signature);
            return -1;
            }
        ret = recv(id_sock, (void*)server_cert, cert_len, 0);
        if(ret <= 0 || ret!=cert_len){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signed_msg);
            free(signature);
            free(server_cert);
            return -1;
            }
        }

    // Check message authenticity
    len_signed_msg = NONCE_SIZE*2 + dh_pub_srv_key_size;
    signed_msg = (unsigned char*)malloc(len_signed_msg);
    if(!signed_msg){
        cerr<<" no msg "<<endl;
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signature);
        free(server_cert);
        return -1;
        }

    memcpy(signed_msg, nonce, NONCE_SIZE);
    memcpy(signed_msg+NONCE_SIZE, server_nonce, NONCE_SIZE);
    memcpy(signed_msg+(2*NONCE_SIZE), dh_server_pubkey, dh_pub_srv_key_size);

    if(ver==AUTH_CLNT_SRV){
        FILE* CA_cert_file = fopen("certification/SecureProject_cert.pem","rb");
        if(!CA_cert_file){
            cerr<<"no CA cert"<<endl;
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signed_msg);
            free(signature);
            free(server_cert);
            return -1;
            }
        FILE* CA_crl_file = fopen("certification/SecureProject_crl.pem","rb");
        if(!CA_crl_file){
            cerr<<"no CA crl"<<endl;
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signed_msg);
            free(signature);
            free(server_cert);
            fclose(CA_cert_file);
            return -1;
            }

        ret = verify_cert_sign(server_cert, cert_len, CA_cert_file, CA_crl_file, signature, len_signature, signed_msg, len_signed_msg);
        if(ret!=1){
            cerr << " invalid signature \n";
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signed_msg);
            free(signature);
            free(server_cert);
            fclose(CA_cert_file);
            fclose(CA_crl_file);
            return -1;
            }
        fclose(CA_cert_file);
        fclose(CA_crl_file);
        }
    else if(ver==AUTH_CLNT_CLNT){
        if(!peer_pub_key){
            cerr << " Peer public key \n";
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signed_msg);
            free(signature);
            return -1;
            }
        ret = verify_pubkey_sign(signature, len_signature, signed_msg, len_signed_msg, peer_pub_key, PUBKEY_DEFAULT_SER);
        if(ret==0){
            cerr << " Fail verification peer signature\n";
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signed_msg);
            free(signature);
            return -1;
            }
        }
    free(signature);
    free(signed_msg);
    free(nonce);


    /*************************************************************
     *  Generate (DH_pubKey_C, DH_privKey_C)
     *************************************************************/
    void* dh_priv_key = NULL;
    unsigned char* dh_pub_key = NULL;
    uint32_t dh_pub_key_len;
    ret = gen_eph_key(&dh_priv_key, &dh_pub_key, &dh_pub_key_len);
    if(ret!=1){
        cerr<<" error ephermeral keys \n";
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        return -1;
        }

    /*************************************************************
     * M3 - Send to the server my DHpubKey and the nonce R2
     *************************************************************/

    uint32_t msg_to_sign_len = NONCE_SIZE + dh_pub_key_len;
    unsigned char* msg_to_sign = (unsigned char*)malloc(msg_to_sign_len);
    if(!msg_to_sign){
        cerr<<"Error malloc\n";
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        free(dh_priv_key);
        free(dh_pub_key);
        return -1;
        }

    memcpy(msg_to_sign, dh_pub_key,dh_pub_key_len );
    memcpy(msg_to_sign+dh_pub_key_len, server_nonce, NONCE_SIZE);

    unsigned char* client_signature = NULL;
    uint32_t client_sign_len;
    string priv_key_file_path = "clients_data/"+actual_user+"/"+actual_user+"_privkey.pem";
    FILE* priv_key_file = fopen(priv_key_file_path.c_str(), "rb");
    if(!priv_key_file){
        cerr<<"Error privkey file\n";
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        free(msg_to_sign);
        free(dh_priv_key);
        free(dh_pub_key);
        return -1;
        }

    ret = sign_document(msg_to_sign, msg_to_sign_len, priv_key_file,NULL, &client_signature, &client_sign_len);
    if(ret!=1){
        cerr<<"unable to sign\n";
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        free(msg_to_sign);
        free(dh_priv_key);
        free(dh_pub_key);
        fclose(priv_key_file);
        return -1;
        }

    free(server_nonce);
    free(msg_to_sign);
    fclose(priv_key_file);

    // Building the message to send
    uint32_t msg_len = sizeof(uint32_t) + dh_pub_key_len + sizeof(uint32_t) + client_sign_len;
    if(ver==AUTH_CLNT_CLNT){
        msg_len = msg_len + sizeof(uint8_t) + sizeof(int); // space for opcode and peer id
        }

    unsigned char* sending_msg_M3 = (unsigned char*)malloc(msg_len);
    if(!sending_msg_M3){
        free(dh_server_pubkey);
        free(server_cert);
        free(client_signature);
        free(dh_priv_key);
        free(dh_pub_key);
        return -1;
        }

    uint32_t n_dh_pub_key_len=htonl(dh_pub_key_len);
    uint32_t n_client_sign_len=htonl(client_sign_len);
    msg_bytes_written = 0;

    if(ver==AUTH_CLNT_CLNT){
        uint8_t op_appo = AUTH;
        memcpy(sending_msg_M3+msg_bytes_written, &op_appo, sizeof(uint8_t));
        msg_bytes_written += sizeof(uint8_t);
        memcpy(sending_msg_M3+msg_bytes_written, &peer_id_net, sizeof(int));
        msg_bytes_written += sizeof(int);
        }

    memcpy(sending_msg_M3 + msg_bytes_written, &n_dh_pub_key_len, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(sending_msg_M3+ msg_bytes_written, dh_pub_key, dh_pub_key_len);
    msg_bytes_written += dh_pub_key_len;
    memcpy(sending_msg_M3 + msg_bytes_written, &n_client_sign_len, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(sending_msg_M3 + msg_bytes_written, client_signature, client_sign_len);
    msg_bytes_written += client_sign_len;

    if(msg_bytes_written != msg_len){
        cerr<<"Error on copying\n";
        free(dh_server_pubkey);
        free(server_cert);
        free(client_signature);
        free(sending_msg_M3);
        free(dh_priv_key);
        free(dh_pub_key);
        return -1;
        }

    // Send the message to send to the server
    if(ver==AUTH_CLNT_SRV){
        ret = send(id_sock, (void*)sending_msg_M3, msg_len, 0);
        if(ret<=0 || ret != msg_len){
            free(dh_server_pubkey);
            free(server_cert);
            free(client_signature);
            free(sending_msg_M3);
            free(dh_priv_key);
            free(dh_pub_key);
            return -1;
            }
        }
    else if(ver==AUTH_CLNT_CLNT){
        ret = secure_send(id_sock, sending_msg_M3, msg_len);
        if(ret==0){
            free(dh_server_pubkey);
            free(client_signature);
            free(sending_msg_M3);
            free(dh_priv_key);
            free(dh_pub_key);
            return -1;
            }
        }

    free(sending_msg_M3);
    free(client_signature);

    /*************************************************************
     * Derive the session key through the master secret
     *************************************************************/
    unsigned char* secret = NULL;
    uint32_t secret_len = derive_secret(dh_priv_key, dh_server_pubkey, dh_pub_srv_key_size, &secret);
    if(secret_len==0){
        free(dh_server_pubkey);
        free(server_cert);
        free(dh_pub_key);
        return -1;
        }

    free(dh_server_pubkey);
    free(dh_pub_key);

    uint32_t len_key;
    if(ver==AUTH_CLNT_SRV){
        len_key = digest_default(secret, secret_len, &sess_key_client_server);
        }
    else if(ver==AUTH_CLNT_CLNT){
        len_key = digest_default(secret, secret_len, &sess_key_client_client);
        }

    if(len_key==0){
        free(server_cert);
        safe_free(sess_key_client_server, sess_key_client_server_len);
        safe_free(sess_key_client_client, sess_key_client_client_len);
        safe_free(secret, secret_len);
        return -1;
        }

    if(ver==AUTH_CLNT_SRV){
        sess_key_client_server_len = len_key;
        }
    else if(ver==AUTH_CLNT_CLNT){
        sess_key_client_client_len = len_key;
        }

    safe_free(secret, secret_len);

    /************************************************************
     * End of Authentication
     ************************************************************/
    if(ver==AUTH_CLNT_SRV){
        ret = get_self_id(id_sock);
        if(ret!=0){
            cerr << " Error getting user id \n";
            return -1;
            }
        }
    // authentication is successful
    return 0;
}



int authentication_receiver(int id_sock)
{
    if(id_sock<0){return -1;}

    int ret;
    int peer_id_net = htonl(peer_id);
    uint8_t opcode_rcvd;
    uint32_t id_dest, id_dest_net;


    /*************************************************************
     * M1 - R1
     *************************************************************/
    uchar* R1 = (uchar*)malloc(NONCE_SIZE);
    if(!R1){
        errorHandler(MALLOC_ERR);
        return -1;
        }
    unsigned char* pt_M1 = NULL;
    uint32_t pt_M1_len = 0;
    uint8_t op_appo_checker;
    uint32_t read_appo_checker;

    do{
        pt_M1_len = secure_recv(id_sock, &pt_M1);
        if(pt_M1_len<=0){
            cerr << " Error rcv first msg\n";
            safe_free(R1, NONCE_SIZE);
            return -1;
            }

        read_appo_checker = sizeof(uint32_t); // seq_number read
        memcpy(&op_appo_checker, pt_M1+read_appo_checker, sizeof(uint8_t));
        read_appo_checker += sizeof(uint8_t);

        if(op_appo_checker==CHAT_CMD){
            // automatic refuse
            int rejected_user;
            memcpy(&rejected_user, pt_M1+read_appo_checker, sizeof(uint32_t));
            ret = negative_rsp(id_sock, rejected_user);
            if(ret==-1){
                safe_free(R1, NONCE_SIZE);
                return -1;
                }
            }
        else if(op_appo_checker!=AUTH){
            safe_free(R1, NONCE_SIZE);
            return -1;
            }
        }while(op_appo_checker!=AUTH);

    uint32_t bytes_read = sizeof(uint32_t); // seq_num read

    // checking
    memcpy(&opcode_rcvd, pt_M1+bytes_read, sizeof(uint8_t));
    bytes_read += sizeof(uint8_t);
    if(opcode_rcvd!=AUTH){
        cerr << " Wrong opcode\n";
        free(R1);
        safe_free(pt_M1, pt_M1_len);
        }

    memcpy(&id_dest_net, pt_M1+bytes_read, sizeof(uint32_t));
    id_dest = ntohl(id_dest_net);
    bytes_read += sizeof(uint32_t);
    if(id_dest!=actual_user_id){
        cerr << " Wrong id \n";
        free(R1);
        safe_free(pt_M1, pt_M1_len);
        }

    memcpy(R1, pt_M1+bytes_read, NONCE_SIZE);
    bytes_read += NONCE_SIZE;

    safe_free(pt_M1, pt_M1_len);

    /*************************************************************
     * M2 - Send R2,pubkey_eph,signature
     *************************************************************/
    uchar* R2 = (uchar*)malloc(NONCE_SIZE);
    if(!R2){
        errorHandler(MALLOC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
        }

    //Creating ephermeral dh keys
    void* eph_privkey_s;
    uchar* eph_pubkey_s;
    uint eph_pubkey_s_len;
    ret = gen_eph_key(&eph_privkey_s, &eph_pubkey_s, &eph_pubkey_s_len);
    if(ret != 1){
        cerr << "Error on gen_eph_key\n";
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    //nonce R2
    ret = gen_random(NONCE_SIZE, R2);
    if(ret != 1){
        cerr <<  "Error on gen_random\n";
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    uint32_t M2_to_sign_length = (NONCE_SIZE*2) + eph_pubkey_s_len;
    uint32_t M2_signed_length;
    uchar* M2_signed;
    uchar* M2_to_sign = (uchar*)malloc(M2_to_sign_length);

    if(!M2_to_sign){
        cerr << "Error on M2_to_sign\n";
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    memcpy(M2_to_sign, R1, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + NONCE_SIZE), R2, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + (2*NONCE_SIZE)), eph_pubkey_s, eph_pubkey_s_len);

    string priv_key_file_path = "clients_data/"+actual_user+"/"+actual_user+"_privkey.pem";
    FILE* priv_key_file = fopen(priv_key_file_path.c_str(), "rb");
    if(!priv_key_file){
        cerr<<"error read privkey file\n";
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        safe_free(M2_to_sign, M2_to_sign_length);
        return -1;
        }


    ret = sign_document(M2_to_sign, M2_to_sign_length, priv_key_file, NULL, &M2_signed, &M2_signed_length);
    if(ret != 1){
        cerr << "Error signing\n";
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        fclose(priv_key_file);
        return -1;
        }

    fclose(priv_key_file);

    //Send M2
    if(M2_signed_length > UINT32_MAX -(sizeof(uint8_t) + sizeof(int) + NONCE_SIZE + sizeof(int)+ sizeof(int))){
        cerr << " Integer Overflow\n";
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    if(eph_pubkey_s_len>UINT_MAX-(sizeof(uint8_t) + sizeof(int) + NONCE_SIZE + sizeof(int)+ sizeof(int) + M2_signed_length)){
        cerr << " Integer Overflow\n";
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    uint M2_size = sizeof(uint8_t) + sizeof(int) + NONCE_SIZE + sizeof(int) + eph_pubkey_s_len + sizeof(int) + M2_signed_length;
    uint offset = 0;
    uchar* M2 = (uchar*)malloc(M2_size);
    if(!M2){
        cerr << "Error malloc\n";
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }
    uint eph_pubkey_s_len_net = htonl(eph_pubkey_s_len);
    uint M2_signed_length_net = htonl(M2_signed_length);

    uint8_t opcode = AUTH;
    memcpy(M2+offset, &opcode, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    memcpy(M2+offset, &peer_id_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy((void*)(M2 + offset), R2, NONCE_SIZE);
    offset += NONCE_SIZE;
    memcpy((void*)(M2 + offset), &eph_pubkey_s_len_net, sizeof(uint));
    offset += sizeof(uint);
    memcpy((void*)(M2 + offset), eph_pubkey_s, eph_pubkey_s_len);
    offset += eph_pubkey_s_len;
    memcpy((void*)(M2 + offset), &M2_signed_length_net ,sizeof(uint));
    offset += sizeof(uint);
    memcpy((void*)(M2 + offset), M2_signed,M2_signed_length);
    offset += M2_signed_length;


    ret = secure_send(id_sock, M2, M2_size);
    if(ret==0){
        cerr << " Error in sending M2 \n";
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    safe_free(M2, M2_size);
    safe_free(M2_to_sign, M2_to_sign_length);
    safe_free(R1, NONCE_SIZE);
    safe_free(eph_pubkey_s, eph_pubkey_s_len);


    /*************************************************************
     * M3 - client_pubkey and signing of pubkey and R2
     *************************************************************/
    uint32_t eph_pubkey_c_len;
    unsigned char* msg3 = NULL;
    uint32_t msg3_len = 0;

    do{
       msg3_len = secure_recv(id_sock, &msg3);
       if(msg3_len <= 0){
            cerr << " Error secure_recv\n";
            safe_free(R2, NONCE_SIZE);
            safe_free_key(eph_privkey_s);
            return -1;
            }

        read_appo_checker = sizeof(uint32_t); // seq number read
        memcpy(&op_appo_checker, msg3+read_appo_checker, sizeof(uint8_t));
        read_appo_checker += sizeof(uint8_t);
        if(op_appo_checker==CHAT_CMD){
            // automatic refuse
            int rejected_user;
            memcpy(&rejected_user, msg3+read_appo_checker, sizeof(uint32_t));
            ret = negative_rsp(id_sock, rejected_user);
            if(ret==-1){
                safe_free(R1, NONCE_SIZE);
                return -1;
                }
            }
        else if(op_appo_checker!=AUTH){
            safe_free(R1, NONCE_SIZE);
            return -1;
            }
        }while(op_appo_checker!=AUTH);


    bytes_read = 4; // seq_num read

    memcpy(&opcode_rcvd, msg3 + bytes_read, sizeof(uint8_t));
    bytes_read += sizeof(uint8_t);
    if(opcode_rcvd!=AUTH){
        cerr << " Wrong opcode_rcvd\n";
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(msg3, msg3_len);
        }

    memcpy(&id_dest_net, msg3+bytes_read, sizeof(uint32_t));
    id_dest = ntohl(id_dest_net);
    bytes_read += sizeof(uint32_t);
    if(id_dest!=actual_user_id){
        cerr << " Wrong id \n";
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(msg3, msg3_len);
        }

    memcpy(&eph_pubkey_c_len, msg3+bytes_read, sizeof(uint32_t));
    bytes_read+=sizeof(uint32_t);
    eph_pubkey_c_len = ntohl(eph_pubkey_c_len);

    uchar* eph_pubkey_c = (uchar*)malloc(eph_pubkey_c_len);
    if(!eph_pubkey_c ){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(msg3, msg3_len);
        return -1;
        }

    if(bytes_read + eph_pubkey_c_len > msg3_len){
        cerr << " Error in message len\n";
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(msg3, msg3_len);
        safe_free(eph_pubkey_c,eph_pubkey_c_len);
        return -1;
        }
    memcpy(eph_pubkey_c, msg3 + bytes_read, eph_pubkey_c_len);
    bytes_read += eph_pubkey_c_len;

    uint32_t m3_signature_len;
    memcpy(&m3_signature_len, msg3+bytes_read, sizeof(uint32_t));
    bytes_read += sizeof(uint32_t);
    m3_signature_len = ntohl(m3_signature_len);

    uchar* M3_signed = (uchar*)malloc(m3_signature_len);
    if(!M3_signed){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(msg3, msg3_len);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        return -1;
        }

    if(bytes_read + m3_signature_len > msg3_len){
        cerr << " Error msg_len\n";
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(msg3, msg3_len);
        safe_free(eph_pubkey_c,eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
        }
    memcpy(M3_signed, msg3+bytes_read, m3_signature_len);
    bytes_read += m3_signature_len;

    safe_free(msg3, msg3_len);

    if(eph_pubkey_c_len>UINT_MAX-NONCE_SIZE){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
        }

    uint m3_document_size = eph_pubkey_c_len + NONCE_SIZE;
    uchar* m3_document = (uchar*)malloc(m3_document_size);
    if(!m3_document){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
        }

    memcpy(m3_document, eph_pubkey_c,eph_pubkey_c_len );
    memcpy(m3_document+eph_pubkey_c_len, R2, NONCE_SIZE);

    if(peer_pub_key==NULL){
        cerr << " No peer public key\n";
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        }

    ret = verify_pubkey_sign(M3_signed, m3_signature_len, m3_document, m3_document_size, peer_pub_key, PUBKEY_DEFAULT_SER);
    if(ret == 0){
        cerr << "Fail verification sign\n";
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
        }

    safe_free(R2, NONCE_SIZE);
    safe_free(M3_signed, m3_signature_len);

    uchar* shared_secret;
    uint shared_secret_len;
    shared_secret_len = derive_secret(eph_privkey_s, eph_pubkey_c, eph_pubkey_c_len, &shared_secret);
    if(shared_secret_len == 0){
        cerr << "Fail derive secret\n";
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free_key(eph_privkey_s);
        return -1;
        }

    sess_key_client_client_len = digest_default(shared_secret, shared_secret_len, &sess_key_client_client);
    if(sess_key_client_client_len == 0){
        cerr << "Failed digest secret\n";
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(shared_secret, shared_secret_len);
        safe_free_key(eph_privkey_s);
        return -1;
        }

    safe_free(eph_pubkey_c, eph_pubkey_c_len);
    safe_free(shared_secret, shared_secret_len);

    cout << "SUCCESS AUTHENTICATION WITH" << peer_username << endl;
    return 0;
}
