#include "server_authentication.h"

int authentication_client(string pwd_for_keys){
    /*************************************************************
     * M1 - R1 and Username
     *************************************************************/
    int ret;
    uchar* R1 = (uchar*)malloc(NONCE_SIZE);
    if(!R1){
        errorHandler(MALLOC_ERR);
        return -1;
    }

    ret = recv(c_socket_id, (void *)R1, NONCE_SIZE, 0);
    if (ret <= 0 || ret != NONCE_SIZE){
        errorHandler(REC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
        }

    uint32_t client_username_len;
    ret = recv(c_socket_id, (void *)&client_username_len, sizeof(uint32_t), 0);
    if (ret <= 0 || ret != sizeof(uint32_t)){
        errorHandler(REC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
        }

    client_username_len = ntohl(client_username_len);

    char* username = (char*)malloc(client_username_len);
    if(!username){
        errorHandler(MALLOC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
        }

    ret = recv(c_socket_id, (void *)username, client_username_len, 0);
    if (ret <= 0 || ret != client_username_len){
        errorHandler(REC_ERR);
        safe_free((uchar*)username, client_username_len);
        safe_free(R1, NONCE_SIZE);
        return -1;
        }

    string client_username(username);

    if(get_socket_from_id(get_id_from_username(username)) != -1){
        log("ERROR user already online");
        safe_free((uchar*)username, client_username_len);
        safe_free(R1, NONCE_SIZE);
        return -1;
        }

    safe_free((uchar*)username, client_username_len);

    /*************************************************************
     * M2 - Send R2,pubkey_eph,signature,certificate
     *************************************************************/
    uchar* R2 = (uchar*)malloc(NONCE_SIZE);
    if(!R2){
        errorHandler(MALLOC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
        }

    //Generate pair of ephermeral DH keys
    void* eph_privkey_s;
    uchar* eph_pubkey_s;
    uint eph_pubkey_s_len;
    ret = gen_eph_key(&eph_privkey_s, &eph_pubkey_s, &eph_pubkey_s_len);
    if(ret != 1){
        log("Error on gen_eph_key");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    //Generate nonce R2
    ret = gen_random(NONCE_SIZE, R2);
    if(ret != 1){
        log("Error on gen_random");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    //Get certificate of Server
    FILE* cert_file = fopen("certification/Server_cert.pem", "rb");
    if(!cert_file){
        log("Error on opening cert file");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    uchar* certificate_ser;
    uint certificate_len = serialize_certificate(cert_file, &certificate_ser);
    if(certificate_len == 0){
        log("Error on serialize certificate");
        fclose(cert_file);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    if(eph_pubkey_s_len > UINT_MAX - NONCE_SIZE*2){
        log("ERROR: unsigned wrap");
        return -1;
        }

    uint M2_to_sign_length = (NONCE_SIZE*2) + eph_pubkey_s_len, M2_signed_length;
    uchar* M2_signed;
    uchar* M2_to_sign = (uchar*)malloc(M2_to_sign_length);
    if(!M2_to_sign){
        log("Error on M2_to_sign");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        fclose(cert_file);
        return -1;
        }

    memcpy(M2_to_sign, R1, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + NONCE_SIZE), R2, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + (2*NONCE_SIZE)), eph_pubkey_s, eph_pubkey_s_len);


    ret = sign_document(M2_to_sign, M2_to_sign_length, server_privk,&M2_signed, &M2_signed_length);
    if(ret != 1){
        log("Error on signing part on M2");
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        fclose(cert_file);
        return -1;
        }

    //Send M2 part by part
    if(eph_pubkey_s_len > UINT_MAX - 3*sizeof(uint) - M2_signed_length){
        log("ERROR unsigned_wrap");
        return -1;
        }

    if(certificate_len > UINT_MAX - 3*sizeof(uint) - eph_pubkey_s_len - M2_signed_length){
        log("ERROR unsigned_wrap");
        return -1;
        }

    uint M2_size = NONCE_SIZE + 3*sizeof(uint) + eph_pubkey_s_len + M2_signed_length + certificate_len;
    uint offset = 0;
    uchar* M2 = (uchar*)malloc(M2_size);

    if(!M2){
        log("ERROR on malloc");
         safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
        }

    uint eph_pubkey_s_len_net = htonl(eph_pubkey_s_len);
    uint M2_signed_length_net = htonl(M2_signed_length);
    uint certificate_len_net = htonl(certificate_len);

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
    memcpy((void*)(M2 + offset), &certificate_len_net ,sizeof(uint));
    offset += sizeof(uint);
    memcpy((void*)(M2 + offset), certificate_ser, certificate_len);
    offset += certificate_len;

    ret = send(c_socket_id, M2, M2_size, 0);
    if(ret < M2_size){
        errorHandler(SEND_ERR);
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
    ret = recv(c_socket_id, &eph_pubkey_c_len, sizeof(uint32_t), 0);
    if(ret <= 0 || ret != sizeof(uint32_t)){
        errorHandler(REC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        return -1;
        }

    eph_pubkey_c_len = ntohl(eph_pubkey_c_len);


    uchar* eph_pubkey_c = (uchar*)malloc(eph_pubkey_c_len);
    if(!eph_pubkey_c ){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        return -1;
        }

    ret = recv(c_socket_id, eph_pubkey_c, eph_pubkey_c_len, 0);
    if(ret <= 0 || ret != eph_pubkey_c_len){
        errorHandler(REC_ERR);
        free(R2);
        free(eph_pubkey_c);
        return -1;
        }

    uint32_t m3_signature_len;
    ret = recv(c_socket_id, &m3_signature_len, sizeof(uint32_t), 0);
    if(ret <= 0){
        errorHandler(REC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        return -1;
        }
    m3_signature_len = ntohl(m3_signature_len);

    uchar* M3_signed = (uchar*)malloc(m3_signature_len);
    if(!M3_signed){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        return -1;
        }

    ret = recv(c_socket_id, M3_signed, m3_signature_len, 0);
    if(ret <= 0){
        errorHandler(REC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
        }


    string client_pubkey_path = "certification/" + client_username + "_pubkey.pem";
    FILE* client_pubkey = fopen(client_pubkey_path.c_str(), "rb");
    if(!client_pubkey){
        log("Unable to open pubkey of client");
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
        }

    if(eph_pubkey_c_len > UINT_MAX - NONCE_SIZE){
        log("ERROR unsigned wrap");
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
        fclose(client_pubkey);
        return -1;
        }

    memcpy(m3_document, eph_pubkey_c,eph_pubkey_c_len );
    memcpy(m3_document+eph_pubkey_c_len, R2, NONCE_SIZE);

    ret = verify_pubkey_sign(M3_signed, m3_signature_len,m3_document,m3_document_size, client_pubkey);
    if(ret == 0){
        log("Failed sign verification on M3");
        safe_free(R2, NONCE_SIZE);
        safe_free_key(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        fclose(client_pubkey);
        return -1;
        }

    fclose(client_pubkey);
    uchar* shared_secret;
    uint shared_secret_len;

    shared_secret_len = derive_secret(eph_privkey_s, eph_pubkey_c, eph_pubkey_c_len, &shared_secret);
    if(shared_secret_len == 0){
        log("Failed derive secret");
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
        }

    session_key_len = digest_default(shared_secret, shared_secret_len, &session_key);
    if(session_key_len == 0){
        log("Failed digest of the secret");
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        safe_free(shared_secret, shared_secret_len);
        return -1;
        }

    safe_free(eph_pubkey_c, eph_pubkey_c_len);
    safe_free(M3_signed, m3_signature_len);
    safe_free(shared_secret, shared_secret_len);

    //Send user id of the client
    int client_id = get_id_from_username(client_username);
    int client_id_net = htonl(client_id);

    //Set that user is online
    ret = set_user_socket(client_username, c_socket_id);
    if(ret == -1){
        log("ERROR on set_user_socket");
        safe_free((uchar*)username, client_username_len);
        safe_free(R1, NONCE_SIZE);
        return -1;
        }

    //SEND User id
    uchar* user_id_msg=(uchar*)malloc(5);
    *user_id_msg=USRID;
    memcpy(user_id_msg+1, &client_id_net,4);

    ret = secure_send(c_socket_id, user_id_msg, 5);
    if(ret == 0){
        log("Error on send secure");
        return -1;
        }

    //Check if present in the user_datastore
    free(username);
    return get_id_from_username(client_username);
}
