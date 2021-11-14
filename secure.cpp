#include "secure.h"

uint serialize_pubkey(EVP_PKEY* pubkey, uchar** pubkey_ser)
{
    BIO* mbio = BIO_new( BIO_s_mem() );

    if(!mbio){
        cerr << "Error: cannot initialize BIO\n";
        return 0;
        }

    if(!PEM_write_bio_PUBKEY(mbio, pubkey)){
        cerr << "Error: unable to write in BIO\n";
        BIO_free(mbio);
        return 0;
        }

    uchar* appo = NULL;

    // obtain size and allocate buffer
    int ret = BIO_get_mem_data(mbio, &appo);
    *pubkey_ser = (uchar*)malloc(ret);
    if(*pubkey_ser == NULL){
        cerr << "unable to allocate buffer for serialized pubkey\n";
        BIO_free(mbio);
        return 0;
    }

    memcpy(*pubkey_ser, appo, ret);
    BIO_free(mbio);
    return ret;
}


int deserialize_pubkey(const uchar* pubkey_ser, uint key_len, EVP_PKEY** pubkey)
{
    BIO* mbio = BIO_new(BIO_s_mem());

    if(!mbio){
        cerr << "Error: cannot initialize BIO\n";
        return 0;
        }

    if(!BIO_write(mbio, pubkey_ser, key_len)){
        cerr << "Error: unable to write in BIO\n";
        BIO_free(mbio);
        return 0;
        }

    *pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);
    if(*pubkey==nullptr){
        cerr << "Error: bio read returned null\n";
        return 0;
        }

    return 1;
}


int auth_enc_encrypt( uchar *plaintext, int plaintext_len, uchar* aad, uint aad_len, uchar *key, uchar** tag, uchar **iv,  uchar **ciphertext)
{
    /* Create and initialize the context */
    const EVP_CIPHER *cypher = AUTH_ENCRYPT_DEFAULT;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if(ctx == nullptr){
        perror("Error: unallocated context\n");
        return 0;
        }

    int block_len = EVP_CIPHER_block_size(cypher);
    int iv_len = EVP_CIPHER_iv_length(cypher);
    int tag_len = TAG_DEFAULT;

    if(plaintext_len > INT_MAX - block_len) {
        perror("Error: integer overflow\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
        }

    // allocate buffers
    *tag = (uchar*)malloc(tag_len);
    if(*tag == nullptr){
        errorHandler(MALLOC_ERR);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
        }

    *ciphertext = (uchar*)malloc(plaintext_len + block_len);
    if(*ciphertext == nullptr){
        errorHandler(MALLOC_ERR);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
        }

    *iv = (uchar*)malloc(iv_len);
    if(iv == nullptr){
        errorHandler(MALLOC_ERR);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
        }

    // generate random IV
    RAND_poll();
    if(1 != RAND_bytes(*iv, iv_len)){
        perror("Error: RAND_bytes failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
        }

    int len;
    int ciphertext_len;

    // Encrypt init
    if(1 != EVP_EncryptInit(ctx,cypher, key, *iv)){
        perror("Error: encryption init failed\n");
        return 0;
        }

    // Encrypt Update: first call
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        perror("Error: encryption update 1 failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    // Encrypt Update: second call
    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)){
        perror("Error: encryption update 2 failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
        }

    ciphertext_len = len;

    //Encrypt Final. Finalize the encryption and adds the padding
    if(1 != EVP_EncryptFinal(ctx, *ciphertext + len, &len)) {
        perror("Error: encryption final failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, *tag)){
        perror("Error: encryption ctrl failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
        }

    // deallocate contxt
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int auth_enc_decrypt(uchar *ciphertext, uint ciphertext_len, uchar* aad, uint aad_len, uchar *key, uchar* tag, uchar *iv,  uchar **plaintext)
{
    const EVP_CIPHER *cypher = AUTH_ENCRYPT_DEFAULT;
    int block_len = EVP_CIPHER_block_size(cypher);

    int iv_len = EVP_CIPHER_iv_length(cypher);
    int tag_len=16;

    if(ciphertext_len > INT_MAX -block_len){
        perror("Error: integer overflow\n");
        return 0;
        }

    // allocates buffer
    *plaintext = (uchar*) malloc(ciphertext_len+block_len);
    if(*plaintext==nullptr) {
        errorHandler(MALLOC_ERR);
        return 0;
        }

    /* Create and initialize the context */
    int len;
    int plaintext_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if(ctx == nullptr){
        perror("Error: unallocated context\n");
        return 0;
        }

    // Encrypt init
    if(1 != EVP_DecryptInit(ctx,cypher, key, iv)){
        perror("Error: decryption-init failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
        }

    // Encrypt Update: 1st call
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        perror("Error: decryption first update failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
        }

    // Encrypt Update: 2nd call
    if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        perror("Error: decryption second update failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
        }

    plaintext_len = len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG, tag_len, tag)){
        perror("Error: decryption ctrl failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
        }

    //Encrypt Final. Finalize the dencryption
    int ret= EVP_DecryptFinal(ctx, *plaintext + len, &len);

    if(ret<=0){
        perror("Error: decryption final failed \n");
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
        }

    plaintext_len += len;

    // deallocate context
    EVP_CIPHER_CTX_cleanup(ctx);
    return plaintext_len;
}

/*
 *  digest computation
 *   cypher input
 *   plaintext input
 *   plaintext_len input
 *   ciphertext output
 *  return digest length, 0 on error
 */
uint digest(const EVP_MD* cypher, uchar* plaintext, uint plaintext_len, uchar** ciphertext)
{
    if(plaintext_len>BUFFER_MAX){
        perror("Error: plaintext too big\n");
        return 0;
        }

    if(cypher==nullptr) {
        perror("Error: unallocated cypher\n");
        return 0;
        }

    uint cipherlen=EVP_MD_size(cypher);

    // allocate buffers
    *ciphertext = (uchar*)malloc(cipherlen);
    if(*ciphertext==nullptr) {
        errorHandler(MALLOC_ERR);
        return 0;
        }

    uint out_len;
    EVP_MD_CTX* md_ctx;
    md_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md_ctx, cypher)){
        perror("Error: encryption init failed\n");
        free(ciphertext);
        return 0;
        }

    if(!EVP_DigestUpdate(md_ctx, plaintext, plaintext_len)){
        perror("Error: encryption update failed\n");
        free(ciphertext);
        return 0;
        }

    if(!EVP_DigestFinal(md_ctx, *ciphertext, &out_len)){
        perror("Error: encryption final failed\n");
        free(ciphertext);
        return 0;
        }

    EVP_MD_CTX_free(md_ctx);
    if(out_len != cipherlen){
        return 0;
        }
    return out_len;
}

// CRYPTO_memcmp wrapper
uint digest_compare(const uchar* digest_a, const uchar* digest_b, const uint len)
{
    if(len > BUFFER_MAX){
        perror("Error: lenght too big\n");
        return 0;
        }
    return CRYPTO_memcmp(digest_a, digest_b, len);
}

uint digest_default(uchar* plaintext, uint plaintext_len, uchar** chipertext)
{
    return digest(DIGEST_DEFAULT, plaintext, plaintext_len, chipertext);
}

int serialize_certificate(FILE* cert_file, uchar** certificate)
{
    *certificate = nullptr;
    if(!cert_file){
        cerr << "Error: cannot open certificate file\n";
        return 0;
        }

    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if(!cert){
        cerr << "Error: PEM_read_X509 returns NULL\n";
        return 0;
        }

    int ret = i2d_X509(cert, certificate);
    X509_free(cert);
    return ret;
}


/**
 *  verify a certificate with a self signed CA certificate and ctrl
 *
 *   certificate is under verification
 *   CAcertificate self signed CA certificate
 *   CAcrl self signed CA ctrl
 *  return 1 if succesfull verification, 0 otherwise
 */
int verify_certificate( X509* certificate, X509* CAcertificate, X509_CRL* CAcrl)
{
    int ret;

    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();

    if(!store){
        cerr << "Error: X509_STORE_new returns NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        return 0;
        }

    ret = X509_STORE_add_cert(store, CAcertificate);
    if(ret != 1) {
        cerr << "Error: X509_STORE_add_cert returns " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        X509_STORE_free(store);
        return 0;
        }

    ret = X509_STORE_add_crl(store, CAcrl);
    if(ret != 1) {
        cerr << "Error: X509_STORE_add_crl returns " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        X509_STORE_free(store);
        return 0;
        }

    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) {
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        X509_STORE_free(store);
        return 0;
        }

    // verify the certificate
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx){
        cerr << "Error: X509_STORE_CTX_new returns NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        X509_STORE_free(store);
        return 0;
        }

    ret = X509_STORE_CTX_init(certvfy_ctx, store, certificate, NULL);
    if(ret != 1) {
        cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        ret=0;
        goto end;
        }

    ret= X509_verify_cert(certvfy_ctx);
end:
    X509_STORE_free(store);
    X509_STORE_CTX_free(certvfy_ctx);
    return ret;
}

int _verify_sing_pubkey(uchar* signature, uint signature_len, uchar* document, uint document_len, EVP_PKEY* pubkey)
{
    int ret;

    // create signature context
    const EVP_MD* md = DIGEST_DEFAULT;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){
        cerr << "Error: EVP_MD_CTX_new returns NULL \n";
        return 0;
        }

    // verify the plaintext, assuming the plaintext isn't great)
    ret = EVP_VerifyInit(md_ctx, md);
    if(ret == 0){
        cerr << "Error: EVP_VerifyInit returns " << ret << "\n";
        EVP_MD_CTX_free(md_ctx);
        return 0;
        }

    ret = EVP_VerifyUpdate(md_ctx, document, document_len);
    if(ret == 0){
        cerr << "Error: EVP_VerifyUpdate returnes " << ret << "\n";
        EVP_MD_CTX_free(md_ctx);
        return 0;
        }

    ret = EVP_VerifyFinal(md_ctx, signature, signature_len, pubkey);
    if(ret == -1){
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
        ret=0;
        }

    EVP_MD_CTX_free(md_ctx);
    return ret;
}

int verify_pubkey_sign(uchar* signature, uint signature_len, uchar* document, uint document_len, uchar* pubkey, uint key_len)
{
    EVP_PKEY* pkey;
    if(!deserialize_pubkey(pubkey, key_len, &pkey)){
        cerr << "Error in deserialize pubkey \n"; return 0;
    }

    int ret =_verify_sing_pubkey(signature, signature_len, document, document_len, pkey);
    EVP_PKEY_free(pkey);

    return ret;
}

int verify_pubkey_sign(uchar* signature, uint signature_len, uchar* document, uint document_len, FILE*pubkey)
{
    EVP_PKEY* pkey = PEM_read_PUBKEY(pubkey, NULL, NULL, NULL);

    int ret = _verify_sing_pubkey(signature, signature_len, document, document_len, pkey );
    EVP_PKEY_free(pkey);

    return ret;
}

int verify_cert_sign(const uchar* certificate, const uint certificate_len, FILE* const CAcertificate, FILE* const CAcrl, uchar* signature, uint signature_len, uchar* document, uint document_len)
{
    int ret;

    if(!signature || signature_len==0) {
        cerr << "Error: no signature \n";
        return 0;
        }
    if(!document || document_len==0){
        cerr << "Error: no document \n";
        return 0;
        }
    if(!certificate || certificate_len==0){
        cerr << "Error: no certificate \n";
        return 0;
        }

    // load the certificate under validation
    X509* cert=d2i_X509(NULL, &certificate, certificate_len);
    if(!cert){
        cerr << "Error: PEM_read_X509 returns NULL\n";
        return 0;
        }

    // load CA certificate
    if(!CAcertificate){
        cerr << "Error: opening ca_certificate file\n";
        X509_free(cert);
        return 0;
        }

    X509* ca_cert = PEM_read_X509(CAcertificate, NULL, NULL, NULL);
    if(!ca_cert){
        cerr << "Error: PEM_read_X509 returns NULL\n";
        X509_free(cert);
        return 0;
        }

    // load CA ctrl for revocation list
    if(!CAcrl){
        cerr << "Error: opening ca ctrl file\n";
        X509_free(ca_cert);
        X509_free(cert);
        return 0;
        }

    X509_CRL* crl = PEM_read_X509_CRL(CAcrl, NULL, NULL, NULL);
    if(!crl){
        cerr << "Error: PEM_read_X509_CRL returns NULL\n";
        X509_free(ca_cert);
        X509_free(cert);
        return 0;
        }

    if(!verify_certificate(cert,  ca_cert, crl)){
        perror("the certificate isn't valid");
        X509_free(ca_cert);
        X509_CRL_free(crl);
        X509_free(cert);
        return 0;
    }

    // verify the signature with extracted public key
    ret = _verify_sing_pubkey(signature, signature_len, document, document_len, X509_get_pubkey(cert));
    X509_free(ca_cert);
    X509_CRL_free(crl);
    X509_free(cert);
    return ret;
}

int sign_document( const uchar* document, uint document_len, FILE* const priv_key, char* const password, uchar** signature, uint* signature_len)
{
    void* pkey = read_privkey(priv_key, password);

    int ret = sign_document(document, document_len, pkey, signature, signature_len);
    safe_free_key(pkey);
    return ret;
}

int sign_document(const uchar* document, uint document_len, void* priv_key, uchar** signature, uint* signature_len)
{
    EVP_PKEY* privkey = (EVP_PKEY*)priv_key;
    if(!privkey){
        cerr << "Error: private key\n";
        return 0;
        }

    if(!document || document_len==0){
        cerr << "Error: document \n";
        return 0;
        }

    int ret;
    const EVP_MD* md = DIGEST_DEFAULT;

    // create signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){
        cerr << "Error: EVP_MD_CTX_new returns NULL\n";
        return 0;
        }

    // allocate buffer
    *signature = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    if(!*signature){
        cerr << "Error: malloc returns NULL\n";
        EVP_MD_CTX_free(md_ctx);
        return 0;
        }

    // sign the plaintext, assuming the plaintext isn't big
    ret = EVP_SignInit(md_ctx, md);
    if(ret == 0){
        cerr << "Error: EVP_SignInit returned " << ret << "\n";
        EVP_MD_CTX_free(md_ctx);
        return 0;
        }

    ret = EVP_SignUpdate(md_ctx, document, document_len);
    if(ret == 0){
        cerr << "Error: EVP_SignUpdate returns " << ret << "\n";
        EVP_MD_CTX_free(md_ctx);
        return 0;
        }

    ret = EVP_SignFinal(md_ctx, *signature, signature_len, privkey);
    if(ret == 0){
        cerr << "Error: EVP_SignFinal returns " << ret << "\n";
        EVP_MD_CTX_free(md_ctx);
        return 0;
        }

    EVP_MD_CTX_free(md_ctx);
    return 1;
}

int gen_eph_key(void** privkey, uchar** pubkey, uint* pubkey_len ){

    EVP_PKEY* dh_params = NULL;
    EVP_PKEY* priv_key = NULL;
    EVP_PKEY_CTX* p_ctx;

    // using elliptic-curve
    p_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!p_ctx){
        cerr << "Error: allocate EC generation context";
        return 0;
        }

    if(!EVP_PKEY_paramgen_init(p_ctx)){
        cerr << "Error: initialize EC parameters generation";
        EVP_PKEY_CTX_free(p_ctx);
        return 0;
    }

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p_ctx, NID_X9_62_prime256v1);
    if(!EVP_PKEY_paramgen(p_ctx, &dh_params)){
        cerr << "Error: generate EC parameters";
        EVP_PKEY_CTX_free(p_ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(p_ctx);

    // DH keys
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL);

    if(!ctx){
        cerr << "Error: allocate context";
        EVP_PKEY_free(dh_params);
        return 0;
        }

    if(1!=EVP_PKEY_keygen_init(ctx)){
        cerr << "Error: initialize context";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh_params);
        return 0;
    }

    if(1!=EVP_PKEY_keygen(ctx, &priv_key)){
        cerr << "Error: generate DH keys";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh_params);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);

    // serialize public key
    *pubkey_len= serialize_pubkey(priv_key, pubkey);
    if(!*pubkey){
        cerr << "Error: unable to serialize DH keys\n";
        return 0;
        }
    *privkey = (void*)priv_key;

    return 1;
}

uint derive_secret(void* privkey, uchar* peer_key, uint peer_key_len , uchar** secret)
{
    EVP_PKEY_CTX *derive_ctx;
    size_t secret_key_len=0;

    // deserialize keys
    EVP_PKEY* priv_key = (EVP_PKEY*) privkey;
    EVP_PKEY* peer_pubkey;

    if(!deserialize_pubkey(peer_key, peer_key_len, &peer_pubkey)){
        cerr << "Error: deserialize peer key\n";
        return 0;
        }

    // secret derivation
    derive_ctx = EVP_PKEY_CTX_new(priv_key,NULL);
    if (!derive_ctx) {
        cerr << "Error: allocate DH derivation context";
        goto end;
        }

    if (EVP_PKEY_derive_init(derive_ctx) <= 0){
        cerr << "Error: initialize DH derivation context";
        goto end;
        }

    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0){
        cerr << "Error: set peer public key";
        goto end;
        }

    // Determine buffer length
    if(!EVP_PKEY_derive(derive_ctx, NULL, &secret_key_len)){
        cerr << "Error: derive DH secret buffer lenght";
        goto end;
        }

    // allocate buffer for shared secret
    *secret = (uchar*)(malloc(int(secret_key_len)));
    if (!*secret){
        cerr << "Error: allocate DH secret buffer";
        goto end;
        }

    // derivation
    if (EVP_PKEY_derive(derive_ctx, *secret, &secret_key_len) <= 0){
        cerr << "Error: derive DH secret";
        secret_key_len=0;
        free(secret);
        goto end;
        }

end:
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_free(priv_key);
    return secret_key_len;
}

int gen_random(const uint lenght, uchar* nonce)
{
    if(!RAND_poll()){
        return 0;
        }

    if(1 != RAND_bytes(nonce, lenght)){
        perror("Error: RAND_bytes failed\n");
        return 0;
        }

    return 1;
}

void safe_free_key(void* key)
{
    EVP_PKEY* priv_key=(EVP_PKEY*) key;
    EVP_PKEY_free(priv_key);
}

void safe_free(uchar* buffer, uint buffer_len )
{
    #pragma optimize("", off)
    memset(buffer, 0, buffer_len);
    #pragma optimize("", on)
    free(buffer);
}

void* read_privkey(FILE* privk_file, char* const password)
{
    if(!privk_file){
        cerr << "Error: cannot open private key file\n";
        return NULL;
        }

    EVP_PKEY* privkey = PEM_read_PrivateKey(privk_file, NULL, NULL, password);
    if(!privkey){
        cerr << "Error: PEM_read_PrivateKey returns NULL\n";
        return NULL;
        }

    return privkey;
}

int serialize_pubkey_from_file(FILE* pubk_file, uchar** pubkey_buf)
{
    if(!pubk_file){
        cerr << "Error: cannot open private key file\n";
        return 0;
        }

    EVP_PKEY* pubk = PEM_read_PUBKEY(pubk_file, NULL, NULL, NULL);
    if(!pubk){
        cerr << "Error: PEM_read_PUBKEY returns NULL\n";
        return 0;
        }

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, pubk);
    long pubkey_size = BIO_get_mem_data(mbio, pubkey_buf);

    return pubkey_size;
}
