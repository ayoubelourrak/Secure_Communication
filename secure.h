#ifndef FUNCTIONS_CRYPTO_INCLUDED
#define FUNCTIONS_CRYPTO_INCLUDED
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>
#include "util.h"
#include "constant.h"
#include <openssl/err.h>

using uchar=unsigned char;
using namespace std;

/**
 *  authenticated encryption decrypt
 *
 *   ciphertext input
 *   ciphertext_len input
 *   aad input
 *   aad_len input
 *   key input
 *   tag input
 *   iv input
 *   plaintext output
 *  return plaintext lenght, 0 on error
 */
int auth_enc_decrypt(uchar *ciphertext, uint ciphertext_len, uchar* aad, uint aad_len, uchar *key, uchar* tag,
                    uchar *iv,  uchar **plaintext);


/**
 *  authenticated encryption encrypt
 *
 *   plaintext input
 *   plaintext_len input
 *   aad input
 *   aad_len input
 *   key input
 *   tag ouput
 *   iv output
 *   ciphertext output
 *  return ciphertext lenght, 0 on error
 */
int auth_enc_encrypt( uchar *plaintext, int plaintext_len, uchar* aad, uint aad_len, uchar *key, uchar** tag,
                    uchar **iv,  uchar **ciphertext);

/**
 *  compare 2 digests
 *
 *   digest_a
 *   digest_b
 *   len lenght of digests
 *  return  0 if equals, 1 if differents
 */
uint digest_compare(const uchar* digest_a, const uchar* digest_b, const uint len);

/**
 *  compute a digest with the default cypher
 *
 *   plaintext input
 *   plaintext_len input
 *   chipertext output
 *  return digest lenght, 0 on error(s)
 */
uint digest_default(uchar* plaintext, uint plaintext_len, uchar** chipertext);

/**
 *  serialize a certificate
 *
 *   cert_file input
 *   certificate output
 *  return lenght of the buffer, 0 on error(s)
 */
int serialize_certificate(FILE* cert_file, uchar** certificate);

/**
 *  verify a signature on a document using the public key of the signer (passed in a buffer)
 *
 *   signature input
 *   signature_len input
 *   document input
 *   document_len input
 *   pubkey input
 *   key_len input
 *  return 1 if succesfully, 0 otherwise
 */
int verify_pubkey_sign(uchar* signature, uint signature_len, uchar* document, uint document_len, uchar* pubkey, uint key_len);

/**
 *  verify a signature on a docuemnt using the public key of the signer (passed as a PEM file)
 *
 *   signature input
 *   signature_len input
 *   document input
 *   document_len input
 *   pubkey input
 *  return int
 */
int verify_pubkey_sign(uchar* signature, uint signature_len, uchar* document, uint document_len,
    FILE*pubkey);

/**
 *  verify a signature on a docuemnt using a certificate, signed by a certification authority
 *
 *   certificate input certificate of the signer
 *   certificate_len input lenght of the certificate of the signer
 *   CAcertificate input certificate of the CA (PEM)
 *   CACtrl input (PEM)
 *   signature input
 *   signature_len input
 *   document input
 *   document_len input
 *  return 1 if succesfully, 0 otherwise
 */
int verify_cert_sign(const uchar* certificate, const uint certificate_len,  FILE* const CAcertificate,
    FILE* const CAcrl, uchar* signature, uint signature_len, uchar* document, uint document_len );

/**
 *  sign a document with a priv_key
 *
 *   document innput
 *   document_len input
 *   priv_key input private key file
 *   password password for private_key file, if NULL and needed it will be asked by terminal input
 *   signature output
 *   signature_len output
 *  return 1 if successful, 0 otherwise
 */
int sign_document( const uchar* document, uint document_len, FILE* const priv_key,char* const password,uchar** signature, uint* signature_len);

/**
 *  sign a document with a priv_key
 *
 *   document innput
 *   document_len input
 *   priv_key input
 *   signature output
 *   signature_len output
 *  return 1 if successful, 0 otherwise
 */
int sign_document( const uchar* document, uint document_len, void* priv_key,uchar** signature, uint* signature_len);
/**
 *  generate a random sequence
 *
 *   lenght number of random bytes
 *   nonce output buffer (ha to be preallocated)
 *  return 1 on succes, 0 otherwise
 */
int gen_random(const uint lenght, uchar* nonce);

/**
 *  generate a pair of DH ephimeral key for key establishemnt
 *
 *   privkey output (NO SERIALIZED)
 *   pubkey output (serialized)
 *   pubkey_len
 *  return 1 on succes, 0 otherwise
 */
int gen_eph_key(void** privkey, uchar** pubkey, uint* pubkey_len );

/**
 *  derive the shared seceret from a pair fo DH keys
 *
 *   privkey input (NO SERIALIZED)
 *   peer_key input (serialized)
 *   peer_key_len input
 *   secret output shred secret
 *  return shared secret lenght, 0 on error(s)
 */
uint derive_secret(void* privkey, uchar* peer_key, uint peer_key_len , uchar** secret );

/**
 *  dellocate an UNSERIALIZED private key in a secure way
 *
 *   key pointer to the key to deallocate
 */
void safe_free_key(void* key);

/**
 *  dellocate a buffer (containing a SERIALIZED key for example) in a secure way
 *
 *   buffer the buffer to deallocate
 *   buffer_len lenght of the buffer
 */
void safe_free(uchar* buffer, uint buffer_len );

/**
 *  read a private key from a file
 *
 *   privk_file file containing the private key
 *   password password for private_key file, if NULL and needed it will be asked by terminal input
 *  return pointer to the UNSERIALIZED private key, musat be freed by safe_free_key()
 */
void* read_privkey(FILE* privk_file, char* const password);

/**
 *  read a public key from a file
 *
 *   pubk_file file containing the public key
 *  return size of serialized pubkey, 0 in case of errors
 */
int serialize_pubkey_from_file(FILE* pubk_file, uchar** pubkey_buf);
#endif
