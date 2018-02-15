#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#include "rluksd_crypt.h"

void rluksd_crypt_encrypt_asym(EVP_PKEY *pubkey, rluksd_message_t *crypt, rluksd_message_t *data)
{
  EVP_PKEY_CTX *ctx;
  ENGINE *eng;
  size_t o;

  eng = ENGINE_get_default_RSA();
  ctx = EVP_PKEY_CTX_new(pubkey, eng);

  if(ctx &&
      EVP_PKEY_encrypt_init(ctx) > 0 &&
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
      EVP_PKEY_encrypt(ctx, NULL, &o, data->message, data->message_l) > 0)
  {
    crypt->message_l = o;
    crypt->message = OPENSSL_malloc(crypt->message_l);

    if(crypt->message)
      EVP_PKEY_encrypt(ctx, crypt->message, &o, data->message, data->message_l);
    else
      crypt->message_l = 0;
  }
}

EVP_PKEY *rluksd_crypt_read_pubkey(char *pubkey_file)
{
  struct stat pubkey;
  FILE *fd;
  EVP_PKEY *pkey = NULL;

  if(stat(pubkey_file, &pubkey) != 0)
    return NULL;

  fd = fopen(pubkey_file, "rb");
  if(!fd)
    return NULL;

  pkey = PEM_read_PUBKEY(fd, NULL, NULL, NULL);
  fclose(fd);
  if(!pkey)
    return NULL;

  return pkey;
}

int rluksd_crypt_verify_signature(rluksd_mgr_t *rluksd, rluksd_message_t *msg)
{
  EVP_MD_CTX *ctx;
  const EVP_MD *md;

  ctx = EVP_MD_CTX_create();
  md = EVP_get_digestbyname("sha256");
  EVP_DigestInit_ex(ctx, md, NULL);
  EVP_DigestUpdate(ctx, msg->message, msg->message_l);

  if(EVP_VerifyFinal(ctx, msg->signature, msg->signature_l, rluksd->pubkey) == 1)
    return 0;

  return -1;
}
