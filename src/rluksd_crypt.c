#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "rluksd_crypt.h"

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

int rluksd_crypt_verify_signature(rluksd_message_t *msg)
{
  // do something
}
