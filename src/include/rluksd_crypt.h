#ifndef RLUKSD_CRYPT_H
#define RLUKSD_CRYPT_H

#include <openssl/evp.h>

EVP_PKEY *rluksd_read_pubkey(char *pubkey_file);

#endif
