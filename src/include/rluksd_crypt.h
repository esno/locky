#ifndef RLUKSD_CRYPT_H
#define RLUKSD_CRYPT_H

#include <openssl/evp.h>

#include "rluksd.h"

EVP_PKEY *rluksd_crypt_read_pubkey(char *pubkey_file);
int rluksd_crypt_verify_signature(rluksd_message_t *msg);

#endif
