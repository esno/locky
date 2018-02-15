#ifndef RLUKSD_CRYPT_H
#define RLUKSD_CRYPT_H

#include <openssl/evp.h>

#include "rluksd.h"

void rluksd_crypt_encrypt_asym(EVP_PKEY *pubkey, rluksd_message_t *crypt, rluksd_message_t *data);
EVP_PKEY *rluksd_crypt_read_pubkey(char *pubkey_file);
int rluksd_crypt_verify_signature(rluksd_mgr_t *rluksd, rluksd_message_t *msg);

#endif
