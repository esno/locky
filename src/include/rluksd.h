#ifndef RLUKSD_H
#define RLUKSD_H

#include <netdb.h>
#include <openssl/evp.h>

#define RLUKSD_NET_PORT "23420"
#define RLUKSD_NET_SOCKET_QUEUE 128
#define RLUKSD_NET_HEADER_METHOD_SIZE 1
#define RLUKSD_NET_HEADER_LENGTH_SIZE 2
#define RLUKSD_NET_PAYLOAD_SIZE 1024
#define RLUKSD_CRYPT_SYM_KEY_SIZE 32

enum {
  RLUKSD_NET_REQ_METHOD_AUTH = 0x01,
  RLUKSD_NET_REQ_METHOD_STATUS,
  RLUKSD_NET_REQ_METHOD_UNLOCK,
  RLUKSD_NET_REQ_METHOD_LOCK,
};

typedef struct rluksd_peer_t rluksd_peer_t;
typedef struct rluksd_nonce_t rluksd_nonce_t;

struct rluksd_peer_t {
  char addr[NI_MAXHOST];
  char port[NI_MAXSERV];
  char cipher[RLUKSD_CRYPT_SYM_KEY_SIZE];
  rluksd_peer_t *next;
};

typedef struct {
  unsigned char method;
  uint16_t message_l;
  uint16_t signature_l;
  uint16_t crypt_l;
  unsigned char *message;
  unsigned char *signature;
  unsigned char *iv;
  unsigned char *crypt;
  rluksd_peer_t peer;
} rluksd_message_t;

struct rluksd_nonce_t {
  unsigned char *nonce;
  uint16_t nonce_l;
  rluksd_nonce_t *next;
};

typedef struct {
  struct {
    int rluksd;
    int luksd;
  } socket;
  struct {
    char *socket_file;
    char *pubkey_file;
  } config;
  EVP_PKEY *pubkey;
  rluksd_peer_t *peers;
  rluksd_nonce_t *nonce;
} rluksd_mgr_t;

void rluksd_handle_req_auth(rluksd_mgr_t *rluksd, rluksd_message_t *msg);
void rluksd_handle_requests(rluksd_mgr_t *rluksd);
int rluksd_parse_args(rluksd_mgr_t *rluksd, int argc, char *argv[]);
void rluksd_register_peer(rluksd_mgr_t *rluksd, rluksd_peer_t *peer);
void rluksd_usage(void);
int rluksd_verify_nonce(rluksd_mgr_t *rluksd, rluksd_message_t *msg);

#endif
