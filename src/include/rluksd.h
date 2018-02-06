#ifndef RLUKSD_H
#define RLUKSD_H

#include <netdb.h>
#include <openssl/evp.h>

#define RLUKSD_SYM_KEY_SIZE 32
#define RLUKSD_NET_PORT "23420"

typedef struct rluksd_peer_t rluksd_peer_t;

struct rluksd_peer_t {
  char addr[NI_MAXHOST];
  char port[NI_MAXSERV];
  char cipher[RLUKSD_SYM_KEY_SIZE];
  rluksd_peer_t *next;
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
} rluksd_mgr_t;

typedef struct {
  unsigned char *chunk;
  size_t size;
} rluksd_message_t;

enum {
  RLUKSD_ENUM_REQ_METHOD_AUTH = 0x1,
  RLUKSD_ENUM_REQ_METHOD_STATUS,
  RLUKSD_ENUM_REQ_METHOD_UNLOCK,
  RLUKSD_ENUM_REQ_METHOD_LOCK,
};

int rluksd_listen(char *port);
int rluksd_parse_args(rluksd_mgr_t *rluksd, int argc, char *argv[]);
void rluksd_run(rluksd_mgr_t *rluksd);
void rluksd_usage(void);

#endif
