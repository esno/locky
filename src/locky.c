#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syscall.h>
#include <linux/random.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

typedef struct locky_peer_t locky_peer_t;

struct locky_peer_t {
  char addr[NI_MAXHOST];
  char port[NI_MAXSERV];
  char cipher[256];
  locky_peer_t *next;
};

typedef struct {
  int socket;
  locky_peer_t *peers;
  EVP_PKEY *pubKey;
} locky_connection_t;

enum {
  _LOCKY_REQ_METHOD_AUTH = 31
};
const int _LOCKY_PKG_MSG_LENGTH_MAX = 256;
const int SOCKET_QUEUE = 128;

void methodAuth(locky_connection_t *locky, locky_peer_t *peer, char *data);
locky_peer_t *registerPeer(locky_connection_t *locky, locky_peer_t peer);
void sendData(locky_peer_t *peer, char *msg, size_t length);

bool authPeer(locky_connection_t *locky, locky_peer_t *peer, char *data) {
  char l[3], chipher[256];
  char *msg, *signature;
  int length;
  EVP_MD_CTX *ctx;
  const EVP_MD *md;

  strncpy(l, data, 2);
  l[3] = '\0';

  length = strtol(l, NULL, 10);
  if(length <= _LOCKY_PKG_MSG_LENGTH_MAX) {
    strncpy(msg, &data[2], length);
    strcpy(msg, &data[2 + length + 1]);

    ctx = EVP_MD_CTX_create();
    md = EVP_get_digestbyname("SHA256");
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestVerifyInit(ctx, NULL,
      md,
      NULL,
      locky->pubKey);
    EVP_DigestVerifyUpdate(ctx, msg, length);
    if(EVP_DigestVerifyFinal(ctx, signature, strlen(signature))) {
      syscall(SYS_getrandom, &peer->cipher, 256, GRND_NONBLOCK);
      return true;
    }
  }

  return false;
}

void connLoop(locky_connection_t *locky) {
  struct sockaddr_storage client;
  socklen_t addrlen = sizeof(client);
  char buffer[1024];
  char *payload;
  locky_peer_t peer;
  locky_peer_t *p;
  int n;
 
  while(1) {
    n = recvfrom(
      locky->socket,
      buffer, sizeof(buffer),
      0,
      (struct sockaddr *) &client,
      &addrlen);
    payload = &(buffer[1]);

    if(n < 0)
      continue;

    memset(peer.addr, 0, sizeof(peer.addr));
    memset(peer.port, 0, sizeof(peer.port));

    getnameinfo(
      (struct sockaddr *) &client,
      addrlen,
      peer.addr, sizeof(peer.addr),
      peer.port, sizeof(peer.port),
      NI_NUMERICHOST);

    printf("received request (0x%02x) from %s:%s (%d bytes)\n", buffer[0], peer.addr, peer.port, n);
    p = registerPeer(locky, peer);

    switch(buffer[0]) {
      _LOCKY_REQ_METHOD_AUTH: methodAuth(locky, p, payload); break;
    }
  }
}

size_t encryptAsym(EVP_PKEY *pubKey, unsigned char *cipher, char *data) {
  EVP_PKEY_CTX *ctx;
  ENGINE *eng;
  size_t i, o;

  eng = ENGINE_get_default_RSA();
  ctx = EVP_PKEY_CTX_new(pubKey, eng);
  if(ctx)
    if(EVP_PKEY_encrypt_init(ctx) > 0)
      if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0)
        if(EVP_PKEY_encrypt(ctx, NULL, &o, data, i) > 0) {
          cipher = OPENSSL_malloc(o);
          if(cipher)
            EVP_PKEY_encrypt(ctx, cipher, &o, data, i);
            return o;
        }
  return 0;
}

void methodAuth(locky_connection_t *locky, locky_peer_t *peer, char *data) {
  unsigned char *cipher;
  size_t length;

  if(authPeer(locky, peer, data)) {
    length = encryptAsym(locky->pubKey, cipher, peer->cipher);
    if(length > 0) {
      printf("send random key to %s:%s", peer->addr, peer->port);
      sendData(peer, cipher, length);
      OPENSSL_free(cipher);
    }
  }
}

bool readPubKey(locky_connection_t *locky, char *pubKeyFile) {
  FILE *fd;
  EVP_PKEY *pubKey;

  fd = fopen(pubKeyFile, "rb");
  if(!fd)
    return false;

  pubKey = PEM_read_PUBKEY(fd, NULL, NULL, NULL);
  if(!pubKey)
    return false;

  locky->pubKey = pubKey;
  return true;
}

locky_peer_t *registerPeer(locky_connection_t *locky, locky_peer_t peer) {
  locky_peer_t *ptr = locky->peers;
  locky_peer_t *new;

  while(ptr) {
    if(strcmp(ptr->addr, peer.addr) == 0 &&
        strcmp(ptr->port, peer.port) == 0) {
      return ptr;
    }
    ptr = ptr->next;
  }

  new = malloc(sizeof(locky_peer_t));
  strcpy(new->addr, peer.addr);
  strcpy(new->port, peer.port);
  new->next = locky->peers;
  locky->peers = new;
  printf("registered new peer %s:%s\n", locky->peers->addr, locky->peers->port);
  return new;
}

void sendData(locky_peer_t *peer, char *msg, size_t length) {
  struct addrinfo hints, *res;
  int n, fd;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  n = getaddrinfo(peer->addr, peer->port, &hints, &res);

  if(n >= 0) {
    fd = socket(
      res->ai_family,
      res->ai_socktype,
      res->ai_protocol);
    if(fd >= 0) {
      connect(fd, res->ai_addr, res->ai_addrlen);
      write(fd, msg, length);
      close(fd);
    }
  }
  freeaddrinfo(res);
}

int main() {
  struct addrinfo hints, *res, *resSave;
  int n;
  locky_connection_t locky;
  locky.peers = NULL;

  if(!readPubKey(&locky, "./keys/public.key.pem")) {
    printf("ERROR: cannot read public key ./keys/public.key.pem\n");
    return 1;
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  n = getaddrinfo("*", "23420", &hints, &res);

  if(n >= 0) {
    resSave = res;
    locky.socket = -1;
    while(res) {
      locky.socket = socket(
        res->ai_family,
        res->ai_socktype,
        res->ai_protocol);

      if(locky.socket >= 0) {
        if(bind(locky.socket, res->ai_addr, res->ai_addrlen) == 0)
          break;

        close(locky.socket);
        locky.socket = -1;
      }
      res = res->ai_next;
    }

    if(locky.socket >= 0) {
      listen(locky.socket, SOCKET_QUEUE);
      connLoop(&locky);
    }
    freeaddrinfo(resSave);
    close(locky.socket);
  }

  return 0;
}
