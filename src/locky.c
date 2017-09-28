#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

#include <openssl/pem.h>

typedef struct locky_peer_t locky_peer_t;

struct locky_peer_t {
  char addr[NI_MAXHOST];
  char port[NI_MAXSERV];
  locky_peer_t *next;
};

typedef struct {
  int socket;
  locky_peer_t *peers;
  EC_KEY *pubKey;
} locky_connection_t;

enum {
  _LOCKY_REQ_METHOD_AUTH = 31
};
const int SOCKET_QUEUE = 128;

locky_peer_t *registerPeer(locky_connection_t *locky, locky_peer_t peer);

void authPeer(locky_connection_t *locky, locky_peer_t *peer, char *payload) {
  printf("do payload signature verification");
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
      _LOCKY_REQ_METHOD_AUTH: authPeer(locky, p, payload); break;
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

  locky->pubKey = EVP_PKEY_get0_EC_KEY(pubKey);
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

      if(!(locky.socket < 0)) {
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
  }

  return 0;
}
