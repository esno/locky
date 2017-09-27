#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct locky_peer_t locky_peer_t;

struct locky_peer_t {
  char addr[NI_MAXHOST];
  char port[NI_MAXSERV];
  locky_peer_t *next;
};

typedef struct {
  int socket;
  locky_peer_t *peers;
} locky_connection_t;

enum {
  _LOCKY_REQ_METHOD_AUTH = 31
};
const int SOCKET_QUEUE = 128;

locky_peer_t *registerPeer(locky_connection_t *locky, locky_peer_t peer);

void connLoop(locky_connection_t *locky) {
  int n;
  struct sockaddr_storage client;
  socklen_t addrlen = sizeof(client);
  char buffer[1024];
  locky_peer_t peer;
  locky_peer_t *p;
 
  while(1) {
    n = recvfrom(
      locky->socket,
      buffer, sizeof(buffer),
      0,
      (struct sockaddr *) &client,
      &addrlen);

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
  }
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
