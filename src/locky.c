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

typedef struct {
  unsigned char *data;
  size_t size;
} locky_message_t;

enum {
  _LOCKY_REQ_METHOD_AUTH = 0x31,
  _LOCKY_REQ_METHOD_UNLOCK
};
const int _LOCKY_PKG_MSG_LENGTH_MAX = 256;
const int SOCKET_QUEUE = 128;

void methodAuth(locky_connection_t *locky, locky_peer_t *peer, locky_message_t *data);
void methodUnlock(locky_connection_t *locky, locky_peer_t *peer, locky_message_t *data);
locky_peer_t *registerPeer(locky_connection_t *locky, locky_peer_t peer);
void sendData(locky_peer_t *peer, locky_message_t *msg);

bool authPeer(locky_connection_t *locky, locky_peer_t *peer, locky_message_t *plaintext, locky_message_t *signature) {
  EVP_MD_CTX *ctx;
  const EVP_MD *md;

  ctx = EVP_MD_CTX_create();
  md = EVP_get_digestbyname("SHA256");
  EVP_DigestInit_ex(ctx, md, NULL);
  EVP_DigestVerifyInit(ctx, NULL,
    md, NULL,
    locky->pubKey);
  EVP_DigestVerifyUpdate(ctx,
    plaintext->data, plaintext->size);
  if(EVP_DigestVerifyFinal(ctx, signature->data, signature->size)) {
    syscall(SYS_getrandom, &peer->cipher, 256, GRND_NONBLOCK);
    printf("authenticated peer %s:%s\n", peer->addr, peer->port);
    return true;
  }

  printf("failed to verify message signature from %s:%s\n", peer->addr, peer->port);
  return false;
}

void connLoop(locky_connection_t *locky) {
  struct sockaddr_storage client;
  socklen_t addrlen = sizeof(client);
  char buffer[1024];
  locky_message_t payload;
  locky_peer_t peer;
  locky_peer_t *p;
  int method = 0;
 
  while(1) {
    payload.size = recvfrom(
      locky->socket,
      buffer, sizeof(buffer),
      0,
      (struct sockaddr *) &client,
      &addrlen);

    if(payload.size < 2)
      continue;

    method = (int) buffer[0];
    payload.size -= 1 * sizeof(char);
    payload.data = &buffer[1];

    memset(peer.addr, 0, sizeof(peer.addr));
    memset(peer.port, 0, sizeof(peer.port));

    getnameinfo(
      (struct sockaddr *) &client,
      addrlen,
      peer.addr, sizeof(peer.addr),
      peer.port, sizeof(peer.port),
      NI_NUMERICHOST);

    printf("received request (0x%02x) from %s:%s (%d bytes)\n", method, peer.addr, peer.port, payload.size);
    p = registerPeer(locky, peer);

    switch(method) {
      case _LOCKY_REQ_METHOD_AUTH: methodAuth(locky, p, &payload); break;
      case _LOCKY_REQ_METHOD_UNLOCK: methodUnlock(locky, p, &payload); break;
      default: printf("request (0x%02x) not impemented...\n", method);
    }
  }
}

size_t decryptSym(locky_peer_t *peer, unsigned char *plain, char *cipher, char *iv) {
  EVP_CIPHER_CTX *ctx;
  int length = strlen(cipher);
  int l;

  ctx = EVP_CIPHER_CTX_new();
  if(ctx)
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, peer->cipher, iv))
      if(EVP_DecryptUpdate(ctx, plain, &length, cipher, length)) {
        plain = OPENSSL_malloc(length);
        EVP_DecryptFinal_ex(ctx, plain + length, &l);
        return l;
      }

  return 0;
}

void encryptAsym(EVP_PKEY *pubKey, locky_message_t *crypt, char *data) {
  EVP_PKEY_CTX *ctx;
  ENGINE *eng;
  size_t i, o;

  eng = ENGINE_get_default_RSA();
  ctx = EVP_PKEY_CTX_new(pubKey, eng);
  if(ctx)
    if(EVP_PKEY_encrypt_init(ctx) > 0)
      if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0)
        if(EVP_PKEY_encrypt(ctx, NULL, &o, data, i) > 0) {
          crypt->size = o;
          crypt->data = OPENSSL_malloc(crypt->size);
          if(crypt->data) {
            EVP_PKEY_encrypt(ctx, crypt->data, &crypt->size, data, i);
          }
        }
}

void methodAuth(locky_connection_t *locky, locky_peer_t *peer, locky_message_t *data) {
  locky_message_t plaintext, signature, crypt;
  int s = 0;

  s |= (data->data[0] << (sizeof(char) * 8));
  s |= (data->data[1]);
  plaintext.size = s;
  signature.size = data->size - plaintext.size - (sizeof(char) *2);

  printf("deserialize auth message (size: %d/%d/%d)\n", plaintext.size, signature.size, data->size);
  if(plaintext.size <= ((data->size - 2) / 2)) {
    char pt[plaintext.size];
    char sig[signature.size];
    memcpy(pt, &data->data[2], plaintext.size);
    memcpy(sig, &data->data[2 + plaintext.size], signature.size);
    plaintext.data = pt;
    signature.data = sig;

    if(authPeer(locky, peer, &plaintext, &signature)) {
      encryptAsym(locky->pubKey, &crypt, peer->cipher);

      if(crypt.size > 0) {
        sendData(peer, &crypt);
        OPENSSL_free(crypt.data);
      }
    }
  }
}

void methodUnlock(locky_connection_t *locky, locky_peer_t *peer, locky_message_t *data) {
  unsigned char *cipher, *plain;
  char iv[16];

  /*
  strncpy(iv, data, 16);
  cipher = &data[16];
  decryptSym(peer, plain, cipher, iv);
  printf("received key %s\n", plain);
  */
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

void sendData(locky_peer_t *peer, locky_message_t *msg) {
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
      write(fd, msg->data, msg->size);
      close(fd);
      printf("sent random key to %s:%s\n", peer->addr, peer->port);
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
