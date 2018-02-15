#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <linux/random.h>

#include "rluksd.h"
#include "rluksd_crypt.h"
#include "rluksd_luksd.h"
#include "rluksd_net.h"

int main(int argc, char *argv[])
{
  rluksd_mgr_t rluksd;
  int parse_arg;
  int running = 1;

  memset(&rluksd, 0, sizeof(rluksd_mgr_t));
  parse_arg = rluksd_parse_args(&rluksd, argc, argv);

  switch(parse_arg) {
    case 1:
      rluksd_usage();
      return 0;
    case 2:
      rluksd_usage();
      return 1;
  }

  rluksd.pubkey = rluksd_crypt_read_pubkey(rluksd.config.pubkey_file);
  if(!rluksd.pubkey)
  {
    fprintf(stderr, "cannot read public key file (%s)\n",
        rluksd.config.pubkey_file);
    return 2;
  }

  rluksd.socket.luksd = rluksd_luksd_connect(rluksd.config.socket_file);
  if(rluksd.socket.luksd < 0)
  {
    fprintf(stderr, "cannot connect to luksd on %s\n",
        rluksd.config.socket_file);
    return 3;
  }

  rluksd.socket.rluksd = rluksd_net_listen(RLUKSD_NET_PORT);
  if(rluksd.socket.rluksd < 0)
  {
    fprintf(stderr, "cannot open port %s\n",
        RLUKSD_NET_PORT);
    return 4;
  }

  while(running)
    rluksd_handle_requests(&rluksd);

  return 0;
}

void rluksd_handle_req_auth(rluksd_mgr_t *rluksd, rluksd_message_t *msg)
{
  rluksd_peer_t *peer = NULL;
  rluksd_message_t response;

  memset(&response, 0, sizeof(rluksd_message_t));

  if(msg->message && msg->signature)
  {
    if(rluksd_verify_nonce(rluksd, msg) == 0 &&
        rluksd_crypt_verify_signature(rluksd, msg) == 0)
    {
      peer = rluksd_register_peer(rluksd, &msg->peer);

      if(peer)
      {
        response.message = peer->cipher;
        response.message_l = RLUKSD_CRYPT_SYM_KEY_SIZE;
        rluksd_send_asym(rluksd, peer, &response);
      }
    }
  }
}

void rluksd_handle_requests(rluksd_mgr_t *rluksd)
{
  rluksd_message_t msg;

  memset(&msg, 0, sizeof(msg));
  rluksd_net_handle_requests(rluksd, &msg);

  switch(msg.method)
  {
    case RLUKSD_NET_REQ_METHOD_AUTH:
      rluksd_handle_req_auth(rluksd, &msg);
      break;
  }
}

int rluksd_parse_args(rluksd_mgr_t *rluksd, int argc, char *argv[])
{
  if(argc == 2 || argc == 3)
  {
    if(strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0)
      return 1;

    rluksd->config.pubkey_file = argv[1];
    rluksd->config.socket_file = (argc == 3) ? argv[2] : NULL;

    return 0;
  }

  return 2;
}

rluksd_peer_t *rluksd_register_peer(rluksd_mgr_t *rluksd, rluksd_peer_t *peer)
{
  rluksd_peer_t *ptr = rluksd->peers;
  rluksd_peer_t *new;

  while(ptr)
  {
    if(strcmp(peer->addr, ptr->addr) == 0 &&
        strcmp(peer->port, ptr->port) == 0)
    {
      syscall(SYS_getrandom, &ptr->cipher, RLUKSD_CRYPT_SYM_KEY_SIZE, GRND_NONBLOCK);
      return ptr;
    }

    ptr = ptr->next;
  }

  new = malloc(sizeof(rluksd_peer_t));
  if(!new)
    return NULL;

  memset(new, 0, sizeof(rluksd_peer_t));
  strcpy(new->addr, peer->addr);
  strcpy(new->addr, peer->addr);
  syscall(SYS_getrandom, &new->cipher, RLUKSD_CRYPT_SYM_KEY_SIZE, GRND_NONBLOCK);

  if(rluksd->peers)
    new->next = rluksd->peers;

  rluksd->peers = new;

  return new;
}

void rluksd_send_asym(rluksd_mgr_t *rluksd, rluksd_peer_t *peer, rluksd_message_t *data)
{
  rluksd_message_t crypt;

  memset(&crypt, 0, sizeof(rluksd_message_t));
  rluksd_crypt_encrypt_asym(rluksd->pubkey, &crypt, data);

  if(crypt.message_l > 0)
  {
    rluksd_net_send(rluksd->socket.rluksd, peer, &crypt);
  }
}

void rluksd_usage(void)
{
  fprintf(stdout, "USAGE: rluksd <pubkey> [<socket>]\n\n");
  fprintf(stdout, " -h|--help\tprints usage page\n");
  fprintf(stdout, " <pubkey>\tpath to the public key\n");
  fprintf(stdout, " <socket>\tpath to the luksd socket file (optional)\n");
  fprintf(stdout, "\t\tdefault: /run/luksd.sock\n");
}

int rluksd_verify_nonce(rluksd_mgr_t *rluksd, rluksd_message_t *msg)
{
  rluksd_nonce_t *nonce = rluksd->nonce;
  rluksd_nonce_t *new;

  while(nonce)
  {
    if(memcmp(nonce->nonce, msg->message, msg->message_l) == 0)
      return -1;

    nonce = nonce->next;
  }

  new = malloc(msg->message_l);
  if(!new)
    return -1;

  memset(new, 0, msg->message_l);
  memcpy(new->nonce, msg->message, msg->message_l);
  new->nonce_l = msg->message_l;

  if(rluksd->nonce)
    new->next = rluksd->nonce;

  rluksd->nonce = new;

  return 0;
}
