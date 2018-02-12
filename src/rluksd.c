#include <stdio.h>
#include <string.h>

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
  if(msg->message && msg->signature)
  {
    if(rluksd_crypt_verify_signature(msg) == 0)
    {
      rluksd_register_peer(rluksd, &msg->peer);
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

void rluksd_register_peer(rluksd_mgr_t *rluksd, rluksd_peer_t *peer)
{
  // do something
}

void rluksd_usage(void)
{
  fprintf(stdout, "USAGE: rluksd <pubkey> [<socket>]\n\n");
  fprintf(stdout, " -h|--help\tprints usage page\n");
  fprintf(stdout, " <pubkey>\tpath to the public key\n");
  fprintf(stdout, " <socket>\tpath to the luksd socket file (optional)\n");
  fprintf(stdout, "\t\tdefault: /run/luksd.sock\n");
}
