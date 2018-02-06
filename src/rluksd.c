#include <stdio.h>
#include <string.h>

#include "rluksd.h"
#include "rluksd_crypt.h"
#include "rluksd_luksd.h"

int rluksd_listen(char *port)
{
  return 0;
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

void rluksd_run(rluksd_mgr_t *rluksd)
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

int main(int argc, char *argv[])
{
  rluksd_mgr_t rluksd;
  int parse_arg;

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

  rluksd.pubkey = rluksd_read_pubkey(rluksd.config.pubkey_file);
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

  rluksd.socket.rluksd = rluksd_listen(RLUKSD_NET_PORT);
  if(rluksd.socket.rluksd < 0)
  {
    fprintf(stderr, "cannot open port %s\n",
        RLUKSD_NET_PORT);
    return 4;
  }

  rluksd_run(&rluksd);

  return 0;
}
