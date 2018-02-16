#include <stdio.h>
#include <string.h>

#include "luksd.h"
#include "luksd_socket.h"

void luksd_handle_requests(luksd_mgr_t *luksd)
{
  // do something
}

int luksd_parse_args(luksd_mgr_t *luksd, int argc, char *argv[])
{
  if(argc >= 2 || argc <= 4)
  {
    if(strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0)
      return 1;

    if(argc >= 3)
    {
      luksd->config.user = argv[1];
      luksd->config.group = argv[2];

      luksd->config.socket_file = (argc == 4) ? argv[3] : NULL;

      return 0;
    }
  }

  return 2;
}

void luksd_usage(void)
{
  fprintf(stdout, "USAGE: luksd <user> <group> [<socket>]\n");
  fprintf(stdout, " -h|--help\tprints usage page\n");
  fprintf(stdout, " <user>\tsocket file owner\n");
  fprintf(stdout, " <group>\tsocket file group\n");
  fprintf(stdout, " <socket>\tpath to socket file (optional)\n");
  fprintf(stdout, "\t\tdefault: /run/luksd.sock\n");
}

int main(int argc, char *argv[])
{
  luksd_mgr_t luksd;
  int parse_args;
  int running = 1;

  memset(&luksd, 0, sizeof(luksd_mgr_t));
  parse_args = luksd_parse_args(&luksd, argc, argv);

  switch(parse_args)
  {
    case 1:
      luksd_usage();
      return 0;
    case 2:
      luksd_usage();
      return 1;
  }

  luksd.socket = luksd_socket_listen(
    luksd.config.user,
    luksd.config.group,
    luksd.config.socket_file);

  if(luksd.socket <= 0)
  {
    fprintf(stderr, "cannot listen on socket file\n");
    return 1;
  }

  while(running)
    luksd_handle_requests(&luksd);

  return 0;
}
