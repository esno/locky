#include <stdio.h>
#include <string.h>

#include "luks.h"

int luks_parse_args(luks_mgr_t *luks, int argc, char *argv[])
{
  if(argc >= 2)
  {
    if(strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0)
      return 1;

    if(strcmp(argv[1], "status") == 0 &&
        argc >= 4)
    {
      luks->config.path = argv[2];
      luks->config.name = argv[3];

      if(argc == 5)
        luks->config.target = argv[4];

      return 2;
    }
  }

  return -1;
}

int luks_request_status(luks_mgr_t *luks)
{
  return 0;
}

void luks_usage(void)
{
  fprintf(stdout, "USAGE: luks <mode> <path> <name> [<target>]\n\n");
  fprintf(stdout, " -h|--help\tprints usage page\n");
  fprintf(stdout, " <mode>\t\tthe form of request that should be done\n");
  fprintf(stdout, " <path>\t\tthe path to luks container device\n");
  fprintf(stdout, " <name>\t\tthe name of the device for device mapper\n");
  fprintf(stdout, " <target>\tpath to the luksd socket file or ip address of rluksd host\n");
  fprintf(stdout, "\t\tdefault: /run/luksd.sock\n");
  fprintf(stdout, "\nMODES\n\n");
  fprintf(stdout, " status\t\tshow the state of requested luks container\n");
}

int main(int argc, char *argv[])
{
  luks_mgr_t luks;
  int parse_args;

  memset(&luks, 0, sizeof(luks_mgr_t));
  parse_args = luks_parse_args(&luks, argc, argv);

  switch(parse_args)
  {
    case -1:
      luks_usage();
      return 1;
    case 1:
      luks_usage();
      return 0;
    case 2:
      return luks_request_status(&luks);
      break;
  }

  return 0;
}
