#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "rluksd_luksd.h"

int rluksd_luksd_connect(char *socket_file)
{
  struct sockaddr_un addr;
  int fd = -1, rc;

  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;

  if(!socket_file)
    strcpy(addr.sun_path, "/run/luksd.sock");
  else
    strcpy(addr.sun_path, socket_file);

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if(fd < 0)
    return fd;

  rc = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
  if(rc == 0)
    return 0;

  close(fd);
  return -1;
}
