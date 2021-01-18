#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "rluksd/socket.h"

typedef struct rluksd_socket_mgr rluksd_socket_mgr_t;
struct rluksd_socket_mgr {
  rluksd_socket_t *list;
};

static rluksd_socket_mgr_t __rluksd_socket = {
  .list = NULL
};

int rluksd_socket_create(const char *owner, const char *group, const char *filename) {
  struct passwd *pwd;
  struct group *grp;
  int sockfd;
  struct sockaddr_un addr;

  pwd = getpwnam(owner);
  grp = getgrnam(group);

  if (pwd == NULL || grp == NULL)
    return -1;

  memset(&addr, 0, sizeof(struct sockaddr_un));
  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

  if (sockfd < 0)
    return -2;

  addr.sun_family = AF_UNIX;
  if (filename == NULL)
    strcpy(addr.sun_path, RLUKSD_SOCKET_FILE);
  else
    strcpy(addr.sun_path, filename);

  unlink(addr.sun_path);

  if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
    close(sockfd);
    return -3;
  }

  chmod(addr.sun_path, 0660);
  chown(addr.sun_path, pwd->pw_uid, grp->gr_gid);

  if (listen(sockfd, 5) != 0) {
    close(sockfd);
    return -4;
  }

  return sockfd;
}
