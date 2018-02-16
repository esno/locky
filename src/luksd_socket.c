#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "luksd.h"
#include "luksd_socket.h"

int luksd_socket_listen(char *user, char *group, char *socket_file)
{
  struct passwd *pwd;
  struct group *grp;
  int sock;
  struct sockaddr_un addr;

  pwd = getpwnam(user);
  grp = getgrnam(group);

  if(pwd == NULL || grp == NULL)
    return -1;

  memset(&addr, 0, sizeof(struct sockaddr_un));
  sock = socket(AF_UNIX, SOCK_STREAM, 0);

  if(sock > 0)
  {
    addr.sun_family = AF_UNIX;

    if(socket_file == NULL)
      strcpy(addr.sun_path, LUKSD_SOCKET_FILE_PATH);
    else
      strcpy(addr.sun_path, socket_file);

    unlink(addr.sun_path);

    if(bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == 0)
    {
      chmod(addr.sun_path, 0660);
      chown(addr.sun_path, pwd->pw_uid, grp->gr_gid);

      if(listen(sock, 5) == 0)
        return sock;
    }

    close(sock);
  }

  return -1;
}
