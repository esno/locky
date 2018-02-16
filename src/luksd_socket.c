#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "luksd.h"
#include "luksd_socket.h"

void luksd_socket_handle_requests(luksd_mgr_t *luksd, luksd_message_t *msg)
{
  int fd = -1;
  luksd_peer_t peer;

  memset(&peer, 0, sizeof(luksd_peer_t));
  fd = accept(
    luksd->socket,
    (struct sockaddr *) &peer.addr,
    &peer.addrlen);

  if(fd > 0)
  {
    luksd_socket_parse_method(fd, msg);

    switch(msg->method)
    {
      case LUKSD_SOCKET_REQ_METHOD_STATUS:
        luksd_socket_parse_status(msg);
        break;
    }
  }
}

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

void luksd_socket_parse_method(int socket, luksd_message_t *msg)
{
  unsigned char chunk;
  int n = 0;

  memset(&chunk, 0, sizeof(chunk));
  n = recv(socket, &chunk, sizeof(chunk), 0);

  if(n == sizeof(chunk))
  {
    msg->method = chunk;
    msg->socket = socket;
  }
}

void luksd_socket_parse_status(luksd_message_t *msg)
{
  unsigned char chunk_l[LUKSD_SOCKET_HEADER_LENGTH_SIZE];
  unsigned char chunk[LUKSD_SOCKET_PAYLOAD_SIZE];
  uint16_t message_l = 0;
  int n = 0;

  memset(&chunk_l, 0, sizeof(chunk_l));
  memset(&chunk, 0, sizeof(chunk));

  n = recv(msg->socket, chunk_l, sizeof(chunk_l), 0);
  if(n == LUKSD_SOCKET_HEADER_LENGTH_SIZE)
  {
    memcpy(&message_l, chunk_l, sizeof(uint16_t));

    if(message_l <= LUKSD_SOCKET_PAYLOAD_SIZE)
    {
      n = recv(msg->socket, &chunk, message_l, 0);
      if(n == message_l)
      {
        msg->message = malloc(message_l);

	if(msg->message)
        {
	  memcpy(msg->message, &chunk, message_l);
	  msg->message_l = message_l;
	}
      }
    }
  }
}
