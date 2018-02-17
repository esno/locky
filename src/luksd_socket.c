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

void luksd_socket_free_msg(luksd_message_t *msg)
{
  if(msg->name) free(msg->name);
  if(msg->path) free(msg->path);
}

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
  unsigned char chunk_nl[LUKSD_SOCKET_HEADER_LENGTH_SIZE];
  unsigned char chunk_pl[LUKSD_SOCKET_HEADER_LENGTH_SIZE];
  unsigned char chunk_n[LUKSD_SOCKET_PAYLOAD_SIZE];
  unsigned char chunk_p[LUKSD_SOCKET_PAYLOAD_SIZE];
  uint16_t name_l = 0, path_l = 0;
  int n = 0, p = 0;

  memset(&chunk_nl, 0, sizeof(chunk_nl));
  memset(&chunk_pl, 0, sizeof(chunk_pl));
  memset(&chunk_n, 0, sizeof(chunk_n));
  memset(&chunk_p, 0, sizeof(chunk_p));

  n = recv(msg->socket, chunk_nl, sizeof(chunk_nl), 0);
  p = recv(msg->socket, chunk_pl, sizeof(chunk_pl), 0);

  if(n == LUKSD_SOCKET_HEADER_LENGTH_SIZE &&
    p == LUKSD_SOCKET_HEADER_LENGTH_SIZE)
  {
    memcpy(&name_l, chunk_nl, sizeof(uint16_t));
    memcpy(&path_l, chunk_pl, sizeof(uint16_t));

    if(name_l <= LUKSD_SOCKET_PAYLOAD_SIZE &&
      path_l <= LUKSD_SOCKET_PAYLOAD_SIZE)
    {
      n = recv(msg->socket, &chunk_n, name_l, 0);
      p = recv(msg->socket, &chunk_p, path_l, 0);
      if(n == name_l && p == path_l)
      {
        msg->name = malloc(name_l);
        msg->path = malloc(path_l);

	if(msg->name)
        {
	  memcpy(msg->name, &chunk_n, name_l);
	  msg->name_l = name_l;
	}

	if(msg->path)
        {
	  memcpy(msg->path, &chunk_p, path_l);
	  msg->path_l = path_l;
	}
      }
    }
  }
}

void luksd_socket_send_status(int socket, luksd_device_t *device)
{
  unsigned char *chunk;
  int size = 1, offset = 0;

  size += sizeof(uint16_t) + device->name_l;
  size += sizeof(uint16_t) + device->path_l;
  size += sizeof(device->status);

  chunk = malloc(size);

  if(chunk)
  {
    chunk[0] = LUKSD_SOCKET_REQ_METHOD_STATUS;
    memcpy(&chunk[1], &device->name_l, sizeof(uint16_t));
    memcpy(&chunk[3], &device->path_l, sizeof(uint16_t));
    memcpy(&chunk[5], &device->status, sizeof(device->status));

    offset = 5 + sizeof(device->status);
    memcpy(&chunk[offset], &device->name, sizeof(device->name_l));
    offset += device->name_l;
    memcpy(&chunk[offset], &device->path, sizeof(device->path_l));

    send(socket, chunk, size, 0);
    free(chunk);
  }
}
