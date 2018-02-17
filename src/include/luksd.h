#ifndef LUKSD_H
#define LUKSD_H

#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <libcryptsetup.h>

#define LUKSD_SOCKET_FILE_PATH "/run/luksd.sock"
#define LUKSD_SOCKET_HEADER_LENGTH_SIZE 2
#define LUKSD_SOCKET_PAYLOAD_SIZE 1024

enum {
  LUKSD_SOCKET_REQ_METHOD_STATUS = 0x02,
  LUKSD_SOCKET_REQ_METHOD_UNLOCK,
  LUKSD_SOCKET_REQ_METHOD_LOCK
};

typedef struct {
  struct crypt_device *ctx;
  unsigned char *name;
  uint16_t name_l;
  unsigned char *path;
  uint16_t path_l;
  unsigned char uuid[36];
  crypt_status_info status;
} luksd_device_t;

typedef struct {
  unsigned char *name;
  uint16_t name_l;
  unsigned char *path;
  uint16_t path_l;
  int socket;
  unsigned char method;
} luksd_message_t;

typedef struct {
  int socket;
  struct {
    char *user;
    char *group;
    char *socket_file;
  } config;
} luksd_mgr_t;

typedef struct {
  struct sockaddr_un addr;
  socklen_t addrlen;
} luksd_peer_t;

void luksd_handle_req_status(luksd_mgr_t *luksd, luksd_message_t *msg);
void luksd_handle_requests(luksd_mgr_t *luksd);
int luksd_parse_args(luksd_mgr_t *luksd, int argc, char *argv[]);
void luksd_usage(void);

#endif
