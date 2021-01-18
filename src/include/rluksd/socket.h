#ifndef _RLUKSD_SOCKET_H
#define _RLUKSD_SOCKET_H 1

#define RLUKSD_SOCKET_FILE "/run/rluksd/luksd.sock"

typedef struct rluksd_socket rluksd_socket_t;
struct rluksd_socket {
  int fd;
  rluksd_socket_t *next;
  rluksd_socket_t *prev;
};

int rluksd_socket_create(const char *owner, const char *group, const char *filename);

#endif
