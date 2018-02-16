#ifndef LUKSD_H
#define LUKSD_H

#define LUKSD_SOCKET_FILE_PATH "/run/luksd.sock"

typedef struct {
  int socket;
  struct {
    char *user;
    char *group;
    char *socket_file;
  } config;
} luksd_mgr_t;

void luksd_handle_requests(luksd_mgr_t *luksd);
int luksd_parse_args(luksd_mgr_t *luksd, int argc, char *argv[]);
void luksd_usage(void);

#endif
