#ifndef LUKS_H
#define LUKS_H

typedef struct {
  struct {
    char *path;
    char *name;
    char *target;
  } config;
} luks_mgr_t;

int luks_parse_args(luks_mgr_t *luks, int argc, char *argv[]);
int luks_request_status(luks_mgr_t *luks);
void luks_usage(void);

#endif
