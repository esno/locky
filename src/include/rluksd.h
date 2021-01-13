#ifndef _RLUKSD_H
#define _RLUKSD_H 1

#include <sys/stat.h>

typedef struct rluksd_device rluksd_device_t;
struct rluksd_device {
  dev_t id;
  int major;
  int minor;
  struct {
    char *name;
    char *uuid;
  } luks;
  rluksd_device_t *next;
  rluksd_device_t *prev;
};

#endif
