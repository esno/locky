#ifndef _RLUKSD_DEVICE_H
#define _RLUKSD_DEVICE_H 1

#include <sys/stat.h>

typedef struct rluksd_device rluksd_device_t;
struct rluksd_device {
  dev_t id;
  unsigned int major;
  unsigned int minor;
  struct {
    char *name;
    char *uuid;
  } luks;
  char *parent;
  rluksd_device_t *next;
  rluksd_device_t *prev;
};

void rluksd_device_add(rluksd_device_t *device);
void rluksd_device_drop(rluksd_device_t *device);
void rluksd_device_free(rluksd_device_t *device);
void rluksd_device_free_all(void);

#endif
