#ifndef _RLUKSD_SYSFS_H
#define _RLUKSD_SYSFS_H 1

#include "rluksd.h"

int rluksd_sysfs_discover_devices(void);
int rluksd_sysfs_discover_parent(const char *name, rluksd_device_t *device);
int rluksd_sysfs_read_device_info(const char *name, rluksd_device_t *device);

#endif
