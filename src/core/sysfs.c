#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "rluksd.h"

#define __RLUKSD_SYSFS_DEV_BLK_PATH "/sys/dev/block"

int rluksd_sysfs_scan(void) {
  DIR *d;
  struct dirent *entry;
  rluksd_device_t device;

  d = opendir(__RLUKSD_SYSFS_DEV_BLK_PATH);
  if (d == NULL) {
    fprintf(stderr, "[sysfs] not supported by your kernel\n");
    return -1;
  }

  while ((entry = readdir(d)) != NULL) {
    memset(&device, 0, sizeof(rluksd_device_t));
    if (sscanf(entry->d_name, "%d:%d", &device.major, &device.minor) != 2)
      continue;

    fprintf(stdout, "[sysfs] found device %d/%d\n", device.major, device.minor);
    device.id = makedev(device.major, device.minor);
  }

  closedir(d);

  return 0;
}
