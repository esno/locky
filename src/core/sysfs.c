#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "rluksd.h"
#include "rluksd/sysfs.h"

#define __RLUKSD_SYSFS_DEV_BLK_PATH "/sys/dev/block"

static char *__read_dm_uuid(const char *name);

static int __is_luks(const char *name) {
  char *dmuuid = __read_dm_uuid(name);

  if (dmuuid == NULL)
    return -1;

  if (strncmp(dmuuid, "CRYPT-LUKS2", 11) != 0) {
    free(dmuuid);
    return -2;
  }

  free(dmuuid);

  return 0;
}

static char *__read_dm_uuid(const char *name) {
  int l = strlen(__RLUKSD_SYSFS_DEV_BLK_PATH) + strlen(name) + 10;
  int c, size;
  char filename[l];
  char *dmuuid;
  FILE *fd;

  memset(filename, 0, sizeof(char) * l);
  snprintf(filename, l, "%s/%s/dm/uuid", __RLUKSD_SYSFS_DEV_BLK_PATH, name);
  fd = fopen(filename, "r");
  if (fd == NULL)
    return NULL;

  fseek(fd, 0L, SEEK_END);
  size = ftell(fd);
  rewind(fd);

  dmuuid = malloc(sizeof(char) * size);
  if (dmuuid == NULL)
    return NULL;

  if ((c = fread(dmuuid, 1, size, fd)) < 0) {
    free(dmuuid);
    fclose(fd);
    return NULL;
  }

  fclose(fd);
  dmuuid[c - 1] = '\0';

  return dmuuid;
}

int rluksd_sysfs_discover_devices(void) {
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

    fprintf(stdout, "[sysfs] found device %d:%d\n", device.major, device.minor);
    device.id = makedev(device.major, device.minor);

    if (__is_luks(entry->d_name) == 0) {
      if (rluksd_sysfs_read_device_info(entry->d_name, &device) == 0) {
        free(device.luks.name);
        free(device.luks.uuid);
      }
    }
  }

  closedir(d);

  return 0;
}

int rluksd_sysfs_read_device_info(const char *name, rluksd_device_t *device) {
  char *dmuuid = __read_dm_uuid(name);
  char *luksname, *uuid;
  int size = strlen(dmuuid);

  if (dmuuid == NULL)
    return -1;

  luksname = malloc(sizeof(char) * (size - 12 - 34) + 1);
  if (luksname == NULL) {
    free(dmuuid);
    return -5;
  }

  uuid = malloc(sizeof(char) * 33 + 1);
  if (uuid == NULL) {
    free(dmuuid);
    free(luksname);
    return -6;
  }

  memset(luksname, 0, sizeof(char) * (size - 46 + 1));
  memset(uuid, 0, sizeof(char) * (33 + 1));
  strncpy(luksname, &dmuuid[45], size - 46);
  strncpy(uuid, &dmuuid[12], 32);

  fprintf(stdout, "[sysfs] identified open luks2 device %s (%s)\n", luksname, uuid);

  device->luks.name = luksname;
  device->luks.uuid = uuid;
  free(dmuuid);

  return 0;
}
