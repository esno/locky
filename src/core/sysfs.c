#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "rluksd/device.h"
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
  size_t l = strlen(__RLUKSD_SYSFS_DEV_BLK_PATH) + strlen(name) + 10;
  size_t size;
  size_t c;
  char filename[l];
  char *dmuuid;
  FILE *fd;

  memset(filename, 0, sizeof(char) * l);
  snprintf(filename, l, "%s/%s/dm/uuid", __RLUKSD_SYSFS_DEV_BLK_PATH, name);
  fd = fopen(filename, "r");
  if (fd == NULL)
    return NULL;

  fseek(fd, 0L, SEEK_END);
  size = (size_t) ftell(fd);
  rewind(fd);

  dmuuid = malloc(sizeof(char) * size);
  if (dmuuid == NULL)
    return NULL;

  if ((c = fread(dmuuid, 1, size, fd)) != size) {
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
  rluksd_device_t *device;

  d = opendir(__RLUKSD_SYSFS_DEV_BLK_PATH);
  if (d == NULL) {
    fprintf(stderr, "[sysfs] not supported by your kernel\n");
    return -1;
  }

  while ((entry = readdir(d)) != NULL) {
    device = malloc(sizeof(rluksd_device_t));
    if (device == NULL)
      continue;

    memset(device, 0, sizeof(rluksd_device_t));
    if (sscanf(entry->d_name, "%d:%d", &device->major, &device->minor) != 2) {
      rluksd_device_free(device);
      continue;
    }

    fprintf(stdout, "[sysfs] found device %d:%d\n", device->major, device->minor);
    device->id = makedev(device->major, device->minor);

    if (__is_luks(entry->d_name) == 0 &&
        rluksd_sysfs_read_device_info(entry->d_name, device) == 0 &&
        rluksd_sysfs_discover_parent(entry->d_name, device) == 0) {
      rluksd_device_add(device);
    } else {
      rluksd_device_free(device);
      device = NULL;
    }
  }

  closedir(d);

  return 0;
}

int rluksd_sysfs_discover_parent(const char *name, rluksd_device_t *device) {
  size_t l = strlen(__RLUKSD_SYSFS_DEV_BLK_PATH) + strlen(name) + 9;
  DIR *d;
  struct dirent *entry;
  char path[l];
  char *parent;

  memset(path, 0, sizeof(char) * l);
  snprintf(path, l, "%s/%s/slaves", __RLUKSD_SYSFS_DEV_BLK_PATH, name);
  d = opendir(path);
  if (d == NULL) {
    fprintf(stderr, "[sysfs] device slaves not supported by your kernel\n");
    return -1;
  }

  while ((entry = readdir(d)) != NULL) {
    parent = malloc(sizeof(char) * (strlen(entry->d_name) + 1));
    if (parent == NULL)
      return -2;

    memset(parent, 0, sizeof(char) * (strlen(entry->d_name) + 1));
    strcpy(parent, entry->d_name);
    device->parent = parent;
  }

  fprintf(stdout, "[sysfs] identified %s as parent of %s\n", device->parent, device->luks.name);

  return 0;
}

int rluksd_sysfs_read_device_info(const char *name, rluksd_device_t *device) {
  char *dmuuid = __read_dm_uuid(name);
  char *luksname, *uuid;
  size_t size;

  if (dmuuid == NULL)
    return -1;

  size = strlen(dmuuid);
  luksname = malloc(sizeof(char) * (size - 12 - 34) + 1);
  if (luksname == NULL) {
    free(dmuuid);
    return -5;
  }

  uuid = malloc(sizeof(char) * 33 + 4 + 1);
  if (uuid == NULL) {
    free(dmuuid);
    free(luksname);
    return -6;
  }

  memset(luksname, 0, sizeof(char) * (size - 46 + 1));
  memset(uuid, 0, sizeof(char) * (33 + 1));
  strncpy(luksname, &dmuuid[45], size - 46);

  strncpy(uuid, &dmuuid[12], 8);
  strcpy(&uuid[8], "-");
  strncpy(&uuid[9], &dmuuid[20], 4);
  strcpy(&uuid[13], "-");
  strncpy(&uuid[14], &dmuuid[24], 4);
  strcpy(&uuid[18], "-");
  strncpy(&uuid[19], &dmuuid[28], 4);
  strcpy(&uuid[23], "-");
  strncpy(&uuid[24], &dmuuid[32], 12);

  fprintf(stdout, "[sysfs] identified open luks2 device %s (%s)\n", luksname, uuid);

  device->luks.name = luksname;
  device->luks.uuid = uuid;
  free(dmuuid);

  return 0;
}
