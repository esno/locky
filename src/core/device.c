#include <stdio.h>
#include <stdlib.h>

#include "rluksd/device.h"

typedef struct rluksd_device_mgr rluksd_device_mgr_t;
struct rluksd_device_mgr {
  rluksd_device_t *list;
};

static rluksd_device_mgr_t __rluksd_device = {
  .list = NULL
};

static int __device_exists(rluksd_device_t *device) {
  rluksd_device_t *ptr = __rluksd_device.list;

  while (ptr != NULL) {
    if (ptr->major == device->major && ptr->minor == device->minor) {
      fprintf(stdout, "[device] duplicate detected (%d:%d)\n", device->major, device->minor);
      return 0;
    }

    ptr = ptr->next;
  }

  return -1;
}

void rluksd_device_add(rluksd_device_t *device) {
  rluksd_device_t *ptr;

  if (__device_exists(device) < 0) {
    if (__rluksd_device.list == NULL) {
      __rluksd_device.list = device;
    } else {
      ptr = __rluksd_device.list;
      while (ptr != NULL) {
        if (ptr->next == NULL) {
          ptr->next = device;
          device->prev = ptr;
        }
        ptr = ptr->next;
      }
    }
  } else {
    rluksd_device_free(device);
  }
}

void rluksd_device_drop(rluksd_device_t *device) {
  if (device->prev == NULL) {
    __rluksd_device.list = device->next;
    if (device->next != NULL)
      device->next->prev = NULL;
  } else {
    device->prev->next = device->next;
    if (device->next != NULL)
      device->next->prev = device->prev;
  }
}

void rluksd_device_free(rluksd_device_t *device) {
  if (device->luks.name != NULL)
    free(device->luks.name);
  if (device->luks.uuid != NULL)
    free(device->luks.uuid);
  if(device->parent != NULL)
    free(device->parent);

  if (__rluksd_device.list == device)
    __rluksd_device.list = device->next;

  free(device);
}

void rluksd_device_free_all(void) {
  while (__rluksd_device.list != NULL)
    rluksd_device_free(__rluksd_device.list);
}
