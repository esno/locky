#include <string.h>
#include <libcryptsetup.h>

#include "luksd.h"
#include "luksd_cryptsetup.h"

int luksd_cryptsetup_read_device(luksd_device_t *device)
{
  unsigned char device_name[device->name_l + 1];
  unsigned char device_path[device->path_l + 1];
  luksd_device_t d;

  memset(&d, 0, sizeof(luksd_device_t));
  memcpy(&device_name, device->name, device->name_l);
  memcpy(&device_path, device->path, device->path_l);
  device_name[device->name_l + 1] = '\0';
  device_path[device->path_l + 1] = '\0';

  if(crypt_init(&d.ctx, device_path) < 0 &&
      crypt_load(d.ctx, CRYPT_LUKS1, NULL) < 0)
    return -1;

  device->ctx = d.ctx;
  device->status = crypt_status(d.ctx, device->name);
  strcpy(device->uuid, crypt_get_uuid(d.ctx));

  return 0;
}
