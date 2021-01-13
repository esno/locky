#include <stdlib.h>

#include "rluksd/device.h"
#include "rluksd/sysfs.h"

int main(int argc, const char **argv) {
  rluksd_sysfs_discover_devices();
  rluksd_device_free_all();

  return EXIT_SUCCESS;
}
