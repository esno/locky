#include <stdlib.h>

#include "rluksd/sysfs.h"

int main(int argc, const char **argv) {
  rluksd_sysfs_discover_devices();

  return EXIT_SUCCESS;
}
