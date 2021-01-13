#include <stdlib.h>

#include "rluksd/sysfs.h"

int main(int argc, const char **argv) {
  rluksd_sysfs_scan();

  return EXIT_SUCCESS;
}
