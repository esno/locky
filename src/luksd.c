#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <libcryptsetup.h>

#define _LUKSD_BUFFER_SIZE 1024

typedef struct {
  int socket;
  struct sockaddr_un addr;
  socklen_t addrlen;
  char *device;
  char *name;
} luksd_connection_t;

bool unlockLuks(char *luksDevice, char *luksName, char *luksKey, size_t keyLength);

void connLoop(luksd_connection_t *luksd) {
  int fd;
  size_t n;
  char buffer[_LUKSD_BUFFER_SIZE];
  bool running = true;

  luksd->addrlen = sizeof(struct sockaddr_in);

  while(running) {
    fd = accept(luksd->socket,
      (struct sockaddr *) &luksd->addr,
      &luksd->addrlen);

    if(fd > 0) {
      n = recv(fd, buffer, _LUKSD_BUFFER_SIZE - 1, 0);
      if(n > 0) {
        buffer[n] = '\0';
        running = !unlockLuks(luksd->device, luksd->name, buffer, n);
      }
    }
    close(fd);
  }
}

bool unlockLuks(char *luksDevice, char *luksName, char *luksKey, size_t keyLength) {
  struct crypt_device *cryptDevice;

  if(crypt_init(&cryptDevice, luksDevice) < 0) {
    fprintf(stderr, "crypt device init failed\n");
    return false;
  }

  if(crypt_load(cryptDevice,
      CRYPT_LUKS1, NULL) < 0) {
    fprintf(stderr, "load luks header failed\n");
    return false;
  }

  if(crypt_activate_by_passphrase(cryptDevice,
      luksName, CRYPT_ANY_SLOT,
      luksKey, keyLength,
      0) < 0) {
    fprintf(stderr, " luks device activation failed\n");
    crypt_free(cryptDevice);
    return false;
  }

  printf("activated luks device (%s) with UUID %s\n",
    luksDevice, crypt_get_uuid(cryptDevice));
  crypt_free(cryptDevice);

  return true;
}

int main(int argc, char *argv[]) {
  luksd_connection_t luksd;
  struct passwd *pwd;
  struct group *grp;
  char *socketOwner, *socketGroup;
  struct stat *luksBlkDev;
  int i;

  if(argc != 5) {
    printf("USAGE: %s <luksDevice> <luksName> <socketOwner> <socketGroup>\n",
      argv[0]);
    return 1;
  }

  luksd.device = argv[1];
  luksd.name = argv[2];
  socketOwner = argv[3];
  socketGroup = argv[4];

  if(stat(luksd.device, luksBlkDev) != 0) {
    fprintf(stderr, "cannot stat blockdevice %s\n", luksd.device);
    return 1;
  }

  if(S_ISBLK(luksBlkDev->st_mode) != 0) {
    fprintf(stderr, "%s is not a blockdevice\n", luksd.device);
    return 1;
  }

  pwd = getpwnam(socketOwner);
  grp = getgrnam(socketGroup);

  if(pwd == NULL && grp == NULL) {
    fprintf(stderr, "socket owner (%s) or group (%s) not found\n",
      socketOwner, socketGroup);
    return 1;
  }

  luksd.socket = socket(AF_UNIX, SOCK_STREAM, 0);
  luksd.addr.sun_family = AF_UNIX;
  strcpy(luksd.addr.sun_path, "/run/luksd.sock");

  if(luksd.socket > 0) {
    unlink("/run/luksd.sock");
    if(bind(luksd.socket, (struct sockaddr *) &luksd.addr, sizeof(luksd.addr)) == 0) {
      printf("world\n");
      chown("/run/luksd.sock", pwd->pw_uid, grp->gr_gid);
      chmod("/run/luksd.sock", 0770);
      if(listen(luksd.socket, 5) == 0)
        printf("foo\n");
        connLoop(&luksd);
    }
    close(luksd.socket);
  }

  return 0;
}
