/*
 * hash.c
 *
 * Compute a 256-bit BLAKE2b hash of the first given file using libsodium.
 */

#include <sodium.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define BUFSIZE 256

int main(int argc, char *argv[])
{
    if (sodium_init() < 0) {
        return -1;
    }

    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash_state hs;
    crypto_generichash_init(&hs, NULL, 0, sizeof hash);

    int fd, n;
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("Can't open file, errno %d\n", errno);
        return -1;
    }

    char buf[BUFSIZE];
    do {
       n = read(fd, buf, BUFSIZE);
       crypto_generichash_update(&hs, buf, n);
    } while (n > 0);

    close(fd);
    memset(buf, 0, BUFSIZE);

    crypto_generichash_final(&hs, hash, sizeof hash);
    for (int i = 0; i < crypto_generichash_BYTES; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}
