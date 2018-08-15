/*
 * pubkey.c
 *
 * Usage:
 * ./pubkey keygen
 *
 * ./pubkey encrypt sk_file pk_file file
 */

#include <sodium.h>

#include <stdio.h>
#include <string.h>

// File I/O
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Error handling
#include <error.h>
#include <errno.h>

#define BUFSIZE 256

/*
 * Generate a keypair and save them in a binary file.
 */
int gen_keyfiles(void)
{
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(pk, sk);

    int fd;
    fd = creat("sk", O_WRONLY);
    if (fchmod(fd, 00600) != 0)
        return -1;

    int n = write(fd, sk, sizeof sk); 
    close(fd);

    fd = creat("pk", O_WRONLY);
    if (fchmod(fd, 00644) != 0)
        return -1;
    write(fd, pk, sizeof pk);
    return 0;
}

/*
 * Encrypt msg for recipient's public key and sign with our secret key.
 */
int encrypt_msg(char *sk_file, char *pk_file, char *msg)
{
    /*
     * Note that this is not a keypair: it is the recipient's public key and
     * the sender's private key.
     */
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char pk[crypto_box_PUBLICKEYBYTES];

    int fd, n;
    fd = open(sk_file, O_RDONLY);
    if (fd == -1)
        error(-1, errno, "Error reading secret key file");
    n = read(fd, sk, sizeof sk);
    close(fd);
    
    fd = open(pk_file, O_RDONLY);
    if (fd == -1)
        error(-1, errno, "Error reading public key file");
    n = read(fd, pk, sizeof pk);
    close(fd);

    size_t msglen = strlen(msg);
    size_t ciphertext_len = msglen + crypto_box_MACBYTES;
    unsigned char ciphertext[ciphertext_len];

    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    if (crypto_box_easy(ciphertext, msg, msglen, nonce, pk, sk) != 0)
       error(-1, errno, "Encryption failed");

    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}

int main(int argc, char *argv[])
{
    if (sodium_init() < 0) {
        return -1;
    }

    if (argc < 2)
        return -2;

    if (strcmp("keygen", argv[1]) == 0) {
        return gen_keyfiles();
    } else if (strcmp("encrypt", argv[1]) == 0) {
        if (argc < 5)
            return -3;
        return encrypt_msg(argv[2], argv[3], argv[4]);
    } else {
        return -2;
    }
}
