/*
 * pb_sockets.c
 *
 * Send encrypted messages via a socket using assymetric cryptography.
 *
 * Copyright (c) 2018 Martijn
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sodium.h>
#include <stdio.h>

// File I/O
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Networking
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string.h>

// Eror handling
#include <error.h>
#include <errno.h>

#define BUFSIZE 256

/*
 * Generate a keypair and save them to the files 'sk' and 'pk' respectively
 */
int gen_keyfiles(void)
{
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(pk, sk);

    int fd;
    fd = creat("sk", O_WRONLY);
    if (fd == -1)
        error(-1, errno, "Can't create secret key file");
    if (fchmod(fd, 00600) != 0)
        error(-1, errno, "Can't set secret key file permissions");

    int n = write(fd, sk, sizeof sk);
    if (n == -1) {
        error(-1, errno, "Can't write secret key");
    } /* TODO: Add case when -1 < n < sizeof sk */
    close(fd);

    fd = creat("pk", O_WRONLY);
    if (fd == -1)
        error(-1, errno, "Can't create public key file");
    if (fchmod(fd, 00644) != 0)
        error(-1, errno, "Can't set public key file permissions");

    n = write(fd, pk, sizeof pk);
    if (n == -1) {
        error(-1, errno, "Can't write public key");
    } /* Same todo as with the secret key */
    close(fd);

    return 0;
}

int read_keyfiles(char *sk, size_t skl, char *pk, size_t pkl)
{
    int fd, n;

    fd = open("sk", O_RDONLY);
    if (fd == -1)
        error(-1, errno, "Can't open secret key file");

    n = read(fd, sk, skl);
    if (n == -1)
        error(-1, errno, "Cant read secret key");
    close(fd);
    /* Todo: catch case when the key isn't read completely (-1 < n < skl) */

    fd = open("pk", O_RDONLY);
    if (fd == -1)
        error(-1, errno, "Can't open public key file");

    n = read(fd, pk, pkl);
    if (n == -1)
        error(-1, errno, "Can't read public key");
    close(fd);

    return 0;
}

/*
 *
 *
int encrypt_msg(unsigned char sk[], unsigned char pk[], char m[], size_t mlen,
        char buf[], size_t buflen, )
{

}
*/

int client(char *host, char *port)
{
    int sockfd, n;
    struct sockaddr_in s_addr;
    struct hostent *server;
    struct addrinfo hints, *res;

    unsigned char c_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char c_sk[crypto_box_SECRETKEYBYTES];
    unsigned char s_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char nonce[crypto_box_NONCEBYTES];

    read_keyfiles(c_sk, sizeof c_sk, c_pk, sizeof c_pk);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    n = getaddrinfo(host, port, &hints, &res);
    if (n != 0)
        error(-1, 0, "Error getting address: %s", gai_strerror(n));

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1)
        error(-1, errno, "Error opening socket");

    printf("Connecting to %s:%s...", host, port);
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1)
        error(-1, errno, "Error connecting to %s:%s", host, port);
    printf("done\n");

    // Connection is set up; now exchange public keys
    n = 0;
    n = read(sockfd, s_pk, crypto_box_PUBLICKEYBYTES);
	if (n == -1) {
        error(-1, errno, "Error receiving server's public key");
    } /* Add case when -1 < n < crypto_box_PUBLICKEYBYTES */

	n = 0;
	do {
		n = write(sockfd, c_pk, crypto_box_PUBLICKEYBYTES - n);
	} while (n > 0 && n < crypto_box_PUBLICKEYBYTES);
}

int server(char *port)
{
    int sockfd, conn_sockfd;
    int client_len;
    int n;
    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in cl_addr;
    struct addrinfo hints, *res;

    unsigned char s_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char s_sk[crypto_box_SECRETKEYBYTES];
    unsigned char c_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char nonce[crypto_box_NONCEBYTES];

    read_keyfiles(s_sk, sizeof s_sk, s_pk, sizeof s_pk);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    n = getaddrinfo(NULL, port, &hints, &res);
    if (n != 0)
        error(-1, 0, "Error in getaddrinfo: %s", gai_strerror(n));

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1)
        error(-1, errno, "Error opening socket");

    if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1)
        error(-1, errno, "Error binding socket");

    if (listen(sockfd, 5) == -1)
        error(-1, errno, "Error listening");

    char buf[BUFSIZE];
    while (1) {
        memset(buf, 0, sizeof buf);
        client_len = sizeof cl_addr;

        conn_sockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &client_len);
        if (conn_sockfd == -1)
            error(-1, errno, "Error accepting connection");

        inet_ntop(AF_INET, &(cl_addr.sin_addr), client_ip, sizeof client_ip);
        printf("Accepted connection from %s:%d\n", client_ip, cl_addr.sin_port);

        /*
         * Should verify if there hasn't been tampered with the pubkeys
         */
        n = 0;
        do {
            n = write(conn_sockfd, s_pk, crypto_box_PUBLICKEYBYTES - n);
        } while (n > 0 && n < crypto_box_PUBLICKEYBYTES);

        n = 0;
        n = read(conn_sockfd, c_pk, crypto_box_PUBLICKEYBYTES);

        // Keys have been exchanged, now we can talk!
    }
}

int main(int argc, char *argv[])
{
    if (sodium_init() < 0) {
        error(-1, errno, "Fatal error: could not initialize libsodium.");
    }

    if (argc < 2)
        return -2;

    if (strcmp("keygen", argv[1]) == 0) {
        return gen_keyfiles();
    }

    return 0;
}
