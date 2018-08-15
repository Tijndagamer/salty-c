/*
 * random_int.c
 * 
 * Generate a random uint32_t with libsodium
 */

#include <sodium.h>
#include <stdio.h>

int main(void)
{
    if (sodium_init() < 0) {
        return -1;
    }

    uint32_t test;
    test = randombytes_random();

    printf("%u\n", test);
}
