#include <stdio.h>
#include <stdint.h>

extern void haraka512256(uint8_t *hash, const uint8_t *msg);

int main(int ac, char **av) {

    uint8_t msg[64];
    uint8_t hash[32];

    char *h = av[1];

    for(int count = 0; count < 64; count++) {
    	if (!sscanf(h, "%2hhx", &msg[count])) {
            return 1;
        }
    	h += 2;
    }

    haraka512256(hash, msg);

    for(int i=0; i<32; ++i) {
        printf("%02x", hash[i]);
    }

    return 0;
}