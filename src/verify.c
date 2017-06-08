#include "hors.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>


int getkey(uint8_t *skseed) {
    int fd = open("./key", O_RDONLY);
    if (fd < 0) return 1;
    int r =read(fd, skseed, N);
    close(fd);
    if (r != N) return 1;
    return 0;

}

int main(int ac, char **av) {
    uint8_t sk[N*T];
    uint8_t skseed[N];
    uint8_t msg[N];
    uint8_t pk[N];
    uint8_t *sig = malloc(SIGLEN);

    if (!sig) {
        fprintf(stderr, "error: malloc failed\n");
        return 1;
    }

    if (ac != 3) {
        fprintf(stderr, "error: two arguments needed\n");
        return 1;
    }
    if (strlen(av[1]) != 2*N) {
        fprintf(stderr, "error: first argument must be %d-chars long\n", 2*N);
        return 1;
    }
    if (strlen(av[2]) != 2*SIGLEN) {
        fprintf(stderr, "error: second argument must be %d-chars long\n", 2*SIGLEN);
        return 1;
    }
     
    char *h = av[1];
    char *s = av[2];

    for(int count = 0; count < N; count++) {
    	if (!sscanf(h, "%2hhx", &msg[count])) {
            fprintf(stderr, "error: non-hex chars found\n");
            return 1;
        }
    	h += 2;
    }
    for(int count = 0; count < SIGLEN; count++) {
    	if (!sscanf(s, "%2hhx", &sig[count])) {
            fprintf(stderr, "error: non-hex chars found\n");
            return 1;
        }
    	s += 2;
    }

    if (getkey(skseed)) {
        fprintf(stderr, "error: getkey failed\n");
        return 1;
    }
    gensk(skseed, sk);
    genpk(sk, pk);

    if (verify(pk, sig, msg)) {
        fprintf(stderr, "error: verify fail\n");
        return 1;
    }

    return 0;
}
