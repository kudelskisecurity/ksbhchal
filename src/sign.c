#include "hors.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>


// TODO: attack = find seed for which sk's all known, after collecting some sk's

int getkey(uint8_t *skseed) {
    int fd = open("./key", O_RDONLY);
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

    getkey(skseed);
    memset(msg, 0x00, N);

    gensk(skseed, sk);
    genpk(sk, pk);

    if (sign(sk, sig, msg)) {
        printf("sign fail\n");
        return 1;
    }

    if (verify(pk, sig, msg)) {
        printf("verify fail\n");
        return 1;
    }

    return 0;
}
