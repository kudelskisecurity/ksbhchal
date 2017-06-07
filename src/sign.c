#include "hors.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>


void printbytes(uint8_t *m, int len) {
	int i;
	for (i = 0; i < len-1; ++i)
		printf("%02x ", m[i]);
	printf("%02x\n", m[len-1]);
}

// TODO: write and read private key from file
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
    //struct horst_sign sig;
    uint8_t *sig = malloc(K*N + TAU*K*N + N);

    //memset(skseed, 0x00, N);
    getkey(skseed);
    printbytes(skseed, N);
    memset(msg, 0x00, N);

    gensk(sk, skseed);
    genpk(sk, pk);

    if (sign(sk, sig, msg)) {
        printf("sign fail\n");
        return 1;
    }

    //printbytes((uint8_t*)sig, N*HORS_t);
    //sig.s.s->h[0] ^= 1;

    if (verify(pk, sig, msg)) {
        printf("verify fail\n");
        return 1;
    }


    return 0;
}
