#include "hors.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void printbytes(uint8_t *m, int len) {
	int i;
	for (i = 0; i < len-1; ++i)
		printf("%02x ", m[i]);
	printf("%02x\n", m[len-1]);
}

// TODO: hash using a seed, add seed to sig
// TODO: attack = find seed for which sk's all known, after collecting some sk's

int main(int ac, char **av) {
    uint8_t sk[N*HORS_t];
    uint8_t seed[N];
    uint8_t msg[N];
    uint8_t pk[N];
    //struct horst_sign sig;
    uint8_t *sig = malloc(HORS_k*N + HORS_tau*HORS_k*N);

    memset(seed, 0x00, N);
    memset(msg, 0x00, N);

    horst_gensk(sk, seed);
    horst_genpk(sk, pk);

    if (horst_sign(sk, sig, msg)) {
        printf("sign fail\n");
        return 1;
    }

    //printbytes((uint8_t*)sig, N*HORS_t);
    //sig.s.s->h[0] ^= 1;

    if (horst_verify(pk, sig, msg)) {
        printf("verify fail\n");
        return 1;
    }


    return 0;
}
