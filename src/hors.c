#include "hors.h"
#include <string.h>
#include <stdlib.h>

extern void haraka256256(uint8_t *hash, const uint8_t *msg);
extern void haraka512256(uint8_t *hash, const uint8_t *msg);


void gensk(const uint8_t *seed, uint8_t *sk)
{
    uint8_t in[2*N];
    HCPY(in, seed);

    for (int i=0; i < T; ++i) {
        haraka256256(sk + (i*N), in);
        in[0] += 1;
        if (!in[0]) in[1] += 1;
    }
}

int genpk(const uint8_t *sk, uint8_t *pk)
{
    uint8_t *buf = malloc(2*T*N);
    if (buf == NULL)
        return 1;

    uint8_t *src = buf+T*N;
    uint8_t *dst = buf;
    uint8_t *tmp;
    int j, l;

    int n = T;
    for (j = 0; j < n; ++j)
        haraka256256(dst+(j*N), sk+(j*N));

    for (l = 0; l < TAU; ++l)
    {
        tmp = src;
        src = dst;
        dst = tmp;
        n >>= 1;
        for (int i = 0; i < n; ++i)
            haraka512256(dst+(i*N), src+(2*i*N));
    }

    HCPY(pk, dst);

    free(buf);
    return 0;
}

int sign(const uint8_t *sk, uint8_t *sig, const uint8_t *msg)
{
    int subset[K];

    uint8_t seedseed[2*N];
    uint8_t seed[N];
    HCPY(seedseed, sk);
    HCPY(seedseed + N, msg);
    haraka512256(seed, seedseed);

    getsubset(msg, seed, subset);

    HCPY(SEED(sig), seed);

    for (int i = 0; i < K; ++i)
    {
        int index = subset[i];
        HCPY(sig+(i*N), sk + (index * N));
        //printbytes(sk + (index*N), N);
    }

    uint8_t *buf = malloc(2*T * N);
    if (buf == NULL)
        return 1;

    uint8_t *src = buf+T*N;
    uint8_t *dst = buf;
    uint8_t *tmp;
    int j, l;

    int n = T;
    for (j = 0; j < n; ++j)
        haraka256256(dst+(j*N), sk+(j*N));

    uint8_t *paths = PATHS(sig);

    for (l = 0; l < TAU; ++l)
    {
        for (int i = 0; i < K; ++i) {
            int index = subset[i];
            int sibling = index + (index % 2 == 0 ? 1 : -1);
            HCPY(paths+(K*N*l)+(i*N), dst+sibling*N);
            subset[i] >>= 1;
        }

        tmp = src;
        src = dst;
        dst = tmp;
        n >>= 1;
        for (int i = 0; i < n; ++i)
            haraka512256(dst+(i*N), src+(2*i*N));
    }

    free(buf);
    return 0;
}

int verify(const uint8_t *pk, const uint8_t *sig, const uint8_t *msg)
{
    int subset[K];
    int i, l;

    const uint8_t *seed = SEED(sig);

    getsubset(msg, seed, subset);

    uint8_t tmp[N];
    uint8_t buf[N*2];
    const uint8_t *paths = PATHS(sig);

    for (i = 0; i < K; ++i)
    {
        int index = subset[i];
        haraka256256(tmp, sig+(i*N));

        for (l = 0; l < TAU; ++l)
        {
            if (index % 2 == 0) {
                HCPY(buf, tmp);
                HCPY(buf+N, paths + (K*N*l) + (i*N));
            } else {
                HCPY(buf, paths + (K*N*l) + (i*N));
                HCPY(buf+N, tmp);
            }

            haraka512256(tmp, buf);

            index >>= 1;
        }

        if (memcmp(pk, tmp, N))
            return 2;
    }

    return 0;
}


void getsubset(const uint8_t *msg, const uint8_t *seed, int *subset)
{
    uint8_t tmp[N];
    uint8_t in[2*N];
    HCPY(in, msg);
    HCPY(in+N, seed);
    haraka512256(tmp, in);
    for (int i = 0; i < K; ++i)
    {
        int index = ((tmp[2*i] << 8) | tmp[2*i+1]) % T;
        subset[i] = index;
    }
}
