#include "hors.h"
#include <string.h>
#include <stdlib.h>

void horst_gensk(uint8_t *sk, const uint8_t *seed)
{
    uint8_t in[32];
    memcpy(in, seed, 32);

    for (int i=0; i < HORS_t; ++i) {
        haraka256256(sk, in);
        in[0] += 1;
        if (!in[0]) in[1] += 1;
    }
}


/* Naive HORST without merging of authentication paths */
int horst_genpk(const uint8_t *sk, uint8_t *pk)
{
    uint8_t *buf = malloc(2*HORS_t * N);
    if (buf == NULL)
        return 1;

    uint8_t *src = buf+HORS_t*N;
    uint8_t *dst = buf;
    uint8_t *tmp;
    int j, l;

    /* Leaves */
    int n = HORS_t;
    for (j = 0; j < n; ++j)
        haraka256256(dst+(j*N), sk+(j*N));

    /* Merkle tree */
    for (l = 0; l < HORS_tau; ++l)
    {
        tmp = src;
        src = dst;
        dst = tmp;
        n >>= 1;
        for (int i = 0; i < n; ++i)
            haraka512256(dst+(i*N), src+(2*i*N));
    }

    memcpy(pk, dst, N);

    free(buf);
    return 0;
}

//int horst_sign(const uint8_t *sk, struct horst_sign *sig, const uint8_t *msg)
int horst_sign(const uint8_t *sk, uint8_t *sig, const uint8_t *msg)
{
    struct hors_subset subset;

    int res = hors_randsubset(msg, &subset);

    /* Values */
    for (int i = 0; i < HORS_k; ++i)
    {
        int index = subset.s[i];
        //memcpy(&sig->s.s[i], sk + (index * N), N);
        memcpy(sig+(i*N), sk + (index * N), N);
    }

    uint8_t *buf = malloc(2*HORS_t * N);
    if (buf == NULL)
        return 1;

    uint8_t *src = buf+HORS_t*N;
    uint8_t *dst = buf;
    uint8_t *tmp;
    int j, l;

    /* Leaves */
    int n = HORS_t;
    for (j = 0; j < n; ++j)
        haraka256256(dst+(j*N), sk+(j*N));

    /* Merkle tree */
    for (l = 0; l < HORS_tau; ++l)
    {
        /* Copy auth path */
        for (int i = 0; i < HORS_k; ++i) {
            int index = subset.s[i];
            int sibling = index + (index % 2 == 0 ? 1 : -1);
            //memcpy(&sig->a[i].p[l], dst+sibling*N, N);
            memcpy(sig+(HORS_k*N)+(HORS_k*N*l)+(i*N), dst+sibling*N, N);
            subset.s[i] >>= 1;
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

//int horst_verify(const uint8_t *pk, const struct horst_sign *sig, const uint8_t *msg)
int horst_verify(const uint8_t *pk, const uint8_t *sig, const uint8_t *msg)
{
    struct hors_subset subset;
    int i, l;

    int res = hors_randsubset(msg, &subset);

    uint8_t tmp[N];
    uint8_t buf[N*2];
    uint8_t *p = sig+(HORS_k*N);

    for (i = 0; i < HORS_k; ++i)
    {
        int index = subset.s[i];
        haraka256256(tmp, sig+(i*N));

        for (l = 0; l < HORS_tau; ++l)
        {
            if (index % 2 == 0) {
                memcpy(buf, tmp, N);
                //memcpy(buf+N, &p->p[l], N);
                memcpy(buf+N, p + (HORS_k*N*l) + (i*N), N);
            } else {
                //memcpy(buf, &p->p[l], N);
                memcpy(buf, p + (HORS_k*N*l) + (i*N), N);
                memcpy(buf+N, tmp, N);
            }

            haraka512256(tmp, buf);

            index >>= 1;
        }

        if (memcmp(pk, tmp, N))
            return 2;
    }

    return 0;
}


int hors_randsubset(const uint8_t *msg, struct hors_subset *subset)
{
    uint8_t tmp[N];
    int i;
    haraka256256(tmp, msg);
    for (i = 0; i < HORS_k; ++i)
    {
        int index = (tmp[2*i] << 8) | tmp[2*i+1];
        subset->s[i] = index % HORS_t;
    }

    return 0;
}

