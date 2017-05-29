#include "hors.h"

#include "prng.h"
#include "hash.h"
#include <string.h>
#include <stdlib.h>

/* Naive HORS without Merkle tree */
void hors_gensk(const struct hash *key, const uint64_t address, struct hors_sk *sk)
{
    uint8_t nonce[16];

    /* TODO: endian-agnostic copy */
    memset(nonce, 0, 16);
    memcpy(nonce, &address, 8);

    prng_gen(key, nonce, sk->k[0].h, HORS_t * HASH_SIZE);
}

void hors_genpk(const struct hors_sk *sk, struct hors_pk *pk)
{
    int j;
    for (j = 0; j < HORS_t; ++j)
        hash_N_to_N(&pk->k[j], &sk->k[j]);
}

int hors_sign(const struct hors_sk *sk, struct hors_sign *sign, const struct hash *msg)
{
    struct hors_subset subset;
    int i;

    int res = hors_randsubset(msg, &subset);
    if (res != GRAVITY_OK)
        return res;

    for (i = 0; i < HORS_k; ++i)
    {
        int index = subset.s[i];
        hashcpy(&sign->s[i], &sk->k[index]);
    }

    return GRAVITY_OK;
}

int hors_verify(const struct hors_pk *pk, const struct hors_sign *sign, const struct hash *msg)
{
    struct hash tmp;
    struct hors_subset subset;
    int i;

    int res = hors_randsubset(msg, &subset);
    if (res != GRAVITY_OK)
        return res;

    for (i = 0; i < HORS_k; ++i)
    {
        int index = subset.s[i];
        hash_N_to_N(&tmp, &sign->s[i]);
        if (hashcmp(&pk->k[index], &tmp))
            return GRAVITY_ERR_VERIF;
    }

    return GRAVITY_OK;
}


/* Naive HORST without merging of authentication paths */
int horst_genpk(const struct hors_sk *sk, struct horst_pk *pk)
{
    /* TODO: Could use 1.5*HORS_t */
    struct hash *buf = malloc(2*HORS_t * sizeof(struct hash));
    if (buf == NULL)
        return GRAVITY_ERR_ALLOC;

    struct hash *src = &buf[HORS_t];
    struct hash *dst = &buf[0];
    struct hash *tmp;
    int j, l;

    /* Leaves */
    int n = HORS_t;
    for (j = 0; j < n; ++j)
        hash_N_to_N(&dst[j], &sk->k[j]);

    /* Merkle tree */
    for (l = 0; l < HORS_tau; ++l)
    {
        /* Swap buffers */
        tmp = src;
        src = dst;
        dst = tmp;
        n >>= 1;

        /* Compute all hashes at current layer */
        hash_compress_pairs(dst, src, n);
    }

    hashcpy(&pk->k, dst);

    /* TODO: wipe buffer? */

    free(buf);
    return GRAVITY_OK;
}

int horst_sign(const struct hors_sk *sk, struct horst_sign *sign, const struct hash *msg)
{
    struct hors_subset subset;
    int i;

    int res = hors_randsubset(msg, &subset);
    if (res != GRAVITY_OK)
        return res;

    /* Values */
    for (i = 0; i < HORS_k; ++i)
    {
        int index = subset.s[i];
        hashcpy(&sign->s.s[i], &sk->k[index]);
    }

    /* Authentication paths */
    /* TODO: Could use 1.5*HORS_t */
    struct hash *buf = malloc(2*HORS_t * sizeof(struct hash));
    if (buf == NULL)
        return GRAVITY_ERR_ALLOC;

    struct hash *src = &buf[HORS_t];
    struct hash *dst = &buf[0];
    struct hash *tmp;
    int j, l;

    /* Leaves */
    int n = HORS_t;
    for (j = 0; j < n; ++j)
        hash_N_to_N(&dst[j], &sk->k[j]);

    /* Merkle tree */
    for (l = 0; l < HORS_tau; ++l)
    {
        /* Copy auth path */
        for (i = 0; i < HORS_k; ++i)
        {
            int index = subset.s[i];
            int sibling = index + (index % 2 == 0 ? 1 : -1);
            hashcpy(&sign->a[i].p[l], &dst[sibling]);
            subset.s[i] >>= 1;
        }

        /* Swap buffers */
        tmp = src;
        src = dst;
        dst = tmp;
        n >>= 1;

        /* Compute all hashes at current layer */
        hash_compress_pairs(dst, src, n);
    }

    free(buf);
    return GRAVITY_OK;
}

int horst_verify(const struct horst_pk *pk, const struct horst_sign *sign, const struct hash *msg)
{
    struct hors_subset subset;
    int i, l;

    int res = hors_randsubset(msg, &subset);
    if (res != GRAVITY_OK)
        return res;

    struct hash tmp;
    struct hash buf[2];
    for (i = 0; i < HORS_k; ++i)
    {
        int index = subset.s[i];
        hash_N_to_N(&tmp, &sign->s.s[i]);

        /* Auth path */
        const struct horst_authpath *p = &sign->a[i];
        for (l = 0; l < HORS_tau; ++l)
        {
            if (index % 2 == 0) {
                hashcpy(&buf[0], &tmp);
                hashcpy(&buf[1], &p->p[l]);
            } else {
                hashcpy(&buf[0], &p->p[l]);
                hashcpy(&buf[1], &tmp);
            }

            hash_2N_to_N(&tmp, buf[0].h);

            index >>= 1;
        }

        if (hashcmp(&pk->k, &tmp))
            return GRAVITY_ERR_VERIF;
    }

    return GRAVITY_OK;
}


/* Improved HORST with cutoff of authentication paths */
int horstcut_genpk(const struct hors_sk *sk, struct horstcut_pk *pk)
{
    /* TODO: Could use 1.5*HORS_t */
    struct hash *buf = malloc(2*HORS_t * sizeof(struct hash));
    if (buf == NULL)
        return GRAVITY_ERR_ALLOC;

    struct hash *src = &buf[HORS_t];
    struct hash *dst = &buf[0];
    struct hash *tmp;
    int j, l;

    /* Leaves */
    int n = HORS_t;
    for (j = 0; j < n; ++j)
        hash_N_to_N(&dst[j], &sk->k[j]);

    /* Merkle tree */
    for (l = 0; l < HORS_tau - HORS_x; ++l)
    {
        /* Swap buffers */
        tmp = src;
        src = dst;
        dst = tmp;
        n >>= 1;

        /* Compute all hashes at current layer */
        hash_compress_pairs(dst, src, n);
    }

    memcpy(pk->k, dst->h, HORS_xxx * HASH_SIZE);

    /* TODO: wipe buffer? */

    free(buf);
    return GRAVITY_OK;
}

int horstcut_sign(const struct hors_sk *sk, struct horstcut_sign *sign, const struct hash *msg)
{
    struct hors_subset subset;
    int i;

    int res = hors_randsubset(msg, &subset);
    if (res != GRAVITY_OK)
        return res;

    /* Values */
    for (i = 0; i < HORS_k; ++i)
    {
        int index = subset.s[i];
        hashcpy(&sign->s.s[i], &sk->k[index]);
    }

    /* Authentication paths */
    /* TODO: Could use 1.5*HORS_t */
    struct hash *buf = malloc(2*HORS_t * sizeof(struct hash));
    if (buf == NULL)
        return GRAVITY_ERR_ALLOC;

    struct hash *src = &buf[HORS_t];
    struct hash *dst = &buf[0];
    struct hash *tmp;
    int j, l;

    /* Leaves */
    int n = HORS_t;
    for (j = 0; j < n; ++j)
        hash_N_to_N(&dst[j], &sk->k[j]);

    /* Merkle tree */
    for (l = 0; l < HORS_tau - HORS_x; ++l)
    {
        /* Copy auth path */
        for (i = 0; i < HORS_k; ++i)
        {
            int index = subset.s[i];
            int sibling = index + (index % 2 == 0 ? 1 : -1);
            hashcpy(&sign->a[i].p[l], &dst[sibling]);
            subset.s[i] >>= 1;
        }

        /* Swap buffers */
        tmp = src;
        src = dst;
        dst = tmp;
        n >>= 1;

        /* Compute all hashes at current layer */
        hash_compress_pairs(dst, src, n);
    }

    free(buf);
    return GRAVITY_OK;
}

int horstcut_verify(const struct horstcut_pk *pk, const struct horstcut_sign *sign, const struct hash *msg)
{
    struct hors_subset subset;
    int i, l;

    int res = hors_randsubset(msg, &subset);
    if (res != GRAVITY_OK)
        return res;

    struct hash tmp;
    struct hash buf[2];
    for (i = 0; i < HORS_k; ++i)
    {
        int index = subset.s[i];
        hash_N_to_N(&tmp, &sign->s.s[i]);

        /* Auth path */
        const struct horstcut_authpath *p = &sign->a[i];
        for (l = 0; l < HORS_tau - HORS_x; ++l)
        {
            if (index % 2 == 0) {
                hashcpy(&buf[0], &tmp);
                hashcpy(&buf[1], &p->p[l]);
            } else {
                hashcpy(&buf[0], &p->p[l]);
                hashcpy(&buf[1], &tmp);
            }

            hash_2N_to_N(&tmp, buf[0].h);

            index >>= 1;
        }

        if (hashcmp(&pk->k[index], &tmp))
            return GRAVITY_ERR_VERIF;
    }

    return GRAVITY_OK;
}


/* Hash to obtain a random subset, various algorithms */
#define GET_BIT(x, i) \
    (((x)[(i) >> 5] >> ((i) & 0x1F)) & 1)

#define SET_BIT(x, i) \
    (x)[(i) >> 5] |= 1u << ((i) & 0x1F)

int hors_randsubset_collect(const struct hash *msg, struct hors_subset *subset)
{
    uint8_t tmp[2*HASH_SIZE];
    int i;

    /* TODO: use PRNG instead? */
    /* compute H(msg || 0), H(msg || 1), ... */
    uint8_t buf[HASH_SIZE+1];
    memcpy(buf, msg->h, HASH_SIZE);
    buf[HASH_SIZE] = 0;

    /* indices collected so far */
    uint32_t *used = malloc(HORS_t / 8);
    if (used == NULL)
        return GRAVITY_ERR_ALLOC;
    memset(used, 0, HORS_t / 8);

    int count = 0;
    while (count < HORS_k)
    {
        /* tmp = H(msg || counter) */
        hash_to_2N(tmp, buf, HASH_SIZE+1);
        for (i = 0; i < HORS_k && count < HORS_k; ++i)
        {
            int index = (tmp[2*i] << 8) | tmp[2*i+1];

            /* index is new, append to subset */
            if (GET_BIT(used, index) == 0)
            {
                subset->s[count] = index;
                ++count;
                SET_BIT(used, index);
            }
        }

        /* increment hash counter */
        ++buf[HASH_SIZE];
    }

    free(used);
    return GRAVITY_OK;
}

int hors_randsubset_bruteforce(const struct hash *msg, struct hors_subset *subset)
{
    uint8_t tmp[2*HASH_SIZE];
    int i, j;

    /* TODO: use PRNG instead? */
    /* compute H(msg || 0), H(msg || 1), ... */
    uint8_t buf[HASH_SIZE+1];
    memcpy(buf, msg->h, HASH_SIZE);
    buf[HASH_SIZE] = 0;

    /* number of indices collected so far */
    int count = 0;
    while (count < HORS_k)
    {
        /* tmp = H(msg || counter) */
        hash_to_2N(tmp, buf, HASH_SIZE+1);
        for (i = 0; i < HORS_k && count < HORS_k; ++i)
        {
            /* unoptimized check if index is new */
            int index = (tmp[2*i] << 8) | tmp[2*i+1];
            for (j = 0; j < count; ++j)
            {
                if (subset->s[j] == index)
                    break;
            }

            /* index is new, append to subset */
            if (j == count)
            {
                subset->s[count] = index;
                ++count;
            }
        }

        /* increment counter */
        ++buf[HASH_SIZE];
    }

    return GRAVITY_OK;
}

int hors_randsubset_weak(const struct hash *msg, struct hors_subset *subset)
{
    uint8_t tmp[2*HASH_SIZE];
    int i;
    /* Original construction */
    hash_N_to_2N(tmp, msg);
    for (i = 0; i < HORS_k; ++i)
    {
        int index = (tmp[2*i] << 8) | tmp[2*i+1];
        subset->s[i] = index;
    }

    return GRAVITY_OK;
}

int hors_randsubset(const struct hash *msg, struct hors_subset *subset)
{
#ifdef HORS_STRONG
    return hors_randsubset_collect(msg, subset);
#else
    return hors_randsubset_weak(msg, subset);
#endif
}

