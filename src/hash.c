#include "hash.h"

#include "blake2.h"
#include <string.h>

void hash_N_to_N(struct hash *dst, const struct hash *src)
{
    blake2b(dst->h, HASH_SIZE, src->h, HASH_SIZE, NULL, 0);
}

void hash_N_to_2N(uint8_t *dst, const struct hash *src)
{
    blake2b(dst, 2*HASH_SIZE, src->h, HASH_SIZE, NULL, 0);
}

void hash_2N_to_N(struct hash *dst, const uint8_t *src)
{
    blake2b(dst->h, HASH_SIZE, src, 2*HASH_SIZE, NULL, 0);
}

void hash_to_N(struct hash *dst, const uint8_t *src, uint64_t srclen)
{
    blake2b(dst->h, HASH_SIZE, src, srclen, NULL, 0);
}

void hash_to_2N(uint8_t *dst, const uint8_t *src, uint64_t srclen)
{
    blake2b(dst, 2*HASH_SIZE, src, srclen, NULL, 0);
}


void hash_keyed_to_N(struct hash *dst, const uint8_t *src, uint64_t srclen, const struct hash *key)
{
    blake2b(dst->h, HASH_SIZE, src, srclen, key->h, HASH_SIZE);
}

void hash_keyed_to_2N(uint8_t *dst, const uint8_t *src, uint64_t srclen, const struct hash *key)
{
    blake2b(dst, 2*HASH_SIZE, src, srclen, key->h, HASH_SIZE);
}


void hash_compress_pairs(struct hash *dst, const struct hash *src, int count)
{
    /* TODO: parallel implementation? */
    int i;
    for (i = 0; i < count; ++i)
        hash_2N_to_N(&dst[i], src[2*i].h);
}

void hash_compress_all(struct hash *dst, const struct hash *src, int count)
{
    /* Fast implementation with a single call to a large input hash function */
    hash_to_N(dst, src->h, count * HASH_SIZE);
    /* TODO: implement a real L-tree with 2N->N compression function */
}


int hashcmp(const struct hash *a, const struct hash *b)
{
    return memcmp(a->h, b->h, HASH_SIZE);
}

void hashcpy(struct hash *dst, const struct hash *src)
{
    memcpy(dst->h, src->h, HASH_SIZE);
}

