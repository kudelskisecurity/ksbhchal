#include "prng.h"

#include "blabla.h"

void prng_gen(const struct hash *seed, const uint8_t nonce[16], uint8_t *out, uint64_t outlen)
{
    blabla_keystream (out, outlen, nonce, seed->h);
}

