#pragma once

#include <stdint.h>
#include <stdio.h>

#define N 32
#define K 8
#define TAU 9
#define T (1 << (TAU))

#define SIGLEN ((K*N) + (K*TAU*N) + N)
#define PATHS(s) (s+(K*N))
#define SEED(s) (s+SIGLEN-N)

#define HCPY(dst,src) memcpy(dst, src, N)

void gensk(const uint8_t *seed, uint8_t *sk);

int genpk(const uint8_t *sk, uint8_t *pk);

int sign(const uint8_t *sk, uint8_t *sign, const uint8_t *msg);

int verify(const uint8_t *pk, const uint8_t *sign, const uint8_t *msg);

void getsubset(const uint8_t *msg, const uint8_t *seed, int *subset);

void printbytes(const uint8_t *m, int len);
