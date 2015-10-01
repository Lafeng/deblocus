// +build cgo

#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>
#include <stdint.h>

enum chacha_constants {
	CHACHA_BLOCKBYTES = 64,
};


typedef struct chacha_key_t {
	unsigned char b[32];
} chacha_key;

typedef struct chacha_iv_t {
	unsigned char b[8];
} chacha_iv;

typedef struct chacha_state_internal_t {
	unsigned char s[48];
	size_t rounds;
	size_t leftover;
	unsigned char buffer[CHACHA_BLOCKBYTES];
} chacha_state_internal;


int chacha_startup(void);

size_t chacha_update(chacha_state_internal *S, const unsigned char *in, unsigned char *out, size_t inlen);

size_t chacha_final(chacha_state_internal *S, unsigned char *out);

void chacha(const chacha_key *key, const chacha_iv *iv, const  unsigned char *in,  unsigned char *out, size_t inlen, size_t rounds);

void chacha_next(const chacha_key *key, const chacha_iv *iv, const  unsigned char *in,  unsigned char *out, size_t inlen, size_t rounds)
{
	chacha(key, iv, in, out, inlen, rounds);
	// Reset IV
	uint32_t *iv4 = (uint32_t *)iv;
	uint8_t shift = *iv4 & 0xf;
	*(iv4++) ^= (uint32_t)(inlen * 16777619) >> shift;
	*iv4 ^= (*iv4 >> shift ) * 16777619;
}

#endif /* CHACHA_H */