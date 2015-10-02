// +build cgo

#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>

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
	unsigned char stream[CHACHA_BLOCKBYTES];
	size_t offset;
} chacha_state_internal;

#ifndef INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define INLINE extern inline
# else
#  define INLINE inline
# endif
#endif
#ifndef uint8_t
# define uint8_t unsigned char
#endif

const size_t wordSize = sizeof(void*);

INLINE void 
fastXORBytes(size_t *dst, size_t *a, size_t *b, size_t n)
{
	size_t i = 0, w = n / wordSize;
	if (w > 0) {
		for (i = 0; i < w; i++) {
			dst[i] = a[i] ^ b[i];
		}
		i *= wordSize;
	}
	if (i < n) {
		uint8_t *d8 = (uint8_t *)dst, *a8 = (uint8_t *)a, *b8 = (uint8_t *)b;
		for (; i < n; i++) {
			d8[i] = a8[i] ^ b8[i];
		}
	}
}

int chacha_startup(void);

size_t chacha_update(chacha_state_internal *S, const unsigned char *in, unsigned char *out, size_t inlen);

size_t chacha_final(chacha_state_internal *S, unsigned char *out);

void chacha(const chacha_key *key, const chacha_iv *iv, const  unsigned char *in,  unsigned char *out, size_t inlen, size_t rounds);

void chacha_xor(chacha_state_internal *state, const unsigned char *in, unsigned char *out, const size_t inlen)
{
	size_t i, j, rem, step;
	j = state->offset;
	for (i = 0; i < inlen; ) {
		rem = CHACHA_BLOCKBYTES - j;
		step = rem <= (inlen-i) ? rem : (inlen-i);
		
		fastXORBytes((size_t *)(out + i), (size_t *)(in + i), (size_t *)(state->stream + j), step);
		i += step;
		j += step;
	
		if (j == CHACHA_BLOCKBYTES) {
			chacha_update(state, state->stream, state->stream, CHACHA_BLOCKBYTES);
			j = state->offset = 0;
		} else {
			state->offset = j;
		}
	}
}

#endif /* CHACHA_H */