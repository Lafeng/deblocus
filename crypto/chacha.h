// +build cgo

#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>

// Ref: https://gist.github.com/nicky-zs/7541169
#if defined(__GNUC__) && defined(__linux)
#include <string.h>

void *__memcpy_glibc_2_2_5(void *, const void *, size_t);

asm(".symver __memcpy_glibc_2_2_5, memcpy@GLIBC_2.2.5");
void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
    return __memcpy_glibc_2_2_5(dest, src, n); 
}
#endif

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
	size_t i = n, w = n / wordSize;
	if (w > 0) {
		for (i = w; i--; *(dst++) = *(a++) ^ *(b++));
		i = n - w*wordSize;
	}
	if (i > 0) {
		uint8_t *d8 = (uint8_t *)dst, *a8 = (uint8_t *)a, *b8 = (uint8_t *)b;
		for (; i--; *(d8++) = *(a8++) ^ *(b8++));
	}
}

int chacha_startup(void);

size_t chacha_update(chacha_state_internal *S, const unsigned char *in, unsigned char *out, size_t inlen);

size_t chacha_final(chacha_state_internal *S, unsigned char *out);

void chacha(const chacha_key *key, const chacha_iv *iv, const  unsigned char *in,  unsigned char *out, size_t inlen, size_t rounds);

void chacha_xor(chacha_state_internal *state, unsigned char *in, unsigned char *out, const size_t inlen)
{
	size_t i, j, rem, step;
	j = state->offset;
	for (i = 0; i < inlen; ) {
		rem = CHACHA_BLOCKBYTES - j;
		step = rem <= (inlen-i) ? rem : (inlen-i);
		
		fastXORBytes((size_t *)out, (size_t *)in, (size_t *)(state->stream + j), step);
		i += step;
		j += step;
		out += step;
		in += step;
	
		if (j == CHACHA_BLOCKBYTES) {
			chacha_update(state, state->stream, state->stream, CHACHA_BLOCKBYTES);
			j = state->offset = 0;
		} else {
			state->offset = j;
		}
	}
}

#endif /* CHACHA_H */
