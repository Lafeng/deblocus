// +build amd64

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

#if __SSE2__
#include <emmintrin.h>
#define VEC __m128i
#define VECP(x) ((__m128i *)(x))
#define LOAD128(m) _mm_loadu_si128(m)
#define XOR128(a, b) _mm_xor_si128(LOAD128(a), LOAD128(b))
#define STORE128(m, r) _mm_storeu_si128(m, r)
#define V16XOR(d, a, b) STORE128(d, XOR128(a, b))
#else
#error SSE2 required
#endif

#ifndef uint8_t
# define uint8_t unsigned char
#endif
#ifdef __GNUC__
#define FORCE_INLINE __attribute__((always_inline)) inline
#else
#define FORCE_INLINE inline
#endif

#define U8P(x) ((uint8_t *)x)
#define	CHACHA_BLOCK_SIZE  64
#define	CHACHA_STREAM_SIZE 512

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
	unsigned char buffer[CHACHA_BLOCK_SIZE];
	unsigned char stream[CHACHA_STREAM_SIZE];
	size_t offset;
} chacha_state_internal;

int chacha_startup(void);

size_t chacha_update(chacha_state_internal *S, const unsigned char *in, unsigned char *out, size_t inlen);

size_t chacha_final(chacha_state_internal *S, unsigned char *out);

void chacha(const chacha_key *key, const chacha_iv *iv, const  unsigned char *in,  unsigned char *out, size_t inlen, size_t rounds);

int is_aligned(const void* addr, size_t n) {
	return ((size_t)addr) & (n-1);
}

static FORCE_INLINE void 
fastXORBytes(uint8_t *dst, uint8_t *a, uint8_t *b, size_t rem)
{
	size_t n = rem/16, *dw, *aw, *bw;
	VEC *v0 = VECP(dst), *v1 = VECP(a), *v2 = VECP(b);
	if (n > 0) {
		rem -= n*16;
		while (n--) V16XOR(v0++, v1++, v2++);
	}
	dw = (size_t *)v0, aw = (size_t *)v1, bw = (size_t *)v2;
	if (rem >= 8) {
		rem -= 8;
		*dw++ = *aw++ ^ *bw++;
	}
	if (rem > 0) {
		dst = U8P(dw), a = U8P(aw), b = U8P(bw);
		while (rem--) *dst++ = *a++ ^ *b++;
	}
}

void chacha_xor(chacha_state_internal *state, unsigned char *in, unsigned char *out, size_t inlen)
{
	size_t rem, step, j = state->offset;
	while (inlen > 0) {
		rem = CHACHA_STREAM_SIZE - j;
		step = rem <= inlen ? rem : inlen;
		inlen -= step;
		
		fastXORBytes(out, in, state->stream + j, step);
		out += step;
		in += step;
		j += step;
	
		if (j == CHACHA_STREAM_SIZE) {
			chacha_update(state, NULL, state->stream, CHACHA_STREAM_SIZE);
			j = state->offset = 0;
		} else {
			state->offset = j;
		}
	}
}

#endif /* CHACHA_H */
