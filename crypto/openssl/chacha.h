/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_CHACHA_H
#define OPENSSL_HEADER_CHACHA_H

#include <openssl/base.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define	CHACHA_STREAM_SIZE 512

typedef struct chacha_state_t {
	uint32_t state[16];
	uint32_t stream[CHACHA_STREAM_SIZE/4];
	size_t rounds;
	size_t offset;
} chacha_state;

/* CRYPTO_chacha_20 encrypts |in_len| bytes from |in| with the given key and
 * nonce and writes the result to |out|, which may be equal to |in|. The
 * initial block counter is specified by |counter|. */
OPENSSL_EXPORT void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in,
                                     size_t in_len, const uint8_t key[32],
                                     const uint8_t nonce[8], size_t counter);

OPENSSL_EXPORT void
CRYPTO_chacha_init(uint32_t *state, uint8_t *key, uint8_t *iv) ;

OPENSSL_EXPORT void
CRYPTO_neon_chacha_core(uint32_t *keystream, uint32_t *state, size_t len, size_t rounds);

OPENSSL_EXPORT void
CRYPTO_neon_chacha_xor(chacha_state *cs, uint8_t *in, uint8_t *out, size_t inlen);

#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_CHACHA_H */
