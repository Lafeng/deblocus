#ifndef OPENSSL_HEADER_MAIN_H
#define OPENSSL_HEADER_MAIN_H

#include "openssl/base.h"
#include "openssl/aead.h"
#include "openssl/chacha.h"
#include "openssl/cipher.h"
#include "openssl/cpu.h"
#include "openssl/err.h"

//
// cpu.h
//

OPENSSL_EXPORT size_t read_cpuid(uint32_t *buf)
{
#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
	size_t i;
	for (i = 0; i < 4; i++) {
		buf[i] = OPENSSL_ia32cap_P[i];
	}
	return i;
#elif defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
	*buf = OPENSSL_armcap_P;
	return 1;
#else
	return 0;
#endif
}

#if !(defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64))
OPENSSL_EXPORT char CRYPTO_is_NEON_capable(void)
{
	return 0;
}
#endif

#endif /* OPENSSL_HEADER_MAIN_H */