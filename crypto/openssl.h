#ifndef OPENSSL_HEADER_MAIN_H
#define OPENSSL_HEADER_MAIN_H

#include "openssl/base.h"
#include "openssl/aead.h"
#include "openssl/cipher.h"
#include "openssl/chacha.h"
#include "openssl/cpu.h"
#include "openssl/err.h"

//
// cpu.h
//

OPENSSL_EXPORT uint32_t* CPU_features()
{
#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
	return OPENSSL_ia32cap_P;
#else
	return NULL;
#endif
}

#if !(defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64))
OPENSSL_EXPORT char CRYPTO_is_NEON_capable(void)
{
	return 0;
}
#endif

#endif /* OPENSSL_HEADER_MAIN_H */