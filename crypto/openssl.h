#ifndef OPENSSL_HEADER_MAIN_H
#define OPENSSL_HEADER_MAIN_H

#include "openssl/base.h"
#include "openssl/aead.h"
#include "openssl/cipher.h"
#include "openssl/err.h"

//
// cpu.h
//


/* Runtime CPU feature support */

/* OPENSSL_ia32cap_P contains the Intel CPUID bits when running on an x86 or
 * x86-64 system.
 *
 *   Index 0:
 *     EDX for CPUID where EAX = 1
 *     Bit 20 is always zero
 *     Bit 28 is adjusted to reflect whether the data cache is shared between
 *       multiple logical cores
 *     Bit 30 is used to indicate an Intel CPU
 *   Index 1:
 *     ECX for CPUID where EAX = 1
 *     Bit 11 is used to indicate AMD XOP support, not SDBG
 *   Index 2:
 *     EBX for CPUID where EAX = 7
 *   Index 3 is set to zero.
 *
 * Note: the CPUID bits are pre-adjusted for the OSXSAVE bit and the YMM and XMM
 * bits in XCR0, so it is not necessary to check those. */
extern uint32_t OPENSSL_ia32cap_P[4];

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
OPENSSL_EXPORT char CRYPTO_is_NEON_capable(void);
#else
OPENSSL_EXPORT char CRYPTO_is_NEON_capable(void)
{
	return 0;
}
#endif


#endif /* OPENSSL_HEADER_MAIN_H */