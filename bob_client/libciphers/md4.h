/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Written by Solar Designer <solar at openwall.com> in 2005, and placed
 * in the public domain.  See md4.c for more information.
 */

#ifdef HAVE_OPENSSL
#include <openssl/md4.h>
#elif !defined(_MD4_H)
#define _MD4_H

/* Any 32-bit or wider unsigned integer data type will do */
typedef uint32_t MD4_u32plus;

typedef struct {
	MD4_u32plus lo, hi;
	MD4_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD4_u32plus block[16];
} MD4_CTX;

extern void MD4_Init(MD4_CTX *ctx);
extern void MD4_Update(MD4_CTX *ctx, void *data, uint32_t size);
extern void MD4_Final(unsigned char *result, MD4_CTX *ctx);

//added by bartavelle
extern void mdfour(unsigned char *out, unsigned char *in, int n);
#ifdef MMX_COEF
extern int mdfourmmx(unsigned char *out, unsigned char *in, int n) __attribute__ ((regparm(3)));
#endif
#endif
