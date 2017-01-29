#ifndef  __MD5_H__
# define __MD5_H__

/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm.
 *
 * Written by Solar Designer <solar@openwall.com> in 2001, and placed in
 * the public domain.  See md5.c for more information.
 */

/* Any 32-bit or wider unsigned integer data type will do */
typedef struct {
	uint32_t lo, hi;
	uint32_t a, b, c, d;
	unsigned char buffer[64];
	uint32_t block[16];
} MD5_CTX;

extern void MD5_Init(MD5_CTX *ctx);
extern void MD5_Update(MD5_CTX *ctx, void *data, unsigned long size);
extern void MD5_Final(unsigned char *result, MD5_CTX *ctx);

#ifdef MMX_COEF
extern int mdfivemmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_nosizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_noinit_sizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_noinit_uniformsizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
#endif

#endif
