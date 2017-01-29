
// extern int mdfoursse2(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
#define INASM
#include "params.h"

#ifdef UNDERSCORES
#define mdfourmmx	_mdfourmmx
#endif

.globl mdfourmmx

.data
.align(16)
const_init_a:
.long 0x67452301
.long 0x67452301
.long 0x67452301
.long 0x67452301
const_init_b:
.long 0xefcdab89
.long 0xefcdab89
.long 0xefcdab89
.long 0xefcdab89
const_init_c:
.long 0x98badcfe
.long 0x98badcfe
.long 0x98badcfe
.long 0x98badcfe
const_init_d:
.long 0x10325476
.long 0x10325476
.long 0x10325476
.long 0x10325476

const_stage2:
.long 0x5a827999
.long 0x5a827999
.long 0x5a827999
.long 0x5a827999
const_stage3:
.long 0x6ed9eba1
.long 0x6ed9eba1
.long 0x6ed9eba1
.long 0x6ed9eba1

.align(16)

#define ctxa %xmm0
#define ctxb %xmm1
#define ctxc %xmm2
#define ctxd %xmm3
#define tmp1 %xmm4
#define tmp2 %xmm5
#define tmp3 %xmm6
#define tmp4 %xmm7

#define ctxa2 %xmm8
#define ctxb2 %xmm9
#define ctxc2 %xmm10
#define ctxd2 %xmm11
#define tmp12 %xmm12
#define tmp22 %xmm13
#define tmp32 %xmm14
#define tmp42 %xmm15


//#define F_MMX(x, y, z)			(z ^ (x & (y ^ z)))

#define F(x,y,z,x2,y2,z2) \
	movapd y, tmp1; \
	movapd y2, tmp12; \
	pxor z, tmp1; \
	pxor z2, tmp12; \
	pand x, tmp1; \
	pand x2, tmp12; \
	pxor z, tmp1; \
	pxor z2, tmp12

//#define G_MMX(x, y, z)			((x & (y | z)) | (y & z))

#define G(x,y,z,x2,y2,z2) \
	movapd y, tmp1; \
	movapd y2, tmp12; \
	movapd y, tmp2; \
	movapd y2, tmp22; \
	por z, tmp1; \
	por z2, tmp12; \
	pand z, tmp2; \
	pand z2, tmp22; \
	pand x, tmp1; \
	pand x2, tmp12; \
	por tmp2, tmp1; \
	por tmp22, tmp12

//#define H_MMX(x, y, z)			(x ^ y ^ z)
#define H(x,y,z,x2,y2,z2) \
	movapd x, tmp1; \
	movapd x2, tmp12; \
	pxor y, tmp1; \
	pxor y2, tmp12; \
	pxor z, tmp1; \
	pxor z2, tmp12

//#define STEP_MMX(f, a, b, c, d, x, s) \
//	(a) += f((b), (c), (d)) + (x); \
//	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

#define STEP1(f, a, b, c, d, x, s, a2, b2, c2, d2) \
	f(b, c, d, b2, c2, d2); \
	paddd (x*32)(%rsi), tmp1; \
	paddd (x*32+16)(%rsi), tmp12; \
	paddd tmp1, a; \
	paddd tmp12, a2; \
	movapd a, tmp3; \
	movapd a2, tmp32; \
	pslld $s, a; \
	pslld $s, a2; \
	psrld $(32-s), tmp3; \
	psrld $(32-s), tmp32; \
	por tmp3, a; \
	por tmp32, a2

#define STEP2(f, a, b, c, d, x, s, a2, b2, c2, d2) \
	f(b, c, d, b2, c2, d2); \
	paddd (x*32)(%rsi), tmp1; \
	paddd (x*32+16)(%rsi), tmp12; \
	paddd tmp4, tmp1; \
	paddd tmp4, tmp12; \
	paddd tmp1, a; \
	paddd tmp12, a2; \
	movapd a, tmp3; \
	movapd a2, tmp32; \
	pslld $s, a; \
	pslld $s, a2; \
	psrld $(32-s), tmp3; \
	psrld $(32-s), tmp32; \
	por tmp3, a; \
	por tmp32, a2


.text
/*
 * Try to do some asm md4 w/ sse2
 * %eax ptr -> out
 * %edx ptr -> in
 * %ecx n
 */

mdfourmmx:
	//MD4 Init
	// output = %rdi <- eax
	// saved plain = %rsi <- edx
	// length = edx  <- ecx
	
	push %rbx

	movapd const_init_a, ctxa
	movapd const_init_b, ctxb
	movapd const_init_c, ctxc
	movapd const_init_d, ctxd
	movapd const_init_a, ctxa2
	movapd const_init_b, ctxb2
	movapd const_init_c, ctxc2
	movapd const_init_d, ctxd2

	STEP1(F, ctxa, ctxb, ctxc, ctxd, 0, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 1, 7, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 2, 11, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 3, 19, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 4, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 5, 7, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 6, 11, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 7, 19, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 8, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 9, 7, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 10, 11, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 11, 19, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 12, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 13, 7, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 14, 11, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 15, 19, ctxb2, ctxc2, ctxd2, ctxa2)
	
	movapd const_stage2, tmp4

	STEP2(G, ctxa, ctxb, ctxc, ctxd, 0, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 4, 5, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 8, 9, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 12, 13, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 1, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 5, 5, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 9, 9, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 13, 13, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 2, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 6, 5, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 10, 9, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 14, 13, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 3, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 7, 5, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 11, 9, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 15, 13, ctxb2, ctxc2, ctxd2, ctxa2)

	movapd const_stage3, tmp4

	STEP2(H, ctxa, ctxb, ctxc, ctxd, 0, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 8, 9, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 4, 11, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 12, 15, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 2, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 10, 9, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 6, 11, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 14, 15, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 1, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 9, 9, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 5, 11, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 13, 15, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 3, 3, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 11, 9, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 7, 11, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 15, 15, ctxb2, ctxc2, ctxd2, ctxa2)

	paddd const_init_a, ctxa
	paddd const_init_b, ctxb
	paddd const_init_c, ctxc
	paddd const_init_d, ctxd
	paddd const_init_a, ctxa2
	paddd const_init_b, ctxb2
	paddd const_init_c, ctxc2
	paddd const_init_d, ctxd2
fin:
	movapd ctxa, 0(%rdi)
	movapd ctxa2, 16(%rdi)
	movapd ctxb, 32(%rdi)
	movapd ctxb2, 48(%rdi)
	movapd ctxc, 64(%rdi)
	movapd ctxc2, 80(%rdi)
	movapd ctxd, 96(%rdi)
	movapd ctxd2, 112(%rdi)

	pop %rbx
	movd ctxa, %rax
	emms
	
	ret

