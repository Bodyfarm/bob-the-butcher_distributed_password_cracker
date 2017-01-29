#define INASM
#include "params.h"

#ifdef UNDERSCORES
# define mdfivemmx	_mdfivemmx
#endif

.globl mdfivemmx

.data
.align(16)
const_init_a: ; .long 0x67452301 ; .long 0x67452301 ; .long 0x67452301 ; .long 0x67452301
const_init_b: ; .long 0xefcdab89 ; .long 0xefcdab89 ; .long 0xefcdab89 ; .long 0xefcdab89
const_init_c: ; .long 0x98badcfe ; .long 0x98badcfe ; .long 0x98badcfe ; .long 0x98badcfe
const_init_d: ; .long 0x10325476 ; .long 0x10325476 ; .long 0x10325476 ; .long 0x10325476
storea: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storeb: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storec: ; .long 0 ; .long 0 ; .long 0 ; .long 0
stored: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storea2: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storeb2: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storec2: ; .long 0 ; .long 0 ; .long 0 ; .long 0
stored2: ; .long 0 ; .long 0 ; .long 0 ; .long 0

#include "stages_sse2_md5.S"

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

//#define G_MMX(x, y, z)			(y ^ (z & (x ^ y)))

#define G(x,y,z,x2,y2,z2) \
	movapd y, tmp1; \
	movapd y2, tmp12; \
	pxor x, tmp1; \
	pxor x2, tmp12; \
	pand z, tmp1; \
	pand z2, tmp12; \
	pxor y, tmp1; \
	pxor y2, tmp12

//#define H_MMX(x, y, z)			(x ^ y ^ z)
#define H(x,y,z,x2,y2,z2) \
	movapd x, tmp1; \
	movapd x2, tmp12; \
	pxor y, tmp1; \
	pxor y2, tmp12; \
	pxor z, tmp1; \
	pxor z2, tmp12

//#define I(x, y, z)			(y ^ (x | ~z))
#define I(x, y, z, x2, y2, z2) \
	movapd z, tmp1; \
	movapd z2, tmp12; \
	pandn tmp4, tmp1; \
	pandn tmp42, tmp12; \
	por x, tmp1; \
	por x2, tmp12; \
	pxor y, tmp1; \
	pxor y2, tmp12


//#define STEP_MMX(f, a, b, c, d, x, s) \
//	(a) += f((b), (c), (d)) + (x); \
//	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

//#define STEP(f, a, b, c, d, x, t, s) \
//	(a) += f((b), (c), (d)) + (x) + (t); \
//	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
//	(a) += (b);


#define STEP(f, a, b, c, d, x, t, s, a2, b2, c2, d2) \
	f(b, c, d, b2, c2, d2); \
	paddd (x*4*MMX_COEF)(%rsi), tmp1; \
	paddd (x*4*MMX_COEF+16)(%rsi), tmp12; \
	paddd t, a; \
	paddd t, a2; \
	paddd tmp1, a; \
	paddd tmp12, a2; \
	movapd a, tmp3; \
	movapd a2, tmp32; \
	psrld $(32-s), tmp3; \
	psrld $(32-s), tmp32; \
	pslld $s, a; \
	pslld $s, a2; \
	por tmp3, a; \
	por tmp32, a2; \
	paddd b, a; \
	paddd b2, a2

.text
/*
 * Try to do some asm md4 w/ mmx
 * %eax ptr -> out -> %rdi
 * %edx ptr -> in -> %rsi
 * %ecx n  
 */

init:
	movapd const_init_a, ctxa
	movapd const_init_b, ctxb
	movapd const_init_c, ctxc
	movapd const_init_d, ctxd
	movapd const_init_a, ctxa2
	movapd const_init_b, ctxb2
	movapd const_init_c, ctxc2
	movapd const_init_d, ctxd2
	ret;

//entry points
mdfivemmx:
	push %rbx
	call init

mdfivemmx_noinit:
	pcmpeqd tmp4, tmp4;
	pcmpeqd tmp42, tmp42;
	
	movapd ctxa, storea
	movapd ctxb, storeb
	movapd ctxc, storec
	movapd ctxd, stored
	movapd ctxa2, storea2
	movapd ctxb2, storeb2
	movapd ctxc2, storec2
	movapd ctxd2, stored2
	
	STEP(F, ctxa, ctxb, ctxc, ctxd, 0, const_stage_1, 7, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(F, ctxd, ctxa, ctxb, ctxc, 1, const_stage_2, 12, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(F, ctxc, ctxd, ctxa, ctxb, 2, const_stage_3, 17, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(F, ctxb, ctxc, ctxd, ctxa, 3, const_stage_4, 22, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(F, ctxa, ctxb, ctxc, ctxd, 4, const_stage_5, 7, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(F, ctxd, ctxa, ctxb, ctxc, 5, const_stage_6, 12, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(F, ctxc, ctxd, ctxa, ctxb, 6, const_stage_7, 17, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(F, ctxb, ctxc, ctxd, ctxa, 7, const_stage_8, 22, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(F, ctxa, ctxb, ctxc, ctxd, 8, const_stage_9, 7, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(F, ctxd, ctxa, ctxb, ctxc, 9, const_stage_10, 12, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(F, ctxc, ctxd, ctxa, ctxb, 10, const_stage_11, 17, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(F, ctxb, ctxc, ctxd, ctxa, 11, const_stage_12, 22, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(F, ctxa, ctxb, ctxc, ctxd, 12, const_stage_13, 7, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(F, ctxd, ctxa, ctxb, ctxc, 13, const_stage_14, 12, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(F, ctxc, ctxd, ctxa, ctxb, 14, const_stage_15, 17, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(F, ctxb, ctxc, ctxd, ctxa, 15, const_stage_16, 22, ctxb2, ctxc2, ctxd2, ctxa2)

	STEP(G, ctxa, ctxb, ctxc, ctxd, 1, const_stage_17, 5, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(G, ctxd, ctxa, ctxb, ctxc, 6, const_stage_18, 9, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(G, ctxc, ctxd, ctxa, ctxb, 11, const_stage_19, 14, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(G, ctxb, ctxc, ctxd, ctxa, 0, const_stage_20, 20, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(G, ctxa, ctxb, ctxc, ctxd, 5, const_stage_21, 5, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(G, ctxd, ctxa, ctxb, ctxc, 10, const_stage_22, 9, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(G, ctxc, ctxd, ctxa, ctxb, 15, const_stage_23, 14, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(G, ctxb, ctxc, ctxd, ctxa, 4, const_stage_24, 20, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(G, ctxa, ctxb, ctxc, ctxd, 9, const_stage_25, 5, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(G, ctxd, ctxa, ctxb, ctxc, 14, const_stage_26, 9, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(G, ctxc, ctxd, ctxa, ctxb, 3, const_stage_27, 14, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(G, ctxb, ctxc, ctxd, ctxa, 8, const_stage_28, 20, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(G, ctxa, ctxb, ctxc, ctxd, 13, const_stage_29, 5, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(G, ctxd, ctxa, ctxb, ctxc, 2, const_stage_30, 9, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(G, ctxc, ctxd, ctxa, ctxb, 7, const_stage_31, 14, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(G, ctxb, ctxc, ctxd, ctxa, 12, const_stage_32, 20, ctxb2, ctxc2, ctxd2, ctxa2)

	STEP(H, ctxa, ctxb, ctxc, ctxd, 5, const_stage_33, 4, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(H, ctxd, ctxa, ctxb, ctxc, 8, const_stage_34, 11, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(H, ctxc, ctxd, ctxa, ctxb, 11, const_stage_35, 16, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(H, ctxb, ctxc, ctxd, ctxa, 14, const_stage_36, 23, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(H, ctxa, ctxb, ctxc, ctxd, 1, const_stage_37, 4, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(H, ctxd, ctxa, ctxb, ctxc, 4, const_stage_38, 11, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(H, ctxc, ctxd, ctxa, ctxb, 7, const_stage_39, 16, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(H, ctxb, ctxc, ctxd, ctxa, 10, const_stage_40, 23, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(H, ctxa, ctxb, ctxc, ctxd, 13, const_stage_41, 4, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(H, ctxd, ctxa, ctxb, ctxc, 0, const_stage_42, 11, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(H, ctxc, ctxd, ctxa, ctxb, 3, const_stage_43, 16, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(H, ctxb, ctxc, ctxd, ctxa, 6, const_stage_44, 23, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(H, ctxa, ctxb, ctxc, ctxd, 9, const_stage_45, 4, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(H, ctxd, ctxa, ctxb, ctxc, 12, const_stage_46, 11, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(H, ctxc, ctxd, ctxa, ctxb, 15, const_stage_47, 16, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(H, ctxb, ctxc, ctxd, ctxa, 2, const_stage_48, 23, ctxb2, ctxc2, ctxd2, ctxa2)

	STEP(I, ctxa, ctxb, ctxc, ctxd, 0, const_stage_49, 6, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(I, ctxd, ctxa, ctxb, ctxc, 7, const_stage_50, 10, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(I, ctxc, ctxd, ctxa, ctxb, 14, const_stage_51, 15, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(I, ctxb, ctxc, ctxd, ctxa, 5, const_stage_52, 21, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(I, ctxa, ctxb, ctxc, ctxd, 12, const_stage_53, 6, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(I, ctxd, ctxa, ctxb, ctxc, 3, const_stage_54, 10, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(I, ctxc, ctxd, ctxa, ctxb, 10, const_stage_55, 15, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(I, ctxb, ctxc, ctxd, ctxa, 1, const_stage_56, 21, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(I, ctxa, ctxb, ctxc, ctxd, 8, const_stage_57, 6, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(I, ctxd, ctxa, ctxb, ctxc, 15, const_stage_58, 10, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(I, ctxc, ctxd, ctxa, ctxb, 6, const_stage_59, 15, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(I, ctxb, ctxc, ctxd, ctxa, 13, const_stage_60, 21, ctxb2, ctxc2, ctxd2, ctxa2)
	STEP(I, ctxa, ctxb, ctxc, ctxd, 4, const_stage_61, 6, ctxa2, ctxb2, ctxc2, ctxd2)
	STEP(I, ctxd, ctxa, ctxb, ctxc, 11, const_stage_62, 10, ctxd2, ctxa2, ctxb2, ctxc2)
	STEP(I, ctxc, ctxd, ctxa, ctxb, 2, const_stage_63, 15, ctxc2, ctxd2, ctxa2, ctxb2)
	STEP(I, ctxb, ctxc, ctxd, ctxa, 9, const_stage_64, 21, ctxb2, ctxc2, ctxd2, ctxa2)

	paddd storea, ctxa
	paddd storeb, ctxb
	paddd storec, ctxc
	paddd stored, ctxd
	paddd storea2, ctxa2
	paddd storeb2, ctxb2
	paddd storec2, ctxc2
	paddd stored2, ctxd2

fin:
	movapd ctxa, 0(%rdi)
	movapd ctxa2, (16)(%rdi)
	//movapd ctxa, storea
	movapd ctxb, (4*MMX_COEF)(%rdi)
	movapd ctxb2, (4*MMX_COEF+16)(%rdi)
	//movapd ctxb, storeb
	movapd ctxc, (8*MMX_COEF)(%rdi)
	movapd ctxc2, (8*MMX_COEF+16)(%rdi)
	//movapd ctxc, storec
	movapd ctxd, (12*MMX_COEF)(%rdi)
	movapd ctxd2, (12*MMX_COEF+16)(%rdi)
	//movapd ctxd, stored

	pop %rbx

	emms
	
	ret

