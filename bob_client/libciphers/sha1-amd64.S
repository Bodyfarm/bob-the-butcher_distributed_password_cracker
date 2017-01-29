
#define INASM
// extern int mdfourmmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));

#include "params.h"

#ifdef UNDERSCORES
#define shammx	_shammx
#endif

.globl shammx;

.data
.align(8*MMX_COEF)
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
const_init_e:
.long 0xc3d2e1f0
.long 0xc3d2e1f0
.long 0xc3d2e1f0
.long 0xc3d2e1f0

.align(8*MMX_COEF)
const_stage0:
.long 0x5a827999
.long 0x5a827999
.long 0x5a827999
.long 0x5a827999
const_stage1:
.long 0x6ed9eba1
.long 0x6ed9eba1
.long 0x6ed9eba1
.long 0x6ed9eba1
const_stage2:
.long 0x8f1bbcdc
.long 0x8f1bbcdc
.long 0x8f1bbcdc
.long 0x8f1bbcdc
const_stage3:
.long 0xca62c1d6
.long 0xca62c1d6
.long 0xca62c1d6
.long 0xca62c1d6

.align(8*MMX_COEF)
mask0f0f:
.long 0x00ff00ff
.long 0x00ff00ff
.long 0x00ff00ff
.long 0x00ff00ff
maskf0f0:
.long 0xff00ff00
.long 0xff00ff00
.long 0xff00ff00
.long 0xff00ff00

storea: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storeb: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storec: ; .long 0 ; .long 0 ; .long 0 ; .long 0
stored: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storee: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storea2: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storeb2: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storec2: ; .long 0 ; .long 0 ; .long 0 ; .long 0
stored2: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storee2: ; .long 0 ; .long 0 ; .long 0 ; .long 0

#define ctxa %xmm0
#define ctxb %xmm1
#define ctxc %xmm2
#define ctxd %xmm3
#define ctxe %xmm4
#define tmp1 %xmm5
#define tmp2 %xmm6
#define tmp3 %xmm7
#define ctxa2 %xmm8
#define ctxb2 %xmm9
#define ctxc2 %xmm10
#define ctxd2 %xmm11
#define ctxe2 %xmm12
#define tmp12 %xmm13
#define tmp22 %xmm14
#define tmp32 %xmm15

//ft(x,y,z) = (x AND y) OR ((NOT x) AND z) ( 0 <= t <= 19) 
#define F0(x,y,z,x2,y2,z2) \
	movapd x, tmp2; \
	movapd x2, tmp22; \
	movapd x, tmp1; \
	movapd x2, tmp12; \
	pand y, tmp2; \
	pand y2, tmp22; \
	pandn z, tmp1; \
	pandn z2, tmp12; \
	por tmp2, tmp1; \
	por tmp22, tmp12; 

//ft(x,y,z) = x XOR y XOR z (20 <= t <= 39)
#define F1(x,y,z,x2,y2,z2) \
	movapd z, tmp1; \
	movapd z2, tmp12; \
	pxor y, tmp1; \
	pxor y2, tmp12; \
	pxor x, tmp1; \
	pxor x2, tmp12

//ft(x,y,z) = (x AND y) OR (x AND z) OR (y AND z) (40 <= t <= 59)
//ft(x,y,z) = (x AND y) | ((x OR y) AND z) (40 <= t <= 59)
#define F2(x,y,z,x2,y2,z2) \
	movapd x, tmp1; \
	movapd x2, tmp12; \
	movapd x, tmp2; \
	movapd x2, tmp22; \
	pand y, tmp1; \
	pand y2, tmp12; \
	por y, tmp2; \
	por y2, tmp22; \
	pand z, tmp2; \
	pand z2, tmp22; \
	por tmp2, tmp1; \
	por tmp22, tmp12;
	
//ft(x,y,z) = x XOR y XOR z (60 <= t <= 79).  = la seconde


#define expand(t) \
	movapd ((t-3)*4*MMX_COEF)(%rsi), tmp1; \
	movapd ((t-3)*4*MMX_COEF+16)(%rsi), tmp12; \
	pxor ((t-8)*4*MMX_COEF)(%rsi), tmp1; \
	pxor ((t-8)*4*MMX_COEF+16)(%rsi), tmp12; \
	pxor ((t-14)*4*MMX_COEF)(%rsi), tmp1; \
	pxor ((t-14)*4*MMX_COEF+16)(%rsi), tmp12; \
	pxor ((t-16)*4*MMX_COEF)(%rsi), tmp1; \
	pxor ((t-16)*4*MMX_COEF+16)(%rsi), tmp12; \
	movapd tmp1, tmp2; \
	movapd tmp12, tmp22; \
	pslld $1, tmp1; \
	pslld $1, tmp12; \
	psrld $31, tmp2; \
	psrld $31, tmp22; \
	por tmp2, tmp1; \
	por tmp22, tmp12; \
	movapd tmp1, (t*4*MMX_COEF)(%rsi); \
	movapd tmp12, (t*4*MMX_COEF+16)(%rsi)

#define subRound(a, b, c, d, e, f, k, data, a2, b2, c2, d2, e2) \
	f(b,c,d,b2,c2,d2); \
	movapd a, tmp2; \
	movapd a2, tmp22; \
	movapd a, tmp3; \
	movapd a2, tmp32; \
	paddd tmp1, e; \
	paddd tmp12, e2; \
	pslld $5, tmp2; \
	pslld $5, tmp22; \
	psrld $27, tmp3; \
	psrld $27, tmp32; \
	por tmp3, tmp2; \
	por tmp32, tmp22; \
	paddd tmp2, e; \
	paddd tmp22, e2; \
	movapd b, tmp2; \
	movapd b2, tmp22; \
	pslld $30, b; \
	pslld $30, b2; \
	paddd k, e; \
	paddd k, e2; \
	paddd (data*4*MMX_COEF)(%rsi), e; \
	paddd (data*4*MMX_COEF+16)(%rsi), e2; \
	psrld $2, tmp2; \
	psrld $2, tmp22; \
	por tmp2, b; \
	por tmp22, b2;

#define subRoundu(a, b, c, d, e, f, k, data, a2, b2, c2, d2, e2) \
	expand(data); \
	paddd tmp1, e; \
	paddd tmp12, e2; \
	f(b,c,d,b2,c2,d2); \
	movapd a, tmp2; \
	movapd a2, tmp22; \
	movapd a, tmp3; \
	movapd a2, tmp32; \
	paddd tmp1, e; \
	paddd tmp12, e2; \
	pslld $5, tmp2; \
	pslld $5, tmp22; \
	psrld $27, tmp3; \
	psrld $27, tmp32; \
	por tmp3, tmp2; \
	por tmp32, tmp22; \
	paddd tmp2, e; \
	paddd tmp22, e2; \
	movapd b, tmp2; \
	movapd b2, tmp22; \
	pslld $30, b; \
	pslld $30, b2; \
	paddd k, e; \
	paddd k, e2; \
	psrld $2, tmp2; \
	psrld $2, tmp22; \
	por tmp2, b; \
	por tmp22, b2;

.text
/*
 * Try to do some asm md4 w/ mmx
 * %eax ptr -> out
 * %edx ptr -> in (80*MMX_WIDTH mots)
 * %ecx n
 */

init_ctx:
	movapd const_init_a, ctxa
	movapd const_init_b, ctxb
	movapd const_init_c, ctxc
	movapd const_init_d, ctxd
	movapd const_init_e, ctxe
	movapd ctxa, ctxa2
	movapd ctxb, ctxb2
	movapd ctxc, ctxc2
	movapd ctxd, ctxd2
	movapd ctxe, ctxe2
	ret

shammx:
	push %rbx
	call init_ctx

shammx_noinit:
	movapd ctxa, storea
	movapd ctxa2, storea2
	movapd ctxb, storeb
	movapd ctxb2, storeb2
	movapd ctxc, storec
	movapd ctxc2, storec2
	movapd ctxd, stored
	movapd ctxd2, stored2
	movapd ctxe, storee
	movapd ctxe2, storee2

round0:
	//prefetchnta (%rdi)
	subRound( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0,   0, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRound( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0,   1, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRound( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0,   2, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRound( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0,   3, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRound( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0,   4, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRound( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0,   5, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRound( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0,   6, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRound( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0,   7, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRound( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0,   8, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRound( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0,   9, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRound( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0,  10, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRound( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0,  11, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRound( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0,  12, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRound( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0,  13, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRound( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0,  14, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRound( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0,  15, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0,  16, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0,  17, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0,  18, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0,  19, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );

round1:
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1,  20, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1,  21, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1,  22, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1,  23, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1,  24, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1,  25, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1,  26, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1,  27, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1,  28, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1,  29, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1,  30, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1,  31, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1,  32, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1,  33, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1,  34, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1,  35, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1,  36, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1,  37, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1,  38, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1,  39, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );

round2:
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2,  40, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2,  41, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2,  42, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2,  43, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2,  44, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2,  45, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2,  46, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2,  47, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2,  48, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2,  49, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2,  50, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2,  51, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2,  52, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2,  53, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2,  54, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2,  55, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2,  56, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2,  57, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2,  58, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2,  59, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );

round3:
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3,  60, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3,  61, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3,  62, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3,  63, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3,  64, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3,  65, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3,  66, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3,  67, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3,  68, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3,  69, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3,  70, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3,  71, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3,  72, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3,  73, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3,  74, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3,  75, ctxa2, ctxb2, ctxc2, ctxd2, ctxe2 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3,  76, ctxe2, ctxa2, ctxb2, ctxc2, ctxd2 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3,  77, ctxd2, ctxe2, ctxa2, ctxb2, ctxc2 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3,  78, ctxc2, ctxd2, ctxe2, ctxa2, ctxb2 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3,  79, ctxb2, ctxc2, ctxd2, ctxe2, ctxa2 );

	paddd storea, ctxa
	paddd storea2, ctxa2
	paddd storeb, ctxb
	paddd storeb2, ctxb2
	paddd storec, ctxc
	paddd storec2, ctxc2
	paddd stored, ctxd
	paddd stored2, ctxd2
	paddd storee, ctxe
	paddd storee2, ctxe2
	movapd ctxa, storea
	movapd ctxa2, storea2
	movapd ctxb, storeb
	movapd ctxb2, storeb2
	movapd ctxc, storec
	movapd ctxc2, storec2
	movapd ctxd, stored
	movapd ctxd2, stored2
	movapd ctxe, storee
	movapd ctxe2, storee2
	jmp endianity

endianity:

//changes indianity ...
	movapd maskf0f0, tmp3
	movapd maskf0f0, tmp32
	movapd ctxa, tmp1
	movapd ctxa2, tmp12
	movapd ctxb, tmp2
	movapd ctxb2, tmp22
	pand tmp3, ctxa
	pand tmp32, ctxa2
	pand tmp3, ctxb
	pand tmp32, ctxb2
	movapd mask0f0f, tmp3
	movapd mask0f0f, tmp32
	pand tmp3, tmp1
	pand tmp32, tmp12
	pand tmp3, tmp2
	pand tmp32, tmp22
	psrld $8, ctxa
	psrld $8, ctxa2
	psrld $8, ctxb
	psrld $8, ctxb2
	pslld $8, tmp1
	pslld $8, tmp12
	pslld $8, tmp2
	pslld $8, tmp22
	por tmp1, ctxa
	por tmp12, ctxa2
	por tmp2, ctxb
	por tmp22, ctxb2
	movapd ctxa, tmp1
	movapd ctxa2, tmp12
	movapd ctxb, tmp2
	movapd ctxb2, tmp22
	psrld $16, ctxa
	psrld $16, ctxa2
	psrld $16, ctxb
	psrld $16, ctxb2
	pslld $16, tmp1
	pslld $16, tmp12
	pslld $16, tmp2
	pslld $16, tmp22
	por tmp1, ctxa
	por tmp12, ctxa2
	por tmp2, ctxb 
	por tmp22, ctxb2 
	movapd ctxa, 0(%rdi)
	movapd ctxa2, 16(%rdi)
	movapd ctxb, (4*MMX_COEF)(%rdi)
	movapd ctxb2, (4*MMX_COEF+16)(%rdi)


//now 2 more register to play with ..
#define tmp4 ctxa
#define tmp42 ctxa2
#define tmp5 ctxb
#define tmp52 ctxb2

	movapd maskf0f0, tmp5
	movapd maskf0f0, tmp52
	movapd ctxc, tmp1
	movapd ctxc2, tmp12
	movapd ctxd, tmp2
	movapd ctxd2, tmp22
	movapd ctxe, tmp3
	movapd ctxe2, tmp32
	pand tmp5, ctxc
	pand tmp52, ctxc2
	pand tmp5, ctxd
	pand tmp52, ctxd2
	pand tmp5, ctxe
	pand tmp52, ctxe2
	movapd mask0f0f, tmp5
	movapd mask0f0f, tmp52
	pand tmp5, tmp1
	pand tmp52, tmp12
	pand tmp5, tmp2
	pand tmp52, tmp22
	pand tmp5, tmp3
	pand tmp52, tmp32
	psrld $8, ctxc
	psrld $8, ctxc2
	psrld $8, ctxd
	psrld $8, ctxd2
	psrld $8, ctxe
	psrld $8, ctxe2
	pslld $8, tmp1
	pslld $8, tmp12
	pslld $8, tmp2
	pslld $8, tmp22
	pslld $8, tmp3
	pslld $8, tmp32
	por tmp1, ctxc
	por tmp12, ctxc2
	por tmp2, ctxd
	por tmp22, ctxd2
	por tmp3, ctxe
	por tmp32, ctxe2
	movapd ctxc, tmp1
	movapd ctxc2, tmp12
	movapd ctxd, tmp2
	movapd ctxd2, tmp22
	movapd ctxe, tmp3
	movapd ctxe2, tmp32
	psrld $16, ctxc
	psrld $16, ctxc2
	psrld $16, ctxd
	psrld $16, ctxd2
	psrld $16, ctxe
	psrld $16, ctxe2
	pslld $16, tmp1
	pslld $16, tmp12
	pslld $16, tmp2
	pslld $16, tmp22
	pslld $16, tmp3
	pslld $16, tmp32
	por tmp1, ctxc
	por tmp12, ctxc2
	por tmp2, ctxd
	por tmp22, ctxd2
	por tmp3, ctxe
	por tmp32, ctxe2

	movapd ctxc, (8*MMX_COEF)(%rdi)
	movapd ctxc2, (8*MMX_COEF+16)(%rdi)
	movapd ctxd, (12*MMX_COEF)(%rdi)
	movapd ctxd2, (12*MMX_COEF+16)(%rdi)
	movapd ctxe, (16*MMX_COEF)(%rdi)
	movapd ctxe2, (16*MMX_COEF+16)(%rdi)

	pop %rbx
	emms
	
	ret
