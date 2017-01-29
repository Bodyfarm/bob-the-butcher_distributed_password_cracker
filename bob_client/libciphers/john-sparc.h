#define ARCH_WORD			long long
#define ARCH_SIZE			8
#define ARCH_BITS			64
#define ARCH_BITS_LOG			6
#define ARCH_BITS_STR			"64"
#define ARCH_LITTLE_ENDIAN		0
#define ARCH_INT_GT_32			0
#define DES_BS_ALGORITHM_NAME           "64/64 BS"
#define ARCH_ALLOWS_UNALIGNED		0

#define OS_TIMER			1
#define OS_FLOCK			1

#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			0
#define DES_COPY			1
#define DES_BS_ASM			0
#define DES_BS				1
#define DES_BS_VECTOR			0
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				0

#define BF_ASM				0
#define BF_SCALE			0

#define MEM_ALIGN_CACHE                        (ARCH_SIZE * 8)

#if ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 7)) || (__GNUC__ > 2)
#define CC_CACHE_ALIGN \
        __attribute__ ((aligned (MEM_ALIGN_CACHE)))
#else
#define CC_CACHE_ALIGN                  /* nothing */
#endif

#if ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 7)) || (__GNUC__ > 2)
#define CC_PACKED                       __attribute__ ((packed))
#else
#define CC_PACKED                       /* nothing */
#endif

#if ARCH_BITS >= 64
#define DES_SIZE			8
#else
#define DES_SIZE			4
#endif

