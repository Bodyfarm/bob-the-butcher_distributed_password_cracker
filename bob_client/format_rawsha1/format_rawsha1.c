/*
 * Copyright (c) 2004 bartavelle
 * bartavelle@bandecon.com
 *
 * Simple MD5 hashes cracker
 * It uses the Solar Designer's md5 implementation
 * 
 */

#include "params.h"
#include <string.h>
#ifdef HAVE_LIBDMALLOC
# include <dmalloc.h>
#else
# include <stdlib.h>
#endif
#include "format.h"
#include "rw.h"
#include "btb.h"
#include "sha.h"

#include JOHN_ARCH

#define FORMAT_LABEL			"raw-sha1"
#define FORMAT_NAME			"Raw SHA1"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"sha1 MMX"
#endif
#if (MMX_COEF == 4)
#define ALGORITHM_NAME			"sha1 SSE2"
#endif
#if (MMX_COEF == 8)
#define ALGORITHM_NAME			"sha1 AMD64"
#endif
#else
#define ALGORITHM_NAME			"sha1"
#endif

#ifdef MMX_COEF
#define BENCHMARK_LENGTH                (2000000*MMX_COEF)
#else
#define BENCHMARK_LENGTH                2000000
#endif


#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		40

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + (i& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct s_format_tests rawsha1_tests[] = {
	{"usr1", "A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	{"usr2", "2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"usr3", "f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"usr4", "1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{NULL}
};

#ifdef MMX_COEF
static char saved_key[80*MMX_COEF + 1] __attribute__ ((aligned(16)));
static char crypt_key[BINARY_SIZE*MMX_COEF+1] __attribute__ ((aligned(16)));
#if (MMX_COEF == 8)
static unsigned int total_len[MMX_COEF];
#else
static unsigned int total_len;
#endif
static unsigned char out[PLAINTEXT_LENGTH];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static char crypt_key[BINARY_SIZE+1];
static SHA_CTX ctx;
#endif

static int valid(char *ciphertext)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void rawsha1_set_salt(void *salt) { }

static void rawsha1_init(void)
{
#ifdef MMX_COEF
	memset(saved_key, 0, sizeof(saved_key));
#endif
}

static void rawsha1_set_key(char *key, int index) {
#ifdef MMX_COEF
	int len;
	int i;
	
	if(index==0)
	{
# if (MMX_COEF != 8)
		total_len = 0;
# endif
		memset(saved_key, 0, sizeof(saved_key));
	}
	len = 0;

	while( ( saved_key[GETPOS(len, index)] = key[len] ) )
	{
		len++;
		if(len==PLAINTEXT_LENGTH)
		{
			saved_key[GETPOS(len, index)] = 0;
			break;
		}
	}
# if (MMX_COEF == 8)
	total_len[index] = len;
	((uint32_t *)saved_key)[ 15*MMX_COEF + index ] = (len<<3);
# else
	total_len += len << ( ( (32/MMX_COEF) * index ) );
# endif
	saved_key[GETPOS(len, index)] = 0x80;
#else
	strncpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static char *rawsha1_get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;

# if (MMX_COEF == 8)
	s = total_len[index];
# else
	s = (total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
# endif
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return out;
#else
	return saved_key;
#endif
}

static int rawsha1_cmp_all(void *binary, int index) { 
	int i=0;
#ifdef MMX_COEF
	while(i< (BINARY_SIZE/sizeof(uint32_t)) )
	{
		if (
			( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF])
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+1])
# if (MMX_COEF >= 4)
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+2])
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+3])
# endif
# if (MMX_COEF >= 8)
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+4])
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+5])
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+6])
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+7])
# endif

		)
			return 0;
		i++;
	}
#else
	while(i<BINARY_SIZE)
	{
		if(((char *)binary)[i]!=((char *)crypt_key)[i])
			return 0;
		i++;
	}
#endif
	return 1;
}

static int rawsha1_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/sizeof(uint32_t));i++)
		if ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return rawsha1_cmp_all(binary, index);
#endif
}

static void rawsha1_crypt_all(int count) {  
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	shammx(crypt_key, saved_key, total_len);
#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, saved_key, strlen( saved_key ) );
	SHA1_Final( crypt_key, &ctx);
#endif
  
}

static void * rawsha1_binary(char *ciphertext) 
{
	static char * realcipher;
	int i;
	
	realcipher = malloc(BINARY_SIZE);
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *)realcipher;
}

static unsigned int binary_hash(void *binary)
{
	return ((uint32_t *)binary)[0] & 0xFF;
}

static unsigned int get_hash(int index)
{
#ifdef MMX_COEF
	return (((uint32_t *)crypt_key)[index] & 0xff);
#else
	return (((uint32_t *)crypt_key)[0] & 0xff);
#endif
}

struct s_format fmt_rawSHA1 = {
	{
		CIPHER_ID_RAWSHA1,
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		0,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		rawsha1_tests
	}, {
		rawsha1_init,
		valid,
		rawsha1_binary,
		format_default_salt,
		rawsha1_set_salt,
		rawsha1_set_key,
		rawsha1_get_key,
		format_default_set_username,
		rawsha1_crypt_all,
		rawsha1_cmp_all,
		rawsha1_cmp_one,
		binary_hash,
		get_hash
	}
};
