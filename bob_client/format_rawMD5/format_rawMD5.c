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
#include "md5.h"
#include "btb.h"

#include JOHN_ARCH

#define FORMAT_LABEL			"raw-md5"
#define FORMAT_NAME			"Raw MD5"
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"raw-md5 MMX"
#endif
#if (MMX_COEF == 4)
#define ALGORITHM_NAME			"raw-md5 SSE2"
#endif
#if (MMX_COEF == 8)
#define ALGORITHM_NAME			"raw-md5 AMD64"
#endif
#ifndef ALGORITHM_NAME
#define ALGORITHM_NAME			"raw-md5"
#endif

#ifdef MMX_COEF
#define BENCHMARK_LENGTH		4000000*MMX_COEF
#else
#define BENCHMARK_LENGTH		-1
#endif

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + (i& (0xffffffff-3) )*MMX_COEF + ((i)&3) )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct s_format_tests rawmd5_tests[] = {
	{"user1", "5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"user2", "ad0234829205b9033196ba818f7a872b", "test2"},
	{"user3", "8ad8757baa8564dc136c1e07507f4a98", "test3"},
	{"user4", "86985e105f79b95d6bc918fb45ec7727", "test4"},
	{"user5", "f999e8f865e1ad139db9ff653631f677", "te st5"},
	{"user6", "d41d8cd98f00b204e9800998ecf8427e", ""},
	{NULL}
};

#ifdef MMX_COEF
static char saved_key[64*MMX_COEF*2 + 1] __attribute__ ((aligned(16)));
static char crypt_key[BINARY_SIZE*MMX_COEF+1] __attribute__ ((aligned(16)));
#if (ARCH_SIZE == 8)
static unsigned int total_len[MMX_COEF];
#else
static unsigned int total_len;
#endif
unsigned char out[PLAINTEXT_LENGTH];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static char crypt_key[BINARY_SIZE+1];
static MD5_CTX ctx;
#endif

static int valid(char * ciphertext)
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

static void rawmd5_set_salt(void *salt) { }

static void rawmd5_set_key(char *key, int index) {
#ifdef MMX_COEF
	int len;
	
	if(index==0)
	{
# if (ARCH_SIZE != 8)
		total_len = 0;
# endif
		memset(saved_key, 0, 64*MMX_COEF);
	}
	len = 0;
	while( (saved_key[GETPOS(len, index)] = key[len]) )
	{
		len++;
		if(len==PLAINTEXT_LENGTH)
		{
			saved_key[GETPOS(len, index)] = 0;
			break;
		}
	}

# if (ARCH_SIZE == 8)
	total_len[index] = len;
	((unsigned int *)saved_key)[ 14*MMX_COEF + index ] = (len<<3);
# else
	total_len += len << ( ( (32/MMX_COEF) * index ) );
# endif
	saved_key[GETPOS(len, index)] = 0x80;
#else
	strncpy(saved_key, key, PLAINTEXT_LENGTH + 1);
#endif
}

static char *rawmd5_get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;

# if (ARCH_SIZE == 8)
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

static int rawmd5_cmp_all(void *binary, int index) { 
	int i=0;
#if MMX_COEF
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
	while(i<(BINARY_SIZE/sizeof(int)))
	{
		if(((int *)binary)[i]!=((int *)crypt_key)[i])
			return 0;
		i++;
	}
#endif
	return 1;
}

static int rawmd5_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/sizeof(uint32_t));i++)
	{
		if ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	}
	return 1;
#else
	return rawmd5_cmp_all(binary, index);
#endif
}

static unsigned int rawmd5_crypt_all(int count) {  
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	mdfivemmx(crypt_key, saved_key, total_len);
#else
	MD5_Init( &ctx );
	MD5_Update( &ctx, saved_key, strlen( saved_key ) );
	MD5_Final( crypt_key, &ctx);
#endif
	return ((unsigned char * )crypt_key)[0];
}

static void * rawmd5_binary(char *ciphertext) 
{
	static unsigned char * realcipher;
	int i;
	
	realcipher = malloc(BINARY_SIZE);
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return realcipher;
}
static int get_hash(int index)
{
#ifdef MMX_COEF
	return (((uint32_t *)crypt_key)[index] & 0xff);
#else
	return (((uint32_t *)crypt_key)[0] & 0xff);
#endif
}

struct s_format fmt_rawMD5 = {
	{
		CIPHER_ID_RAWMD5,
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
		rawmd5_tests
	}, {
		format_default_init,
		valid,
		rawmd5_binary,
		format_default_salt,
		rawmd5_set_salt,
		rawmd5_set_key,
		rawmd5_get_key,
		format_default_set_username,
		rawmd5_crypt_all,
		rawmd5_cmp_all,
		rawmd5_cmp_one,
		format_default_binary_hash,
		get_hash
	}
};
