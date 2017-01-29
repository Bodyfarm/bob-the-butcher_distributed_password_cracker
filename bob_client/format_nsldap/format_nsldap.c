// Fix for john the ripper 1.6.37 by Sun-Zero, 2004. 07. 26.
/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * Minor performance enhancement by bartavelle@bandecon.com
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
#include "sha.h"
#include "base64.h"
#include "btb.h"


#define FORMAT_LABEL			"nsldap"
#define FORMAT_NAME			"Netscape LDAP SHA"
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
#define BENCHMARK_LENGTH		(2000000*MMX_COEF)
#else
#define BENCHMARK_LENGTH		2000000
#endif

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		33

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + (i& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{sha}"
#define NSLDAP_MAGIC_LENGTH 5

static struct s_format_tests tests[] = {
	{"usr1", "{SHA}cMiB1KJphN3OeV9vcYF8nPRIDnk=", "aaaa"},  
	{"usr2", "{SHA}iu0TIuVFC62weOH7YKgXod8loso=", "bbbb"},  
	{"usr3", "{SHA}0ijZPTcJXMa+t2XnEbEwSOkvQu0=", "ccccccccc"},  
	{"usr4", "{SHA}vNR9eUfJfcKmdkLDqNoKagho+qU=", "dddddddddd"},  
	{NULL}
};

#ifdef MMX_COEF
static char crypt_key[BINARY_SIZE*MMX_COEF];
static char saved_key[80*MMX_COEF];
#if (MMX_COEF == 8)
static unsigned int total_len[MMX_COEF];
#else
static unsigned int total_len;
#endif
static unsigned char buffer[80*4*MMX_COEF] __attribute__ ((aligned(8*MMX_COEF)));
static unsigned char out[PLAINTEXT_LENGTH];
#else
static char crypt_key[BINARY_SIZE];
static char saved_key[PLAINTEXT_LENGTH + 1];
#endif

static void * binary(char *ciphertext) {
	static char * realcipher;

	/* FIXME use a real base64 algorithm without stupid overwrites */
	realcipher = malloc(BINARY_SIZE + 9);
	memset(realcipher, 0, BINARY_SIZE + 9);

	base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH , realcipher);
	return (void *)realcipher;
}

static int 
valid(char *ciphertext)
{
	if(ciphertext && strlen(ciphertext) == CIPHERTEXT_LENGTH)
		return !strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH);
	return 0;
}

static unsigned int binary_hash(void *binary)
{
	return ((int *)binary)[0] & 0xFF;
}

static unsigned int get_hash(int index)
{
	return ((uint32_t *)crypt_key)[index] & 0xFF;
}

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	int len;
	int i;
	
	if(index==0)
	{
# if (MMX_COEF != 8)
		total_len = 0;
#endif
		memset(saved_key, 0, sizeof(saved_key));
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;
# if (MMX_COEF == 8)
	total_len[index] = len;
	((uint32_t *)saved_key)[ 15*MMX_COEF + index ] = (len<<3);
# else
	total_len += len << ( ( (32/MMX_COEF) * index ) );
# endif
	for(i=0;i<len;i++)
		saved_key[GETPOS(i, index)] = key[i];
	
	saved_key[GETPOS(i, index)] = 0x80;
#else
  strncpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static char *get_key(int index)
{
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

static int 
cmp_all(void *binary, int index)
{
	int i = 0;
#ifdef MMX_COEF
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF])
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+1])
#if (MMX_COEF >= 4)
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+2])
			&& ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+3])
#endif
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

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((uint32_t *)binary)[i] != ((uint32_t *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static void set_salt(void *salt) {
}

static unsigned int crypt_all(int count) {  
#ifdef MMX_COEF
	shammx(crypt_key, saved_key, total_len);
#else
	static SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, saved_key, strlen(saved_key));
	SHA1_Final(crypt_key, &ctx);
#endif
	return ((unsigned char *)crypt_key)[0];
}


struct s_format fmt_NSLDAP = {
  {
	  CIPHER_ID_NSLDAP,
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
	  tests
  }, {
	  format_default_init,
	  valid,
	  binary,
	  format_default_salt,
	  set_salt,
	  set_key,
	  get_key,
	  format_default_set_username,
	  crypt_all, 
	  cmp_all,
	  cmp_one,
	  binary_hash,
	  get_hash
  }
};

