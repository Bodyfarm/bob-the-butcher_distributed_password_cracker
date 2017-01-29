/*
 * NTLM patch for john version 0.3
 *
 * (C) 2001 Olle Segerdahl <olle@nxs.se>
 *
 * license: GPL <http://www.gnu.org/licenses/gpl.html>
 *
 * This file is based on code from John the Ripper,
 * Copyright (c) 1996-99 by Solar Designer
 *
 * performance enhancements by bartavelle@bandecon.com
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
#include "md4.h"
#include "btb.h"

#define FORMAT_LABEL			"nt"
#define FORMAT_NAME			"NT MD4"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7000000

#define PLAINTEXT_LENGTH		54
#define CIPHERTEXT_LENGTH		36
#define BINARY_SIZE			16


static struct s_format_tests tests[] = {
	{"user1", "b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
	{"user2", "8846f7eaee8fb117ad06bdd830b7586c", "password"},
	{"user3", "0cb6948805f797bf2a82807973b89537", "test"},
	{"user4", "31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{NULL}
};

#ifdef MMX_COEF
#define ALGORITHM_NAME			MMX_TYPE
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i,idx)	( ((i)&0xfffe)*MMX_COEF + ((i)&1) + ((idx)<<1) )
static unsigned char saved_plain[64 * MMX_COEF] __attribute__ ((aligned(32)));
static unsigned char tmpbuf[64 * MMX_COEF] __attribute__ ((aligned(32)));
static unsigned char output[BINARY_SIZE*MMX_COEF + 1] __attribute__ ((aligned(32)));
static unsigned char out[32];
static unsigned long total_len;
#else
#define ALGORITHM_NAME			"TridgeMD4"
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
unsigned char saved_plain[PLAINTEXT_LENGTH + 1];
unsigned char output[BINARY_SIZE + 1];
#endif

#define SALT_SIZE			0



static int valid(char *ciphertext)
{
	unsigned int pos;

        for (pos = 0; atoi16[ARCH_INDEX(ciphertext[pos])] != 0x7F; pos++);
	if(pos != (BINARY_SIZE*2))
		return 0;
	return 1;
}

static void *get_binary(char *ciphertext)
{
	//static unsigned char binary[BINARY_SIZE];
	static unsigned char * binary;
	int i;

	binary = malloc(BINARY_SIZE);
	for (i=0; i<BINARY_SIZE; i++)
	{
 		binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
 		binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
	}

	return binary;
}

static unsigned int crypt_all(int count)
{
#ifdef MMX_COEF
	mdfourmmx(output, saved_plain, total_len);
#else
	uint16_t wpwd[129];
	mdfour(output, (unsigned char *)wpwd, to_unicode_b(wpwd, saved_plain)*2);
#endif
	return output[0];
}

static int cmp_all(void *binary, int count)
{
	int i = 0;
#ifdef MMX_COEF
	while(i<(BINARY_SIZE/4))
	{
		if (
			( ((unsigned long *)binary)[i] != ((unsigned long *)output)[i*MMX_COEF])
#if (MMX_COEF >= 2 )
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)output)[i*MMX_COEF+1])
#endif
#if (MMX_COEF >= 4 )
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)output)[i*MMX_COEF+2])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)output)[i*MMX_COEF+3])
#endif	

		)
			return 0;
		i++;
	}
#else
	while(i<BINARY_SIZE)
	{
		if(((char *)binary)[i]!=((char *)output)[i])
			return 0;
		i++;
	}
#endif
	return 1;
}

static int cmp_one(void *source, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)source)[i] != ((unsigned long *)output)[i*MMX_COEF+index] )
			return 0;
#endif
	return 1;
}

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	int len;
	int i;

	if(index==0)
	{
		total_len = 0;
		memset(saved_plain, 0, 64*MMX_COEF);
	}
	len = strlen(key);
	if(len > 32)
                len = 32;

	total_len += len << (1 + ( (32/MMX_COEF) * index ) );

	for(i=0;i<len;i++)
		((unsigned short *)saved_plain)[ GETPOS(i, index) ] = key[i] ;
	((unsigned short *)saved_plain)[ GETPOS(i, index) ] = 0x80;
#else
	strncpy(saved_plain, key, PLAINTEXT_LENGTH);
	saved_plain[PLAINTEXT_LENGTH] = 0;
#endif
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	unsigned int s, i;
#if (MMX_COEF == 4)
	s = (total_len >> (1+((32/MMX_COEF)*(index)))) & 0xff;
#else
	if(index == 0)
		s = (total_len & 0xffff) >> 1 ;
	else
		s = total_len >> 17;
#endif
	for(i=0;i<s;i++)
		out[i] = ((unsigned short *)saved_plain)[ GETPOS(i, index) ];
	out[i]=0;
	return out;
#else
	return saved_plain;
#endif
}
static unsigned int get_hash(int index)
{ 
#ifdef MMX_COEF
	return (output[index*MMX_COEF] & 0xff); 
#else
	return (output[0] & 0xff);
#endif
}

struct s_format fmt_NT = {
	{
		CIPHER_ID_NT,
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
		get_binary,
		format_default_get_salt,
		format_default_set_salt,
		set_key,
		get_key,
		format_default_set_username,
		crypt_all,
		cmp_all,
		cmp_one,
		format_default_binary_hash,
		get_hash
	}
};
