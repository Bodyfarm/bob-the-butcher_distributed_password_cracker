/*
 * Copyright (c) 2004 Simon Marechal
 * bartavelle@bandecon.com
 *
 * This is a plugin that adds Microsoft credential's cache hashing algorithm,
 * MS Cache Hash, a.k.a. MS Cash. 
 * In order to get those hashes, use the CacheDump utility :
 *
 * http://www.cr0.net:8040/misc/cachedump.html
 *
 * It uses 
 * - smbencrypt.c Copyright (C) Andrew Tridgell 1997-1998
 * - md4.c, md4.h by Solar Designer
 *  
 */

#include <stdlib.h>
#include <string.h>
#include "params.h"
#ifdef HAVE_LIBDMALLOC
# include <dmalloc.h>
#else
# include <stdlib.h>
#endif
#include "md4.h"
#include "format.h"
#include "rw.h"
#include "btb.h"

#define FORMAT_LABEL			"mscash"
#define FORMAT_NAME			"M$ Cache Hash"
#define ALGORITHM_NAME			"mscash"

#define BENCHMARK_LENGTH		1024*300

#define PLAINTEXT_LENGTH		32

#define BINARY_SIZE			16
//max username size is 64, double for unicode "optimization"
#define SALT_SIZE			0
#define CIPHERTEXT_LENGTH		(BINARY_SIZE*2 + 128)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct s_format_tests mscash_tests[] = {
	{"test1", "64cd29e36a8431a2b111378564a10631", "test1" },
	{"test2", "ab60bdb4493822b175486810ac2abe63", "test2" },
	{"test3", "14dd041848e12fc48c0aa7a416a4a00c", "test3" },
	{"test4", "b945d24866af4b01a6d89b9d932a153c", "test4" },
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
//stores the ciphertext for value currently being tested
static char crypt_key[BINARY_SIZE+1];

static int salt_length; //the length of the current username
static unsigned short cur_salt[64]; //current salt

static int valid(char *ciphertext)
{
	int i;

	if(strlen(ciphertext)!=PLAINTEXT_LENGTH)
		return 0;
	for (i = 0; i <  PLAINTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	
	return 1;
}

static void mscash_set_salt(void *salt) {
	return;
}

static void mscash_set_key(char *key, int index) {
	strncpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *mscash_get_key(int index) {
    return saved_key;
}

static int mscash_cmp_all(void *binary, int index) { 
	int i=0;
	while(i<(BINARY_SIZE/sizeof(int)))
	{
		if(((int *)binary)[i]!=((int *)crypt_key)[i])
			return 0;
		i++;
	}
	return 1;
}

static unsigned int mscash_crypt_all(int count) {  
	unsigned char buffer[BINARY_SIZE+128];
	uint16_t wpwd[129];
	/* get plaintext input in saved_key put it into ciphertext crypt_key */
	
	/* stage 1 : build nt hash of password */
	/* Password must be converted to NT unicode */
	mdfour(buffer, (unsigned char *)wpwd, to_unicode_l(wpwd, saved_key) * 2);

	/* stage 2 : append cleartext to buffer */
	memcpy(buffer+BINARY_SIZE, cur_salt, salt_length*2);

	/* stage 3 : generate final hash and put it in crypt_key */
	mdfour(crypt_key, buffer, BINARY_SIZE+salt_length*2);

	/* returns first byte, unsigned ! */
	return ((unsigned char *)crypt_key)[0];
}

static void * mscash_binary(char *ciphertext) 
{
	static unsigned char * realcipher;
	int i;
	
	realcipher = malloc(BINARY_SIZE);
	int l = strlen(ciphertext);
	for(i=0; i<BINARY_SIZE ;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+l-BINARY_SIZE*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+l-BINARY_SIZE*2+1])];
	}
	return (void *)realcipher;
}

static void * mscash_get_salt(char * ciphertext)
{
	return 0;
}

static int mscash_cmp_one(void *binary, int count){
	return (1);
}

static void mscash_set_username(char * username, int index)
{
	salt_length = to_unicode_l(cur_salt, username);
	return;
}

static unsigned int get_hash(int index) { return (crypt_key[0] & 0xff); }

struct s_format fmt_mscash = {
	{
		CIPHER_ID_MSCASH,
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		USERNAME_USED,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		mscash_tests
	}, {
		format_default_init,
		valid,
		mscash_binary,
		mscash_get_salt,
		mscash_set_salt,
		mscash_set_key,
		mscash_get_key,
		mscash_set_username,
		mscash_crypt_all,
		mscash_cmp_all,
		mscash_cmp_one,
		format_default_binary_hash,
		get_hash
	}
};
