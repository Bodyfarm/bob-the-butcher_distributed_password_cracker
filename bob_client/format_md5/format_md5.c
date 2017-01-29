/*
    Modified by Sun-Zero <sun-zero@freemail.hu>
    2004. 07. 26. 
    
    Now, its work with md5 hash of apache.
*/

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 */
#include "params.h"
#include <string.h>
#ifdef HAVE_LIBDMALLOC
# include <dmalloc.h>
#else
# include <stdlib.h>
#endif

#include "MD5_std.h"
#include "format.h"
#include "rw.h"
#include "btb.h"

#define FORMAT_LABEL			"md5"
#define FORMAT_NAME			"FreeBSD MD5"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		10

#define PLAINTEXT_LENGTH		15
#define CIPHERTEXT_LENGTH		22

#define BINARY_SIZE			4
#define SALT_SIZE			8

#define MIN_KEYS_PER_CRYPT		MD5_N
#define MAX_KEYS_PER_CRYPT		MD5_N

static struct s_format_tests tests[] = {
	{"usr1", "$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	{"usr2", "$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
	{"usr3", "$1$12345678$xek.CpjQUVgdf/P2N9KQf/", ""},
	{"usr4", "$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	{"usr5", "$1$ab$M67h3RfhpYrEev4O4viuU1", "pwd1"},
	{"usr6", "$1$abc$UbQ5mVGrdh8sJW5JLgA4W0", "pwd2"},
	{"usr7", "$1$abcd$hFjwdL.Mcs8f7VrzarWWa0", "pwd3"},
	{"usr8", "$1$abcde$nImpspPSfMd.62xNxWKti/", "pwd4"},
	{NULL}
};

static char saved_key[MD5_N][PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext)
{
	char *pos, *start;

	if (strncmp(ciphertext, "$1$", 3)) return 0;
	
	for (pos = &ciphertext[3]; *pos && *pos != '$'; pos++);
	
	if (!*pos || pos < &ciphertext[3] || pos > &ciphertext[11]) return 0;

	start = ++pos;
	while ((*pos) && (atoi64[ARCH_INDEX(*pos)] != 0x7F)) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 0x3C) return 0;

	return 1;
}

static unsigned int binary_hash(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFF;
}

static unsigned int get_hash(int index)
{
	return MD5_out[index][0] & 0xFF;
}

static void set_key(char *key, int index)
{
	MD5_std_set_key(key, index);

	strncpy(saved_key[index], key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	saved_key[index][PLAINTEXT_LENGTH] = 0;

	return saved_key[index];
}

static int cmp_all(void *binary, int index)
{
#if MD5_X2
	return *(ARCH_WORD *)binary == MD5_out[0][0] ||
		*(ARCH_WORD *)binary == MD5_out[1][0];
#else
	return *(ARCH_WORD *)binary == MD5_out[0][0];
#endif
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, MD5_out[index], sizeof(MD5_binary));
}

static void set_salt(char * salt)
{
	MD5_std_set_salt(salt);
/*
	static char cursalt[10];
	if(salt!=NULL)
	{
		memset(cursalt, 0, sizeof(cursalt));
		strncpy(cursalt, salt, 9);
	}
	MD5_std_set_salt(cursalt);
*/
}

static unsigned int crypt_all(int count) {
	//set_salt(NULL);
	MD5_std_crypt(MD5_TYPE_STD);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	return MD5_std_get_salt(ciphertext, MD5_TYPE_STD);
}

static void *get_binary(char *ciphertext) 
{
	//void * tmp;
	//tmp = MD5_std_get_binary(ciphertext, MD5_TYPE_STD);
	//return tmp;
	return MD5_std_get_binary(ciphertext, MD5_TYPE_STD);
}



struct s_format fmt_MD5 = {
	{
		CIPHER_ID_MD5,
		FORMAT_LABEL,
		FORMAT_NAME,
		MD5_ALGORITHM_NAME,
		0,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		tests
	}, {
		MD5_std_init,
		valid,
		get_binary,		//(void *(*)(char *))MD5_std_get_binary,
		get_salt,		//(void *(*)(char *))MD5_std_get_salt,
		//(void (*)(void *))MD5_std_set_salt,
		set_salt,
		set_key,
		get_key,
		format_default_set_username,
		crypt_all,		// (void (*)(int))MD5_std_crypt,
		cmp_all,
		cmp_one,
		binary_hash,
		get_hash
	}
};
