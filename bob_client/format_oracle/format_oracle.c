/*
 * Copyright (c) 2004 Simon Marechal
 * simon.marechal@thales-security.com
 */

#include "params.h"
#include <string.h>
#ifdef HAVE_LIBDMALLOC
# include <dmalloc.h>
#else
# include <stdlib.h>
#endif

#include "format.h"
#include "des.h"
#include "rw.h"
#include "btb.h"

#define FORMAT_LABEL			"oracle"
#define FORMAT_NAME			"Oracle"
#define ALGORITHM_NAME			"oracle"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		100000

#define PLAINTEXT_LENGTH		16

#define BINARY_SIZE			8
#define SALT_SIZE			0
#define CIPHERTEXT_LENGTH		(BINARY_SIZE + 32)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct s_format_tests oracle_tests[] = {
	{"SIMon", "4F8BC1809CB2AF77", "a"},
	{"simon", "183D72325548EF11", "THAles2" },
	{"SiMON", "C4EB3152E17F24A4", "TST" },
	{"SYsTEM", "9EEDFA0AD26C6D52", "THALES" },
	{NULL}
};

//stores the ciphertext for value currently being tested
static char crypt_key[BINARY_SIZE+1];

static unsigned char cur_salt[(32 + PLAINTEXT_LENGTH)*2 + 1]; //current salt

static unsigned char deskey[8];
static unsigned char salt_iv[8];
static DES_key_schedule desschedule1;
static DES_key_schedule desschedule2;

static int salt_length;
static int salt_offset;
static int key_length;

static int valid(char *ciphertext)
{
	int i;

	if(strlen(ciphertext)!=PLAINTEXT_LENGTH)
		return 0;
	for (i = 0; i < PLAINTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
			(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
			|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	
	return 1;
}

static void oracle_init(void)
{
	deskey[0] = 0x01;
	deskey[1] = 0x23;
	deskey[2] = 0x45;
	deskey[3] = 0x67;
	deskey[4] = 0x89;
	deskey[5] = 0xab;
	deskey[6] = 0xcd;
	deskey[7] = 0xef;

	my_des_set_key(&deskey, &desschedule1);
}

static void oracle_set_username(char *salt, int count) {
	salt_offset = 0;

	memset(salt_iv, 0, 8);
	salt_length = to_unicode_b(cur_salt, salt);
	//faut gagner du temps
	if(salt_length > 4)
	{
		salt_offset = (salt_length & (~3))*2;
		my_des_ncbc_encrypt(cur_salt, salt_offset, &desschedule1, salt_iv);
	}
}

static void oracle_set_key(char *key, int index) {
	key_length = to_unicode_b(cur_salt + salt_length*2, key);
}

static char *oracle_get_key(int index) {
	static unsigned char out[PLAINTEXT_LENGTH];
	unsigned int i;
	for(i=0;i<key_length;i++)
		out[i] = ((unsigned short *)cur_salt)[salt_length + i] ENDIAN_SHIFT8_R;
	out[i] = 0;
	return out;
}

static int oracle_cmp_all(void *binary, int index) { 
	int i=0;
	while(i<(BINARY_SIZE/sizeof(int)))
	{
		if(((int *)binary)[i]!=((int *)crypt_key)[i])
			return 0;
		i++;
	}
	return 1;
}

static void oracle_crypt_all(int count)  
{
	unsigned int l;

	l = (salt_length + key_length)*2;
	//dump_stuff(cur_salt, l);
	memcpy(crypt_key, salt_iv, 8);
	my_des_ncbc_encrypt(cur_salt + salt_offset, l - salt_offset, &desschedule1, crypt_key);
	my_des_set_key(crypt_key, &desschedule2);
	memset(crypt_key, 0, 8);
	my_des_ncbc_encrypt(cur_salt, l , &desschedule2, crypt_key);
	//dump_stuff(crypt_key, 8);
}

static void * oracle_binary(char *ciphertext) 
{
	static unsigned char * out3;
	int l;
	int i;

	out3 = malloc(BINARY_SIZE);
	
	l = strlen(ciphertext) - PLAINTEXT_LENGTH;
	for(i=0;i<BINARY_SIZE;i++) 
	{
		out3[i] = atoi16[ARCH_INDEX(ciphertext[i*2+l])]*16 
			+ atoi16[ARCH_INDEX(ciphertext[i*2+l+1])];
	}
	return out3;
}

static int oracle_cmp_one(void *binary, int count){
	return oracle_cmp_all(binary, 0);
}

static unsigned int get_hash(int index) { return (crypt_key[0] & 0xff); }

struct s_format fmt_oracle = {
	{
		CIPHER_ID_ORACLE,
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		USERNAME_USED | ALL_CAPS,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		oracle_tests
	}, {
		oracle_init,
		valid,
		oracle_binary,
		format_default_get_salt,
		format_default_set_salt,
		oracle_set_key,
		oracle_get_key,
		oracle_set_username,
		oracle_crypt_all,
		oracle_cmp_all,
		oracle_cmp_one,
		format_default_binary_hash,
		get_hash
	}
};
