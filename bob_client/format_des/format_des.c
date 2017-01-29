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

#include "format.h"
#include "rw.h"
#include "DES_std.h"
#include "btb.h"

#define FORMAT_LABEL			"des"
#define FORMAT_NAME			"Traditional DES"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		300000

#define PLAINTEXT_LENGTH		8
#define CIPHERTEXT_LENGTH_1		13
#define CIPHERTEXT_LENGTH_2		24

static struct s_format_tests tests[] = {
	{"usr1", "CCNf8Sbh3HDfQ", "U*U*U*U*"},
	{"usr2", "CCX.K.MFy4Ois", "U*U***U"},
	{"usr3", "CC4rMpbg9AMZ.", "U*U***U*"},
	{"usr4", "XXxzOu6maQKqQ", "*U*U*U*U"},
	{NULL}
};

#if DES_BS

#include "DES_bs.h"

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			ARCH_SIZE

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

#else

#define ALGORITHM_NAME			DES_STD_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			ARCH_SIZE

#define MIN_KEYS_PER_CRYPT		0x40
#if DES_128K
#define MAX_KEYS_PER_CRYPT		0x100
#else
#define MAX_KEYS_PER_CRYPT		0x80
#endif

static struct {
	union {
		double dummy;
		struct {
			DES_KS KS;
			DES_binary binary;
		} data;
	} aligned;
	char key[PLAINTEXT_LENGTH];
} buffer[MAX_KEYS_PER_CRYPT];

#endif

#if DES_BS

static void init(void)
{
	DES_bs_init(0);
}

#endif

static int valid(char *ciphertext)
{
	char *pos;

	if (!ciphertext[0] || !ciphertext[1]) return 0;

	for (pos = &ciphertext[2]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos && *pos != ',') return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;

	switch (pos - ciphertext) {
	case CIPHERTEXT_LENGTH_1:
		return 1;

	case CIPHERTEXT_LENGTH_2:
		if (atoi64[ARCH_INDEX(ciphertext[12])] & 3) return 0;
		return 2;

	default:
		return 0;
	}
}

static void *salt(char *ciphertext)
{
	static ARCH_WORD * out;

#if DES_BS
	out = DES_raw_get_salt(ciphertext);
#else
	out = DES_std_get_salt(ciphertext);
#endif

	return out;
}

#if DES_BS

static unsigned int binary_hash(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFF;
}

static int get_hash(int index)
{
	return DES_bs_get_hash(index, 8);
}

static void set_salt(void *salt)
{
	DES_bs_set_salt(*(ARCH_WORD *)salt);
}

static unsigned int crypt_all(int count)
{
	DES_bs_expand_keys();
	DES_bs_crypt_25();
	return 0;
}

static int cmp_all(void *binary, int count)
{
	return DES_bs_cmp_all((ARCH_WORD *)binary);
}

static int cmp_one(void *binary, int index)
{
	if(DES_bs_cmp_one((ARCH_WORD *)binary, 32, index))
		return DES_bs_cmp_one((ARCH_WORD *)binary, 64, index);
}

#else

static unsigned int binary_hash(void *binary)
{
	return DES_STD_HASH_1(*(ARCH_WORD *)binary);
}

static int get_hash(int index)
{
	ARCH_WORD binary;

	return DES_STD_HASH_1(binary);
}

static void set_salt(void *salt)
{
	DES_std_set_salt(*(ARCH_WORD *)salt);
}

static unsigned int crypt_all(int count)
{
	int index;

	for (index = 0; index < count; index++)
	{
		printf("DS=%x / binary=%x\n", buffer[index].aligned.data.KS, buffer[index].aligned.data.binary);
		DES_std_crypt(buffer[index].aligned.data.KS,
			buffer[index].aligned.data.binary);
		printf("%d\n", index);
		dump_stuff(buffer[index].aligned.data.KS, sizeof(buffer[index].aligned.data.KS));
		dump_stuff(buffer[index].aligned.data.binary, BINARY_SIZE);
	}

	return 0;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*(unsigned ARCH_WORD *)binary ==
				(buffer[index].aligned.data.binary[0] & DES_BINARY_MASK))
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	unsigned int i;
	for(i=0;i<sizeof(DES_binary)/sizeof(ARCH_WORD);i++)
		if ( ((unsigned ARCH_WORD *)binary)[i] !=
				(buffer[index].aligned.data.binary[i] & DES_BINARY_MASK)  )
			return 0;
}

#endif

#if !DES_BS
static void set_key(char *key, int index)
{
	DES_std_set_key(key);
	memcpy(buffer[index].aligned.data.KS, DES_KS_current, sizeof(DES_KS));
	memcpy(buffer[index].key, key, PLAINTEXT_LENGTH);
}
#endif

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

#if DES_BS
	memcpy(out, DES_bs_all.keys[index], PLAINTEXT_LENGTH);
#else
	memcpy(out, buffer[index].key, PLAINTEXT_LENGTH);
#endif
	out[PLAINTEXT_LENGTH] = 0;

	return out;
}

struct s_format fmt_DES = {
	{
		CIPHER_ID_DES,
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
#if DES_BS
		init,
#else
		DES_std_init,
#endif
		valid,
		(void *(*)(char *))
#if DES_BS
			DES_bs_get_binary,
#else
			DES_std_get_binary,
#endif
		salt,
		set_salt,
#if DES_BS
		DES_bs_set_key,
#else
		set_key,
#endif
		get_key,
		format_default_set_username,
		crypt_all,
		cmp_all,
		cmp_one,
		binary_hash,
		get_hash
	}
};
