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


#define FORMAT_LABEL			"bsdi"
#define FORMAT_NAME			"BSDI DES"

//#define BENCHMARK_COMMENT		" (x725)"
#define BENCHMARK_LENGTH		200

#define PLAINTEXT_LENGTH		64
#define CIPHERTEXT_LENGTH		20

// fails when too many tests are included 
static struct s_format_tests tests[] = {
	{"usr1", "_J9..CCCCXBrJUJV154M", "U*U*U*U*"},
	{"usr2", "_J9..CCCCXUhOBTXzaiE", "U*U***U"}, 
	{"usr3", "_J9..CCCC4gQ.mB/PffM", "U*U***U*"}, 
	{"usr4", "_J9..XXXXvlzQGqpPPdk", "*U*U*U*U"}, 
	{"usr5", "_J9..XXXXsqM/YSSP..Y", "*U*U*U*U*"}, 
	{"usr6", "_J9..XXXXVL7qJCnku0I", "*U*U*U*U*U*U*U*U"},
	{"usr7", "_J9..XXXXAj8cFbP5scI", "*U*U*U*U*U*U*U*U*"},
	{"usr8", "_J9..SDizh.vll5VED9g", "ab1234567"}, 
	{"usr9", "_J9..SDizRjWQ/zePPHc", "cr1234567"},
	{"usra", "_J9..SDizxmRI1GjnQuE", "zxyDPWgydbQjgq"},
	{"usrx", "_K9..SaltNrQgIYUAeoY", "726 even"},
	{"urc", "_J9..SDSD5YGyRCr4W4c", ""},
	{NULL}
};

#if DES_BS

#include "DES_bs.h"

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			(ARCH_SIZE * 2)

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

#else

#define ALGORITHM_NAME			DES_STD_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			(ARCH_SIZE * 2)

#define MIN_KEYS_PER_CRYPT		4
#define MAX_KEYS_PER_CRYPT		8

ARCH_WORD saved_salt, current_salt;

#endif

static int saved_count;


static char *strnfcpy(char *dst, char *src, int size)
{
        char *dptr = dst, *sptr = src;
        int count = size;

        while (count--)
                if (!(*dptr++ = *sptr++)) break;

        return dst;
}

static char *strnzcpy(char *dst, char *src, int size)
{
        char *dptr = dst, *sptr = src;
        int count = size;

        if (count)
                while (--count)
                        if (!(*dptr++ = *sptr++)) break;
        *dptr = 0;

        return dst;
}

static struct {
#if !DES_BS
	union {
		double dummy;
		struct {
			DES_KS KS;
			DES_binary binary;
		} data;
	} aligned;
#endif
	char key[PLAINTEXT_LENGTH];
} buffer[MAX_KEYS_PER_CRYPT];

static void init(void)
{
	DES_std_init();

#if DES_BS
	DES_bs_init(0);

	DES_std_set_salt(0);
	DES_count = 1;
#else
	current_salt = -1;
#endif
}

static int valid(char *ciphertext)
{
	char *pos;

	if (ciphertext[0] != '_') return 0;

	for (pos = &ciphertext[1]; pos < &ciphertext[9]; pos++)
	if (!*pos) return 0;

	for (pos = &ciphertext[9]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;

	return 1;
}

static void *salt(char *ciphertext)
{
	static ARCH_WORD * out;
	static ARCH_WORD * out2;
	out = malloc(sizeof(ARCH_WORD)*2);

#if DES_BS
	out2 = DES_raw_get_salt(ciphertext);
#else
	out2 = DES_std_get_salt(ciphertext);
#endif
	out[0] = *out2;
	out[1] = DES_raw_get_count(ciphertext);

	return out;
}

#if DES_BS

static unsigned int binary_hash(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFF;
}

static unsigned int get_hash(int index)
{
	return DES_bs_get_hash(index, 8);
}

static void set_salt(void *salt)
{
	DES_bs_set_salt(((ARCH_WORD *)salt)[0]);
	saved_count = ((ARCH_WORD *)salt)[1];
}

#else

static unsigned int binary_hash(void *binary)
{
	return DES_STD_HASH_1(*(ARCH_WORD *)binary);
}

static unsigned int get_hash(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].aligned.data.binary[0];
	return DES_STD_HASH_1(binary);
}

static void set_salt(void *salt)
{
	saved_salt = ((ARCH_WORD *)salt)[0];
	saved_count = ((ARCH_WORD *)salt)[1];
}

#endif

static void set_key(char *key, int index)
{
	char *ptr, *chr;
	int pos, word;
	unsigned ARCH_WORD block[2];
	union {
		double dummy;
		DES_binary binary;
	} aligned;
	char chars[8];
#if DES_BS
	char *final = key;
#endif

	DES_std_set_key(key);

	for (pos = 0, ptr = key; pos < 8 && *ptr; pos++, ptr++);
	block[1] = block[0] = 0;

	while (*ptr) {
		ptr -= 8;
		for (word = 0; word < 2; word++)
		for (pos = 0; pos < 4; pos++)
			block[word] ^= (ARCH_WORD)*ptr++ << (1 + (pos << 3));

#if !DES_BS
		if (current_salt)
			DES_std_set_salt(current_salt = 0);
		DES_count = 1;
#endif

		DES_std_set_block(block[0], block[1]);
		DES_std_crypt(DES_KS_current, aligned.binary);
		DES_std_get_block(aligned.binary, block);

		chr = chars;
		for (word = 0; word < 2; word++)
		for (pos = 0; pos < 4; pos++) {
			*chr++ = 0x80 |
				((block[word] >> (1 + (pos << 3))) ^ *ptr);
			if (*ptr) ptr++;
		}

#if DES_BS
		final = chars;
		if (*ptr)
#endif
			DES_raw_set_key(chars);
	}

#if DES_BS
	DES_bs_set_key(final, index);
#else
	memcpy(buffer[index].aligned.data.KS, DES_KS_current, sizeof(DES_KS));
#endif
	strnfcpy(buffer[index].key, key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

	return strnzcpy(out, buffer[index].key, PLAINTEXT_LENGTH + 1);
}

#if DES_BS

static unsigned int crypt_all(int count)
{
	DES_bs_expand_keys();
	DES_bs_crypt(saved_count);
	return 0;
}

static int cmp_all(void *binary, int count)
{
	return DES_bs_cmp_all((ARCH_WORD *)binary);
}

static int cmp_one(void *binary, int index)
{
	return DES_bs_cmp_one((ARCH_WORD *)binary, 32, index);
}

#else

static unsigned int crypt_all(int count)
{
	int index;

	if (current_salt != saved_salt)
		DES_std_set_salt(current_salt = saved_salt);

	memset(DES_IV, 0, sizeof(DES_IV));
	DES_count = saved_count;

	for (index = 0; index < count; index++)
		DES_std_crypt(buffer[index].aligned.data.KS,
			buffer[index].aligned.data.binary);
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
	return *(unsigned ARCH_WORD *)binary ==
		(buffer[index].aligned.data.binary[0] & DES_BINARY_MASK);
}

#endif

struct s_format fmt_BSDI = {
	{
		CIPHER_ID_BSDI,
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
		init,
		valid,
		(void *(*)(char *))
#if DES_BS
			DES_bs_get_binary,
#else
			DES_std_get_binary,
#endif
		salt,
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
