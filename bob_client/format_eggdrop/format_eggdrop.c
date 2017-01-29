/*
 * This file is part of Eggdrop blowfish patch for John The Ripper.
 * Copyright (c) 2002 by Sun-Zero <sun-zero@freemail.hu>
 * This is a free software distributable under terms of the GNU GPL. 
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
#include "blowfish.h"
#include "btb.h"

#define FORMAT_LABEL			"bfegg"
#define FORMAT_NAME			"Eggdrop [broken]"
#define ALG_NAME			"blowfish"

#define BENCHMARK_LENGTH		250000

#define PLAINTEXT_LENGTH		31
#define CIPHERTEXT_LENGTH		33

#define BINARY_SIZE			13
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct s_format_tests tests[] = {
    {"user1", "+9F93o1OxwgK1", "123456"},
    {"user2", "+C/.8o.Wuph9.", "qwerty"},
    {"user3", "+EEHgy/MBLDd0", "walkman"},
    {"user4", "+vPBrs07OTXE/", "tesztuser"},
    {"user5", "+zIvO/1nDsd9.", "654321"},
    {NULL}
};

int zerolengthkey = 0;

static unsigned char crypt_key[BINARY_SIZE + 1]; //changed by bartavelle so that it works on alpha
static unsigned char saved_key[PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext) {
    if (strncmp(ciphertext, "+", 1) != 0) return 0;
    if (strlen(ciphertext) != 13) return 0;
    
    return 1;
}

void init() {
    blowfish_first_init();
}


static void set_key(char *key, int index) {
    strncpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *get_key(int index) {
  return saved_key;
}

static int cmp_all(void *binary, int index) {
  if (zerolengthkey) return 0;
  return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static int cmp_exact(void *source, int index) {
  return 1;
}

static unsigned int crypt_all(int count) {  
    if (saved_key[0] == '\0') {
	zerolengthkey = 1;
    } else {
	zerolengthkey = 0;
        blowfish_encrypt_pass(saved_key, crypt_key);
    }
    return ((unsigned char *)crypt_key)[0];
}

static unsigned int get_hash(int index) { return (crypt_key[1] & 0xff); }
static unsigned int get_binary_hash(void * binary) { return (((unsigned char *)binary)[1] & 0xff); }

struct s_format fmt_BFEgg = {
  {
    CIPHER_ID_EGGDROP,
    FORMAT_LABEL,
    FORMAT_NAME,
    ALG_NAME,
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
    format_default_binary,
    format_default_get_salt,
    format_default_set_salt,
    set_key,
    get_key,
    format_default_set_username,
    crypt_all, 
    cmp_all,
    cmp_exact,
    get_binary_hash,
    get_hash
  }
};

