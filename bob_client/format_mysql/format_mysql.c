/*
 * stolen from john's contribs
 */

////////////////////////////////////////////////////////////////
// MySQL password cracker - v1.0 - 16.1.2003
//
//    by Andrew Hintz <http://guh.nu> drew@overt.org
//  
//    This production has been brought to you by
//    4tphi <http://4tphi.net> and violating <http://violating.us>
//
// This file is an add-on to John the Ripper <http://www.openwall.com/john/> 
//
// Part of this code is based on the MySQL brute password cracker
//   mysqlpassword.c by Chris Given
// This program executes about 75% faster than mysqlpassword.c
// John the ripper also performs sophisticated password guessing.
//
// John the Ripper will expect the MySQL password file to be
// in the following format (without the leading // ):
// dumb_user:5d2e19393cc5ef67
// another_luser:28ff8d49159ffbaf
//
// performance enhancements by bartavelle@bandecon.com

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "params.h"
#ifdef HAVE_MATH_H
#include <math.h>
#endif
#ifdef HAVE_TGMATH_H
#include <tgmath.h>
#endif
#include <string.h>
#ifdef HAVE_LIBDMALLOC
# include <dmalloc.h>
#else
# include <stdlib.h>
#endif

#include "format.h"
#include "btb.h"

//johntr defines
#define FORMAT_LABEL "mysql"
#define FORMAT_NAME "mysql"
#define ALGORITHM_NAME "mysql"

#define BENCHMARK_COMMENT ""
#define BENCHMARK_LENGTH -1

// Increase the PLAINTEXT_LENGTH value for longer passwords.
// You can also set it to 8 when using MySQL systems that truncate 
//  the password to only 8 characters.
#define PLAINTEXT_LENGTH 32

#define CIPHERTEXT_LENGTH 16

#define BINARY_SIZE 16
#define SALT_SIZE 0

#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 1


//used for mysql scramble function
struct rand_struct {
	unsigned long seed1,seed2,max_value;
	double max_value_dbl;
};


void make_scrambled_password(char *,const char *);
char *scramble(char *,const char *,const char *, int);

//test cases
static struct s_format_tests mysql_tests[] = {
	{"user1", "30f098972cc8924d", "http://guh.nu"},
	{"user2", "3fc56f6037218993", "Andrew Hintz"},
	{"user3", "697a7de87c5390b2", "drew"},
	{"user4", "1eb71cf460712b3e", "http://4tphi.net"},
	{"user5", "28ff8d49159ffbaf", "http://violating.us"},
	{"user6", "5d2e19393cc5ef67", "password"},
	{NULL}
};


//stores the ciphertext for value currently being tested
static char crypt_key[BINARY_SIZE+1];

//used by set_key
static char saved_key[PLAINTEXT_LENGTH + 1];

static int mysql_valid(char *ciphertext) { //returns 0 for invalid ciphertexts

	int i; //used as counter in loop

	//ciphertext is 16 characters
	if (strlen(ciphertext) != 16) return 0;  

	//ciphertext is ASCII representation of hex digits
	for (i = 0; i < 16; i++){
		if (!(  ((48 <= ciphertext[i])&&(ciphertext[i] <= 57)) ||
					((97 <= ciphertext[i])&&(ciphertext[i] <= 102))  ))
			return 0;
	}

	return 1;
}

static void mysql_set_key(char *key, int index) {
	strncpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *mysql_get_key(int index) {
	return saved_key;
}

static int mysql_cmp_all(void *binary, int index) { //also is mysql_cmp_one
	int i = 0;
	while(i<BINARY_SIZE)
	{
		if(((char *)binary)[i]!=((char *)crypt_key)[i])
			return 0;
		i++;
	}
	return 1;
}

static int mysql_cmp_exact(void *source, int count){
	return (1); //  mysql_cmp_all fallthrough?
}

static unsigned int mysql_crypt_all(int count) {  
	// get plaintext input in saved_key put it into ciphertext crypt_key
	make_scrambled_password(crypt_key,saved_key);
	return ((unsigned char *)crypt_key)[0];
}

////////////////////////////////////////////////////////////////
//begin mysql code
// This code was copied from mysqlpassword.c by Chris Given
// He probably copied it from password.c in the MySQL source
// The code is GPLed

void randominit(struct rand_struct *rand_st,unsigned long seed1, unsigned long seed2) {
	rand_st->max_value= 0x3FFFFFFFL;
	rand_st->max_value_dbl=(double) rand_st->max_value;
	rand_st->seed1=seed1%rand_st->max_value ;
	rand_st->seed2=seed2%rand_st->max_value;
}
static void old_randominit(struct rand_struct *rand_st,unsigned long seed1) {
	rand_st->max_value= 0x01FFFFFFL;
	rand_st->max_value_dbl=(double) rand_st->max_value;
	seed1%=rand_st->max_value;
	rand_st->seed1=seed1 ; rand_st->seed2=seed1/2;
}
double rnd(struct rand_struct *rand_st) {
	rand_st->seed1=(rand_st->seed1*3+rand_st->seed2) %
		rand_st->max_value;
	rand_st->seed2=(rand_st->seed1+rand_st->seed2+33) %
		rand_st->max_value;
	return(((double) rand_st->seed1)/rand_st->max_value_dbl);
}
void hash_password(unsigned long *result, const char *password) {
	unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
	unsigned long tmp;
	for (; *password ; password++) {
		if (*password == ' ' || *password == '\t')
			continue;
		//tmp= (unsigned long) (unsigned char) *password;
		tmp= (unsigned long) (*password & 0xFF);
		nr^= (((nr & 63)+add)*tmp)+ (nr << 8);
		nr2+=(nr2 << 8) ^ nr;
		add+=tmp;
	}
	result[0]=nr & (((unsigned long) 1L << 31) -1L); /* Don't use sign bit
							    (str2int) */;
	result[1]=nr2 & (((unsigned long) 1L << 31) -1L);
	return;
}
void make_scrambled_password(char *to,const char *password) {
	unsigned long hash_res[2];
	hash_password(hash_res,password);
	sprintf(to,"%08lx%08lx",hash_res[0],hash_res[1]);
}
static inline unsigned int char_val(char X) {
	return (unsigned int) (X >= '0' && X <= '9' ? X-'0' : X >= 'A' && X <= 'Z' ?
			X-'A'+10 : X-'a'+10);
}
char *scramble(char *to,const char *message,const char *password, int
		old_ver) {
	struct rand_struct rand_st;
	unsigned long hash_pass[2],hash_message[2];
	if(password && password[0]) {
		char *to_start=to;
		hash_password(hash_pass,password);
		hash_password(hash_message,message);
		if (old_ver)
			old_randominit(&rand_st,hash_pass[0] ^
					hash_message[0]);
		else
			randominit(&rand_st,hash_pass[0] ^ hash_message[0],
					hash_pass[1] ^ hash_message[1]);
		while (*message++)
			*to++= (char) (floor(rnd(&rand_st)*31)+64);
		if (!old_ver) {
			char extra=(char) (floor(rnd(&rand_st)*31));
			while(to_start != to)
				*(to_start++)^=extra;
		}
	}
	*to=0;
	return to;
}

//end mysql code
////////////////////////////////////////////////////////////////

static unsigned int get_hash(int index) { return (crypt_key[0] & 0xff); }
struct s_format fmt_MYSQL = 
{
	{
		CIPHER_ID_MYSQL,
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
		mysql_tests
	}, {
		format_default_init,
		mysql_valid, 
		format_default_binary,
		format_default_get_salt,
		format_default_set_salt,
		mysql_set_key,
		mysql_get_key,
		format_default_set_username,
		mysql_crypt_all,
		mysql_cmp_all,
		mysql_cmp_exact, //fallthrough
		format_default_binary_hash,
		get_hash
	}
};
