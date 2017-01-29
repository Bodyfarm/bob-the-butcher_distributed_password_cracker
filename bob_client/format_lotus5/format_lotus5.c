//original work by Jeff Fay
//some optimisations by bartavelle@bandecon.com
#include "params.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_LIBDMALLOC
# include <dmalloc.h>
#else
# include <stdlib.h>
#endif

#include JOHN_ARCH

#include "format.h"
#include "rw.h"
#include "btb.h"

/*preprocessor constants that John The Ripper likes*/

#define FORMAT_LABEL                   "lotus5"
#define FORMAT_NAME                    "Lotus5"
#define ALGORITHM_NAME			"Lotus v5 Proprietary"
#define BENCHMARK_LENGTH               1024*100*3
#define PLAINTEXT_LENGTH               16
#define CIPHERTEXT_LENGTH              32
#define BINARY_SIZE                    16
#define SALT_SIZE                      0
#if LOTUS_ASM
#define MIN_KEYS_PER_CRYPT             LOTUS_KPC
#define MAX_KEYS_PER_CRYPT             LOTUS_KPC
#else
#define MIN_KEYS_PER_CRYPT             1
#define MAX_KEYS_PER_CRYPT             1
#endif

#if LOTUS_ASM
extern void lotus_transform_password_asm (unsigned char *inpass) __attribute__((regparm(3)));
extern void lotus_mix_asm (unsigned char *lotus_matrix) __attribute__((regparm(3)));
extern void lotus_xor_asm (unsigned char *lotus_matrix) __attribute__((regparm(3)));
#endif

/*A struct used for JTR's benchmarks*/
static struct s_format_tests tests[] = {
  {"username1", "06E0A50B579AD2CD5FFDC48564627EE7", "secret"},
  {"username2", "355E98E7C7B59BD810ED845AD0FD2FC4", "password"},
  {"username3", "CD2D90E8E00D8A2A63A81F531EA8A9A3", "lotus"},
  {"username4", "69D90B46B1AC0912E5CCF858094BBBFC", "dirtydog"},
  {NULL}
};

static const char lotus_magic_table[256] = {
  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
  0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
  0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
  0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
  0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
  0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
  0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
  0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
  0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
  0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
  0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
  0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
  0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
  0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
  0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
  0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
  0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
  0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
  0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
  0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
  0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
  0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
  0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
  0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
  0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
  0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
  0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
  0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
  0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
  0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
  0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
};

/*Some more JTR variables*/
static char crypt_key[BINARY_SIZE*MAX_KEYS_PER_CRYPT+1];
static char saved_key[PLAINTEXT_LENGTH*MAX_KEYS_PER_CRYPT + 1];
static int key_length[MAX_KEYS_PER_CRYPT];


/*Utility function to convert hex to bin */
static void * binary (char *ciphertext)
{
  char * realcipher;
  int i;
  realcipher = malloc (BINARY_SIZE);
  for (i = 0; i < BINARY_SIZE; i++)
  {
      realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
  }
  return (void *) realcipher;
}

/*Another function required by JTR: decides whether we have a valid
 * ciphertext */
static int valid (char *ciphertext)
{
  int i;
  
  for (i = 0; i < CIPHERTEXT_LENGTH; i++)
	  if (!(((ciphertext[i] >= '0') && (ciphertext[i] <= '9'))
				  || ((ciphertext[i] >= 'a') && (ciphertext[i] <= 'f'))
				  || ((ciphertext[i] >= 'A') && (ciphertext[i] <= 'F'))))
	  {
		  return 0;
	  }
  return 1;
}

/*sets the value of saved_key so we can play with it*/
static void set_key (char *key, int index)
{
	unsigned char x;

	x=0;
	while(*key && (x<PLAINTEXT_LENGTH))
	{
		saved_key[ARCH_INDEX(x)+index*PLAINTEXT_LENGTH] = *key;
		key++;
		x++;
	}
	memset (saved_key + x + index*PLAINTEXT_LENGTH, (PLAINTEXT_LENGTH - x), PLAINTEXT_LENGTH - x);
	key_length[index] = x;
//  strncpy (saved_key, key, PLAINTEXT_LENGTH + 1);
}

/*retrieves the saved key; used by JTR*/
static char * get_key (int index)
{
	static char ret[PLAINTEXT_LENGTH+1];
	
	strncpy(ret, saved_key + PLAINTEXT_LENGTH*index, key_length[index]);
	return ret;
}

static int cmp_all (void *binary, int index)
{
	int i = 0;

	while(i<BINARY_SIZE/sizeof(int))
	{
#if LOTUS_ASM 
		if (
				(((int *)binary)[i]!=((int *)crypt_key)[i]) &&
				(((int *)binary)[i]!=((int *)crypt_key)[i+BINARY_SIZE/sizeof(int)]) &&
				(((int *)binary)[i]!=((int *)crypt_key)[i+2*BINARY_SIZE/sizeof(int)]) 
		)
			return 0;
#else
		if(((int *)binary)[i]!=((int *)crypt_key)[i])
			return 0;
#endif
		i++;
	}

	return 1;
}

static int cmp_one (unsigned char * binary, int index)
{
	int i = 0;
	for(i=0;i<BINARY_SIZE;i++)
		if( ((unsigned char *)crypt_key)[i+BINARY_SIZE*index] != binary[i] )
			return 0;
	return 1;
}

static void set_salt (void *salt) { }


/*Beginning of private functions*/
/* Takes the plaintext password and generates the second row of our
 * working matrix for the final call to the mixing function*/
void
lotus_transform_password (unsigned char *inpass, unsigned char *outh)
{
  unsigned char prevbyte;
  int i;

  prevbyte = 0x00;
  for (i = 0; i < 16; i++)
    {
      *outh = lotus_magic_table[ARCH_INDEX((*inpass) ^ prevbyte)];
      prevbyte = *outh;
      ++outh;
      ++inpass;
    }
}

/* The mixing function: perturbs the first three rows of the matrix*/
void lotus_mix (unsigned char *lotus_matrix)
{
	int i, j;
	unsigned char prevbyte;
	unsigned char *temp;

	prevbyte = 0x00;

	for (i = 0; i < 18; i++)
	{
		temp = lotus_matrix;
		for (j = 48; j > 0; j--)
		{
			*temp = *temp ^ lotus_magic_table[ARCH_INDEX( (j + prevbyte) & 0xff)];
			prevbyte = *temp;
			temp++;
		}
	}
}

/*the last public function; generates ciphertext*/
static unsigned int crypt_all (int count)
{
#if LOTUS_ASM
	unsigned char lotus_matrix[64*MAX_KEYS_PER_CRYPT];
#else
	unsigned char password[PLAINTEXT_LENGTH];
	unsigned char lotus_matrix[64];
#endif
	unsigned int i;

#if LOTUS_ASM
	memset (lotus_matrix, 0, 16);
	memset (lotus_matrix+64, 0, 16);
	memset (lotus_matrix+128, 0, 16);

	memcpy (lotus_matrix+16, saved_key, 16);
	memcpy (lotus_matrix+16+64, saved_key+16, 16);
	memcpy (lotus_matrix+16+128, saved_key+32, 16);
	
	memcpy (lotus_matrix+32, saved_key, 16);
	memcpy (lotus_matrix+32+64, saved_key+16, 16);
	memcpy (lotus_matrix+32+128, saved_key+32, 16);

	lotus_transform_password_asm (lotus_matrix+16);

	lotus_mix_asm (lotus_matrix);
	lotus_xor_asm(lotus_matrix);
	lotus_mix_asm (lotus_matrix);

	memcpy (crypt_key, lotus_matrix, BINARY_SIZE);
	memcpy (crypt_key+BINARY_SIZE, lotus_matrix+64, BINARY_SIZE);
	memcpy (crypt_key+2*BINARY_SIZE, lotus_matrix+128, BINARY_SIZE);
#else
	memset (lotus_matrix, 0, 16);
	memcpy (lotus_matrix+16, saved_key, 16);
	memcpy (lotus_matrix+32, saved_key, 16);
	lotus_transform_password (lotus_matrix+16, lotus_matrix+48);
	lotus_mix (lotus_matrix);
	memcpy (lotus_matrix+16, lotus_matrix+48, 16);
	for (i = 0; i < 16; i++)
	{
		lotus_matrix[i+32] = lotus_matrix[i] ^ lotus_matrix[i+48];
	}
	lotus_mix (lotus_matrix);
	memcpy (crypt_key, lotus_matrix, BINARY_SIZE);
#endif
	return ((unsigned char * )crypt_key)[0];
}


static unsigned int get_hash(int index) { return (((unsigned int *)crypt_key)[index*BINARY_SIZE/sizeof(int)] & 0xff); }
static int binary_hash(void * binary) { return (((unsigned int *)binary)[0] & 0xff); }

/* C's version of a class specifier */
struct s_format fmt_lotus5 = {
	{
		CIPHER_ID_LOTUS_5,
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
