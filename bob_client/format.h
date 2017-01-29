/*
 * format flags definition
 */

#ifndef __FORMAT_H__
# define __FORMAT_H__

#define USERNAME_USED 1 /* username is to be set */
#define ALL_CAPS 2 /* this cipher likes caps */

struct s_format_tests {
	char * username;
	char * ciphertext;
	char * plaintext;
};

struct s_format_params {
	unsigned int id; /* format id, for communication with the server .. */
	char * labelname; /* label name, for command line and stuff */
	char * name; /* format name, ie. "Microsoft MS Cache" */
	char * algname; /* algorithm name */
	unsigned int flags;
	/* for future bitsliced thingies ? */
	unsigned int min_pwd_per_crypt;
	unsigned int max_pwd_per_crypt;
	/* sizes */
	int benchmark_length;
	unsigned int plaintext_length;
	unsigned int binary_size;
	unsigned int salt_size;

	/* test passwords */
	struct s_format_tests * tests;
};

struct s_format_methods
{
	/* 
	 * used to initialize internal structures
	 * only valid() should work without this
	 */
	void (*init)(void);
	int (*valid)(char * ciphertext); /* Checks if a ciphertext is valid according to this format */
	void *(*binary)(char * ciphertext); /* converts ascii ciphertext to binary */
	void *(*salt) (char * string); /* gets salt from string, and convert it into internal representation */
	void (*set_salt)(void * salt); /* sets the current salt for the crypt method */
	void (*set_key)(char * key, int index); /* set a key (that's gonna be hashed and compared for a particular index ¤ [min_pwd_per_crypt-1:max_pwd_per_crypt] */
	char *(*get_key)(int index); /* returns a key set by set_key */
	void (*set_username)(char * username); /* puts a particular username in the username stuff */
	unsigned int (*crypt_all)(int count); /* crypts up to count keys, set by set_key, must return a hash value, **positive** */
	int (*cmp_all)(void * binary, int count); /* compares up to count keys in the hashed keys structure with a given binary*/
	int (*cmp_one)(void * binary, int index); /* compares a given binary with a hashed key specified by index */
	unsigned int (*binary_hash)(void *binary); /* These functions calculate a hash out of a binary ciphertext. To be used
					      * for hash table initialization. One of the three should be used depending
					      * on the hash table size. */
	/* These functions calculate a hash out of a ciphertext that has just been
	 * generated with the crypt_all() method. To be used while cracking. */
        unsigned int (*get_hash)(int index);
};

struct s_format
{
	struct s_format_params params;
	struct s_format_methods methods;
	struct s_format * next;
};

void format_default_init(void);
struct s_format * format_find(unsigned int id);
struct s_format * format_find_name(char * name);
void format_init_all(void);
void * format_default_salt(char * salt);
void format_default_set_username(char * username);
void * format_default_binary(char * ciphertext);
void * format_default_get_salt (char * string); /* gets salt from string, and convert it into internal representation */
void format_default_set_salt(void * salt); /* sets the current salt for the crypt method */
unsigned int format_default_binary_hash(void * binary);

extern struct s_format fmt_mscash;
extern struct s_format fmt_lotus5;
extern struct s_format fmt_rawMD5;
extern struct s_format fmt_MYSQL;
extern struct s_format fmt_BFEgg;
extern struct s_format fmt_NT;
extern struct s_format fmt_MD5;
extern struct s_format fmt_DES;
extern struct s_format fmt_NSLDAP;
extern struct s_format fmt_rawSHA1;
extern struct s_format fmt_BSDI;
extern struct s_format fmt_oracle;

extern struct s_format * format_list;

#endif   /* __FORMAT_H__ */
