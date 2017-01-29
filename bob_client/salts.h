#ifndef  __SALTS_H__
# define __SALTS_H__

/*
 * This one is used by the client
 */

/*
 * holds passwords having the same salt
 */
struct s_password
{
	struct s_password * next;
	char * binary; /* ciphertext in internal representation */
	char * ciphertext; /* ciphertext in ascii representation */
	char * username; /* username */
};

/*
 * linked list containing passwords with the same "hash"
 */
struct s_same_hash
{
	struct s_same_hash * next;
	struct s_password * pwd;
};

/*
 * holds the different salts
 */
struct s_salt
{
	struct s_salt * next;
	struct s_password * pwd; /* list of passwords with this salt */
	/* there will be a hash table here someday */
	int count; /* number of passwords with this salt */
	struct s_same_hash * hashtable[256]; /* hash table for fast password lookup */
	char * salt; /* salt in internal representation */
};

extern struct s_salt * salt_list;

int insert_password(char * username, char * ciphertext, struct s_format * fmt);
int remove_password(char * username, char * ciphertext, struct s_format * fmt);
void remove_all_salts(void);
void show_hashtables();
# ifdef DEBUG
void show_salt_list(struct s_format * fmt);
# endif

#endif
