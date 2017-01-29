#include "params.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "btb.h"
#include "client.h"

#include "format.h"
#include "salts.h"
#include "log.h"
#include "rw.h"

extern t_client_opt opt;

struct s_salt * salt_list;

void init_salt_list(void)
{
	salt_list = 0;
}

static struct s_salt * get_salt_struct(char * binsalt, int size)
{
	unsigned int s;
	struct s_salt * cursalt;
	
	cursalt = salt_list;
	while(cursalt)
	{
		s=0;
		while(s<size)
		{
			if(binsalt[s]!=cursalt->salt[s])
				break;
			s++;
		}
		if(s==size)
			return cursalt;
		cursalt = cursalt->next;
	}
	return 0;
}

/*
 * inserts a password in the salt_list structure
 */
int insert_password(char * username, char * ciphertext, struct s_format * fmt)
{
	struct s_password * pwd;
	struct s_salt * cursalt;
	struct s_same_hash * pwdhash;
	char * binsalt;
	unsigned int hash;

#ifdef DEBUG
	TAB_WRITE;
	printf(" %s (%s/%s) - %s\n", __func__, username, ciphertext, fmt->params.labelname);
#endif
	
	if(!fmt->methods.valid(ciphertext))
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" invalid password\n");
#endif
		return 0;
	}
	
	pwd = malloc(sizeof(struct s_password));
	pwd->binary = fmt->methods.binary(ciphertext);
#ifdef HAVE_STRNDUP
	pwd->username = strndup(username, 1024);
	pwd->ciphertext = strndup(ciphertext, 1024);
#else
	pwd->username = strdup(username);
	pwd->ciphertext = strdup(ciphertext);
#endif
	if(fmt->params.flags & ALL_CAPS)
		to_upper(pwd->username);
	binsalt = 0;

	/* finds the good salt structure to add the password to */
	if(fmt->params.salt_size>0)
	{
		if(opt.debug)
			debug_log("calculating salt");
		binsalt = fmt->methods.salt(ciphertext);
		cursalt = get_salt_struct(binsalt, fmt->params.salt_size);
	}
	else
		cursalt = salt_list;
	
	if(cursalt == 0) /* must create a new salt struct */
	{
		cursalt = malloc(sizeof(struct s_salt));
		if(!cursalt)
		{
			error_log("insert_password(): malloc cursalt failed");
			return 0;
		}
		cursalt->next = salt_list;
		cursalt->count = 0;
		cursalt->pwd = 0;
		cursalt->salt = binsalt;
		memset(cursalt->hashtable, 0, sizeof(struct s_same_hash *)*256);
		salt_list = cursalt;
	}
	else
		if(binsalt)
			free(binsalt);
	
	/* now puts the password in */
	pwd->next = cursalt->pwd;
	cursalt->pwd = pwd;

	/* fill the hash table */
	hash = fmt->methods.binary_hash(pwd->binary); 
	pwdhash = malloc(sizeof(struct s_same_hash));
	pwdhash->next = cursalt->hashtable[hash];
	pwdhash->pwd = pwd;
	cursalt->hashtable[hash] = pwdhash;
	
	cursalt->count++;
	return 1;
}

/*
 * show all the hash lists
 */
void show_hashtables()
{
	struct s_salt * cursalt;
	struct s_same_hash * pwdhash;
	int i;

	printf("hashtable:\n");
	cursalt = salt_list;
	while(cursalt)
	{
		if(cursalt->salt)
			printf("Salt [%x]\n", cursalt->salt[0]);
		for(i=0;i<256;i++) if ( (pwdhash = cursalt->hashtable[i]) )
		{
			printf("\tChain %.2x ", i);
			//pwdhash = cursalt->hashtable[i];
			while(pwdhash)
			{
				printf("%s:%s ", pwdhash->pwd->username, pwdhash->pwd->ciphertext);
				pwdhash = pwdhash->next;
			}
			printf("\n");
		}
		printf("\n");
		cursalt = cursalt->next;
	}
}

/*
 * removes a salt from the salt list
 */
static int remove_salt(struct s_salt * rsalt)
{
	struct s_salt * cursalt;
	struct s_salt * prevsalt;

	//printf("removing salt %x\n", *rsalt->salt);
	prevsalt = 0;
	cursalt = salt_list;

	while(cursalt && (cursalt!=rsalt) )
	{
		prevsalt = cursalt;
		cursalt = cursalt->next;
	}
	if(!cursalt)
		return 0;
	
	if(prevsalt == 0)
		salt_list = cursalt->next;
	else
		prevsalt->next = cursalt->next;
	
	if(cursalt->salt)
		free(cursalt->salt);

	free(cursalt);

	return 2;
}

/*
 * removes a password from the salt_list structure
 */
int remove_password(char * username, char * ciphertext, struct s_format * fmt)
{
	char * binsalt;
	struct s_salt * cursalt;
	struct s_password * curpwd;
	struct s_password * prevpwd;

	unsigned int hash;
	struct s_same_hash * curhasht;
	struct s_same_hash * prevhasht;

	if(!fmt->methods.valid(ciphertext))
		return 0;

	if(fmt->params.salt_size>0)
	{
		binsalt = fmt->methods.salt(ciphertext);
		cursalt = get_salt_struct(binsalt, fmt->params.salt_size);
	}
	else
		cursalt = salt_list;

	if(!cursalt)
		return 0;

	curpwd = cursalt->pwd;
	prevpwd = 0;
	while(curpwd)
	{
		if( !strncmp(username, curpwd->username, 128) ) if( !memcmp(ciphertext, curpwd->ciphertext, fmt->params.plaintext_length) )
		{
			if(prevpwd)
				prevpwd->next = curpwd->next;
			else
				cursalt->pwd = curpwd->next;
			
			/* remove from the hashtable */
			prevhasht = NULL;
			hash = fmt->methods.binary_hash(curpwd->binary);
			curhasht = cursalt->hashtable[hash];
			while(curhasht && (curhasht->pwd != curpwd) )
			{
				prevhasht = curhasht;
				curhasht = curhasht->next;
			}
			if(prevhasht)
				prevhasht->next = curhasht->next;
			else
				cursalt->hashtable[hash] = curhasht->next;

			free(curhasht);
					
			/* remove from the salt list */
			cursalt->count--;
			free(curpwd->ciphertext);
			free(curpwd->binary);
			free(curpwd->username);
			free(curpwd);

			/* delete salts ... */
			if(cursalt->pwd == 0)
				return remove_salt(cursalt);
			
			return 1;
		}
		prevpwd = curpwd;
		curpwd = curpwd->next;
	}
	return 0;
}

/*
 * deletes all passwords from a salt_list structure
 */
void remove_all_passwords(struct s_salt * salt)
{
	struct s_password * pwd;

	while(salt->pwd)
	{
		pwd = salt->pwd;
		free(pwd->ciphertext);
		free(pwd->binary);
		free(pwd->username);
		salt->pwd = pwd->next;
		free(pwd);
	}
}

/*
 * deletes all entries in the hashtable
 */

void remove_all_hashtable(struct s_salt * salt)
{
	struct s_same_hash * hash;
	int i;

	for(i=0;i<256;i++)
	{
		while(salt->hashtable[i])
		{
			hash = salt->hashtable[i];
			salt->hashtable[i] = hash->next;
			free(hash);
		}
	}
}


/*
 * deletes all salts from the salt list
 */
void remove_all_salts(void)
{
	struct s_salt * cursalt;

	while(salt_list)
	{
		cursalt = salt_list;
		remove_all_passwords(cursalt);
		remove_all_hashtable(cursalt);
		if(cursalt->salt)
			free(cursalt->salt);
		salt_list = salt_list->next;
		free(cursalt);
	}
}

#ifdef DEBUG
/*
 * show the salt_list structure
 */
void show_salt_list(struct s_format * fmt)
{
	struct s_salt * cursalt;
	struct s_password * curpwd;
	unsigned int i;

	cursalt = salt_list;
	printf("Salt list for algo %s:\n", fmt->params.name);
	while(cursalt)
	{
		if(fmt->params.salt_size)
		{
			printf("Salt ");
			for(i=0; i < fmt->params.salt_size; i++)
			{
				printf("%.2x", cursalt->salt[i]);
			}
			printf("\n");
		}
		curpwd = cursalt->pwd;
		while(curpwd)
		{
			printf("\t%s:%s\n", curpwd->username, curpwd->ciphertext);
			curpwd = curpwd->next;
		}
		cursalt = cursalt->next;
	}
	printf("Finished\n");
}
#endif
