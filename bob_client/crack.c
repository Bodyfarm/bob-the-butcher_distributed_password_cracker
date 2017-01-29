
#include "params.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "btb.h"
#include "client.h"
#include "log.h"
#include "format.h"
#include "crack.h"
#include "salts.h"
#include "rw.h"
#include "client_connect.h"
#include "timer.h"

extern t_client_opt opt;

#ifdef MMX_COEF
#define DO_BENCH(text,time,func, mul, charset) \
	asm("emms"); \
	nb = 0; printf(text); start_timer(time); start_chrono(); while(timer_active) { func; nb++; }; \
	asm("emms"); \
	stop_chrono(nb*mul, charset); 
#else
#define DO_BENCH(text,time,func, mul, charset) \
	nb = 0; printf(text); start_timer(time); start_chrono(); while(timer_active) { func; nb++; }; \
	stop_chrono(nb*mul, charset); 
#endif

/* horreur malheur, à refaire ! */
static void benchmark(struct s_format * fmt)
{
	uint64_t i;
	unsigned int idx;
	unsigned int ok;
	unsigned int supok;
	uint64_t nb;
	uint64_t end;
	extern struct s_salt * salt_list;
	struct s_salt * cursalt;
	struct s_password * curpwd;
	struct s_same_hash * hasht;
	int hash;
	int fail = 0;
	unsigned int j,k,t;

	if(fmt->params.benchmark_length>0)
		end = fmt->params.benchmark_length;
	else
		end = DEFAULT_BENCH_LEN;
	
	idx = 0;
	printf("Benchmarking %s [%s]\n", fmt->params.name, fmt->params.algname);
	/* first checks that all test thingies are valid, and init stuff ... */
	while(fmt->params.tests[idx].username)
	{
		if(!fmt->methods.valid(fmt->params.tests[idx].ciphertext))
		{
			printf("%s is not valid\n", fmt->params.tests[idx].ciphertext);
			error_log("Valid() failed");
		}
		insert_password(fmt->params.tests[idx].username, fmt->params.tests[idx].ciphertext, fmt);
		idx ++;
	}

	idx = 0;

	//first case : USERNAME_USED
	//
	if (fmt->params.flags & USERNAME_USED)
	{
		cursalt = salt_list;
		while(cursalt)
		{
			if(cursalt->salt)
			{
				if(opt.debug)
					debug_log("set salt");
				fmt->methods.set_salt(cursalt->salt);
			}

			curpwd = cursalt->pwd;
			while(curpwd)
			{
				fmt->methods.set_username( curpwd->username);

				for(i=0; i<15; i++)
				{
					idx++;
					if( (fmt->params.tests[idx].username) == 0 )
						idx = 0;
					fmt->methods.set_key( fmt->params.tests[idx].plaintext, 0);

					fmt->methods.crypt_all(1);
					if( fmt->methods.cmp_all( curpwd->binary, 0 ) )
					{
						ok=1;
						break;
					}
				}
				curpwd = curpwd->next;
			}
			cursalt = cursalt->next;
		}
	}
	//no USERNAME_USED
	//code is duplicated ... sucks
	else
	{
		cursalt = salt_list;
		while(cursalt)
		{
			if(cursalt->salt)
			{
				if(opt.debug)
					debug_log("set salt");
				fmt->methods.set_salt(cursalt->salt);
			}

			supok = 0;

			for(i=0; i<1; i++)
			{
				for(j=0;j < fmt->params.max_pwd_per_crypt;j++)
				{
					struct s_password * curpwd;
					//be
deb:
					idx++;
					if( (fmt->params.tests[idx].username) == NULL )
						idx = 0;
					
					curpwd = cursalt->pwd;
					while(curpwd)
					{
						if(!strcmp(curpwd->ciphertext, fmt->params.tests[idx].ciphertext))
							break;
						curpwd = curpwd->next;
					}
					if(curpwd==NULL)
					{
						goto deb;
					}

					fmt->methods.set_key( fmt->params.tests[idx].plaintext, j);
				}

				fmt->methods.crypt_all(fmt->params.max_pwd_per_crypt);

				ok = 0;
				for(j=0;j < fmt->params.max_pwd_per_crypt;j++)
				{
					hash = fmt->methods.get_hash(j);
					hasht = cursalt->hashtable[hash];
					while(hasht)
					{
						if(fmt->methods.cmp_all( hasht->pwd->binary, fmt->params.max_pwd_per_crypt ) )
						{
							for(k=0;k<fmt->params.max_pwd_per_crypt;k++)
							{
								if(fmt->methods.cmp_one( hasht->pwd->binary, k))
								{
									if(fail)
									{
										//printf("g");
										//printf("cmp one %d\n", k);
									}
									ok++;
								}
							}
						}
						hasht = hasht->next;
					}
				}

				if(ok!=fmt->params.max_pwd_per_crypt)
				{
					/*
					if(fail == 0)
						error_log("Cmp failed");
					else */
						printf("[f ok(%d) max(%d)]", ok, fmt->params.max_pwd_per_crypt);
					fail = 1;
				}
			}

			cursalt = cursalt->next;
		}
	}

	if(fail)
		printf("\n");

	if(opt.benchmark>1)
	{
		DO_BENCH("\tset_key\t\t:", 1, fmt->methods.set_key( fmt->params.tests[0].plaintext, (nb % fmt->params.max_pwd_per_crypt) ), 1, 0);
		DO_BENCH("\tcmp_all\t\t:", 1, fmt->methods.cmp_all( salt_list->pwd->binary, fmt->params.max_pwd_per_crypt ), 1, 0);
		DO_BENCH("\tcmp_one\t\t:", 1, fmt->methods.cmp_one( salt_list->pwd->binary, 0 ), 1, 0 );
		if ( fmt->params.salt_size > 0 )
		{
			DO_BENCH("\tset_salt\t:", 1, fmt->methods.set_salt( salt_list->salt ), 1, 0);
		}
		if ( fmt->params.flags & USERNAME_USED)
		{
			DO_BENCH("\tset_username\t:", 1, fmt->methods.set_username( fmt->params.tests[0].username), 1, 0);
		}
	}
	j = 62;
	if(fmt->params.flags & ALL_CAPS)
		j -= 26;

	DO_BENCH("\tcrypt\t\t:", 2, fmt->methods.crypt_all(fmt->params.max_pwd_per_crypt), fmt->params.max_pwd_per_crypt, j)

	DO_BENCH("\tfull crack\t:", 2, 
			for(t=0;t<fmt->params.max_pwd_per_crypt;t++)
				fmt->methods.set_key( fmt->params.tests[0].plaintext, t);
			fmt->methods.crypt_all(fmt->params.max_pwd_per_crypt);
			fmt->methods.cmp_all(salt_list->pwd->binary, fmt->params.max_pwd_per_crypt);
			, fmt->params.max_pwd_per_crypt, j)

	remove_all_salts();
}

/* let's say that max password length is 64 ... */
#define MAX_PWD_LEN 64

static int set_pwd(unsigned char * password, uint64_t pos, unsigned int charset_size)
{
	unsigned int i;

	i= MAX_PWD_LEN - 1;
	while(pos)
	{
		password[i] = idx2chr[(unsigned int) pos % charset_size];
		pos = pos / charset_size;
		i--;
	}
	return i + 1 ;
}

static int update_pwd(unsigned char * password)
{
	unsigned int i;

	i = MAX_PWD_LEN - 1 ;
	while ( (password[i] = incrementer[(unsigned int) password[i]]) == 0)
	{
		password[i] = incrementer[0];
		i--;
		if(password[i]==0)
		{
			password[i] = incrementer[0];
			return i;
		}
	}
	return i;
}

static int crack_salt(struct s_format * fmt, struct s_salt * cursalt)
{
	struct s_same_hash * hasht;
	unsigned int hash;
	unsigned int i;

	if(!cursalt)
		return 0;
	for(i=0;i<fmt->params.max_pwd_per_crypt;i++)
	{
		hash = fmt->methods.get_hash(i);
		hasht = cursalt->hashtable[hash];
		while(hasht)
		{
			if (fmt->methods.cmp_one( hasht->pwd->binary, i ))
			{
				//show_hashtables();
				// found one password !
				if(opt.verbose | opt.standalone)
					printf("found! %s:%s:%s\n", hasht->pwd->username, hasht->pwd->ciphertext, fmt->methods.get_key(i));
				if(!opt.standalone)
					client_password_found(hasht->pwd->username, hasht->pwd->ciphertext, fmt->methods.get_key(i));

				if(remove_password(hasht->pwd->username, hasht->pwd->ciphertext, fmt) == 2)
				{
					return 2;
				}
				hasht = cursalt->hashtable[hash];
				if(!hasht)
					continue; 
			}
			hasht = hasht->next;
		}
	}
	return 1;
}

static int crack_salt_username(struct s_format * fmt, struct s_password * curpwd )
{
	unsigned int i;

	if(!curpwd)
		return 0;

	if( fmt->methods.cmp_all( curpwd->binary, fmt->params.max_pwd_per_crypt ) )
		for(i=0;i < fmt->params.max_pwd_per_crypt; i++)
			if (fmt->methods.cmp_one( curpwd->binary, i))
			{
				if(opt.verbose | opt.standalone) 
					printf("found! %s:%s:%s\n", curpwd->username, curpwd->ciphertext, fmt->methods.get_key(i));
				if(!opt.standalone)
					client_password_found(curpwd->username, curpwd->ciphertext, fmt->methods.get_key(i));
				if( remove_password(curpwd->username, curpwd->ciphertext, fmt) == 2)
				{
					return 2;
				}
			}
	return 1;
}


static int main_crack_loop(struct s_format * fmt, uint64_t start, uint64_t end, uint64_t * nb, struct s_salt * cursalt)
{
	unsigned char password[MAX_PWD_LEN + 1];
	uint64_t cur;
	unsigned int pos;
	unsigned int npos;
	struct s_password * curpwd = NULL;
	unsigned int i;
	unsigned int charset_size;

	//FIXME same username un-optimization ...

	charset_size = 26 + 26 + 10;
	if (fmt->params.flags & ALL_CAPS)
		charset_size = 26 + 10;

	if (fmt->params.flags & USERNAME_USED)
	{
		curpwd = cursalt->pwd;
new_username:
		if(opt.debug)
			printf("set username %s\n", curpwd->username);
		fmt->methods.set_username( curpwd->username );
	}

	/* generates the nth combination - init stuff */
	memset(password, 0, MAX_PWD_LEN + 1);
	cur = start;
	pos = set_pwd(password, cur, charset_size);
	//fmt->methods.set_key( password + pos, 0);

	if(opt.debug)
		printf("Start working %s with algo %s (%lld)", password + pos, fmt->params.algname, cur);

	if(cursalt->salt)
	{
		if(opt.debug)
			printf(", salt %x", (unsigned char)*cursalt->salt);
		fmt->methods.set_salt(cursalt->salt);
	}

	if ( (fmt->params.flags & USERNAME_USED) && opt.debug )
		printf(", username %s", curpwd->username);

	if(opt.debug)
		printf("\n");

	while(cur<=end)
	{
		//sets keys to hash
		for(i=0;i < fmt->params.max_pwd_per_crypt; i++)
		{
			fmt->methods.set_key( password + pos, i);
			npos = update_pwd(password);
			if(npos<pos)
				pos = npos;
		}

		//crypt
		fmt->methods.crypt_all(fmt->params.max_pwd_per_crypt);
		*nb += fmt->params.max_pwd_per_crypt;
		cur += fmt->params.max_pwd_per_crypt;

		if (fmt->params.flags & USERNAME_USED)
		{
			if(crack_salt_username(fmt, curpwd) == 2)
				return 2;
		}
		else
			if(crack_salt(fmt, cursalt) == 2)
				return 2;
	}
	if (fmt->params.flags & USERNAME_USED)
	{
		curpwd = curpwd->next;
		if(curpwd)
			goto new_username;
	}
	return 1;
}

void stupid_brute_force(struct s_format * fmt, uint64_t start, uint64_t end)
{
	uint64_t cur;
	uint64_t nb;
	extern struct s_salt * salt_list;
	struct s_salt * cursalt;
	unsigned int charset_size;

	cur = start;
	nb = 0;
#ifdef DEBUG
	UP_SPACE_LEVEL;
	printf(" %s %lld -> %lld\n", __func__, start, end);
#endif
#ifdef MMX_COEF
	asm("emms");
#endif

	if(opt.verbose | opt.standalone)
		start_chrono();
	cursalt = salt_list;
	while(cursalt)
	{
		if(main_crack_loop(fmt, start, end, &nb, cursalt) == 2)
			cursalt = salt_list;
		if(!cursalt)
			break;
		cursalt = cursalt->next;
	}
#ifdef MMX_COEF
	asm("emms");
#endif
	charset_size = 26 + 26 + 10;
	if (fmt->params.flags & ALL_CAPS)
		charset_size = 26 + 10;
	if(opt.verbose | (opt.standalone && (salt_list == 0) ) )
		stop_chrono(nb, charset_size);

#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
}

/*
 * This functions finds the right crack function to run
 */
void do_crack(unsigned int type, struct s_format * fmt, uint64_t start, uint64_t end)
{
	if ((type!=0) && (fmt == NULL))
	{
		error_log("Invalid algorithm");
		return;
	}

	if(type != 0)
		incrementer_init(fmt->params.flags);

	switch(type)
	{
		/* bench */
		case 0:
			if(opt.verbose)
				verbose_log("Benchmark mode");
			if( fmt == NULL)
			{
				fmt = format_list;
				while(fmt)
				{
					incrementer_init(fmt->params.flags);
					benchmark(fmt);
					fmt = fmt->next;
				}
			}
			else
				benchmark(fmt);
			break;
		/* stupid brute force */
		case 1:
			if(opt.verbose)
				verbose_log("Basic brute force mode");
			stupid_brute_force(fmt, start, end);
			break;
	}
}

/*
 * This functions is used when generating passwords via JtR
 */
int john_crack(struct s_format * fmt)
{
#ifdef DEBUG
	UP_SPACE_LEVEL;
	printf(" %s\n", __func__);
#endif

	FILE * pjohn = NULL;
	unsigned char cmdline[500];
	unsigned char output[100];
	unsigned char tmpfilename[] = "/tmp/bob-XXXXXX";
	int tmpfile;
	FILE * tmpfilef;
	struct s_salt * cursalt;
	struct s_password * curpwd;
	
	if( (opt.wordlist == NULL) || (fmt == NULL))
		goto john_error;

	if( strlen(opt.john) + strlen(opt.wordlist) + strlen(tmpfilename) + strlen(fmt->params.labelname) + 17 > sizeof(cmdline) ) /* uh uh */
		goto john_error;

	tmpfile = mkstemp(tmpfilename);
	if(tmpfile <=0 )
		goto john_error;

	tmpfilef = fdopen(tmpfile, "w");
	if(tmpfilef == NULL)
		goto john_error;

	cursalt = salt_list;
	while(cursalt)
	{
		curpwd = cursalt->pwd;
		while(curpwd)
		{
			fprintf(tmpfilef, "%s:%s\n", curpwd->username, curpwd->ciphertext);
			curpwd = curpwd->next;
		}
		cursalt = cursalt->next;
	}
	fclose(tmpfilef);

	memset(cmdline, 0, sizeof(cmdline));
	strncpy(cmdline, opt.john, sizeof(cmdline));
	strcat(cmdline, "-w:");
	strncat(cmdline, opt.wordlist, sizeof(cmdline) - strlen(opt.john) - 15);
	strcat(cmdline, " -rules -f ");
	strcat(cmdline, fmt->params.labelname);
	strcat(cmdline, " ");
	strcat(cmdline, tmpfilename);

	pjohn = popen(cmdline, "r");
	while(fgets(output, sizeof(output), pjohn) != EOF)
	{
		unsigned char username[MAX_PWD_LEN];
		unsigned char password[MAX_PWD_LEN];
		if(vsscanf("%[^ ]*%[ ]%[^ ]", username, password)==2)
		{
			client_password_found(username, NULL, password);
		}
	}

	return 1;
john_error:
#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
	return 0;
}
