
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "bob_server.h"

void show_passwords(struct hpasswd * hpasswd)
{
	struct s_passwd * curpwd;

	TAILQ_FOREACH_REVERSE(curpwd, hpasswd, next, hpasswd)
	{
#ifdef DEBUG
		TAB_WRITE;
#endif
		printf(" %s %s", curpwd->username, curpwd->password);
		if(curpwd->cleartext != NULL)
			printf(" %s", curpwd->cleartext);
		printf("\n");
	}
}

struct s_passwd *add_passwd(struct hpasswd  *hpasswd,
                            char            *username,
                            char            *passwd,
                            unsigned int    cipher)
{
#ifdef DEBUG
   TAB_WRITE;
   printf(" %s [user=%s] [pwd=%s] [c=%d]\n", __func__, username, passwd, cipher); 
#endif
    struct s_passwd *res = NULL;

    res = (struct s_passwd *) calloc (1, sizeof(struct s_passwd));
    if ( res == NULL)
        XPERROR("calloc", MEM_EXIT);

    res->username = username;
    res->password = passwd;
    res->cipher   = cipher;
    res->cleartext = NULL;

    TAILQ_INSERT_TAIL(hpasswd, res, next);

    return(res);
}

void    remove_all_passwds(struct hpasswd *hpasswd)
{
#ifdef DEBUG
    TAB_WRITE;
    printf(" %s\n",  __func__);
#endif
    struct s_passwd *tmp = NULL;

    TAILQ_FOREACH_REVERSE(tmp, hpasswd, next, hpasswd)
    {
        TAILQ_REMOVE(hpasswd, tmp, next);
        XFREE(tmp->username);
        XFREE(tmp->password); 
	if(tmp->cleartext)
	{
		XFREE(tmp->cleartext); 
	}
        XFREE(tmp);
    }
}

void password_found(
		void * vjob,
		char * username,
		char * pwd,
		char * cleartext)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s (%s/%s/%s)\n", __func__, username, pwd, cleartext);
#endif
	struct s_passwd * curpwd;
	struct s_jobs * job;

	job = (struct s_jobs *) vjob; //STUPID !

	TAILQ_FOREACH_REVERSE(curpwd, job->passwd, next, hpasswd)
	{
		if( 
				( strncmp(curpwd->username, username, MAX_PWD_SIZE) == 0 ) && 
				( (strncmp(curpwd->password, pwd, MAX_PWD_SIZE) == 0) || (pwd == NULL) ) && //for john mode ..
				( curpwd->cleartext == NULL )
				)
		{
			curpwd->cleartext = strndup(cleartext, MAX_PWD_SIZE);
			job->nb_found_pwd++;
			if(job->nb_found_pwd == job->nb_pwd)
			{
#ifdef DEBUG
				TAB_WRITE;
				printf(" JOB FINISHED\n");
#endif
				job->status = JOB_FINISHED;
			}
		}
	}
}
