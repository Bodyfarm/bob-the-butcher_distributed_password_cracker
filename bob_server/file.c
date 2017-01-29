#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "bob_server.h"

/*
    File type

    username: string;
    password: string;
    cipher:   string;

    token: username password cipher ;

    tokens: token |
            tokens token;

    job: int tokens;

    jobs:   job |
            jobs job;

*/
static const char   *filename = NULL;

int     load_file (const char *fl)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
	UP_SPACE_LEVEL;
#endif
	
	unsigned char * buf = NULL;
	unsigned char * tmp1 = NULL;
	unsigned char * tmp2 = NULL;
	unsigned char * tmp3 = NULL;
	unsigned int i = 0;

	uint64_t start;
	uint64_t end;
	enum status_space status;

	FILE    *file = NULL;
	unsigned int mode = 0;

	struct s_jobs * curjob = NULL;
	struct s_jobs tmpjob;
	struct s_passwd * curpwd;


	filename = fl;
	file = fopen(filename, "r");
	if ( file == NULL)
	{
#ifdef DEBUG
		printf("   - fopen failed. %s not found.\n", filename);
		DOWN_SPACE_LEVEL;
#endif
		return (0);
	}

	buf = malloc(5000);
	tmp1 = malloc(5000);
	tmp2 = malloc(5000);
	tmp3 = malloc(5000);
	if( (!buf) || (!tmp1) || (!tmp2) || (!tmp3) )
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" can't malloc\n");
		DOWN_SPACE_LEVEL;
#endif
		return 0;
	}

	while(1)
	{
		if(fgets(buf, 5000, file) == NULL)
			break;
		if(!strncmp(buf, "job", 3))
		{
			mode = 1;
			continue;
		}
		if(!strncmp(buf, "passwords", 9))
		{
			mode = 2;
			continue;
		}
		if(!strncmp(buf, "spaces", 6))
		{
			mode = 3;
			continue;
		}

		buf[strlen(buf)-1] = 0;

		switch(mode)
		{
			case 1:
				if(sscanf(buf, "%d:%[^:]:%d:%d:%d:%d:%lld",
							&(tmpjob.id),
							tmp1,
							&(tmpjob.date_start),
							&(tmpjob.status),
							&(tmpjob.prior),
							&(tmpjob.current_prior),
							&(tmpjob.interval_size))==7)
				{
					mode = 4;
				}
#ifdef DEBUG
				else
				{
					TAB_WRITE;
					printf(" cannot parse %s (%d)\n", buf, mode);
				}
#endif
					
				break;
			case 4:
				if(sscanf(buf, "%d:%d:%d:%d",
							&(tmpjob.cipher),
							&(tmpjob.crack_method),
							&(tmpjob.nb_pwd),
							&(tmpjob.nb_found_pwd))==4)
				{
					curjob = add_job(get_hjobs(NULL), strdup(tmp1), tmpjob.cipher, tmpjob.crack_method, tmpjob.nb_pwd);
					curjob->date_start = tmpjob.date_start;
					curjob->status = tmpjob.status;
					curjob->prior = tmpjob.prior;
					curjob->current_prior = tmpjob.current_prior;
					curjob->interval_size = tmpjob.interval_size;
				}
#ifdef DEBUG
				else
				{
					TAB_WRITE;
					printf(" cannot parse %s (%d)\n", buf, mode);
				}
#endif

				break;
			case 2:
				if(!curjob)
					break;
				if(sscanf(buf, "%[^:]:%[^:]::%d", tmp1, tmp2, &i)==3)
				{
					curpwd = add_passwd(curjob->passwd, strdup(tmp1), strdup(tmp2), i);
				}
				else if(sscanf(buf, "%[^:]:%[^:]:%[^:]:%d", tmp1, tmp2, tmp3, &i)==4)
				{
					curpwd = add_passwd(curjob->passwd, strdup(tmp1), strdup(tmp2), i);
					password_found(curjob, tmp1, tmp2, tmp3);
				}
#ifdef DEBUG
				else
				{
					TAB_WRITE;
					printf(" cannot parse %s (%d)\n", buf, mode);
				}
#endif

				break;
			case 3:
				if(!curjob)
					break;
				if(sscanf(buf, "%lld:%lld:%d", &start, &end, &status)==3)
				{
					if(status != DONE)
						enqueue_space(curjob->space, start, end, ABORTED);
					else
						enqueue_space(curjob->space, start, end, DONE);
				}
#ifdef DEBUG
				else
				{
					TAB_WRITE;
					printf(" cannot parse %s (%d)\n", buf, mode);
				}
#endif
				break;
				
		}
	}


	free(tmp3);
	free(tmp2);
	free(tmp1);
	free(buf);
	fclose(file);
#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
	return (1);
}

void    save_file (void)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif
	FILE    *file = NULL;

	struct h_jobs * hjobs = NULL;
	struct s_jobs * job = NULL;
	
	struct s_passwd * pwd;
	struct s_space * space;

	umask (0077);
	file = fopen(filename, "w+");

	if(file == NULL)
	{
		printf(" CANNOT SAVE STATE IN %s\n", filename);
		return;
	}

	hjobs = get_hjobs(NULL);
	TAILQ_FOREACH(job, hjobs, next)
	{
		fprintf(file, "job\n");
		fprintf(file, "%d:%s:%d:%d:%d:%d:%lld\n", 
				job->id,
				job->name,
				(unsigned int) job->date_start,
				job->status,
				job->prior,
				job->current_prior,
				job->interval_size);
		fprintf(file, "%d:%d:%d:%d\n",
				job->cipher,
				job->crack_method,
				job->nb_pwd,
				job->nb_found_pwd);
		fprintf(file, "passwords\n");
		TAILQ_FOREACH(pwd, job->passwd, next)
		{
			if(pwd->cleartext)
				fprintf(file, "%s:%s:%s:%d\n",
					pwd->username,
					pwd->password,
					pwd->cleartext,
					pwd->cipher);
			else
				fprintf(file, "%s:%s::%d\n",
					pwd->username,
					pwd->password,
					pwd->cipher);
		}
		fprintf(file, "spaces\n");
		TAILQ_FOREACH(space, job->space, next)
		{
			fprintf(file, "%lld:%lld:%d\n",
					space->start,
					space->end,
					space->status);
		}
	}
	fclose (file);
	return;
}
