#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bob_server.h"

/*
 * Add new job to scheduler
*/

struct s_jobs     *add_job( struct h_jobs *hjobs, 
                            const char      *name,
                            unsigned int    cipher,
                            unsigned int    type,
                            unsigned int    nb_pwd)
{
#ifdef DEBUG
    TAB_WRITE;
    printf(" %s [name=%s] [cipher=%d] [type=%d] [nbpwd=%d]\n", 
            __func__, name, cipher, type, nb_pwd);
#endif

    struct  s_jobs  *job = NULL;

    job = (struct s_jobs *) calloc(1, sizeof(struct s_jobs));
    if ( job == NULL)
        XPERROR("calloc", MEM_EXIT);

    job->id  = search_id(hjobs);
    job->name = name;
    job->cipher = cipher;
    job->crack_method = type;
    job->nb_pwd = nb_pwd;
    job->status = JOB_PREPARE;
    job->prior = OPT_PRIOR_INIT;
    job->current_prior = OPT_PRIOR_INIT;
    job->interval_size = INTERVAL_LENGTH;
    job->nb_found_pwd = 0;

    job->date_start = time(NULL);

    job->passwd = (struct hpasswd *) calloc(1, sizeof(struct hpasswd));
    if ( job->passwd == NULL )
        XPERROR("calloc", MEM_EXIT);
    TAILQ_INIT(job->passwd);

    job->space = (struct h_space *) calloc(1, sizeof(struct h_space));
    if ( job->space == NULL )
	    XPERROR("calloc", MEM_EXIT);
    TAILQ_INIT(job->space);

    TAILQ_INSERT_TAIL(hjobs, job, next);
    return(job);   
}

struct h_jobs       *get_hjobs(struct h_jobs *hjobs)
{
    static struct h_jobs    *res = NULL;

    if (hjobs != NULL)
        res = hjobs;
    return(res);
}


void    print_jobs(struct h_jobs *hjobs)
{
#ifdef DEBUG
    printf(" %s\n", __func__);
#endif
    struct s_jobs    *job = NULL;

    TAILQ_FOREACH(job, hjobs, next)
    {
        printf("   - Job %s (%d)\n", job->name, job->id);
    }
}

unsigned int     search_id(struct h_jobs *hjobs)
{
#ifdef DEBUG
    TAB_WRITE;
    printf(" %s\n", __func__);
#endif
    struct s_jobs   *job = NULL;
    unsigned int    res = 0;

    TAILQ_FOREACH(job, hjobs, next)
    {
        if (res < job->id)
            return (res);
        res++;   
    }
    return (res);
}

void        remove_all_jobs(struct h_jobs *hjobs)
{
#ifdef DEBUG
    TAB_WRITE;
    printf(" %s\n", __func__);
#endif 
    struct s_jobs   *job = NULL;

    TAILQ_FOREACH_REVERSE(job, hjobs, next, h_jobs)
    {
        TAILQ_REMOVE(hjobs, job, next);
        remove_all_passwds(job->passwd); 
        XFREE(job);
    }
}
void        del_job(struct h_jobs *hjobs, uint32_t id)
{
#ifdef DEBUG
    TAB_WRITE;
    printf(" %s\n", __func__);
#endif    
    struct s_jobs   *job = NULL;
    
    TAILQ_FOREACH_REVERSE(job, hjobs, next, h_jobs)
    {
        if (job->id == id)
        {
           TAILQ_REMOVE(hjobs, job, next);
           remove_all_passwds(job->passwd); 
           XFREE(job);  
        }
    }
    return;
}

struct s_jobs   *search_job(struct h_jobs *hjobs, uint32_t id)
{
#ifdef DEBUG
    TAB_WRITE;
    printf(" %s\n", __func__);
#endif   
    struct s_jobs   *job = NULL;

    TAILQ_FOREACH_REVERSE(job, hjobs, next, h_jobs)
    {
        if (job->id == id)
            return(job);
    }
    return(NULL);
}

/*
 * finds the job with highest prio in O(n) ... not good
 */
struct s_jobs * select_job(struct h_jobs *hjobs, uint64_t capabilities)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s cap=%ld\n", __func__, capabilities);
#endif
	struct s_jobs * job = NULL;
	struct s_jobs * best_job = NULL;
	int max_prio = -100000;
	int nb_job = 0;
	
	TAILQ_FOREACH(job, hjobs, next)
	{
		if ( ( (1<<job->cipher) & capabilities) && (job->status==JOB_ACTIVE) )
		{
			job->current_prior++;
			nb_job++;

			if ( job->current_prior * job->prior > max_prio )
			{
				max_prio = job->current_prior * job->prior;
				best_job = job;
			}
		}
	}
	if(best_job == NULL)
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" could not select a job!\n");
#endif
		return NULL;
	}
#ifdef DEBUG
	TAB_WRITE;
	printf(" selected job %d with prio %d\n", best_job->id, best_job->current_prior);
#endif
	best_job->current_prior -= nb_job;
	return best_job;
}
