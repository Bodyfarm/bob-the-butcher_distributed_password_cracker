#ifndef   __JOBS_H__
# define  __JOBS_H__

typedef struct  s_jobs
{
    int                     id;
    const char              *name;
    time_t                  date_start;
    unsigned char           status;
    char                    prior;
    int current_prior;
    uint64_t interval_size;
    
    struct
    {
        unsigned int        cipher;
        unsigned int        crack_method;
        struct hpasswd      *passwd;
        unsigned int        nb_pwd;
        unsigned int        nb_found_pwd;
    };

    struct h_space * space;

    TAILQ_ENTRY (s_jobs)    next;
}               t_jobs;


TAILQ_HEAD(h_jobs, s_jobs);

# define    JOB_PREPARE     0x00
# define    JOB_ACTIVE      0x01
# define    JOB_PAUSED      0x02
# define    JOB_FINISHED    0x03


struct s_jobs   *add_job(struct h_jobs *, const char *, unsigned int, unsigned int, unsigned int);
void            del_job(struct h_jobs *, uint32_t);
struct h_jobs   *get_hjobs(struct h_jobs *);
struct s_jobs   *search_job(struct h_jobs *, uint32_t);
void            print_jobs(struct h_jobs *);
unsigned int    search_id(struct h_jobs *);
void            remove_all_jobs(struct h_jobs *hjobs);
struct s_jobs * select_job(struct h_jobs *hjobs, uint64_t capabilities);

#endif /* __JOBS_H__ */
