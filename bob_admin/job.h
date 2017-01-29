#ifndef   __JOB_H__
# define  __JOB_H__

# include "queue.h"
# include "btb-data.h"

typedef struct	s_list_pwd
{
  struct s_pwd			pwd;
  TAILQ_ENTRY (s_list_pwd)	next;
}       		t_list_pwd;

typedef struct  s_opt_value
{
    const char      *label;
    unsigned char   id;
}               t_opt_value;

# define    L_OPT_STATUS  "status"
# define    L_OPT_CIPHER  "cipher"
# define    L_OPT_PRIOR   "prior"

# ifdef NEED_OPT_STRUCT
struct s_opt_value  opt_value[] = 
{
    {L_OPT_STATUS, OPT_STATUS},
    {L_OPT_CIPHER, OPT_CIPHER},
    {0,0}
};
#  else
extern struct s_opt_value  *opt_value;
# endif
# define    OPT_STRUCT_SIZE 3

void	newjob(int, char **, struct s_admin_opt *);
void	deljob(int, char **, struct s_admin_opt *);
void	status(int, char **, struct s_admin_opt *);
void    setopt(int, char **, struct s_admin_opt *);
void    getinf(int, char **, struct s_admin_opt *);

#endif /* __JOB_H__ */
