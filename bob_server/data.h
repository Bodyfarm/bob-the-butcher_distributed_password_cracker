#ifndef   __DATA_H__
# define  __DATA_H__

int     get_data(int, struct s_array_client *);

typedef struct  s_data
{
  unsigned char   q;
  int             (*f)(int, struct s_array_client *, struct s_rw *, struct s_network *);
}               t_data;


int     admin_status(int, struct s_array_client *, struct s_rw *, struct s_network *);
int     admin_add_job(int, struct s_array_client *, struct s_rw *, struct s_network *);
int     admin_add_pwd(int, struct s_array_client *, struct s_rw *, struct s_network *);
//int     admin_alter_job(int, struct s_array_client *);
//int     admin_job_info(int, struct s_array_client *);
int     admin_del_job(int, struct s_array_client *, struct s_rw *, struct s_network *);
//int     admin_shutdown(int, struct s_array_client *);
int     admin_setopt(int, struct s_array_client*, struct s_rw *, struct s_network *);
int     admin_getinf(int, struct s_array_client*, struct s_rw *, struct s_network *);
int     admin_client(int, struct s_array_client*, struct s_rw *, struct s_network *);
int     admin_cltinf(int, struct s_array_client*, struct s_rw *, struct s_network *);

int	client_idle(int, struct s_array_client*, struct s_rw *, struct s_network *);
int	client_cinfo(int, struct s_array_client*, struct s_rw *, struct s_network *);
int     client_passwd_found(int, struct s_array_client *, struct s_rw *, struct s_network *);
int	client_job_finished(int, struct s_array_client*, struct s_rw *, struct s_network *);
int	client_job_aborted(int, struct s_array_client*, struct s_rw *, struct s_network *);

# ifdef NEED_DATA_STRUCT
struct s_data   client_struct[]=
{
  { 0, 0},
  {CMD_IDLE, &client_idle},
  {CMD_INFO, &client_cinfo},
  {CMD_PWDFOUND, &client_passwd_found},
  {CMD_JOBFINISH, &client_job_finished},
  {CMD_JOBABORT, &client_job_aborted},
  { 0, 0}
};
# define CLIENT_STRUCT_SIZE 6

struct s_data   admin_struct[]=
{
  { 0, 0},
  { CMD_NEWJOB, &admin_add_job},
  { CMD_DELJOB, &admin_del_job},
  { CMD_ADDPWD, &admin_add_pwd},
  { 0, 0},
  { CMD_SETOPT, &admin_setopt},
  { CMD_STATUS, &admin_status},
  { CMD_GETINF, &admin_getinf},
  { CMD_CLIENT, &admin_client},
  { CMD_CLTINF, &admin_cltinf},
  { 0, 0} 
};
# define ADMIN_STRUCT_SIZE  10
# endif

#endif /* __DATA_H__ */
