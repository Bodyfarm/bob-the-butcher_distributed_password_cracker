#ifndef   __DATA_H__
# define  __DATA_H__

typedef struct  s_data
{
  unsigned char   q;
  int             (*f)(int, struct s_rw *);
}               t_data;

int	server_id(int, struct s_rw *);
int	server_cinfo(int, struct s_rw *);
int	server_nojob(int, struct s_rw *);
int	server_newjob(int, struct s_rw *);

# ifdef NEED_DATA_STRUCT
struct s_data   server_struct[]=
{
  { 0, 0},
  {CMD_SID, &server_id},
  {CMD_CINFO, &server_cinfo},
  {CMD_NOJOB, &server_nojob},
  {CMD_CJOB, &server_newjob},
  { 0, 0}
};
# define SERVER_STRUCT_SIZE 5
#endif


#endif /* __DATA_H__ */
