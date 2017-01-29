#ifndef   __CLIENT_H__
# define  __CLIENT_H__

# define RERUN_IDLE     0x42
# define MORE_DATA_TO_COME 0x111
# define WORK_NOW 0x11

typedef struct  s_client_opt
{
  uint32_t      id;
  char          *username;
  char          *passwd;
  char          *host;

  char		*filename;
  char		*remote_hostname;
  char		*format;
  unsigned char working;
  uint32_t  	port;
  int32_t  	priority;
  uint32_t  	benchmark;
  uint64_t	capabilities;
  unsigned char verbose;
  unsigned char debug;
  unsigned char daemon;
  unsigned char standalone;
  struct s_format * fmt;
  uint32_t	crack_method;
  uint32_t	cipherid;
  uint32_t	jobid;
  uint64_t	start;
  uint64_t	end;
  unsigned char * wordlist;
  unsigned char * john;
}  t_client_opt;


#endif
