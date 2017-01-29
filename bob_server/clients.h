#ifndef   __CLIENTS_H__
# define  __CLIENTS_H__

#include <sys/utsname.h>

uint32_t	generate_id(void);

typedef struct	s_clients
{
  uint32_t	id;
  char		username[MAX_USER_SIZE];
  uint64_t	capabilities;
  struct	
  {
    unsigned char	state_info;
    char		sysname[SYS_NAMELEN];
    char		release[SYS_NAMELEN];
    char		machine[SYS_NAMELEN];
  };
  struct s_space	* space;
  struct h_space	* hspace;
  struct s_jobs		* job;

  time_t		time;
  
  TAILQ_ENTRY(s_clients) next;
}		t_clients;

TAILQ_HEAD(h_clients,s_clients);

struct h_clients	*get_hclients(struct h_clients *);
struct s_clients	*add_clients(struct h_clients *, uint32_t, char *, uint64_t cap);
struct s_clients	*search_clients(struct h_clients *, uint32_t);

#endif /* __CLIENTS_H__ */
