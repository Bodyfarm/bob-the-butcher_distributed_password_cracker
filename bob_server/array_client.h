#ifndef   __ARRAY_CLIENT_H__
# define  __ARRAY_CLIENT_H__

# include <sys/signal.h>
# include <sys/time.h>
# ifdef WIN32
#  include <windows.h>
# endif
# include <event.h>

typedef struct  s_array_client
{
    u_char                      type;
    u_char                      state;
    uint32_t                    fd;
    uint32_t                   	cap;
    uint32_t                    psize;
    int                         (*save_func)(int, struct s_array_client *); 
    struct event                ev;
    TAILQ_ENTRY(s_array_client) next;
}               t_array_client;

TAILQ_HEAD(h_array_client,s_array_client);

#define STATE_INIT      0x00
#define STATE_WORK      0x01

struct s_array_client   *add_client(struct h_array_client *,
                                    unsigned int);
struct s_array_client   *get_client(struct h_array_client *, unsigned int);
struct h_array_client   *get_hclient(struct h_array_client *);
int                     rem_client( struct h_array_client *, 
                                    struct s_array_client *);
#endif /* __ARRAY_SOCKET_H__ */
