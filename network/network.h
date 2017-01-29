#ifndef   __NETWORK_H__
# define  __NETWORK_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int	net_connect(const char *, int);
struct s_network	*net_init(unsigned char, unsigned char);
void	net_flush(int fd, struct s_network *);
int 	net_read(int , struct s_network *, uint32_t );
int 	net_read_buf(int , char *, uint32_t, struct s_network * );
void	net_close(int);
int     open_port(unsigned int);
int     accept_client(int , struct sockaddr_in *, socklen_t *); 
int     get_main_fd(int);
int	get_header_data(int, struct s_network *);
int	dispatch_data(int, struct s_network *, char *);
int	net_crypto_init(struct s_network * net);
void	net_crypto_free(struct s_network * net);
void	net_crypt(struct s_network * net, unsigned char * buffer, unsigned int size);
void	net_setkey(unsigned char * key);
void    net_free(struct s_network * net);
void net_crypto_init_state(struct s_network * net);

uint64_t hton64(uint64_t x);
#define ntoh64(x) hton64(x)
//uint64_t ntoh64(uint64_t x);

#endif /* __NETWORK_H__ */
