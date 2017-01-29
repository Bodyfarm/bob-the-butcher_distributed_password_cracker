#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

#include "rw.h"
#include "btb.h"
#include "btb-data.h"
#include "network.h"

//cygwin stupid fix
#ifndef MSG_WAITALL
# define MSG_WAITALL 0x100
#endif

int	net_connect(const char *host, int port)
{
	int			res = 0;
	struct sockaddr_in	remote_addr;
	struct hostent		*remote = NULL;
	int			tmp = 0;

	res = socket(AF_INET, SOCK_STREAM, 0);
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s = %.2x\n", __func__, res);
#endif
	if ( res < 0)
		XPERROR("socket", NET_EXIT);
	remote = gethostbyname(host);
	if (remote == NULL)
		XPERROR("gethostbyname", NET_EXIT);

	remote_addr.sin_family = AF_INET;
	memcpy( &remote_addr.sin_addr, remote->h_addr, remote->h_length);
	remote_addr.sin_port = htons(port);

	tmp = connect(res, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	if (tmp < 0)
		XPERROR("connect", NET_EXIT);

	//is_blocking(res);

	return(res);
}

void	net_close(int fd)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s(%.2x)\n", __func__, fd);
#endif
	close(fd);
}

void net_free(struct s_network * net)
{
	if(net->cryptostate!=NULL)
		free(net->cryptostate);
}

struct s_network *net_init(unsigned char type, unsigned char cmd)
{
	struct s_network	*res = NULL;
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s(%.2x/%.2x)\n", __func__, type, cmd);
#endif
	
	res = (struct s_network *) calloc(1, sizeof(struct s_network));
	if ( res == NULL )
		XPERROR("calloc", MEM_EXIT);
	res->type = type;
	res->cmd  = cmd;
	res->psize = sizeof(res->psize);
	res->str = str_init(0);
	res->cryptostate = NULL;
	
	if(!res->str)
		XPERROR("strn_create", MEM_EXIT);
	str_append_char(res->str, type);
	str_append_char(res->str, cmd);
	
	net_crypto_init(res);

	return(res);
}

void net_flush(int fd, struct s_network * net)
{
	uint32_t size;
	uint32_t psize;
	unsigned char * buf;
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [size=%d] ", __func__, STRLEN(net->str));
	dump_stuff(STRING(net->str), STRLEN(net->str));
#endif

	psize = htonl(STRLEN(net->str));
	write(fd, &psize, sizeof(psize));

	write(fd, net->seed, CRYPTO_SEED_SIZE);

	buf = malloc(STRLEN(net->str));
	if(!buf)
		perror("malloc");

	memcpy(buf, STRING(net->str), STRLEN(net->str));
	net_crypt(net, buf, STRLEN(net->str));
	size = write(fd, buf, STRLEN(net->str));
	free(buf);
#ifdef DEBUG
	if (size != STRLEN(net->str))
	{
		TAB_WRITE;
		printf(" write error\n");
	}
#endif
}
	
int     get_main_fd(int fd)
{
	static int  res = 0;

	if (fd != 0)
		res = fd;

	return(res);
}

int net_read_buf(int fd, char * ptr, uint32_t size, struct s_network * net)
{
	int status;

	if(size == 0)
		return 0;
	
	status = recv(fd, ptr, size, MSG_WAITALL);

	net_crypt(net, ptr, size);

	return status;
}

int    open_port(unsigned int  port)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [port=%d]\n", __func__, port);
#endif
	struct sockaddr_in  myaddr;
	int                 yes = 1;
	int                 fd = 0;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if ( fd == -1 )
		XPERROR("socket", NET_EXIT); 
	if ( setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == (-1))
		XPERROR("setsockopt", NET_EXIT);

	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = INADDR_ANY;
	myaddr.sin_port = htons(port);
	memset(&(myaddr.sin_zero), 0, 8);

	if (bind(fd, (struct sockaddr *) &myaddr, sizeof(struct sockaddr_in)) == -1)
		XPERROR("bind", NET_EXIT);
	if (listen(fd, 10) == (-1))
		XPERROR("listen", NET_EXIT);

	get_main_fd(fd);

	return(fd);
}

int     accept_client(int fd, struct sockaddr_in *remoteaddr, socklen_t *len) 
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif
	int res = 0;

	res = accept(fd, (struct sockaddr *) remoteaddr,len);
	if (res == -1)
		XPERROR("accept", NET_EXIT);
	return(res);
}

uint64_t hton64(uint64_t x)
{
#ifdef WORDS_BIGENDIAN
	return x;
#else
	uint64_t out;

	((unsigned char *)&out)[7] = (x) & 0xff;
	((unsigned char *)&out)[6] = (x >> 8) & 0xff;
	((unsigned char *)&out)[5] = (x >> 16) & 0xff;
	((unsigned char *)&out)[4] = (x >> 24) & 0xff;
	((unsigned char *)&out)[3] = (x >> 32) & 0xff;
	((unsigned char *)&out)[2] = (x >> 40) & 0xff;
	((unsigned char *)&out)[1] = (x >> 48) & 0xff;
	((unsigned char *)&out)[0] = (x >> 56) & 0xff;

	return out;
#endif
}

/*
uint64_t ntoh64(uint64_t x)
{
	uint64_t ret;
#ifdef WORDS_BIGENDIAN
	ret =  x;
#else
	ret = hton64(x);
#endif
	return ret;
}
*/
