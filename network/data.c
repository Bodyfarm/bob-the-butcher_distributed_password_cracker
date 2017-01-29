#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "btb.h"
#include "btb-data.h"
#include "network.h"

//cygwin stupid fix
#ifndef MSG_WAITALL
# define MSG_WAITALL 0x100
#endif

int	get_header_data(int fd, struct s_network *net)
{
	unsigned char nseed[ CRYPTO_SEED_SIZE ];
	recv(fd, &(net->psize), sizeof(uint32_t), MSG_WAITALL);
	recv(fd, nseed, CRYPTO_SEED_SIZE, MSG_WAITALL);
	if(memcmp(net->seed, nseed, CRYPTO_SEED_SIZE))
	{
		memcpy(net->seed, nseed, CRYPTO_SEED_SIZE);
		net_crypto_init_state(net);
	}
	
	net->psize = ntohl(net->psize) - 2*sizeof(unsigned char);

	if(recv(fd, &(net->type), sizeof(unsigned char), MSG_WAITALL)!=1)
		return(NET_EXIT);
	if(recv(fd, &(net->cmd), sizeof(unsigned char), MSG_WAITALL)!=1)
		return(NET_EXIT);
	
	net_crypt(net, &(net->type), sizeof(unsigned char));
	net_crypt(net, &(net->cmd), sizeof(unsigned char));

	net->str = NULL;
	
	return(0);
}

int	dispatch_data(int fd, struct s_network *net, char *buf)
{
	net_read_buf(fd, buf, net->psize, net);
	/*
	int nsize = 0;

	if (net->psize > 0)
	{
		nsize = recv(fd, buf, net->psize, MSG_WAITALL);
		if (nsize != net->psize)
			return(NET_EXIT);
		net_crypt(net, buf, net->psize);
		dump_stuff(
	}
	*/
	return(0);
}
