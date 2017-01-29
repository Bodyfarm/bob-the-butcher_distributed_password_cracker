#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NEED_DATA_STRUCT

#include "bob_server.h"

int     get_data(int fd, struct s_array_client *client)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	struct s_network * net;
	int			check = 0; 
	char		buf[NET_BUF_MAX];
	unsigned char	x = 0;
	struct s_rw * rw;

	
	net = net_init(0,0);
	check = get_header_data(fd, net);

	if (check != 0)
		return(check);
	client->psize = net->psize;
	client->type  = net->type;
	check = dispatch_data(fd, net, buf);
	if (check != 0)
		return(check);
#ifdef DEBUG
	UP_SPACE_LEVEL;
	TAB_WRITE;
	printf(" Received header [fd=%d] [type=%d] [cmd=%d] [psize=%u] ", 
			fd, net->type, net->cmd, client->psize );
	dump_stuff(buf, client->psize);
#endif
	rw = rw_init(buf, client->psize);
	if(!rw)
		return(-1);
	switch(net->type)
	{ 
		case CLIENT_CLIENT:
			x = net->cmd & CLIENT_MASK;
			if ( (x < CLIENT_STRUCT_SIZE)
					&& ( net->cmd == client_struct[x].q))
				client_struct[x].f(fd, client, rw, net);
			break;
		case CLIENT_ADMIN:
			if ( (net->cmd < ADMIN_STRUCT_SIZE)
					&& ( net->cmd == admin_struct[net->cmd].q))
				admin_struct[net->cmd].f(fd, client, rw, net);
			break;
		default:
#ifdef DEBUG
			TAB_WRITE;
			printf(" Received type not allowed\n");
#endif	
			break;
	}
#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
	return(1);
}
