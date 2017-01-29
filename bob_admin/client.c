#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bob_admin.h"
#include "network.h"

void	client_help()
{
	fprintf(stderr, "Usage command: client\n");
	exit(1);
}

void    client(int c, char **v, struct s_admin_opt *opt)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [c=%d]\n", __func__, c);
#endif
	struct s_network	*net = NULL;
	struct s_admin_client	*client = NULL;
	int			fd = 0;
	uint32_t		nb_clients = 0;

	if (c != 0)
		client_help();
	fd = net_connect(opt->host, opt->port);
	net = net_init(CLIENT_ADMIN, CMD_CLIENT);
	net_flush(fd, net);
	// TODO
	/*
	net_read(fd, net, sizeof(struct s_admin_client));
	client = (struct s_admin_client *) &(net->buf);
	nb_clients = htonl(client->nb_clients); 
	*/
#ifdef DEBUG
	UP_SPACE_LEVEL;
	TAB_WRITE;
	printf(" [nb_clients=%d]\n", nb_clients);
	DOWN_SPACE_LEVEL;
#endif 
}

void	cltinf_help(void)
{
	fprintf(stderr, "Usage command: cltinf ID\n");
	exit(1);
}

void    cltinf(int c, char **v, struct s_admin_opt *opt)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [c=%d]\n", __func__, c);
#endif
	struct s_network	*net = NULL;
	struct s_client_id	*client_id = NULL;
	int			fd = 0;
	uint32_t		id = 0;

	if (c != 1)
		cltinf_help();
	id = atoi(*v);
#ifdef DEBUG
	UP_SPACE_LEVEL;
	TAB_WRITE;
	printf(" %s [id=%d]\n", __func__, id);
	DOWN_SPACE_LEVEL;
#endif
	fd = net_connect(opt->host, opt->port);
	net = net_init(CLIENT_ADMIN, CMD_CLTINF);
	//FIXME TODO
	/*
	client_id = (struct s_client_id *) &(net->buf);
	client_id->id = htonl(id);
	net->psize += sizeof(struct s_client_id);*/
	net_flush(fd, net);
	net_close(fd);
}
