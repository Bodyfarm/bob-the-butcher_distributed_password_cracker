#include <stdio.h>
#include <stdlib.h>

#include "bob_server.h"

struct s_array_client   *add_client(struct h_array_client   *hclient, unsigned int fd)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif
	struct s_array_client   *client = NULL;

	client = (struct s_array_client *) calloc(1, sizeof(struct s_array_client));
	if ( client == NULL )
		XPERROR("calloc", MEM_EXIT);

	client->fd    = fd;
	client->state = STATE_INIT;

	TAILQ_INSERT_TAIL(hclient, client, next);

	return (client);    
}

struct s_array_client   *get_client(struct h_array_client *hclient, unsigned int fd)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif
	struct s_array_client   *client = NULL;

	TAILQ_FOREACH(client, hclient, next)
	{
		if ( client->fd == fd)
			return(client);
	}
	return(NULL);
}

struct h_array_client   *get_hclient(struct h_array_client  *hclient)
{
	static struct h_array_client    *res = NULL;

	if (hclient != NULL)
		res = hclient;

	return(res);
}

int     rem_client(struct h_array_client *hclient, struct s_array_client *client)
{
	struct s_array_client   *tmp = NULL;

	TAILQ_FOREACH(tmp, hclient, next)
	{
		if (client == tmp)
		{
			TAILQ_REMOVE(hclient, client, next);
			XFREE(client);
			return(0);
		}
	}
	return(1);
}
