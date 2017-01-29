
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "bob_server.h"
#include "clients.h"

#define	INIT_SEED	0x4242

uint32_t generate_id(void)
{
	static unsigned char	state_random = 0;

	if (state_random == 0)
	{
		srandom(INIT_SEED);
		state_random++;
	}
	return(random());
}

void update_client(struct h_clients * hclients, struct s_clients * client)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
	UP_SPACE_LEVEL;
#endif
	time_t tv;
	struct s_clients * curclient;

	/* update connection time */
	tv = time(0);
	client->time = tv;

	/* drop clients that are not responding */
	TAILQ_FOREACH(curclient, hclients, next)
	{
		if ( (tv - curclient->time) > MAX_IDLE_TIME )
		{
#ifdef DEBUG
			TAB_WRITE;
			printf(" *** removing client idle time %d secs for user %s ***\n", (int) (tv - curclient->time), curclient->username);
#endif
			if(curclient->space)
				curclient->space->status = ABORTED;
#ifdef DEBUG
			else
			{
				TAB_WRITE;
				printf("NO SPACE FOR THIS CLIENT WTF?\n");
			}
#endif
			TAILQ_REMOVE(hclients, curclient, next);
			XFREE(curclient);
		}
	}
#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
}


struct s_clients *add_clients(struct h_clients	*hclients,
				     uint32_t		id,
				     char		*username,
				     uint64_t		cap)
{
#ifdef DEBUG
  TAB_WRITE;
  printf(" %s\n", __func__);
#endif
  struct s_clients	*res = NULL;
  
  res = (struct s_clients *) calloc(1, sizeof(struct s_clients));
  if ( res == NULL )
    XPERROR("calloc", MEM_EXIT);
  
  res->id = id;
  memcpy(res->username, username, MAX_USER_SIZE);
  res->state_info = 0;
  res->capabilities = cap;

  
  TAILQ_INSERT_TAIL(hclients, res, next);

  update_client(hclients, res);

  return(res);
}

struct h_clients       *get_hclients(struct h_clients *hclients)
{
    static struct h_clients    *res = NULL;

    if (hclients != NULL)
        res = hclients;
    return(res);
}

struct s_clients	*search_clients(struct h_clients *hclients, 
		uint32_t id)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif 
	struct s_clients	*clients = NULL;

	if(TAILQ_EMPTY(hclients))
		return NULL;

	TAILQ_FOREACH(clients, hclients, next)
	{
		if ( clients->id == id)
		{
			update_client(hclients, clients);
			return(clients);
		}
	}
	return(NULL);
}

