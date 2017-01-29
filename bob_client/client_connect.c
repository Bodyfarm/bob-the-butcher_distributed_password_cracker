/*
 * Network connection handling for the clients
 */
#include "params.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "config.h"
#include "config_types.h"
#define NEED_G_SPACE
#include "btb.h"
#include "btb-data.h"
#include "compat.h"

#include "network.h"
#define NEED_DATA_STRUCT
#include "data.h"

#include "client.h"
#include "format.h"
#include "client_connect.h"
#include "log.h"
#include "crack.h"
#include "salts.h"

extern t_client_opt opt;

/*
 * sends a message to the server
 * format :
 * int32_t : size
 * char * message
 */

int client_password_found(char * username, char * ciphertext, char * cleartext)
{
	int	fd = 0;
	struct s_network * net = NULL;
	
	fd = net_connect(opt.remote_hostname, opt.port);
	net = net_init(CLIENT_CLIENT, CMD_PWDFOUND);
	
	str_append_int32(net->str, opt.id);
	str_append_netstring(net->str, username, strlen(username));
	str_append_netstring(net->str, ciphertext, strlen(ciphertext));
	str_append_netstring(net->str, cleartext, strlen(cleartext));
	
	net_flush(fd, net);
	net_close(fd);
	return 1;
}

void job_change_status(unsigned int status)
{
	int fd = 0;
	struct s_network * net = NULL;

#ifdef DEBUG
	TAB_WRITE;
	printf(" %s = %d\n", __func__, status);
#endif
	fd = net_connect(opt.remote_hostname, opt.port);
	net = net_init(CLIENT_CLIENT, status);
	str_append_int32(net->str, opt.id);
	net_flush(fd, net);
	net_close(fd);
}

int	client_idle(void)
{
	int			fd = 0;
	struct s_network	*net = NULL;
	struct s_network	* recv;
	char * buf;
	int			res = 0;
	int			oneshot = 1;
	int			check = 0;
	struct s_rw * rw;

	fd = net_connect(opt.remote_hostname, opt.port);
	net = net_init(CLIENT_CLIENT, CMD_IDLE);
	str_append_int32(net->str, opt.id);
	str_append_int64(net->str, opt.capabilities);
	str_append_netstring(net->str, opt.username, strlen(opt.username));

	net_flush(fd, net);

	recv = net;

	while(oneshot == 1)
	{
		if (get_header_data(fd, recv) != 0)
			return(res);
#ifdef DEBUG
		UP_SPACE_LEVEL;
		TAB_WRITE;
		printf(" Received header [fd=%d] [type=%x] [cmd=%x] [psize=%u]\n", 
				fd, recv->type, recv->cmd, recv->psize);
#endif
		if(recv->psize > MAX_PACKET_SIZE)
			return(res);
		buf = malloc(recv->psize);
		if(!buf)
			return(res);
		oneshot = 0;
		if (dispatch_data(fd, recv, buf) != 0)
		{
			free(buf);
			return(res);
		}
		
		rw = rw_init(buf, recv->psize);
		if(!rw)
			return(-1);

		switch (recv->type)
		{
			case CLIENT_SERVER:
				if ( (recv->cmd < SERVER_STRUCT_SIZE)
						&& ( recv->cmd == server_struct[recv->cmd].q))
				{

					check = server_struct[recv->cmd].f(fd, rw);
					if (check == RERUN_IDLE)
						res++;
					if (check == MORE_DATA_TO_COME)
						oneshot = 1;
				}
#ifdef DEBUG
				else
				{
					TAB_WRITE;
					printf(" wtf?!?\n");
				}
#endif

				break;
			default:
#ifdef DEBUG
				TAB_WRITE;
				printf(" Received type not allowed\n");
#endif	
				break;
		}
		rw_free(rw);

#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
	}
	free(buf);
	net_close(fd);
	if(check == WORK_NOW)
	{
		opt.working = 1;
		do_crack(opt.crack_method, opt.fmt, opt.start, opt.end);
		res++;
		job_change_status(CMD_JOBFINISH);
		opt.working = 0;
	}
	return(res);
}


void	client_dispatch(void)
{
	int	check = 0;

	while(1)
	{
		do
		{
			check = client_idle();
#ifdef DEBUG
			TAB_WRITE;
			printf(" %s [rerun=%s]\n", __func__, ON_OFF_STR(check));
#endif
		} while (check > 0);
		sleep(30);
	}
}

