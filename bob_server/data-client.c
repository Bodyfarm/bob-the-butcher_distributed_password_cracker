#include <string.h>
#include <stdio.h>
#include <time.h>

#include "bob_server.h"
#include "rw.h"

int	send_id(int fd, uint32_t id)
{
	struct s_network	*net = NULL;

	if (id == 0)
	{
		id = generate_id();
#ifdef DEBUG
		TAB_WRITE;
		printf(" Generate new id [id=%d]\n", id);
#endif
	}
	net = net_init(CLIENT_SERVER, CMD_SID);
	str_append_int32(net->str, id);
	net_flush(fd, net);
	net_close(fd);
	return(id);
}

void send_nojob(int fd)
{
	struct s_network	*net = NULL;

	net = net_init(CLIENT_SERVER, CMD_NOJOB);
	net_flush(fd, net);
	net_close(fd);
}

int	give_work(int fd, struct s_clients * client)
{
	struct s_network	*net = NULL;
	struct s_jobs		*job = NULL;
	struct s_client_newjob  *newjob = NULL;
	//struct s_client_work	*work = NULL;
	struct s_pwd		*pwd = NULL;
	struct s_passwd		*curpass = NULL;
	//unsigned int i;

#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n",__func__);
	UP_SPACE_LEVEL;
#endif
	if(client == NULL)
	{
		send_nojob(fd);
#ifdef DEBUG
		DOWN_SPACE_LEVEL;
#endif
		return 1;
	}
	job = select_job(get_hjobs(NULL), client->capabilities);
	if(job == NULL)
	{
		send_nojob(fd);
#ifdef DEBUG
		DOWN_SPACE_LEVEL;
#endif
		return 1;
	}

	client->space = return_space(job->space, job->interval_size);
	client->hspace = job->space;
	client->job = job;

	net = net_init(CLIENT_SERVER, CMD_CJOB);

	str_append_int32(net->str, job->id);
	str_append_int32(net->str, job->cipher);
	str_append_int32(net->str, job->crack_method);
	str_append_int32(net->str, job->nb_pwd - job->nb_found_pwd);
	str_append_int64(net->str, client->space->start);
	str_append_int64(net->str, client->space->end);

	printf(" [jobid=%d] [cipherid=%d] [crack_method=%d] [nb_pwd=%d-%d] ", job->id, job->cipher, job->crack_method, job->nb_pwd, job->nb_found_pwd);

	//show_passwords(job->passwd);
	//send pwds
	
	TAILQ_FOREACH(curpass, job->passwd, next)
	{
		if(curpass->cleartext == NULL)
		{
			int psize;

			str_append_netstring(net->str, curpass->username, strlen(curpass->username));
			str_append_netstring(net->str, curpass->password, strlen(curpass->password));
		}
	}
		
	net_flush(fd, net);
	net_close(fd);
	
#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
	return 0;
}

int     client_idle(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
	UP_SPACE_LEVEL;
#endif
	struct s_clients		*clients = NULL;
	uint32_t			id = 0;
	unsigned char * username;
	uint64_t	capabilities;

	id = read_uint32_t(rw);
	capabilities = read_uint64_t(rw);
	username = read_netstring(rw);
	if(!username)
		return -1;
	
#ifdef DEBUG
	TAB_WRITE;
	printf(" Receive idle [id=%d] [user=%s] [cap=0x%llx]\n", id, username, capabilities);
#endif
	if (id != 0)
		clients = search_clients(get_hclients(NULL), id);

	if ( (id == 0) || (clients == NULL) )
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" sending new id\n");
#endif
		id = send_id(fd, id);
		add_clients(get_hclients(NULL), id, username, capabilities);
		goto out2;
	}

	free(username);

	if (clients->state_info == 0)
	{
		struct s_network	*net = NULL;

#ifdef DEBUG
		TAB_WRITE;
		printf(" state info is 0\n");
#endif
		net = net_init(CLIENT_SERVER, CMD_CINFO);
		net_flush(fd, net);
		net_close(fd);
		goto out2;
	}
	//default
	//id = send_id(fd, id);
out:
	give_work(fd, clients);
out2:
#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
	return(0);
}

int     client_cinfo(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	struct s_clients	*clients = NULL;
	uint32_t id;
	unsigned char * s;

	id = read_uint32_t(rw);
	if (id == 0)
		return(1);
	clients = search_clients(get_hclients(NULL), id);
	if (clients == NULL)
		return(1);

	clients->state_info++;
	
	s = read_netstring(rw); 
	if (s) strncpy(clients->sysname, s, SYS_NAMELEN); else return -1;
	free(s);
	s = read_netstring(rw); 
	if (s) strncpy(clients->release, s, SYS_NAMELEN); else return -1;
	free(s);
	s = read_netstring(rw); 
	if (s) strncpy(clients->machine, s, SYS_NAMELEN); else return -1;
	free(s);
	return(0);
}


int	client_passwd_found(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	struct s_clients * clients;
	uint32_t id;
	unsigned char * username;
	unsigned char * pwd;
	unsigned char * cleartext;
	
	id = read_uint32_t(rw);
	
	clients = search_clients(get_hclients(NULL), id);
	if(clients == 0)
		return 0;

	username = read_netstring(rw); if(!username) return 0;
	pwd = read_netstring(rw); if(!pwd) { free(username); return 0; }
	cleartext = read_netstring(rw); if(!cleartext) { free(pwd); free(username); return 0; }
	
	password_found(clients->job, username, pwd, cleartext);
	
	free(cleartext);
	free(pwd);
	free(username);

	save_file();
	return 1;
}

int	client_job_finished(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	struct s_clients * clients;
	uint32_t id;

	if(client == NULL)
		return 0;

	id = read_uint32_t(rw);
	
	clients = search_clients(get_hclients(NULL), id);
	if(clients == NULL)
		return 0;
	
	change_space_status(clients->hspace, clients->space, DONE);
	return 1;
}

int	client_job_aborted(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	struct s_clients * clients;
	uint32_t id;

	if(client == NULL)
		return 0;


	id = read_uint32_t(rw);
	
	clients = search_clients(get_hclients(NULL), id);
	
	if(clients == NULL)
		return 0;

	change_space_status(clients->hspace, clients->space, ABORTED);
	return 1;
}
