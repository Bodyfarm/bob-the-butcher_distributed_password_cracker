
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "bob_server.h"
#include "rw.h"

int     admin_status(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	struct s_jobs		*job = NULL;
	struct h_jobs		*hjobs = get_hjobs(NULL);
	struct s_clients	*clients = NULL;
	struct h_clients	*hclients = get_hclients(NULL);
	struct s_status		status;

	int			psize = 0;
	struct s_str * str;
	uint32_t x;

	memset(&status, 0, sizeof(struct s_status));

	TAILQ_FOREACH(job, hjobs, next)
	{
		status.nb_job++;	    
#ifdef DEBUG
		UP_SPACE_LEVEL;
		TAB_WRITE;
		printf(" job [id=%.2d] [user=%s]\n", job->id, job->name);
		DOWN_SPACE_LEVEL;
#endif
	}
	TAILQ_FOREACH(clients, hclients, next)
	{
		status.nb_clients++;
#ifdef DEBUG
		UP_SPACE_LEVEL;
		TAB_WRITE;
		printf(" client [id=%d] [user=%s]\n", clients->id, clients->username);
		DOWN_SPACE_LEVEL;	    
#endif
	}

	if(net->str)
		str_free(net->str);

	net->str = str_init(0);
	if(!net->str)
		return MEM_EXIT;

	str_append_int32(net->str, status.nb_job);
	str_append_int32(net->str, status.nb_clients);
	str_append_int32(net->str, get_global_uptime());

	//uptime

	TAILQ_FOREACH(job, hjobs, next)
	{
		str_append_int32(net->str, job->id);
		str_append_int32(net->str, job->date_start);
		str_append_int32(net->str, job->status);
		str_append_int32(net->str, job->prior);
		str_append_int32(net->str, job->cipher);
		str_append_int32(net->str, job->crack_method);
		str_append_int32(net->str, job->nb_pwd);
		str_append_int32(net->str, job->nb_found_pwd);
		str_append_netstring(net->str, job->name, strlen(job->name));
	}

	net_flush(fd, net);

	/*
	x = ntohl(STRLEN(str));
	psize = write(fd, &x, 4);
	if (psize != 4)
		return(NET_EXIT);

	psize = write(fd, STRING(str), STRLEN(str));
	if (psize != STRLEN(str))
		return(NET_EXIT);
	*/

	return(0);
}

int     admin_add_job(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
	UP_SPACE_LEVEL;
#endif
	struct s_jobs		*jobs = NULL;
	uint32_t	job_id = 0;
	unsigned char * username;
	uint32_t cipher;

	username = read_netstring(rw);
	cipher = read_uint32_t(rw);

	jobs = add_job(get_hjobs(NULL), username, cipher, 0x01, 0x00);

	job_id = htonl(jobs->id);

	net_crypt(net, &job_id, sizeof(uint32_t));
	write(fd, &job_id, sizeof(uint32_t));

#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
	return(0);
}

int     admin_add_pwd(int fd, struct s_array_client *client, struct s_rw *rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
	UP_SPACE_LEVEL;
#endif
	struct s_pwd		pwd;
	struct s_jobs		*job = NULL;
	uint32_t		id = 0;
	uint32_t		nb_pwd = 0;
	uint32_t		i = 0;

	id = read_uint32_t(rw);
	nb_pwd = read_uint32_t(rw);
#ifdef DEBUG
	TAB_WRITE;
	printf(" Want to add %d password(s) to job %d\n", nb_pwd, id);
#endif
	job = search_job(get_hjobs(NULL), id);
	if (!job)
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" bad job id\n");
		DOWN_SPACE_LEVEL;
#endif
		return 1;
	}
	if (nb_pwd > MAX_PWD_LIST)
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" Number of pwd is too high\n");
		DOWN_SPACE_LEVEL;
#endif
		return(1);
	}
	for (i = nb_pwd; i > 0; i--)
	{
		int	nsize = 0;

		/* FIXME fix this */
		nsize = net_read_buf(fd, &pwd, sizeof(struct s_pwd), net);
		if (nsize < 0)
			break;
		add_passwd(job->passwd, 
				strdup(pwd.username), 
				strdup(pwd.pwd), 
				job->cipher);
		job->nb_pwd++;
	}
	job->status = JOB_ACTIVE;
#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif
	return(0);
}

int     admin_del_job(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	uint32_t		to_del = 0;

	to_del = read_uint32_t(rw);
	del_job(get_hjobs(NULL), to_del);
#ifdef DEBUG
	UP_SPACE_LEVEL;
	TAB_WRITE;
	printf(" delete job [id=%d]\n", to_del);
	DOWN_SPACE_LEVEL;
#endif
	return(0);
}

int     admin_setopt(int fd, struct s_array_client *client,  struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
	UP_SPACE_LEVEL;
#endif
	//FIXME TODO
/*
	struct s_opt    setopt;
	uint32_t        id = 0;
	struct s_jobs   *job = NULL;

	id = read_uint32_t(rw);
#ifdef DEBUG
	TAB_WRITE;
	printf(" setopt [status=%s] [id=%d]\n", (setopt.status == J_STATUS_ACTIVE) ? "active" : "paused" , id);
#endif
	job = search_job(get_hjobs(NULL), id);
	if (job == NULL)
	{
#ifdef DEBUG
		DOWN_SPACE_LEVEL;
#endif
		return (1);
	}
	if (setopt.status != DONT_CHANGE)
		job->status = setopt.status;   
	if ( (job->status == J_STATUS_ACTIVE) && (job->date_start == 0) )
		job->date_start = time(0);
	if (htonl(setopt.prior)  != DONT_CHANGE)
		job->prior = htonl(setopt.prior);

#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif*/
	return(0);
}

int     admin_getinf(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	uint32_t        id   = 0;
	struct s_jobs   *job = NULL;
	int             psize = 0;
	struct s_passwd * passwd;
	struct s_processed_space pspace;
	struct s_str * str;

	id = read_uint32_t(rw);
#ifdef DEBUG
	UP_SPACE_LEVEL;
	TAB_WRITE;
	printf(" getinf [id=%d]\n", id);
	DOWN_SPACE_LEVEL;
#endif
	job = search_job(get_hjobs(NULL), id);
	if (job == NULL)
		return (1);

	str = str_init(0);
	str_append_int32(str, id);
	str_append_netstring(str, job->name, strlen(job->name));
	str_append_int32(str, job->date_start);
	str_append_int32(str, job->status);
	str_append_int32(str, job->prior);
	str_append_int32(str, job->cipher);
	str_append_int32(str, job->nb_pwd);
	str_append_int32(str, job->nb_found_pwd);
	processed_space(job->space, &pspace);
	printf("processed space = %lld\n", pspace.done);
	str_append_int64(str, pspace.done);
	str_append_int32(str, time(NULL) - job->date_start);
	
	TAILQ_FOREACH(passwd, job->passwd, next)
	{
		if(passwd->cleartext)
		{
			str_append_netstring(str, passwd->username, strlen(passwd->username));
			str_append_netstring(str, passwd->password, strlen(passwd->password));
			str_append_netstring(str, passwd->cleartext, strlen(passwd->cleartext));
		}
	}

	psize = htonl(STRLEN(str));
	write(fd, &psize, 4);
	write(fd, net->seed, CRYPTO_SEED_SIZE);
	net_crypt(net, STRING(str), STRLEN(str));
	psize = write(fd, STRING(str), STRLEN(str));
#ifdef DEBUG
	if(psize != STRLEN(str))
	{
		TAB_WRITE;
		printf(" write error in %s\n", __func__);
	}
#endif

	return(0);
}

int	admin_client(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif
	// FIXME TODO
	/*
	struct s_admin_client	admin_client;
	struct s_clients	*clients = NULL;
	struct h_clients	*hclients = get_hclients(NULL);
	uint32_t		nb_clients = 0;

	memset(&admin_client, 0, sizeof(struct s_admin_client));
	TAILQ_FOREACH(clients, hclients, next)
	{
		nb_clients++;
#ifdef DEBUG
		UP_SPACE_LEVEL;
		TAB_WRITE;
		printf(" client [id=%d] [username=%s]\n",
				clients->id, 
				clients->username);
		DOWN_SPACE_LEVEL;
#endif
	}
	*/
	return(0);
}

int	admin_cltinf(int fd, struct s_array_client *client, struct s_rw * rw, struct s_network * net)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [fd=%d]\n", __func__, fd);
#endif

	return(0);
}
