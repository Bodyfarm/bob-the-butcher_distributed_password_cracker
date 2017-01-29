
#include "params.h"

#ifdef HAVE_SYSCTL_H
#include <sys/sysctl.h>
#endif
#include <sys/utsname.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "rw.h"

#include "format.h"
#include "client.h"

#include "network.h"
#include "data.h"
#include "btb.h"
#include "btb-data.h"

#include "salts.h"

extern struct s_client_opt	opt;

int	server_id(int fd, struct s_rw * rw)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif
	opt.id = read_uint32_t(rw);
#ifdef DEBUG
	UP_SPACE_LEVEL;
	if (opt.id != 0)
	{
		TAB_WRITE;
		printf(" already had an id\n");
	}
	TAB_WRITE;
	printf(" get new id [id=%d]\n", opt.id);
	DOWN_SPACE_LEVEL;
#endif
	return(RERUN_IDLE);
}

int	server_cinfo(int fd, struct s_rw * rw)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif 
	struct s_network	*net = NULL;
	struct utsname		label;
	int				fd2 = 0;
	int check;

	check = uname(&label);
	if (check < 0)
		XPERROR("uname", MEM_EXIT);
#ifdef DEBUG
	UP_SPACE_LEVEL;
	TAB_WRITE;
	printf(" %s [sysname=%s] [release=%s] [machine=%s]\n", __func__,
			label.sysname,
			label.release,
			label.machine);
	DOWN_SPACE_LEVEL;
#endif  
	fd2 = net_connect(opt.remote_hostname, opt.port);
	net = net_init(CLIENT_CLIENT, CMD_INFO);
	str_append_int32(net->str, opt.id);
	str_append_netstring(net->str, label.sysname, strlen(label.sysname));
	str_append_netstring(net->str, label.release, strlen(label.release));
	str_append_netstring(net->str, label.machine, strlen(label.machine));
	net_flush(fd2, net);
	net_close(fd2);
	return(RERUN_IDLE);
}

int server_nojob(int fd, struct s_rw * rw)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif
	return(0);
}

int server_newjob(int fd, struct s_rw * rw)
{
	//struct s_client_newjob newjob;
	//struct s_pwd pwd;
	unsigned int i;
	unsigned int nb_pwd_to_crack;

#ifdef DEBUG
	TAB_WRITE;
	printf(" %s", __func__);
	UP_SPACE_LEVEL;
#endif
	remove_all_salts();
	opt.jobid = read_uint32_t(rw);
	opt.cipherid = read_uint32_t(rw);
	opt.crack_method = read_uint32_t(rw);
	nb_pwd_to_crack = read_uint32_t(rw);
	opt.start = read_uint64_t(rw);
	opt.end = read_uint64_t(rw);
	opt.fmt = format_find(opt.cipherid);
#ifdef DEBUG
	printf(" [jobid=%d] [cipherid=%d] [crack_method=%d] [nb_pwd=%d] ", opt.jobid, opt.cipherid, opt.crack_method, nb_pwd_to_crack);
#endif
	if(opt.fmt == NULL)
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" wtf with format %d?!?\n", opt.cipherid);
		DOWN_SPACE_LEVEL;
#endif
		return 0;
	}

	opt.format = opt.fmt->params.labelname;

#ifdef DEBUG
	printf(" adding job cipher %s(%d)\n", opt.format, opt.cipherid);
#endif

	for(i=0;i<nb_pwd_to_crack;i++)
	{
		unsigned int nsize = 0;
		unsigned int pos = 0;
		unsigned char * pwd;
		unsigned char * username;

		username = read_netstring(rw);
		pwd = read_netstring(rw);

		if(pwd)
		{
			if(opt.fmt!=NULL)
				insert_password(username, pwd, opt.fmt);
			free(pwd);
		}
		else
			return 0;

		if(username)
			free(username);
		else
			return 0;
	}

#ifdef DEBUG
	DOWN_SPACE_LEVEL;
#endif

	return(WORK_NOW);
}


