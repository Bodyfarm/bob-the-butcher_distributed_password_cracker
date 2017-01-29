#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define NEED_G_SPACE
#include "bob_admin.h"
#include "job.h"
#include "client.h"
#include "compat.h"
#include "get_full_login.h"

void    usage(int c, char **v, struct s_admin_opt *opt)
{
	fprintf(stderr, "Usage: bob_admin [-v] [-k] command ...\n\n");
	fprintf(stderr, "Switches:\n");
	fprintf(stderr, "\t-v: set verbose mode on (defaut: off)\n");
	fprintf(stderr, "\t-k <key>: set psk\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "\tnewjob: add a new job\n");
	fprintf(stderr, "\tdeljob: delete a job\n");
	fprintf(stderr, "\tsetopt: set options to a specific job\n");
	fprintf(stderr, "\tgetopt: get options from a specific job\n");
	fprintf(stderr, "\tstatus: get server's status\n");
	fprintf(stderr, "\tjobinf id: get info from a specific job\n");
	fprintf(stderr, "\tclient: list all clients\n");
	fprintf(stderr, "\tcltinf: get info from a specific client\n");  
	fprintf(stderr, "\n");
	exit(1);
}

struct s_btb_admin	btb_admin[] =
{
	{ CMD_NEWJOB, "newjob", &newjob},
	{ CMD_DELJOB, "deljob", &deljob},
	{ CMD_ADDPWD, "addpwd", &usage},
	{ CMD_GETOPT, "getopt", &usage},
	{ CMD_SETOPT, "setopt", &setopt},
	{ CMD_STATUS, "status", &status},
	{ CMD_GETINF, "jobinf", &getinf}, 
	{ CMD_CLIENT, "client", &client},
	{ CMD_CLTINF, "cltinf", &cltinf},
	{ 0,          "null",   &usage}
};

void	print_options(struct s_admin_opt *opt)
{
	if (opt->verbose)
	{
		printf("Options:\n");
		printf("  * host: %s\n", opt->host);
		printf("  * port: %d\n", opt->port);
		printf("  * username: %s\n", opt->username);
		printf("\n");
	}
}

int main(int c, char **v)
{
	int			i = 0;
	struct s_admin_opt	opt;

	memset(&opt, 0, sizeof(struct s_admin_opt));
	opt.host = (char *) strndup(DEFAULT_HOST, strlen(DEFAULT_HOST));
	opt.port = DEFAULT_PORT; 
	opt.username = get_full_login(opt.username);

	if (c < 2)
		usage(c, v, &opt);

	if (strncmp(*(v + 1), "-v", strlen("-v")) == 0)
	{
		opt.verbose++;
		c -= 1;
		v += 1;
	}

	if (strncmp(*(v + 1), "-k", 2) == 0 )
	{
		c -= 2; v += 2;
		net_setkey(*v);
	}

	if (c < 2)
		usage(c, v, &opt);

	print_options(&opt);
	while ((btb_admin[i].id != 0) 
			&& (strcmp( *(v + 1), btb_admin[i].label) != 0))
		i++;
	c -= 2;
	v += 2;
	btb_admin[i].f(c, v, &opt);
	return(0);
}


