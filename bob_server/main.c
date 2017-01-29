#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

extern	char	*optarg;
extern	int	optind, opterr, optopt;

#define NEED_G_SPACE
#include "bob_server.h"

/* daemonize server */
void daemonize (void)
{
#ifdef DEBUG
	printf("* %s\n", __func__);
#endif

	return ;
}

void usage(void)
{
	fprintf(stderr, "Usage:\n\
	-D	: daemon mode\n\
	-p port	: set port\n\
	-f file	: set state file\n\
	-v	: increment verbose mode\n\
	-h	: this help message\n\
	-k key	: set crypto key\n"); 
	exit(USAGE_EXIT);
}


int	main(int c, char **v)
{
	int ch = 0;
	char _verbose = 0;
	char _daemon = 0;
	unsigned int _port = 0;
	char * _filename = DEFAULT_FILENAME;
	struct h_jobs hjobs;
	int fd = 0; 
	struct h_array_client hclient;
	struct h_clients hclients;

	while ( (ch = getopt(c, v, "vhDp:f:k:")) != (-1) )
		switch (ch)
		{
			case 'D':
				_daemon++;
				break;
			case 'p':
				_port = atoi (optarg);
				break;
			case 'f':
				_filename = optarg;
				break; 
			case 'v':
				_verbose++;
				break;
			case 'h': 
				usage ();
				break;
			case 'k':
				net_setkey(optarg);
				break;
			default:
				usage ();
		}
	if (_verbose > 0)
	{
		printf("* Options:\n");
		printf(" - Daemon mode = %s\n", (_daemon > 0) ? "on" : "off");
		printf(" - Port = %d\n", _port);
		printf(" - Filename = %s\n", _filename);
	}

	set_global_uptime();
	TAILQ_INIT(&hjobs);
	TAILQ_INIT(&hclient);
	TAILQ_INIT(&hclients);
	get_hclient(&hclient);
	get_hclients(&hclients);
	get_hjobs(&hjobs);

	load_file (_filename);

	if (_port == 0) _port = DEFAULT_PORT; 
	fd = open_port (_port);

	if (_daemon) daemonize ();

	bob_dispatch(fd);

	save_file (_filename);
	remove_all_jobs(&hjobs);
	return (0);
}
