#include "params.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include <get_full_login.h>
#include "client.h"
#include "log.h"
#include "rw.h"
#include "format.h"
#include "client_connect.h"
#include "timer.h"
#include "crack.h"
#include "standalone.h"

#include <btb.h>

t_client_opt opt;

void usage(char * program_name)
{
	printf("Usage: %s [options] [hostname [port]]\n", program_name);
	printf("Where options are:\n");
	printf("\t-s <file>: standalone mode\n");
	printf("\t-f <format>: specifies format\n");
	printf("\t-v: verbose mode\n");
	printf("\t-d: debug mode (implies -v)\n");
	printf("\t-p <priority>: priority of the process, see nice(1)\n");
	printf("\t-b: benchmark\n");
	printf("\t-D: daemon mode\n");
	printf("\t-w <wordfile>: wordfile for john mode\n");
	printf("\t-j <path to john>: binary for john mode\n");
	printf("\t-k <key>: psk\n");
}

int main(int argc, char * * argv)
{
	int optchar = 0;
	int nb_opts = 1;
	static char default_john_binary[] = "john";

	opt.debug = 0;
	opt.verbose = 0;
	opt.standalone = 0;
	opt.daemon = 0;
	opt.benchmark = 0;
	opt.id = 0;
	opt.port = 0;
	opt.remote_hostname = NULL;
	opt.host = NULL;
	opt.username = NULL;
	opt.working = 0;
	opt.wordlist = NULL;
	opt.john = NULL;

	while ( (optchar = getopt (argc, argv, "vdDbf:s:p:w:j:k:")) != -1)
	{
		switch(optchar)
		{
			case 'v':
				opt.verbose = 1;
				break;
			case 'd':
				opt.debug = 1;
				opt.verbose = 1;
				break;
			case 'p':
				opt.priority = atoi(optarg);
				nb_opts++;
				break;
			case 'D':
				opt.daemon = 1;
				break;
			case 'b':
				opt.benchmark++;
				break;
			case 's':
				opt.standalone = 1;
				opt.filename = optarg;
				nb_opts++;
				break;
			case 'f':
				opt.format = optarg;
				nb_opts++;
				break;
			case 'w':
				opt.wordlist = optarg;
				nb_opts++;
				break;
			case 'j':
				opt.john = optarg;
				nb_opts++;
				break;
			case 'k':
				net_setkey(optarg);
				nb_opts++;
				break;
			default:
				printf("Unknown option -%c\n", optchar);
				usage(argv[0]);
				return -1;
		}
		nb_opts++;
	}

	if(opt.john == NULL)
		opt.john = default_john_binary;
	opt.username = get_full_login(opt.username);

	if(opt.priority!=0)
	{
		if( (opt.priority>20) || (opt.priority<-19) )
		{
			printf("bad priority %d\n", opt.priority);
			usage(argv[0]);
			return -1;
		}
		if(opt.debug)
			printf("Trying to set priority to %d\n", opt.priority);
		if(setpriority(PRIO_PROCESS, 0, opt.priority) != 0)
		{
			perror("Set priority");
			return -1;
		}
	}

	/* check if hostname / port have been submitted */
	switch(argc - nb_opts)
	{
		/* port + hostname submitted */
		case 2:
			opt.port = atoi(argv[nb_opts+1]);
			if( (opt.port<1) || (opt.port>65535) )
			{
				fprintf(stdout, "port value invalid: %s\n", argv[nb_opts+1]);
				return -1;
			}
		/* hostname submitted */
		case 1:
			opt.remote_hostname = strdup(argv[nb_opts]);
			break;
		/* defaults hostname:port */
		case 0:
			break;
		/* nii? */
		default:
			usage(argv[0]);
			return -1;
	}
	
	if(opt.port == 0)
		opt.port = DEFAULT_PORT;
	if (opt.remote_hostname == NULL)
		opt.remote_hostname = strdup(DEFAULT_HOST);

	if(opt.verbose)
		printf("Selecting hostname %s:%d\n", opt.remote_hostname, opt.port);

	if(opt.daemon)
	{
		int pid;
		int n;
		
		if(opt.debug)
			printf("Trying to demonize\n");
		/* Copy & paste from Christophe Devine's Tiny Shell */
		pid = fork();
		if(pid<0)
		{
			perror("fork");
			return -1;
		}
		if(pid!=0)
			return 0;
		if(setsid()<0)
		{
			perror("setsid");
			return -1;
		}
		/* close all file descriptors */
		for(n=0;n<1024;n++)
			close(n);
	}

	log_init();
	atoi_init();
	signal_init();
	format_init_all();

	normal_log("Client started");

	
	if(opt.benchmark)
	{
		do_crack(0, format_find_name(opt.format), 0, 0);
	}	
	else if (opt.standalone==1)
	{
		standalone(opt.filename, opt.format);
	}
	else
	{
		client_dispatch();
	}
	
	log_close();
	if(opt.remote_hostname)
		free(opt.remote_hostname);
	return 0;
}
