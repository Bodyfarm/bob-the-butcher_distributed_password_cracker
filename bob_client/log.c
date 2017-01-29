#include "params.h"
#include <stdio.h>
#include <syslog.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "client.h"

extern t_client_opt opt;

void log_init(void)
{
	openlog("bob_client", LOG_PID, LOG_DAEMON);
}

void normal_log(char * s)
{
	if(opt.daemon==0)
		printf("%s\n", s);
	syslog(LOG_DAEMON | LOG_NOTICE, s);
}

void verbose_log(char * s)
{	
	if(opt.daemon==0)
		printf("%s\n", s);
	syslog(LOG_DAEMON | LOG_INFO, s);
}

void debug_log(char * s)
{
	if(opt.daemon==0)
		printf("%s\n", s);
	syslog(LOG_DAEMON | LOG_DEBUG, s);
}

void error_log(char * s)
{
	if(opt.daemon==0)
		fprintf(stderr, "%s\n", s);
	syslog(LOG_DAEMON | LOG_ERR, s);
}

void log_close(void)
{
	closelog();
}
