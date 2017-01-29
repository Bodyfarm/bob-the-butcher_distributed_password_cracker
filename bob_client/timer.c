#include "params.h"
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <stdio.h>

#include <time.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "timer.h"
#include "btb.h"
#include "format.h"
#include "crack.h"
#include "client.h"
#include "client_connect.h"

extern t_client_opt opt;

static struct timeval tv;
static struct timezone tz;

int timer_active;

void start_chrono(void)
{
	tz.tz_minuteswest = 0;
	tz.tz_dsttime = 0;
	gettimeofday(&tv, &tz);
}

void start_timer(unsigned int time)
{
	timer_active = 1;
	alarm(time);
}

/* show stats */
void stop_chrono(uint64_t nb, unsigned int charset)
{
	double totaltime, total, total2;
	struct timeval tv2;

	gettimeofday(&tv2, &tz);

	totaltime = (tv2.tv_sec - tv.tv_sec) + (float)(tv2.tv_usec - tv.tv_usec)/1000000;
	total = nb/totaltime;

	if(total>10000000)
	{
		printf("\t%.2fM c/s real", total/1000000);
	}
	else if(total>100000)
	{
		printf("\t%.2fK c/s real", total/1000);
	}
	else
		printf("\t%.2f c/s real", total);
	if(charset)
	{
		printf(" (all 7 char passwords (charset size %d) in ", charset);

		total2 = charset*charset*charset*charset*charset/60 / total  ;
		total2 *= charset*charset;
		if(total2 < 600)
			printf("%.2f minutes)", total2);
		else if (total2 < 60*100)
			printf("%.2f hours)", total2/60);
		else 
			printf("%.2f days)", total2/60/24);
	}
	printf("\n");
}

void stop_timer(void)
{
	timer_active = 0;
}

void abort_job(void)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif
	if(opt.working == 1)
	{
		job_change_status(CMD_JOBABORT);
		exit(0);
	}
	exit(0);
}

void signal_init(void)
{
	//sigset_t sigmask;
	
	//sigemptyset(&sigmask);
        //sigaddset(&sigmask, SIGALRM);
	sigset(SIGALRM, stop_timer); 
	sigset(SIGTERM, abort_job); 
	sigset(SIGINT, abort_job); 
}
