#include <strings.h>
#include <signal.h>

#ifndef HAVE_SIGSET

void	sigset(int sig, void (*func)(int))
{
	signal(sig, func);
}

#endif
