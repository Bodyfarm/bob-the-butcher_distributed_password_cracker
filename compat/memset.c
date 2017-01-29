#include <strings.h>

#ifndef HAVE_MEMSET

void	memset(void *s, int c, size_t n)
{
	register char	*str = (char *) s;

	for (; n--; *str++ = c);
	return;
}

#endif
