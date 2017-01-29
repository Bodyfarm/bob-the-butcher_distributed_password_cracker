#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#ifndef HAVE_MEMCPY

int memcmp(const void *s1, const void *s2, register size_t n)
{
	register const char	*c1 = (const char *) s1;
	register const char	*c2 = (const char *) s2;
	


	if ( (c1 == 0) || (c2 == 0))
		{
			fprintf (stderr, "memcmp failed to null pointer\n");
			exit (-1);
		}
	for (; (*c1 && *c2) && (*c1 == *c2); c1++, c2++);
	return (*(c1 - 1) - *(c2 - 1));
}

#endif
