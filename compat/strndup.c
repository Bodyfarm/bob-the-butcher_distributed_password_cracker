#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "compat.h"

char	*strndup(const char *s, size_t n)
{
	char	*ret = NULL;

	n = strnlen(s, n);
	ret = (char *) malloc(n + 1);
	if (ret == NULL)
		return(NULL);
	memcpy(ret, s, n);
	ret[n] = 0;
	return(ret);
}
