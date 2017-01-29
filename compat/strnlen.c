# include <string.h>

size_t	strnlen(register const char *s, register size_t maxlen)
{
   	const char *end = (const char *) memchr (s, '\0', maxlen);
   
	return end ? (size_t) (end - s) : maxlen;
}
