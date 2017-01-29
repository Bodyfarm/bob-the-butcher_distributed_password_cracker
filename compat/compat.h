#ifndef   __COMPAT_H__
# define  __COMPAT_H__

#ifndef HAVE_STRNDUP
char    *strndup(const char *, size_t);
#endif

#ifndef HAVE_STRNLEN
size_t  strnlen(const char *, size_t);
#endif

#ifndef HAVE_MEMSET
void    *memset(void *, int, size_t);
#endif

#ifndef HAVE_MEMCMP
int     memcmp(const void *, const void *, size_t);
#endif

#endif /* __COMPAT_H__ */
