#include "config.h"
#include "config_types.h"

#include <stdio.h>
#ifdef HAVE_LIBDMALLOC
# include <dmalloc.h>
#else
# include <stdlib.h>
#endif

#include <string.h>


#include "rw.h"
#include "network.h"

/*
 * checks that the buffer size is sufficient
 */
static void str_check_size(t_str * str, unsigned int size)
{
	if(BUFLEN(str) > size)
		return;
	STRING(str) = realloc(STRING(str), ( size | STRMASK) + 1 );
	BUFLEN(str) = ( size | STRMASK ) + 1;
}

t_str * str_init(unsigned int size)
{
	t_str * out = NULL;

	out = malloc(sizeof(t_str));
	if(!out)
		return NULL;
	
	//size++;
	
	STRING(out) = malloc( ( size | STRMASK) + 1 );
	if(!STRING(out))
	{
		free(out);
		return NULL;
	}
	BUFLEN(out) = (size | STRMASK) + 1 ;
	STRLEN(out) = size;

	memset(STRING(out), 0, BUFLEN(out));
	
	return out;
}

/*
 * creates a str stuff with source buffer 'string'
 * that is at most n byte long
 */
t_str * strn_create(unsigned char * string, unsigned int size)
{
	t_str * out = NULL;
	unsigned char * p1;
	unsigned char * p2;


	out = malloc(sizeof(t_str));
	if(!out)
		return NULL;
	
	size++;
	
	STRING(out) = malloc( ( size | STRMASK) + 1 );
	if(!STRING(out))
	{
		free(out);
		return NULL;
	}
	BUFLEN(out) = (size | STRMASK) + 1 ;

	if(string == NULL)
	{
		STRLEN(out) = size;
		memset(STRING(out), 0, size);
	}
	else
	{
		p1 = string;
		p2 = STRING(out);

		while( *p1 )
		{
			if( (p1 - string + 1) >= size )
				break;
			*p2 = *p1;
			p2++;
			p1++;
		}
		*p2 = 0;
		STRLEN(out) = (p1 - string)  ;
	}
	return out;
}

/* uneffective algorithm */
t_str * str_create(unsigned char * string)
{
	unsigned int i = 0;

	if(!string)
		return NULL;

	while(string[i])
		i++;

	return strn_create(string, i );
}

void strn_copy(t_str * dst, t_str * src, unsigned int size)
{
	unsigned int nsize;

	if( STRLEN(src)>size )
		nsize = size;
	else
		nsize = STRLEN(src);

	str_check_size(dst, nsize);
	memcpy(STRING(dst), STRING(src), nsize);
	STRING(dst)[nsize] = 0;
	STRLEN(dst) =  nsize;
}

void str_copy(t_str * dst, t_str * src)
{
	strn_copy(src, dst, STRLEN(src));
}

void str_show(t_str * str)
{
	if(!str)
	{
		printf("error printing string\n");
		return;
	}
	printf("[%s] size(%d) bufsize(%d)\n", STRING(str), STRLEN(str), BUFLEN(str));
}

void str_free(t_str * str)
{
	free(STRING(str));
	free(str);
}

t_str * str_dup(t_str * src)
{
	t_str * dst;

	dst = malloc(sizeof(t_str));
	if(!dst)
		return NULL;
	
	STRING(dst) = malloc(BUFLEN(src));

	if(!STRING(dst))
	{
		free(dst);
		return NULL;
	}

	BUFLEN(dst) = BUFLEN(src);
	STRLEN(dst) = STRLEN(src);
	memcpy(STRING(dst), STRING(src), STRLEN(src) + 1 );

	return dst;
}

void str_append_char(t_str * str, u_char x)
{
	str_check_size(str, STRLEN(str) + 1);
	STRING(str)[ STRLEN(str) ] = x;
	STRLEN(str)++;
	STRING(str)[ STRLEN(str) ] = 0;
}

void str_append_int32(t_str * str, uint32_t x)
{
	unsigned int i;
	str_check_size(str, STRLEN(str) + 4);
#ifdef WORDS_BIGENDIAN
	i = x;
#else
	i = htonl(x);
#endif
	memcpy(STRING(str) + STRLEN(str), &i, 4);
	STRLEN(str) += 4;
	STRING(str)[ STRLEN(str) ] = 0;
}

void str_append_int64(t_str * str, uint64_t x)
{
	uint64_t i;
	str_check_size(str, STRLEN(str) + 8);
#ifdef WORDS_BIGENDIAN
	i = x;
#else
	i = hton64(x);
#endif
	memcpy(STRING(str) + STRLEN(str), &i, 8);
	STRLEN(str) += 8;
	STRING(str)[STRLEN(str)] = 0;
}

void str_append_str(t_str * dst, t_str * src)
{
	str_check_size(dst, STRLEN(src) + STRLEN(dst) + 2);
	memcpy(STRING(dst) + STRLEN(dst), STRING(src), STRLEN(src));
	STRLEN(dst) += STRLEN(src);
	STRING(dst)[STRLEN(dst)] = 0;
}

void str_append_netstring(t_str * dst, unsigned char * src, uint32_t size)
{
	str_append_int32(dst, size);
	str_check_size(dst, STRLEN(dst) + size);
	memcpy(STRING(dst) + STRLEN(dst), src, size);
	STRLEN(dst) += size;
	STRING(dst)[STRLEN(dst)] = 0;
}

void str_set(t_str * str, unsigned char * text, unsigned int len)
{
	str_check_size(str, len);
	memcpy(STRING(str), text, len);
	STRING(str)[len] = 0;
	STRLEN(str) = len;
}

unsigned int str_cmp(t_str * str1, t_str * str2)
{
	unsigned int i;
	if(STRLEN(str1)!=STRLEN(str2))
		return 0;
	for(i=0;i<STRLEN(str1);i++)
		if ( STRING(str1)[i] != STRING(str2)[i] )
			return 0;
	return 1;
}
