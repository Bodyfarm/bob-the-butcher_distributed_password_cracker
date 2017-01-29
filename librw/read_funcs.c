#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "config_types.h"
#include "rw.h"

uint32_t   read_uint32_t(struct s_rw *rw)
{
	uint32_t    res = 0;

	RW_SIZE_CHECK(rw, 4);
	res = (uint32_t) (*rw->ptr       << 24)
		+ (uint32_t) (*(rw->ptr + 1) << 16)
		+ (uint32_t) (*(rw->ptr + 2) << 8 )
		+ (uint32_t) (*(rw->ptr + 3)      );
	rw->ptr += sizeof(uint32_t);

	return(res);
}

struct s_rw * rw_init(u_char * buf, int size)
{
	struct s_rw * ret;

	ret = malloc(sizeof(struct s_rw));
	if(!ret)
		return NULL;
	ret->size = size;
	ret->buf = buf;
	ret->ptr = buf;

	return ret;
}

void rw_free(struct s_rw * rw)
{
	if(rw)
		free(rw);
}

uint64_t read_uint64_t(struct s_rw *rw)
{
	uint64_t    res = 0;
	int i;

	RW_SIZE_CHECK(rw, 8);
	memcpy(&res, rw->ptr, 8);
	
	for(i=0;i<8;i++)
	{
		res <<= 8;
		res += *rw->ptr;
		rw->ptr++;
	}
	return(res);
}

u_char * read_netstring(struct s_rw *rw)
{
	unsigned char * s;
	unsigned int size;

	size = read_uint32_t(rw);
	if(size == 0)
		return NULL;
	RW_SIZE_CHECK(rw, size);
	s = malloc(size + 1);
	memcpy(s, rw->ptr, size);
	rw->ptr += size;
	s[size] = 0;

	return s;
}

u_char      read_u_char(struct s_rw *rw)
{
	u_char  res = 0;

	res = *rw->ptr++;

	return(res);
}
