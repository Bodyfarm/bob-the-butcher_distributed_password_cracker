#include "config.h"
#include "config_types.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

char * memcpy_alloc(char * src, int size)
{
	char * dst;
	
	dst = malloc(size);
	if(!dst)
	{
		printf("memcpy_alloc no src\n");
		return 0;
	}
	if(!dst)
		return 0;
	memcpy(dst, src, size);
	return dst;
}

/*
 * reads a chunk of data,
 * alloc memory, returns a string
 * int8		size
 * char[]	data
 */
char * read_netstr(unsigned char * buf, int maxlen)
{
	char * ret;
	int len;
	
	if(buf[0]>maxlen)
	{
#ifdef DEBUG
		printf("Buffer overflow at read_netstr avoided\n");
#endif
		return 0;
	}
	len = buf[0];
	ret = malloc(len+1);
	if(!ret)
	{
		perror("read_netstr malloc");
		return 0;
	}
	memcpy(ret, buf+1, len);
	ret[len] = 0;
	return ret;
}

/*
 * get 4 bytes int bleh bleh
 */
uint32_t get_int32_from_buf(unsigned char * buf)
{
	return ( 
			( ((uint32_t)buf[0])<<24) + 
			( ((uint32_t)buf[1])<<16) + 
			( ((uint32_t)buf[2])<<8) + 
			buf[3] );
}

uint64_t get_int64_from_buf(unsigned char * buf)
{
	return ( 
			( ((uint64_t)buf[0])<<56) + 
			( ((uint64_t)buf[1])<<48) + 
			( ((uint64_t)buf[2])<<40) + 
			( ((uint64_t)buf[3])<<32) + 
			( ((uint64_t)buf[4])<<24) + 
			( ((uint64_t)buf[5])<<16) + 
			( ((uint64_t)buf[6])<<8) + 
			buf[7] );
}

void put_int64_in_buf(unsigned char * buf, uint64_t val)
{
	buf[7] = val & 0xFF; val = val >> 8;
	buf[6] = val & 0xFF; val = val >> 8;
	buf[5] = val & 0xFF; val = val >> 8;
	buf[4] = val & 0xFF; val = val >> 8;
	buf[3] = val & 0xFF; val = val >> 8;
	buf[2] = val & 0xFF; val = val >> 8;
	buf[1] = val & 0xFF; val = val >> 8;
	buf[0] = val & 0xFF; val = val >> 8;
}

void put_int32_in_buf(unsigned char * buf, uint32_t val)
{
	buf[3] = val & 0xFF; val = val >> 8;
	buf[2] = val & 0xFF; val = val >> 8;
	buf[1] = val & 0xFF; val = val >> 8;
	buf[0] = val & 0xFF; val = val >> 8;
}

void dump_stuff(unsigned char * stuff, int size)
{
	int i;

	for(i=0;i<size;i++)
		printf("%.2x", stuff[i]);
	printf("\n");
}
#ifdef MMX_COEF
#define GETPOS(i, index)		( (index)*4 + (i& (0xffffffff-3) )*MMX_COEF + ((i)&3) )
void dump_stuff_mmx(unsigned char * buf, unsigned int size, unsigned int index)
{
        int i;
        for(i=0;i<size;i++)
        {
                if(!(i%4))
                        printf(" ");
                printf("%.2x", buf[GETPOS(i, index)]);
        }
        printf("\n");
}
#endif

inline unsigned char upper(unsigned char b)
{
	if( (b>='a') && (b<='z'))
		b -= 0x20;
	return b;
}

inline void to_upper(unsigned char * b)
{
	while(*b)
	{
		*b = upper(*b);
		b++;
	}
}
