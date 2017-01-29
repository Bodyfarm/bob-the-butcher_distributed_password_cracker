#include "params.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "btb.h"

#include "client.h"
#include "format.h"
#include "salts.h"
#include "standalone.h"
#include "rw.h"
#include "crack.h"

extern t_client_opt opt;

char * load_line_element(char * * ptr)
{
	unsigned int i;
	unsigned char * element;
	
	i=0;
	while( ((*ptr)[i] != ':') && ((*ptr)[i] != '\r') && ((*ptr)[i] != '\n') && ((*ptr)[i] != 0) )
		i++;
	element = malloc(i+1);
	memcpy(element, *ptr, i);
	element[i] = 0;
	*ptr += i + 1;
	return element;
}

void standalone(char * filename, char * formatname)
{
	struct s_format * fmt;
	FILE * fichier;
	char * buffer;
	char * ptr;
	char * tmp1;
	char * tmp2;
	uint64_t start;

#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
#endif

	opt.standalone = 1;
	fmt = NULL;
	if(formatname)
		fmt = format_find_name(formatname);

	if(!fmt)
	{
		if(formatname)
			printf("bad format name %s\n", formatname);
		else
			printf("bad format name\n");
		return;
	}

	incrementer_init(fmt->params.flags);
	
	if( ! (fichier = fopen(filename, "r")) )
	{
		perror("fopen");
		return;
	}

	/* bleh ! FIXME */
	buffer = malloc(1024);
	tmp1 = malloc(1024);
	tmp2 = malloc(1024);

	while(fgets(buffer, 1024, fichier))
	{
		sscanf(buffer, "%[^:]:%s", tmp1, tmp2);
		if(!fmt)
		{
			fmt = format_list;
			while(fmt)
			{
				if( fmt->methods.valid(tmp2) )
					break;
				fmt = fmt->next;
			}
		}
		if(!fmt)
			continue;
		ptr = buffer;
		if(!insert_password(tmp1, tmp2, fmt))
		{
			printf("password %s/%s invalid\n", tmp1, tmp2);
		}
	}
	free(tmp2);
	free(tmp1);


	free(buffer);

	if(opt.debug)
		show_hashtables();
	start = 1;

	if(fmt->params.benchmark_length<=0)
		fmt->params.benchmark_length = DEFAULT_BENCH_LEN;
	while(salt_list)
	{
		stupid_brute_force(fmt, start, start + fmt->params.benchmark_length);
		start += fmt->params.benchmark_length;
	}
}
