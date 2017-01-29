
#include "params.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "client.h"
#include "format.h"
#include "btb.h"

/* chained list of all the formats */
struct s_format * format_list;
extern t_client_opt opt;

void format_default_init(void)
{
}

void * format_default_salt(char * salt)
{
	return 0;
}

void format_default_set_username(char * username)
{
}


/* niiiiii */
static void format_add(struct s_format * format)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s(%s)\n", __func__, format->params.labelname);
#endif
	format->next = format_list;
	format_list = format;
	format->methods.init();
	opt.capabilities += (1 << format->params.id);
}

/* puts all the needed formats in the format list */
void format_init_all(void)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s\n", __func__);
	UP_SPACE_LEVEL;
#endif
	
	format_list = &fmt_mscash;
	format_list->next = 0;
	format_list->methods.init();
	opt.capabilities = 1 << fmt_mscash.params.id;
	format_add(&fmt_lotus5);
	//format_add(&fmt_BFEgg);
	format_add(&fmt_rawMD5);
	format_add(&fmt_MYSQL);
	format_add(&fmt_NT);
	format_add(&fmt_MD5);
	format_add(&fmt_DES);
	format_add(&fmt_rawSHA1);
	format_add(&fmt_NSLDAP);
	format_add(&fmt_BSDI);
	format_add(&fmt_oracle);
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s cap=%llx\n", __func__, opt.capabilities);
	DOWN_SPACE_LEVEL;
#endif
}

struct s_format * format_find(unsigned int id)
{
	struct s_format * curfmt;

	curfmt = format_list;
	while(curfmt)
	{
		if( curfmt->params.id == id )
			return curfmt;
		curfmt = curfmt->next;
	}
	return 0;
}

struct s_format * format_find_name(char * name)
{
	struct s_format * curfmt;

	if(!name)
		return NULL;
	curfmt = format_list;
	while(curfmt)
	{
		if( !strcmp(curfmt->params.labelname, name ) )
			return curfmt;
		curfmt = curfmt->next;
	}
	return NULL;
}

void * format_default_binary(char * ciphertext)
{
	return ((void *)strdup(ciphertext));
}


void * format_default_get_salt (char * string)
{
	return 0;
}

void format_default_set_salt(void * salt)
{
	return;
}

unsigned int format_default_binary_hash(void * binary)
{
	return ((unsigned char *) binary)[0];
}


