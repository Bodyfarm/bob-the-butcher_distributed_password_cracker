
/*
 * This file is part of John the Ripper password cracker.
 * Copyright (c) 1996-99 by Solar Designer
*/

#include <string.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "config_types.h"
#include "rw.h"
#include "bob_client/format.h"

char itoa64[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
char atoi64[0x100];

char itoa16[16] =
	"0123456789abcdef";
char atoi16[0x100];

char idx2chr[0x100];
char incrementer[0x100];

static int initialized = 0;

void atoi_init(void)
{
	char        *pos;
	unsigned int i;

	if (initialized) 
        return;

	memset(atoi64, 0x7F, sizeof(atoi64));
	for (pos = itoa64; pos <= &itoa64[63]; pos++)
		atoi64[ARCH_INDEX(*pos)] = pos - itoa64;

	memset(atoi16, 0x7F, sizeof(atoi16));
	for (pos = itoa16; pos <= &itoa16[15]; pos++)
		atoi16[ARCH_INDEX(*pos)] = pos - itoa16;

	atoi16['A'] = atoi16['a'];
	atoi16['B'] = atoi16['b'];
	atoi16['C'] = atoi16['c'];
	atoi16['D'] = atoi16['d'];
	atoi16['E'] = atoi16['e'];
	atoi16['F'] = atoi16['f'];

	initialized = 1;
}

void incrementer_init(unsigned int type)
{
	unsigned int old;
	unsigned int i;

	memset(incrementer, 0, sizeof(incrementer));
	old = 0;
	switch(type & (ALL_CAPS))
	{
		case ALL_CAPS:
			for(i=0;i<62-26;i++)
			{
				if(i<10)
					idx2chr[i] = i + 48;
				else 
					idx2chr[i] = i + 65 - 10;
				incrementer[old] = idx2chr[i];
				old = idx2chr[i];
			}
			break;
		default:
			for(i=0;i<62;i++)
			{
				if(i<10)
					idx2chr[i] = i + 48;
				else if(i<36)
					idx2chr[i] = i + 65 - 10;
				else 
					idx2chr[i] = i + 97 - 36;
				incrementer[old] = idx2chr[i];
				old = idx2chr[i];
			}
	}
}
