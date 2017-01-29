#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

//#include "rw.h"
#include "btb.h"
#include "btb-data.h"
#include "network.h"

#define SWAP(x,y) { unsigned char tmp = x; x = y; y = tmp; }

static unsigned char * key = NULL;

void net_crypto_init_state(struct s_network * net)
{
	unsigned char * buffer;
	unsigned int i;
	unsigned int j;
	unsigned int l;

	if(key == NULL)
		return;

	l = strlen(key) + CRYPTO_SEED_SIZE;
	buffer = malloc(l + 1);
	if(!buffer)
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" can't malloc(%d)\n", l+1);
#endif
		return;
	}

	memcpy(buffer, net->seed, CRYPTO_SEED_SIZE);
	strcpy(buffer + CRYPTO_SEED_SIZE, key);

	for(i=0;i<256;i++)
	{
		net->cryptostate[i] = i & 0xff;
	}
	j = 0;
	for(i=0;i<255;i++)
	{
		j = (j + net->cryptostate[i] + buffer[i%l]) & 0xff;
		SWAP(net->cryptostate[i], net->cryptostate[j]);
	}
	
	j = 0;
	for(i=0;i<1024;i++)
	{
		j = (j + net->cryptostate[i & 0xff]) & 0xff;
		SWAP(net->cryptostate[i & 0xff], net->cryptostate[j]);
	}
	net->j = j;
	net->d = i;
}

int net_crypto_init(struct s_network * net)
{
	FILE * random;

	if(key == NULL)
	{
		net->cryptostate = NULL;
#ifdef DEBUG
		TAB_WRITE;
		printf(" no crypto key!\n");
#endif
		return 1;
	}

#ifdef DEBUG
	TAB_WRITE;
	printf(" %s(%s)\n", __func__, key);
#endif

	random = fopen("/dev/urandom", "r");
	if(random == NULL)
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" can't find /dev/urandom\n");
#endif
		return 0;
	}
	
	fread(net->seed, CRYPTO_SEED_SIZE, 1, random);
	fclose(random);

	net->cryptostate = malloc(256);
	if(!net->cryptostate)
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" can't malloc(256)\n");
#endif
		return 0;
	}
	net_crypto_init_state(net);
	net->d = 0;
	return 1;
}

void net_crypto_free(struct s_network * net)
{
	if(net->cryptostate)
		free(net->cryptostate);
}

void net_crypt(struct s_network * net, unsigned char * buffer, unsigned int size)
{
	unsigned int i;
	unsigned int j;

	if(key == NULL)
		return;
	if(net->cryptostate == NULL)
		return;

	j = net->j;
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s [size=%d]\n", __func__, size);
#endif
	for(i=0;i<size;i++)
	{
		j = (j + net->cryptostate[ (i + net->d) & 0xff]) & 0xff;
		SWAP(net->cryptostate[ (i + net->d) & 0xff], net->cryptostate[j]);
		buffer[i] ^= net->cryptostate[ (net->cryptostate[ (i + net->d) & 0xff ] + net->cryptostate[j]) & 0xff ];
	}
	net->j = j;
	net->d += size;
}

void net_setkey(unsigned char * cryptokey)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s(%s)\n", __func__, cryptokey);
#endif
	key = cryptokey;
}
