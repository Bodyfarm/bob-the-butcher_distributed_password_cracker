#ifndef _DES_H
#define _DES_H

//#include <openssl/des.h>
typedef unsigned long DES_LONG;

typedef unsigned char DES_cblock[8];

typedef struct DES_ks
    {
    union
	{
	DES_cblock cblock;
	/* make sure things are correct size on machines with
	 * 8 byte longs */
	DES_LONG deslong[2];
	} ks[16];
    } DES_key_schedule;



void my_des_ncbc_encrypt(const unsigned char *input,
               long length, DES_key_schedule *schedule, DES_cblock *ivec);
void my_des_set_key(DES_cblock *key, DES_key_schedule *schedule);


#endif
