#ifndef   __BTB_DATA_H__
# define  __BTB_DATA_H__

#include "rw.h"

# define SYS_NAMELEN 255
# define MAX_PWD_LIST 6000

# define CRYPTO_SEED_SIZE 8

typedef struct	s_network 
{
  unsigned char	type;
  unsigned char	cmd;
  uint32_t	psize;
  t_str	* 	str;
  unsigned char * cryptostate;
  unsigned char seed[ CRYPTO_SEED_SIZE ];
  unsigned int j;
  unsigned int d;
} t_network;

typedef struct	s_status 
{
  uint32_t	nb_job;
  uint32_t	nb_clients;
  time_t	uptime;
} __attribute__ ((packed)) t_status;

#define	MAX_PWD_SIZE	0xFF
typedef struct	s_pwd 
{
  char		username[MAX_PWD_SIZE];
  char		pwd[MAX_PWD_SIZE];
  uint32_t	salt;
} __attribute__ ((packed)) t_pwd;


#endif /* __BTB_DATA_H__ */
