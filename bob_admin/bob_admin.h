#ifndef   __BOB_ADMIN_H__
# define  __BOB_ADMIN_H__

#include "config.h"
#include "config_types.h"
#include "btb.h"
#include "btb-data.h"
#include "compat.h"

# define CMD_MAX_LEN	0x0F
# define USER_HOST_SEP	'@'
# define ASSIGN_OPT     '='

typedef struct	s_admin_opt
{
  char		*username;
  char		*passwd;
  char		*host;
  unsigned int	port;
  unsigned char	verbose;
}		t_admin_opt;

typedef struct	s_btb_admin
{
  unsigned char	id;
  char		*label;
  void		(*f)(int , char **, struct s_admin_opt *);
}		t_btb_admin;

typedef struct  s_cipher
{
    char            *label;
    unsigned char   id;
}               t_cipher;

# ifdef NEED_CIPHER_STRUCT
struct s_cipher scipher[] =
{
    { "mscash" , CIPHER_ID_MSCASH },
    { "lotus5" , CIPHER_ID_LOTUS_5},
    { "lotus" , CIPHER_ID_LOTUS_5},
    { "domino" , CIPHER_ID_LOTUS_5},
    { "rawmd5" , CIPHER_ID_RAWMD5 },
    { "mysql"  , CIPHER_ID_MYSQL  },
    { "nt"     , CIPHER_ID_NT     },
    { "eggdrip", CIPHER_ID_EGGDROP}, 
    { "nsldap" , CIPHER_ID_NSLDAP },
    { "rawsha1", CIPHER_ID_RAWSHA1},
    { "md5"    , CIPHER_ID_MD5    },
    { "des"    , CIPHER_ID_DES    },
    { "bsdi"   , CIPHER_ID_BSDI   },
    { "oracle"   , CIPHER_ID_ORACLE   },
    { NULL        , 0}
# define CIPHER_STRUCT_SIZE 1000 //TODO FIXME
};
#  else
extern struct s_cipher  *scipher;
# endif

#endif /* __BOB_ADMIN_H__ */
