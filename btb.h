#ifndef   __BTB_H__
# define  __BTB_H__

#ifndef _POSIX_SOURCE
# define _POSIX_SOURCE
#endif

# include "config_types.h"

//# ifndef MSG_WAITALL
//#  define MSG_WAITALL 0x100
//# endif

# define MAX_USER_SIZE		0x30
# define INTERVAL_LENGTH	5000000

# define    ON_STR        "on"
# define    ON_OFF(x) (strncmp(ON_STR, x, strlen(ON_STR)) ? 0 : 1)
# define    ON_OFF_STR(x) ( (x == 0) ? "off" : "on ")

# define	CLIENT_UNKNOWN  0x00
# define	CLIENT_CLIENT   0x01
# define	CLIENT_ADMIN    0x02
# define	CLIENT_SERVER	0xF0

// Admin commands
# define	CMD_NEWJOB	0x01
# define	CMD_DELJOB	0x02
# define	CMD_ADDPWD	0x03
# define	CMD_GETOPT	0x04
# define	CMD_SETOPT	0x05
# define	CMD_STATUS	0x06
# define	CMD_GETINF	0x07
# define	CMD_CLIENT	0x08
# define	CMD_CLTINF	0x09

// Client commands
# define	CLIENT_CMD_MASK	0xF0
# define	CLIENT_MASK	0x0F
# define	CMD_IDLE	(CLIENT_CMD_MASK | 0x01)
# define	CMD_INFO	(CLIENT_CMD_MASK | 0x02)
# define	CMD_PWDFOUND	(CLIENT_CMD_MASK | 0x03)
# define	CMD_JOBFINISH	(CLIENT_CMD_MASK | 0x04)
# define	CMD_JOBABORT	(CLIENT_CMD_MASK | 0x05)

// Server commands
# define	CMD_SID		0x01
# define	CMD_CINFO	0x02
# define	CMD_NOJOB	0x03
# define	CMD_CJOB	0x04
# define	CMD_NEWPWD	0x05
# define	CMD_WORK	0x06

# define    OPT_STATUS      0X01
# define    OPT_CIPHER      0x02
# define    OPT_PRIOR       0x03

# define    DONT_CHANGE     0x42

// OPT_STATUS value
# define    J_STATUS_PAUSED ON_OFF("off")
# define    J_STATUS_ACTIVE ON_OFF("on")

// Ciphers
# define CIPHER_ID_LOTUS_5      1
# define CIPHER_ID_RAWMD5       2
# define CIPHER_ID_MYSQL        3
# define CIPHER_ID_NT           4
# define CIPHER_ID_EGGDROP      5
# define CIPHER_ID_NSLDAP       6
# define CIPHER_ID_RAWSHA1      7
# define CIPHER_ID_MD5          8
# define CIPHER_ID_DES          9
# define CIPHER_ID_BSDI         10
# define CIPHER_ID_ORACLE	11
# define CIPHER_ID_MSCASH       12

# define    OPT_PRIOR_MIN       (-20)
# define    OPT_PRIOR_INIT      0
# define    OPT_PRIOR_MAX       (20)

/* space definition */
# define    LEN_SPACE_STR   6 
# define    DEFAULT_SPACE   '.'

# ifdef    NEED_G_SPACE
unsigned int    g_space = 0;
unsigned char   g_space_str[LEN_SPACE_STR] = "*+|=-.";
#  else
extern unsigned int    g_space; 
extern unsigned char    g_space_str[LEN_SPACE_STR];
# endif /* NEED_G_SPACE */

# define    NB_SPACE    2
# define    UP_SPACE_LEVEL      g_space+=NB_SPACE
# define    DOWN_SPACE_LEVEL    {g_space-=NB_SPACE; if(g_space <0) g_space = 0;}
# define    SPACE_RESET         g_space=0
# define TAB_WRITE do {\
int i = 0; \
char c = ' '; \
while (i++ < g_space) write(0, &c, 1); \
if ((g_space / 2) > LEN_SPACE_STR) \
    c = DEFAULT_SPACE; \
else \
    c = g_space_str[g_space/2]; \
write(0, &c, 1); \
} while (0)

# define NET_HEADER_SIZE    ( sizeof(char) + sizeof(char) + sizeof(uint32_t) )
# define NET_BUF_MAX        ( 1024 - NET_HEADER_SIZE )

# define XFREE(p)   do { \
    if (p == NULL) XPERROR("free", MEM_EXIT); \
    free(p); \
} while (0)

#  define XPERROR(msg,code)  do { \
    perror(msg); \
    exit(code); \
} while (0)

# define DEFAULT_PORT	9034   /* port we're listening on */
# define DEFAULT_HOST	"localhost"

#endif /* __BTB_H__ */
