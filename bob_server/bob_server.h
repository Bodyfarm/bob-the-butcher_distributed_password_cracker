#ifndef   __BOB_SERVER_H__
# define  __BOB_SERVER_H__

# include <unistd.h>

# include "queue.h"
# include "config_types.h"
# include "btb.h"
# include "btb-data.h"
# include "space.h"
# include "compat.h"
# include "uptime.h"
# include "config.h"
# include "params.h"
# include "passwords.h"
# include "jobs.h"
# include "file.h"
# include "signal.h"
# include "network.h"
# include "array_client.h"
# include "data.h"
# include "clients.h"

# define DEFAULT_FILENAME   "bob.state"
# define MAX_IDLE_TIME 3600 /* 1h */

//wtf ?
# ifndef SIGINT
# define SIGINT 2
# endif
# ifndef SIGTERM
# define SIGTERM 15
# endif
# ifndef SIGPIPE
# define SIGPIPE 13
# endif

#endif /* __BOB_SERVER_H__ */
