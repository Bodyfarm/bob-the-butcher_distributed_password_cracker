#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

//#include "btb.h"
#define NEED_CIPHER_STRUCT  1
#include "bob_admin.h"
#include "network.h"
# define NEED_OPT_STRUCT    1
#include "job.h"

//cygwin stupid fix
#ifndef MSG_WAITALL
# define MSG_WAITALL 0x100
#endif

static TAILQ_HEAD(h_list_pwd, s_list_pwd)	l_pwd;

void	newjob_help(void)
{
	fprintf(stderr, "Usage command: newjob FILE ALGO\n");
	exit (1);
}

int	read_pwd(FILE * fichier)
{
	int	res = 0;
	char	buf[BUFSIZE];
	struct s_list_pwd	*pwd = NULL;

	//buffer overflow possible ...
	while(fgets(buf, BUFSIZE, fichier) && (res<MAX_PWD_LIST))
	{
		pwd = (struct s_list_pwd *) calloc(1, sizeof(struct s_list_pwd));
		sscanf(buf, "%[^:]:%[^:\n]", (char *) &pwd->pwd.username, (char *) &pwd->pwd.pwd);
		TAILQ_INSERT_TAIL(&l_pwd, pwd, next);
		res++;
	}

	if(res == MAX_PWD_LIST)
		fprintf(stderr, "Too many passwords, sending %d\n", res);

	return(res);
}

uint32_t    get_cipher(const char *str)
{
	int     c = 0;

	printf("cipher = %s\n", str); 
	for ( c = 0; 
			( c < CIPHER_STRUCT_SIZE ) 
			&& (scipher[c].label!=NULL)
			&& (strncmp(str, scipher[c].label, strlen(scipher[c].label)) != 0);
			c++ )
		;
	return(scipher[c].id);
}

void	show_cipher(void)
{
	int c = 0;

	printf("Valid ciphers are:\n");
	for ( c = 0; 
			( c < CIPHER_STRUCT_SIZE ) 
			&& (scipher[c].label!=NULL)
			; c++)
		printf(" * %s (%d)\n", scipher[c].label, scipher[c].id);
}


char        *get_cipher_str(uint32_t id)
{
	int i = 0;
	
	while(scipher[i].label != NULL)
	{
		if (scipher[i].id == id)
			return(scipher[i].label);
		i++;
	}
	return("Unknown");
}

void	newjob(int c, char **v, struct s_admin_opt *opt)
{
#ifdef DEBUG
	printf(" * %s [c=%d]\n", __func__, c);
#endif
	struct s_network	*net = NULL;
	struct s_list_pwd	*pwd = NULL;
	int			fd = 0;
	FILE	*		fichier = NULL;
	int			nb_pwd = 0;
	uint32_t			job_id = 0;
	int           i = 0;
	uint32_t	cipher;
	struct s_pwd tmppwd;

	if (c != 2)
		newjob_help();

	// Add job

	cipher = get_cipher(*(v + 1));
	if(!cipher)
	{
		printf(" * bad cipher name!\n");
		show_cipher();
		exit(-1);
	}


	fd = net_connect(opt->host, opt->port);
	net = net_init(CLIENT_ADMIN, CMD_NEWJOB);
	str_append_netstring(net->str, opt->username, strlen(opt->username));
	str_append_int32(net->str, cipher);
	net_flush(fd, net);

	recv(fd, &job_id, sizeof(uint32_t), MSG_WAITALL);
	net_crypt(net, &job_id, sizeof(uint32_t));
	job_id = ntohl(job_id);
	printf(" * Job added with id=%d\n", job_id);
	net_close(fd);

	// Add pwd list
	fichier = fopen( *v, "r");
	if (fichier == NULL)
		XPERROR("open", USAGE_EXIT);
	TAILQ_INIT(&l_pwd);
	nb_pwd = read_pwd(fichier);

	fd = net_connect(opt->host, opt->port);
	net = net_init(CLIENT_ADMIN, CMD_ADDPWD);
	str_append_int32(net->str, job_id);
	str_append_int32(net->str, nb_pwd);
	net_flush(fd, net);

	/* FIXME fix me, do not send structs on the net ! */
	TAILQ_FOREACH(pwd, &l_pwd, next)
	{
		int	nsize = 0;
		
		memcpy(&tmppwd, &(pwd->pwd), sizeof(struct s_pwd));
		net_crypt(net, &tmppwd, sizeof(struct s_pwd));
		nsize = write(fd, &tmppwd, sizeof(struct s_pwd));
		i++;
		if (nsize != sizeof(struct s_pwd))
			break;
	}
	printf(" * %d passwd added to Job id=%d\n", i, job_id);
	net_close(fd);
	fclose(fichier);
}

void	status_help(void)
{
	fprintf(stderr, "Usage command: status\n");
	exit(1);
}

void    print_uptime(time_t uptime)
{
	uint32_t day = 0;
	uint32_t hour = 0;
	uint32_t min = 0;
	uint32_t sec = 0;

	sec  = uptime % 60; uptime /= 60;
	min  = uptime % 60; uptime /= 60;
	hour = uptime % 24; uptime /= 24;
	day  = uptime ;
	printf(" * Uptime: %d day(s), %d hour(s), %d min(s), %d sec(s)\n", day, hour, min, sec);

}

void	status(int c, char **v, struct s_admin_opt *opt)
{
#ifdef DEBUG
	printf(" * %s [c=%d]\n", __func__, c);
#endif
	struct s_network *net = NULL;
	int fd = 0;
	int nb_job = 0;
	int nb_clients = 0;
	time_t uptime = 0;
	uint32_t x;
	struct s_rw * rw;
	unsigned char * buf;

	if (c != 0)
		status_help();
	fd  = net_connect(opt->host, opt->port);
	net = net_init(CLIENT_ADMIN, CMD_STATUS);
	net_flush(fd, net);

	recv(fd, &x, 4, MSG_WAITALL);
	x = ntohl(x);

	recv(fd, net->seed, CRYPTO_SEED_SIZE, MSG_WAITALL);

	//net_crypto_init_state(net);

#ifdef DEBUG
	TAB_WRITE;
	printf(" packet size=0x%x\n", x);
#endif

	buf = malloc(x);
	if(!buf)
		return;

	rw = rw_init(buf, recv(fd, buf, x, MSG_WAITALL)); /* hum !! */
	net_crypt(net, buf, x);

	nb_job = read_uint32_t(rw);
	nb_clients = read_uint32_t(rw);
	uptime = read_uint32_t(rw);
	printf(" * Number of jobs: %d\n", nb_job);
	printf(" * Number of clients: %d\n", nb_clients);
	print_uptime(uptime);
	while(nb_job--)
	{
		unsigned char * username;
		uint32_t id;
		uint32_t status;
		uint32_t cipher;
		uint32_t prior;
		uint32_t nb_found_pwd;
		uint32_t nb_pwd;
		uint32_t data_start;
		uint32_t crack_method;

		id = read_uint32_t(rw);
		data_start = read_uint32_t(rw);
		status = read_uint32_t(rw);
		prior = read_uint32_t(rw);
		cipher = read_uint32_t(rw);
		crack_method = read_uint32_t(rw);
		nb_pwd = read_uint32_t(rw);
		nb_found_pwd = read_uint32_t(rw);
		username = read_netstring(rw);
		printf("   | [id=%.2d] [u=%s] [s=%s] [c=%s] [pwd=%d/%d]\n", 
				id, 
				username,
				ON_OFF_STR(status),
				get_cipher_str(cipher),
				nb_found_pwd,
				nb_pwd);
		if(username)
			free(username);
	}
	net_close(fd);
}

void	deljob_help(void)
{
	fprintf(stderr, "Usage command: deljob ID\n");
	exit(1);
}

void	deljob(int c, char **v, struct s_admin_opt *opt)
{
#ifdef DEBUG
	printf(" * %s [c=%d]\n", __func__, c);
#endif
	struct s_network	*net = NULL;
	int			fd = 0;

	if (c < 1)
		deljob_help();
	fd = net_connect(opt->host, opt->port);
	net = net_init(CLIENT_ADMIN, CMD_DELJOB);
	str_append_int32(net->str, atoi(*(v)));
	net_flush(fd, net);
	net_close(fd);
}

void    setopt_help(void)
{
	fprintf(stderr, "setopt JOBID opt=value ...\n");
	exit(1);
}

/*
int     setopt_struct(struct s_opt *setopt, char *str)
{
	int     len = 0;
	char    *value = NULL;


	if ( !str )
		return(0);
	len    = strlen(str);
	value = (char *) memchr(str, ASSIGN_OPT, len);
	*value = 0; 
	if ( (value == NULL) || (*++value == 0) )
		return(1);

	if ( strncmp(L_OPT_STATUS, str, strlen(L_OPT_STATUS) ) == 0)  
	{
		setopt->status = ON_OFF(value);
#ifdef DEBUG
		printf("  - setopt status=%s\n", ON_OFF_STR(setopt->status));
#endif
		return(0);
	}
	if ( strncmp(L_OPT_PRIOR, str, strlen(L_OPT_PRIOR) ) == 0)
	{
		setopt->prior = htonl(atoi(value));
		if ( (setopt->prior < OPT_PRIOR_MIN) || (setopt->prior > OPT_PRIOR_MAX))
		{
			fprintf(stderr, "priority must be in range [%d;%d]\n", 
					OPT_PRIOR_MIN, OPT_PRIOR_MAX);
			setopt_help();
		}
#ifdef DEBUG
		printf("  - setopt prior=%d\n", htonl(setopt->prior));
#endif
		return(0);
	}
	return(1);
}
*/
void    setopt(int c, char **v, struct s_admin_opt *opt)
{
#ifdef DEBUG
	printf(" * %s [c=%d]\n", __func__, c);
#endif
	struct s_network   *net = NULL;
	struct s_opt       *setopt = NULL;
	int                fd = 0;

	if (c < 2)
		setopt_help();
	fd = net_connect(opt->host, opt->port);
	net = net_init(CLIENT_ADMIN, CMD_SETOPT);
	/* FIXME */
	/*
	setopt = (struct s_opt *) &(net->buf);
	setopt->status=DONT_CHANGE;
	setopt->prior = htonl(DONT_CHANGE);
	setopt->id = htonl(atoi(*v));
	while (*v++)
		if (setopt_struct(setopt, *v) != 0)
			setopt_help();
	net->psize += sizeof(struct s_opt); */
	net_flush(fd, net);
	net_close(fd);
}

void    getinf_help(void)
{
	fprintf(stderr, "Usage command: getinf JOBID\n");
	exit(1);
}

//TODO
unsigned char * get_pwd_ascii(uint64_t nb)
{
	static unsigned char ret[255];
	unsigned int i = 0;

	memset(ret, 0, sizeof(ret));

	return ret;
}

void    getinf(int c, char **v, struct s_admin_opt *opt)
{
#ifdef DEBUG
	printf(" * %s [c=%d]\n", __func__, c);
#endif
	struct s_network  *net = NULL;
	int               fd = 0;
	struct tm * timestruct;
	unsigned char s[500];
	unsigned char unit = ' ';
	uint64_t processed_uptime;
	uint32_t psize;
	unsigned char * buf;
	struct s_rw * rw;

	
	uint32_t id;
	unsigned char * username;
	uint32_t date_start;
	uint32_t status;
	uint32_t prior;
	uint32_t cipher;
	uint32_t nb_pwd;
	uint32_t nb_found_pwd;
	uint64_t pspace;
	uint32_t uptime;

	if (c < 1)
		getinf_help();

	fd = net_connect(opt->host, opt->port);
	net = net_init(CLIENT_ADMIN, CMD_GETINF);
	str_append_int32(net->str, atoi(*v));
	dump_stuff(STRING(net->str), STRLEN(net->str));
	net_flush(fd, net);

	if( recv(fd, &psize, 4, MSG_WAITALL) != 4 )
	{
#ifdef DEBUG
		TAB_WRITE;
		printf(" glah glah could not read!\n");
#endif
		return;
	}

	psize = ntohl(psize);
	
	recv(fd, net->seed, CRYPTO_SEED_SIZE, MSG_WAITALL);

	buf = malloc(psize);
	if(!buf)
		return;

	rw = rw_init(buf, recv(fd, buf, psize, MSG_WAITALL));

	net_crypt(net, buf, psize);
	
	id = read_uint32_t(rw);
	username = read_netstring(rw);
	date_start = read_uint32_t(rw);
	status = read_uint32_t(rw);
	prior = read_uint32_t(rw);
	cipher = read_uint32_t(rw);
	nb_pwd = read_uint32_t(rw);
	nb_found_pwd = read_uint32_t(rw);
	pspace = read_uint64_t(rw);
	printf("pspace %0.8llx\n", pspace);
	uptime = read_uint32_t(rw);
	
	printf("[Jobid=%.2d]\t[user=%s]\n", id, username);
	printf("[status=%s]\t[prior=%d]\n", ON_OFF_STR(status), prior);
	printf("[cipher=%s]\t[pwd=%d/%d]\n",  get_cipher_str(cipher), nb_found_pwd, nb_pwd);
	timestruct = gmtime(&date_start);
	
	strftime(s, 500, "%F %T", timestruct);

	print_uptime(uptime);

	processed_uptime = pspace / uptime;
	
	while(processed_uptime>100000)
	{
		processed_uptime = processed_uptime/1000;
		switch(unit)
		{
			case ' ': unit = 'K'; break;
			case 'K': unit = 'M'; break;
			case 'M': unit = 'G'; break;
			default: unit = '?'; break;
		}
	}
	printf("Keys processed : %llu in %d secs (%lld %ck/s) (Approx to %s)\n", pspace, uptime, processed_uptime, unit, get_pwd_ascii(pspace) );
	printf("[start=%s]\nPasswords found:\n", s);
	
	while(nb_found_pwd--)
	{
		unsigned char * username;
		unsigned char * pwd;
		unsigned char * cleartext;

		username = read_netstring(rw);
		pwd = read_netstring(rw);
		cleartext = read_netstring(rw);

		printf("%s:%s:%s\n", username, pwd, cleartext);

		if(cleartext) free(cleartext);
		if(pwd) free(pwd);
		if(username) free(username);
	}

	net_close(fd);
} 
