#include <unistd.h>
#include <string.h>

#define USER_HOST_SEP	'@'
#define BUFSIZE		1024

char	*get_full_login(char *login)
{
  char	*username = NULL;
  char	hostname[BUFSIZE];
  char	*tmp = (char *)&hostname;
  
  username = (login != NULL) ? login : getlogin();
  if(username == NULL) /* FIXME */
	  return "blahblah";
  memcpy(tmp, username, strlen(username));
  tmp   += strlen(username);
  *tmp++ = USER_HOST_SEP;
  gethostname(tmp, BUFSIZE - (strlen(username) + 1));
  while (*tmp)
    tmp++;
  *tmp++ = '.';
  getdomainname(tmp, BUFSIZE + ((char *) &hostname -(char *) tmp));
  printf(" login@hostname = %s\n", hostname);
  return(strdup(hostname));
}

