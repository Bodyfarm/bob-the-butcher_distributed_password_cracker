/*
 * ressouce file for client connections
 */
 
#ifndef  __CLIENT_CONNECT_H__
# define __CLIENT_CONNECT_H__

int start_client_cnx(char * hostname, int port);
void start_working(void);
int client_password_found(char * username, char * ciphertext, char * cleartext);
void job_change_status(unsigned int status);
void	client_dispatch(void);
#endif
