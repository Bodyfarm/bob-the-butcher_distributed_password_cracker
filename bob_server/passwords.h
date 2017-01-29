#ifndef   __PASSWORDS_H__
# define  __PASSWORDS_H__

typedef struct  s_passwd
{
    int                     num;
    char                    *username;
    char                    *password;
    char		    *cleartext;
    unsigned int            cipher;
    TAILQ_ENTRY(s_passwd)   next;
}               t_passwd;

TAILQ_HEAD(hpasswd, s_passwd);

struct s_passwd *add_passwd(struct hpasswd *, char *, char *, unsigned int);
void             remove_all_passwds(struct hpasswd *);
void password_found(void *, char * username, char * pwd, char * cleartext);
void show_passwords(struct hpasswd * hpasswd);

#endif /* __PASSWORDS_H__ */
