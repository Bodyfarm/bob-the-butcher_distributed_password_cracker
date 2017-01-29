#ifndef  __LOG_H__
# define __LOG_H__

void log_init(void);
void normal_log(char * s);
void verbose_log(char * s);
void debug_log(char * s);
void error_log(char * s);
void log_close(void);

#endif
