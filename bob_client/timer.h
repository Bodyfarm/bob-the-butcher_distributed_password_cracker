#ifndef  __TIMER_H_
# define  __TIMER_H_
void start_chrono(void);
void start_timer(unsigned int time);
void stop_chrono(uint64_t nb, unsigned int charset);
void signal_init(void);
extern int timer_active;
#endif
