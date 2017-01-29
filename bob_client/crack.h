#ifndef  __CRACK_H__
# define __CRACK_H__

/* these functions crack (heh) */
void do_crack(unsigned int type, struct s_format * fmt, uint64_t start, uint64_t end);
void stupid_brute_force(struct s_format * fmt, uint64_t start, uint64_t end);

#endif
