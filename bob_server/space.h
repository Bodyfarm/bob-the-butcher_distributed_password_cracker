#ifndef   __SPACE_H__
# define  __SPACE_H__

enum status_space { UNDEF, DOING, DONE, ABORTED };

typedef struct  s_space
{
	uint64_t start;
	uint64_t end;
	enum status_space status;

	TAILQ_ENTRY (s_space)    next;
}	t_space;

typedef struct s_processed_space
{
	uint64_t done;
	uint64_t other;
} t_processed_space;

TAILQ_HEAD(h_space, s_space);

/* finds a suitable space for work */
struct s_space * return_space(struct h_space * hspace, uint64_t interval_size);

/* change a space status, usually when a client has aborted or completed computation */
int change_space_status(struct h_space * hspace, struct s_space * space, enum status_space status);

/* adds a space at the end of the queue, used by the file loader */
struct s_space * enqueue_space(struct h_space * hspace, uint64_t start, uint64_t end, enum status_space status);

/* returns the amount of keyspace processed on a particular job */
int processed_space(struct h_space * hspace, struct s_processed_space * processed_space);

#endif
