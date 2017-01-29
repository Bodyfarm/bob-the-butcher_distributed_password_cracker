#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bob_server.h"

void show_space(struct h_space * hspace)
{
	struct s_space * curspace;

	TAILQ_FOREACH_REVERSE(curspace, hspace, next, h_space)
	{
#ifdef DEBUG
		TAB_WRITE;
#endif
		printf(" %lld -> %lld = ", curspace->start, curspace->end);
		switch(curspace->status)
		{
			case DONE: printf("DONE"); break;
			case UNDEF: printf("UNDEF"); break;
			case DOING: printf("DOING"); break;
			case ABORTED: printf("ABORTED"); break;
			default: printf("?? %d", curspace->status); break;
		}
		printf("\n");
	}
}

struct s_space * return_space(struct h_space * hspace, uint64_t interval_size)
{
	struct s_space * search_space;
	struct s_space * new_space;

	TAILQ_FOREACH_REVERSE(search_space, hspace, next, h_space)
	{
		if(search_space->status == ABORTED)
			break;
	}
	if(search_space == NULL)
	{
		new_space = (struct s_space *) calloc(1, sizeof(struct s_space));
		search_space = TAILQ_LAST(hspace, h_space);
		if(search_space == NULL)
		{
			new_space->start = 0;
		}
		else
		{
			new_space->start = search_space->end;
		}
		new_space->end = new_space->start + interval_size;
		TAILQ_INSERT_TAIL(hspace, new_space, next);
	}
	else
		new_space = search_space;

	new_space->status = DOING;

	show_space(hspace);

	return new_space;
}

struct s_space * enqueue_space(struct h_space * hspace, uint64_t start, uint64_t end, enum status_space status)
{
#ifdef DEBUG
	TAB_WRITE;
	printf(" %s %lld->%lld (%d)\n", __func__, start, end, status);
#endif
	struct s_space * new_space;
	
	new_space = (struct s_space *) calloc(1, sizeof(struct s_space));
	new_space->start = start;
	new_space->end = end;
	new_space->status = status;

	TAILQ_INSERT_TAIL(hspace, new_space, next);

	return new_space;
}

int change_space_status(struct h_space * hspace, struct s_space * space, enum status_space status)
{
	struct s_space * prevspace;
	space->status = status;
	/* merging now */
	while( 
			(prevspace = TAILQ_PREV(space, h_space, next)) && 
			(prevspace->status == space->status) && 
			(prevspace->status == DONE) && 
			(prevspace->end == space->start))
	{
		space->start = prevspace->start;
		TAILQ_REMOVE(hspace, prevspace, next);
		XFREE(prevspace);
	}
	return 1;
}

int processed_space(struct h_space * hspace, struct s_processed_space * processed_space)
{
	struct s_space * curspace;

	processed_space->done = 0;
	processed_space->other = 0;

	TAILQ_FOREACH(curspace, hspace, next)
	{
		switch(curspace->status)
		{
			case DONE:
				processed_space->done += curspace->end - curspace->start + 1;
				break;
			default:
				processed_space->other += curspace->end - curspace->start + 1;
				break;
		}
	}

	return 1;
}
