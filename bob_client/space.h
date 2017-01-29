/* structure liée à la gestion de l'espace */


#ifndef  __SPACE_H__
# define __SPACE_H__
enum status_space { UNDEF, DOING, DONE };

struct s_space
{
	struct s_space * next;
	uint64_t start;
	uint64_t end;
	unsigned int type; /* bf, dico, ... */
	enum status_space status; /* fait / en cours */
};

struct s_space * 		space_new(void);
void 								space_delete_all(struct s_space * space);
struct s_space * 		space_insert(struct s_space * space, uint64_t size, unsigned int type, enum status_space status);
int 								space_delete(struct s_space * * space_list, struct s_space * space_to_del);
void 								space_blend(struct s_space * space);
struct s_space * 		space_add(struct s_space * space, uint64_t start, uint64_t end, unsigned int type, enum status_space status);
void 								space_test(void);
void 								space_list(struct s_space *);

#endif /* __SPACE_H__ */
