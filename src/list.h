/* list.c */
struct list;

typedef int (*list_iterator_t)(void *item, void *data);
typedef int (*list_comp_t)(void *, void *);

struct list *list_create();
void list_destroy(struct list **list, list_iterator_t free, void *data);
void list_iterate(struct list *list, list_iterator_t itr, void *data);
void *list_current(struct list *list);
void *list_first();
void *list_next();
size_t list_count(struct list *list);
void list_append(struct list *list, void *data);
void list_prepend(struct list *list, void *data);
void *list_locate(struct list *list, void *data, list_comp_t cmp);
void *list_remove_current(struct list *list);
void *list_remove(struct list *list, void *data, list_comp_t cmp);
void list_append_list(struct list *a, struct list *b);
