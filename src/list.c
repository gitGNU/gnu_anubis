/*
   list.c

   This file is part of GNU Anubis.
   Copyright (C) 2003 The Anubis Team.

   GNU Anubis is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   GNU Anubis is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Anubis; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   GNU Anubis is released under the GPL with the additional exemption that
   compiling, linking, and/or using OpenSSL is allowed.
*/

#include "headers.h"

struct list_entry {
	struct list_entry *next;
	void *data;
};

struct list {
	size_t count;
	struct list_entry *head, *tail, *cur, *next;
};

struct list *
list_create()
{
	struct list *p = xmalloc(sizeof(*p));
	p->head = p->tail = p->cur = p->next = NULL;
	return p;
}

void
list_destroy(struct list **plist, list_iterator_t user_free, void *data)
{
	struct list_entry *p;

	if (!*plist)
		return;
	
	p = (*plist)->head;
	while (p) {
		struct list_entry *next = p->next;
		if (user_free)
			user_free(p->data, data);
		free(p);
		p = next;
	}
	free(*plist);
	*plist = NULL;
}

void
list_iterate(struct list *list, list_iterator_t itr, void *data)
{
	if (!list)
		return;
	for (list->cur = list->head; list->cur; list->cur = list->next) {
		list->next = list->cur->next;
		itr(list->cur, data);
	}
}

void *
list_current(struct list *list)
{
	if (!list)
		return NULL;
	return list->cur ? list->cur->data : NULL;
}

void *
list_first(struct list *list)
{
	if (!list)
		return NULL;
	list->cur = list->head;
	if (list->cur)
		list->next = list->cur->next;
	return list_current(list);
}

void *
list_next(struct list *list)
{
	if (!list || !list->next)
		return NULL;
	list->cur = list->next;
	if (list->cur)
		list->next = list->cur->next;
	return list_current(list);
}	

size_t
list_count(struct list *list)
{
	if (!list)
		return 0;
	return list->count;
}

void
list_append(struct list *list, void *data)
{
	struct list_entry *ep;

	if (!list)
		return;
	ep = xmalloc(sizeof(*ep));
	ep->next = NULL;
	ep->data = data;
	if (list->tail)
		list->tail->next = ep;
	else
		list->head = ep;
	list->tail = ep;
}

void
list_prepend(struct list *list, void *data)
{
	struct list_entry *ep;

	if (!list)
		return;
	ep = xmalloc(sizeof(*ep));
	ep->data = data;
	ep->next = list->head;
	list->head = ep;
	if (!list->tail)
		list->tail = list->head;
	list->count++;
}

static int
cmp_ptr(void *a, void *b)
{
	return a == b;
}

void *
list_locate(struct list *list, void *data, list_comp_t cmp)
{
	if (!list)
		return NULL;
	if (!cmp)
		cmp = cmp_ptr;
	for (list->cur = list->head; list->cur; list->cur = list->cur->next)
		if (cmp(list->cur->data, data) == 0)
			break;
	return list_current(list);
}
	
static struct list_entry *
_list_remove_item(struct list *list, struct list_entry *item)
{
	struct list_entry *p = NULL;
	if (item == list->head) {
		list->head = list->head->next;
		if (!list->head)
			list->tail = NULL;
	} else {
		for (p = list->head; p && p->next != item; p = p->next) 
			;
		p->next = item->next;
		if (item == list->tail)
			list->tail = p;
	}

	free(item);
	list->count--;
	return p;
}

void *
list_remove_current(struct list *list)
{
	struct list_entry *cur;
	void *data;
	
	if (!list || !list->cur)
		return NULL;

	cur = list->cur;
	data = cur->data;
	if (list->cur == list->head) {
		list->cur = cur->next;
		_list_remove_item(list, cur);
	} else
		list->cur = _list_remove_item(list, cur);
	return data;
}
	
void *
list_remove(struct list *list, void *data, list_comp_t cmp)
{
	struct list_entry *p;

	if (!list)
		return NULL;
	if (!list->head)
		return NULL;
	if (!cmp)
		cmp = cmp_ptr;
	for (p = list->head; p; p = p->next)
		if (cmp(p->data, data) == 0)
			break;
	if (p == list->cur)
		return list_remove_current(list);
	else
		_list_remove_item(list, p);
	return data;
}

void
list_append_list(struct list *a, struct list *b)
{
	if (a->tail) {
		a->tail->next = b->head;
		a->tail = b->tail;
	} else {
		a->head = b->head;
		a->tail = b->tail;
	}
	a->count += b->count;

	b->head = b->tail = b->cur = NULL;
}

/* EOF */

