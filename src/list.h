/*
   list.h

   This file is part of GNU Anubis.
   Copyright (C) 2003-2014 The Anubis Team.

   GNU Anubis is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   GNU Anubis is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.
*/

typedef struct list *ANUBIS_LIST;
typedef struct iterator *ITERATOR;

typedef int (*list_iterator_t) (void *, void *);
typedef int (*list_comp_t) (void *, void *);

ANUBIS_LIST list_create (void);
void list_destroy (ANUBIS_LIST *, list_iterator_t, void *);
void list_iterate (ANUBIS_LIST, list_iterator_t, void *);
void *list_item (ANUBIS_LIST, size_t);
void *list_head_item (struct list *list);
void *list_tail_item (struct list *list);
size_t list_count (ANUBIS_LIST);
void list_append (ANUBIS_LIST, void *);
void list_prepend (ANUBIS_LIST, void *);
void *list_locate (ANUBIS_LIST, void *, list_comp_t);
void *list_remove (ANUBIS_LIST, void *, list_comp_t);
ANUBIS_LIST list_intersect (ANUBIS_LIST  a, ANUBIS_LIST  b,
			     list_comp_t cmp);

void *iterator_current (ITERATOR);
ITERATOR iterator_create (ANUBIS_LIST);
void iterator_destroy (ITERATOR *);
void *iterator_first (ITERATOR);
void *iterator_next (ITERATOR);

/* EOF */
