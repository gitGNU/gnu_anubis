/*
   list.h

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

typedef struct list LIST;
typedef struct iterator ITERATOR;

typedef int (*list_iterator_t)(void *, void *);
typedef int (*list_comp_t)(void *, void *);

LIST *list_create();
void list_destroy(LIST **list, list_iterator_t free, void *data);
void list_iterate(LIST *list, list_iterator_t itr, void *data);
void *list_item(LIST *list, size_t n);
size_t list_count(LIST *list);
void list_append(LIST *list, void *data);
void list_prepend(LIST *list, void *data);
void *list_locate(LIST *list, void *data, list_comp_t cmp);
void *list_remove(LIST *list, void *data, list_comp_t cmp);

void *iterator_current(ITERATOR *ip);
ITERATOR *iterator_create(LIST *list);
void iterator_destroy(ITERATOR **ip);
void *iterator_first(ITERATOR *ip);
void *iterator_next(ITERATOR *ip);

/* EOF */

