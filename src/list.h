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

typedef int (*list_iterator_t)(void *, void *);
typedef int (*list_comp_t)(void *, void *);

struct list *list_create(void);
void list_destroy(struct list **, list_iterator_t, void *);
void list_iterate(struct list *, list_iterator_t, void *);
void *list_current(struct list *);
void *list_first(struct list *);
void *list_next(struct list *);
void *list_item(struct list *, size_t);
size_t list_count(struct list *);
void list_append(struct list *, void *);
void list_prepend(struct list *, void *);
void *list_locate(struct list *, void *, list_comp_t);
void *list_remove_current(struct list *);
void *list_remove(struct list *, void *, list_comp_t);
void list_append_list(struct list *, struct list *);

/* EOF */

