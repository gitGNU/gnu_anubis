/*
   list.c

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

#include "headers.h"

struct list_entry
{
  struct list_entry *next;
  void *data;
};

struct list
{
  size_t count;
  struct list_entry *head, *tail;
  struct iterator *itr;
};

struct iterator
{
  struct iterator *next;
  ANUBIS_LIST list;
  struct list_entry *cur;
  int advanced;
};

struct list *
list_create ()
{
  struct list *p = xmalloc (sizeof (*p));
  p->head = p->tail = NULL;
  p->itr = NULL;
  p->count = 0;
  return p;
}

void
list_destroy (struct list **plist, list_iterator_t user_free, void *data)
{
  struct list_entry *p;

  if (!*plist)
    return;

  p = (*plist)->head;
  while (p)
    {
      struct list_entry *next = p->next;
      if (user_free)
	user_free (p->data, data);
      xfree (p);
      p = next;
    }
  xfree (*plist);		/* zeroes *plist as well */
}

void *
iterator_current (ITERATOR ip)
{
  if (!ip)
    return NULL;
  return ip->cur ? ip->cur->data : NULL;
}

static void
_iterator_attach (ANUBIS_LIST list, ITERATOR itr)
{
  itr->list = list;
  itr->cur = NULL;
  itr->next = list->itr;
  itr->advanced = 0;
  list->itr = itr;
}

static int
_iterator_detach (ITERATOR ip)
{
  ITERATOR itr, prev;

  if (!ip)
    return 1;
  for (itr = ip->list->itr, prev = NULL; itr; prev = itr, itr = itr->next)
    if (ip == itr)
      break;
  if (itr)
    {
      if (prev)
	prev->next = itr->next;
      else
	itr->list->itr = itr->next;
      return 0;
    }
  return 1;
}
     

ITERATOR 
iterator_create (ANUBIS_LIST list)
{
  ITERATOR itr;

  if (!list)
    return NULL;
  itr = xzalloc (sizeof (*itr));
  _iterator_attach (list, itr);
  return itr;
}

void
iterator_destroy (ITERATOR *ip)
{
  if (!ip || !*ip)
    return;
  if (_iterator_detach (*ip) == 0)
    {
      xfree (*ip);
      *ip = NULL;
    }
}

void *
iterator_first (ITERATOR ip)
{
  if (!ip)
    return NULL;
  ip->cur = ip->list->head;
  ip->advanced = 0;
  return iterator_current (ip);
}

void *
iterator_next (ITERATOR ip)
{
  if (!ip || !ip->cur)
    return NULL;
  if (!ip->advanced)
    ip->cur = ip->cur->next;
  ip->advanced = 0;
  return iterator_current (ip);
}

static void
_iterator_advance (ITERATOR ip, struct list_entry *e)
{
  for (; ip; ip = ip->next)
    {
      if (ip->cur == e)
	{
	  ip->cur = e->next;
	  ip->advanced++;
	}
    }
}

void *
list_item (struct list *list, size_t n)
{
  struct list_entry *p;
  if (n > list->count)
    return NULL;
  for (p = list->head; n > 0 && p; p = p->next, n--)
    ;
  return p->data;
}

void *
list_head_item (struct list *list)
{
  struct list_entry *p = list->head;
  return p ? p->data : NULL;
}

void *
list_tail_item (struct list *list)
{
  struct list_entry *p = list->tail;
  return p ? p->data : NULL;
}

size_t
list_count (struct list * list)
{
  if (!list)
    return 0;
  return list->count;
}

void
list_append (struct list *list, void *data)
{
  struct list_entry *ep;

  if (!list)
    return;
  ep = xmalloc (sizeof (*ep));
  ep->next = NULL;
  ep->data = data;
  if (list->tail)
    list->tail->next = ep;
  else
    list->head = ep;
  list->tail = ep;
  list->count++;
}

void
list_prepend (struct list *list, void *data)
{
  struct list_entry *ep;

  if (!list)
    return;
  ep = xmalloc (sizeof (*ep));
  ep->data = data;
  ep->next = list->head;
  list->head = ep;
  if (!list->tail)
    list->tail = list->head;
  list->count++;
}

static int
cmp_ptr (void *a, void *b)
{
  return a != b;
}

void *
list_remove (struct list *list, void *data, list_comp_t cmp)
{
  struct list_entry *p, *prev;

  if (!list)
    return NULL;
  if (!list->head)
    return NULL;
  if (!cmp)
    cmp = cmp_ptr;
  for (p = list->head, prev = NULL; p; prev = p, p = p->next)
    if (cmp (p->data, data) == 0)
      break;

  if (!p)
    return 0;
  _iterator_advance (list->itr, p);
  if (p == list->head)
    {
      list->head = list->head->next;
      if (!list->head)
	list->tail = NULL;
    }
  else
    prev->next = p->next;

  if (p == list->tail)
    list->tail = prev;

  data = p->data; /* make sure we return actual data, not the one supplied
		     at the invocation */
  xfree (p);
  list->count--;

  return data;
}

void
list_iterate (struct list *list, list_iterator_t func, void *data)
{
  struct iterator itr;
  void *p;

  if (!list)
    return;
  _iterator_attach (list, &itr);
  for (p = iterator_first (&itr); p; p = iterator_next (&itr))
    {
      if (func (p, data))
	break;
    }
  _iterator_detach (&itr);
}

void *
list_locate (struct list *list, void *data, list_comp_t cmp)
{
  struct list_entry *cur;
  if (!list)
    return NULL;
  if (!cmp)
    cmp = cmp_ptr;
  for (cur = list->head; cur; cur = cur->next)
    if (cmp (cur->data, data) == 0)
      break;
  return cur ? cur->data : NULL;
}

/* Computes an intersection of the two lists. The resulting list
   contains elements from the list A that are also encountered
   in the list B. Elements are compared using function CMP.
   The resulting list preserves the ordering of A. */
ANUBIS_LIST 
list_intersect (ANUBIS_LIST a, ANUBIS_LIST b, list_comp_t cmp)
{
  ANUBIS_LIST res;
  ITERATOR itr = iterator_create (a);
  void *p;

  if (!itr)
    return NULL;
  res = list_create ();
  for (p = iterator_first (itr); p; p = iterator_next (itr))
    {
      if (list_locate (b, p, cmp))
	list_append (res, p);
    }
  iterator_destroy (&itr);
  return res;
}

/* EOF */
