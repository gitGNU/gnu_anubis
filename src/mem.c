/*
   mem.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003, 2007 The Anubis Team.

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

void (*memory_error) (const char *message);

void *
xmalloc (int n)
{
  void *p;

  p = malloc (n);
  if (p == NULL)
    {
      memory_error (_("malloc() failed. Cannot allocate enough memory."));
    }
  memset (p, 0, n);
  return p;
}

void *
xrealloc (void *p, int n)
{
  if (p == NULL)
    return xmalloc (n);

  p = realloc (p, n);
  if (p == NULL)
    {
      memory_error (_("realloc() failed. Cannot reallocate enough memory."));
    }
  return p;
}

char *
allocbuf (char *s, int maxsize)
{
  char *p = NULL;
  int len;

  if (s == NULL)
    return NULL;

  len = strlen (s);
  if (maxsize != 0)
    {
      if (len > maxsize)
	len = maxsize;
    }
  len++;

  p = (char *) xmalloc (len);
  if (p)
    {
      strncpy (p, s, len - 1);
      return p;
    }
  else
    return NULL;
}

#ifndef HAVE_STRDUP
char *
strdup (const char *s)
{
  char *p = NULL;
  int len;

  if (s == NULL)
    return NULL;

  len = strlen (s);
  p = (char *) xmalloc (len + 1);
  strncpy (p, s, len);
  return p;
}
#endif /* not HAVE_STRDUP */

/* EOF */
