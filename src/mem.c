/*
   mem.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003 The Anubis Team.

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

void *
xmalloc(int n)
{
	void *p;

	p = (void *)malloc(n);
	if (p == 0) {
		anubis_error(HARD,
			_("malloc() failed. Cannot allocate enough memory."));
		quit(EXIT_FAILURE); /* force exit */
	}
	else
		memset(p, 0, n);
	return p;
}

void *
xrealloc(void *p, int n)
{
	if (p == 0)
		return xmalloc(n);

	p = (void *)realloc(p, n);
	if (p == 0) {
		anubis_error(HARD,
			_("realloc() failed. Cannot reallocate enough memory."));
		quit(EXIT_FAILURE); /* force exit */
	}
	return p;
}

char *
allocbuf(char *s, int maxsize)
{
	char *p = 0;
	int len;

	if (s == 0)
		return 0;

	len = strlen(s);
	if (maxsize != 0) {
		if (len > maxsize)
			len = maxsize;
	}
	len++;

	p = (char *)xmalloc(len);
	if (p) {
		strncpy(p, s, len - 1);
		return p;
	}
	else
		return 0;
}

#ifndef HAVE_STRDUP
char *
strdup(const char *s)
{
	char *p = 0;
	int len;

	if (s == 0)
		return 0;

	len = strlen(s);
	p = (char *)xmalloc(len + 1);
	strncpy(p, s, len);
	return p;
}
#endif /* not HAVE_STRDUP */

void
free_pptr(char **pptr)
{
	char **p = pptr;

	if (!pptr)
		return;
	while (*p) {
		free(*p);
		p++;
	}
	free(pptr);
	return;
}

/* EOF */

