/*
   setenv.c

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
   along with GNU Anubis; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

   GNU Anubis is released under the GPL with the additional exemption that
   compiling, linking, and/or using OpenSSL is allowed.
*/

#include "headers.h"

#ifdef HAVE_PUTENV
int
setenv(const char *name, const char *value, int overwrite)
{
	char *buf = 0;
	int rs = -1;

	if (overwrite == 0 && getenv(name) != 0)
		return 0;

	buf = xmalloc(strlen(name) + strlen(value) + 2);
	strcpy(buf, name);
	strcat(buf, "=");
	strcat(buf, value);

	rs = putenv(buf);
	return rs;
}
#endif /* HAVE_PUTENV */

/* EOF */

