/*
   map.c

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
#include "extern.h"

/***************************
 The translation map parser
****************************/

void
parse_transmap(int *cs, char *extuser, char *extaddr, char *dst, int size)
{
	char *p = 0;
	char *ptr1 = 0;
	char *ptr2 = 0;
	char a1[65];
	char a2[65];
	char translate[65];
	char into[65];
	char user[65];
	char address[65];
	char oneline[LINEBUFFER+1];
	int cu = 0; /* check a user name */
	unsigned long inaddr;
	struct sockaddr_in addr;
	struct list *p1;
	struct list *p2;

	memset(&addr, 0, sizeof(addr));
	*cs = -1; /* failed by default: unmatched */

	if (session.transmap == NULL)
		return;
	else
		p1 = session.transmap;

	safe_strcpy(a1, extaddr);
	do
	{
		p2 = p1->next;
		strncpy(oneline, p1->line, LINEBUFFER);
		free(p1->line);
		free(p1);

		if (regex_match("^[^ ]+[ \t]*=[ \t]*[^ ]+[ \t]+[^ ]+[ \t]*=[ \t]*[^ ]+",
				oneline) == 0) {
			info(VERBOSE, _("Translation map: incorrect syntax."));
			continue; /* failed */
		}
		ptr1 = parse_line_option(oneline);
		ptr2 = parse_line_option(ptr1);
		p = strchr(ptr1, ' ');
		*p = '\0';
		safe_strcpy(translate, ptr1);
		safe_strcpy(into, ptr2);

		if (strstr(translate, "@")) {
			if (extuser == 0)
				continue; /* failed */
			safe_strcpy(user, translate);
			p = strchr(user, '@');
			*p++ = '\0';
			safe_strcpy(address, p);
			cu = 1;
		}
		else
			safe_strcpy(address, translate);

		inaddr = inet_addr(address);
		if (inaddr != INADDR_NONE)
			memcpy(&addr.sin_addr, &inaddr, sizeof(inaddr));
		else {
			struct hostent *hp = 0;
			hp = gethostbyname(address);
			if (hp == 0) {
				cu = 0;
				hostname_error(address);
				continue; /* failed */
			}
			else {
				if (hp->h_length != 4 && hp->h_length != 8) {
					anubis_error(HARD,
					_("Illegal address length received for host %s"), address);
					cu = 0;
					continue; /* failed */
				}
				else {
					memcpy((char *)&addr.sin_addr.s_addr, hp->h_addr,
						hp->h_length);
				}
			}
		}

		safe_strcpy(a2, inet_ntoa(addr.sin_addr));
		if (cu && !(topt & T_ERROR)) {
			if (strcmp(extuser, user) == 0) {
				/* a temporary solution */
				if (strcmp(a2, "0.0.0.0") == 0) {
					*cs = 1; /* success */
					break;
				}
				if (strcmp(a1, a2) == 0) {
					*cs = 1; /* success */
					break;
				}
			}
		}
		else if (cu == 0 && !(topt & T_ERROR)) {
			/* a temporary solution */
			if (strcmp(a2, "0.0.0.0") == 0) {
				*cs = 1; /* success */
				break;
			}
			if (strcmp(a1, a2) == 0) {
				*cs = 1; /* success */
				break;
			}
		}
		topt &= ~T_ERROR;

		if (p2)
			p1 = p2;
	} while (p2 != NULL);
	session.transmap = NULL;

	if (*cs == 1) { /* success */
		if (check_username(into)) {
			info(NORMAL, _("%s remapped to %s@localhost."), translate, into);
			memset(dst, 0, size);
			strncpy(dst, into, size - 1);
		}
		else
			*cs = 0; /* failed: invalid user name */
	}
	topt &= ~T_ERROR;
	return;
}

/* EOF */

