/*
   misc.c

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

/* String lists */

static int
_mem_free(void *item, void *data)
{
	free(item);
	return 0;
}

void
destroy_string_list(struct list **plist)
{
	list_destroy(plist, _mem_free, NULL);
}

static int
_assoc_free(void *item, void *data)
{
	assoc_free(item);
	return 0;
}

void
destroy_assoc_list(struct list **plist)
{
	list_destroy(plist, _assoc_free, NULL);
}

void
assoc_free(ASSOC *asc)
{
	free(asc->key);
	free(asc->value);
	free(asc);
}

ASSOC *
header_assoc(char *line)
{
	char *p = strchr(line, ':');
	ASSOC *entry = xmalloc(sizeof(*entry));
	if (p) {
		int len = p - line;
		entry->key = xmalloc(len + 1);
		memcpy(entry->key, line, len);
		entry->key[len] = 0;
		entry->value = strdup(p + 1);
	} else {
		/* Malformed header. Save everything as rhs */
		entry->key = NULL;
		entry->value = strdup(line);
	}
	return entry;
}

char *
assoc_to_header(ASSOC *asc)
{
	char *buf;

	if (asc->key) {
		buf = xmalloc(strlen(asc->key) + strlen(asc->value) + 3);
		sprintf(buf, "%s: %s", asc->key, asc->value);
	} else
		buf = strdup(asc->value);
	return buf;
}

/****************************
 An extra port number parser
*****************************/

void
parse_mtaport(char *opt, char *host, unsigned int *port)
{
	struct servent *p;
	char opt_tmp[256];
	char *port_tmp = 0;
	safe_strcpy(opt_tmp, opt);

	if ((port_tmp = strrchr(opt_tmp, ':'))) {
		*port_tmp++ = '\0';
		if ((p = getservbyname(port_tmp, "tcp")))
			*port = ntohs(p->s_port);
		else
			*port = (unsigned int)atoi(port_tmp);
	}
	strncpy(host, opt_tmp, sizeof(session.mta) - 1);
	return;
}

/**************************
 An extra host name parser
***************************/

void
parse_mtahost(char *opt, char *host, unsigned int *port)
{
	struct servent *p;
	char opt_tmp[256];
	char *port_tmp = 0;
	safe_strcpy(opt_tmp, opt);

	if ((port_tmp = strrchr(opt_tmp, ':'))) {
		*port_tmp++ = '\0';
		if ((p = getservbyname(port_tmp, "tcp")))
			*port = ntohs(p->s_port);
		else
			*port = (unsigned int)atoi(port_tmp);
		strncpy(host, opt_tmp, sizeof(session.tunnel) - 1);
	}
	else { /* only port number available */
		if ((p = getservbyname(opt, "tcp")))
			*port = ntohs(p->s_port);
		else
			*port = (unsigned int)atoi(opt);
	}
	return;
}

/*********************
 Remove a single line
**********************/

void
remline(char *s, char *line)
{
	char *pos1 = 0;
	char *pos2 = 0;
	int len;

	if (s == 0 || line == 0)
		return;
	pos1 = strstr(s, line);
	if (pos1 == 0)
		return;

	pos2 = pos1;
	do {
		pos2++;
	} while (*pos2 != '\n');
	pos2++;
	len = strlen(pos2);
	pos2 = (char *)memmove(pos1, pos2, len);
	pos2[len] = '\0';
	return;
}

void
remcrlf(char *s)
{
	int len;

	if (s == 0)
		return;
	len = strlen(s);

	if (len >= 2 && s[len - 2] == '\r' && s[len - 1] == '\n') { /* CRLF */
		s[len - 2] = '\0';
		s[len - 1] = '\0';
	}
	else if (len >= 2 && s[len - 2] != '\r' && s[len - 1] == '\n') /* LF */
		s[len - 1] = '\0';
	else if (len >= 1 && s[len - 1] == '\r') /* CR */
		s[len - 1] = '\0';
	else if (len >= 1 && s[len - 1] == '\n') /* LF */
		s[len - 1] = '\0';
	return;
}

/***********************************
 Substitutions (RE back-references)
************************************/

char *
substitute(char *inbuf, char **subbuf)
{
	char **tmp = subbuf;
	char *tmpout = 0;
	char *tmpbuf = 0;
	char sign[5];
	int i = 0;

	if (inbuf == 0 || subbuf == 0)
		return 0;

	tmpbuf = allocbuf(inbuf, 0);
	tmp++;
	while (*tmp)
	{
		snprintf(sign, 4, "\\%d", i + 1);
		tmpout = insert(tmpbuf, sign, *tmp);
		if (tmpout) {
			tmpbuf = (char *)xrealloc((char *)tmpbuf, strlen(tmpout) + 1);
			strcpy(tmpbuf, tmpout);
			free(tmpout);
		}
		tmp++;
		i++;
	}
	return tmpbuf;
}

char *
insert(char *inbuf, char *sign, char *fill_in)
{
	int len1 = 0;
	int len2 = 0;
	int psign_len = 0;
	char *psign = 0;
	char *outbuf = 0;

	if (inbuf == 0 || sign == 0 || fill_in == 0)
		return 0;

	psign = strstr(inbuf, sign);
	if (psign == 0)
		return 0;

	psign_len = strlen(psign);
	len1 = strlen(inbuf);
	len1 -= psign_len;
	len2 = len1 + 1;
	len2 += strlen(fill_in);
	len2 += (psign_len - 2);

	outbuf = (char *)xmalloc(len2);
	memset(outbuf, 0, len2);
	psign += 2;

	strncpy(outbuf, inbuf, len1);
	strcat(outbuf, fill_in);
	strcat(outbuf, psign);

	if (strstr(outbuf, sign)) {
		char *outbuf2 = 0;
		outbuf2 = insert(outbuf, sign, fill_in);
		free(outbuf);
		outbuf = outbuf2;
	}

	return outbuf;
}

/***************************
 change to lower characters
****************************/

void
change_to_lower(char *s)
{
	int c;
	int len;

	if (s == 0)
		return;
	len = strlen(s);

	for (c = len - 1; c >= 0; c--)
		s[c] = tolower((unsigned char)s[c]);
	return;
}

/* EOF */

