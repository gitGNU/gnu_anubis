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

/* General-purpose function for use with list_destroy when deallocating
   simple lists */
int
anubis_free_list_item(void *item, void *data)
{
	free(item);
	return 0;
}

/* String lists */

void
destroy_string_list(LIST **plist)
{
	list_destroy(plist, anubis_free_list_item, NULL);
}

static int
_assoc_free(void *item, void *data)
{
	assoc_free(item);
	return 0;
}

void
destroy_assoc_list(LIST **plist)
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
		for (p++; *p && isspace(*(u_char*)p); p++)
			;
		entry->value = strdup(p);
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
parse_mtaport (char *opt, char *host, unsigned int *port)
{
	struct servent *p;
	char opt_tmp[256];
	char *port_tmp = NULL;
	safe_strcpy(opt_tmp, opt);

	if ((port_tmp = strrchr(opt_tmp, ':'))) {
		*port_tmp++ = '\0';
		if ((p = getservbyname(port_tmp, "tcp")))
			*port = ntohs(p->s_port);
		else
			*port = (unsigned int)atoi(port_tmp);
	}
	strncpy(host, opt_tmp, sizeof(session.mta) - 1);
}

/**************************
 An extra host name parser
***************************/

void
parse_mtahost (char *opt, char *host, unsigned int *port)
{
	struct servent *p;
	char opt_tmp[256];
	char *port_tmp = NULL;
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
}

/*********************
 Remove a single line
**********************/

void
remline (char *s, char *line)
{
	char *pos1 = NULL;
	char *pos2 = NULL;
	int len;

	if (!s || !line)
		return;
	pos1 = strstr(s, line);
	if (!pos1)
		return;

	pos2 = pos1;
	do {
		pos2++;
	} while (*pos2 != '\n');
	pos2++;
	len = strlen(pos2);
	pos2 = (char *)memmove(pos1, pos2, len);
	pos2[len] = '\0';
}

void
remcrlf (char *s)
{
	int len;

	if (!s)
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
}

/***********************************
 Substitutions (RE back-references)
************************************/

static char *
insert (char *inbuf, char *sign, char *fill_in)
{
	int len1 = 0;
	int len2 = 0;
	int psign_len = 0;
	char *psign = NULL;
	char *outbuf = NULL;

	if (!inbuf || !sign || !fill_in)
		return NULL;

	psign = strstr(inbuf, sign);
	if (!psign)
		return NULL;

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
		char *outbuf2 = insert(outbuf, sign, fill_in);
		free(outbuf);
		outbuf = outbuf2;
	}

	return outbuf;
}

char *
substitute (char *inbuf, char **subbuf)
{
	char **tmp = subbuf;
	char *tmpout = NULL;
	char *tmpbuf = NULL;
	char sign[5];
	int i = 0;

	if (!inbuf || !subbuf)
		return NULL;

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

/********************
 Change to lowercase
*********************/

void
make_lowercase (char *s)
{
	int c, len;

	if (!s)
		return;
	len = strlen(s);

	for (c = len - 1; c >= 0; c--)
		s[c] = tolower((unsigned char)s[c]);
}

char *
get_localname (void)
{
	static char *localname = NULL;

	if (!localname)	{
		char *name;
		int name_len = 256;
		int status = 1;
		struct hostent *hp;

		name = malloc (name_len);
		while (name
		       && (status = gethostname (name, name_len)) == 0
		       && !memchr (name, 0, name_len)) {
			name_len *= 2;
			name = realloc (name, name_len);
		}
		if (status) {
			info (NORMAL,
			      _("Can't find out my own hostname"));
			exit (1);
		}

		hp = gethostbyname (name);
		if (hp)	{
			struct in_addr inaddr;
			inaddr.s_addr = *(unsigned int *) hp->h_addr;
			hp = gethostbyaddr ((const char *) &inaddr,
					    sizeof (struct in_addr), AF_INET);
			if (hp) {
				free (name);
				name = strdup ((char *) hp->h_name);
			}
		}
		localname = name;
	}
	return localname;
}

char *
get_localdomain (void)
{
	if (!anubis_domain) {
		char *localname = get_localname(),
		     *p = strchr(localname, '.');
		if (!p)
			anubis_domain = strdup(localname);
		else 
			anubis_domain = strdup(p+1);
	}
	return anubis_domain;
}

/* EOF */

