/*
   message.c

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

#include "headers.h"
#include "extern.h"

void
message_add_header(MESSAGE *msg, char *hdr, char *value)
{
	ASSOC *asc = xmalloc(sizeof(*asc));
	asc->key = strdup(hdr);
	asc->value = strdup(value);
	list_append(msg->header, asc);
}

void
message_add_body(MESSAGE *msg, char *key, char *value)
{
	if (!key) {
		msg->body = xrealloc(msg->body,
				     strlen(msg->body) + strlen(value) + 1);
		strcat(msg->body, value);
	} else {
		/*FIXME*/
	}
}

void
message_remove_headers(MESSAGE *msg, char *key)
{
        ASSOC *asc;
        ITERATOR *itr;
        RC_REGEX *regex = anubis_regex_compile(key, 0);
	
        itr = iterator_create(msg->header);
        for (asc = iterator_first(itr); asc; asc = iterator_next(itr)) {
		char **rv;
		int rc;

		if (anubis_regex_match(regex, asc->key, &rc, &rv)) {
			list_remove(msg->header, asc, NULL);
			assoc_free(asc);
		}
		if (rc)
			free_pptr(rv);
	}
	iterator_destroy(&itr);
	anubis_regex_free(regex);
}


void
message_modify_headers(MESSAGE *msg, char *key, char *key2, char *value)
{
	ASSOC *asc;
	ITERATOR *itr;

        itr = iterator_create(msg->header);
	for (asc = iterator_first(itr); asc; asc = iterator_next(itr)) {
		if (asc->key && strcasecmp(asc->key, key) == 0) {
			if (key2) {
				free(asc->key);
				asc->key = strdup(key2);
			}
			free(asc->value);
			asc->value = strdup(value);
		}
	}
	iterator_destroy(&itr);
}

void
message_external_proc(MESSAGE *msg, char **argv)
{
	int rc = 0;
	char *extbuf = 0;
	extbuf = exec_argv(&rc, argv, msg->body, 0, 0);
	if (rc != -1 && extbuf) {
		xfree(msg->body);
		msg->body = extbuf;
	}
}

void
message_init(MESSAGE *msg)
{
	memset(msg, 0, sizeof(*msg));
}

void
message_free(MESSAGE *msg)
{
	destroy_assoc_list(&msg->commands);
	destroy_assoc_list(&msg->header);
	destroy_string_list(&msg->mime_hdr);
	
	xfree(msg->body);
	msg->body = NULL;
	xfree(msg->boundary);
	msg->boundary = NULL;
}

/* EOF */

