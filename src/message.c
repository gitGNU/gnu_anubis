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

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

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
message_modify_body(MESSAGE *msg, char *key, char *value)
{
	if (!value)
		value = "";
	if (!key) {
		int len = strlen(value);
		
		xfree(msg->body);
		if (len > 0 && value[len-1] != '\n') {
			msg->body = xmalloc(len+2);
			strcpy(msg->body, value);
			msg->body[len] = '\n';
			msg->body[len+1] = 0;
		} else			
			msg->body = strdup(value);
	} else {
		RC_REGEX *regex = anubis_regex_compile(key, 0);
		char *start, *end;
		int stack_level = 0;
		struct obstack stack;

		start = msg->body;
		while (start && *start) {
			int len;
			char *newp;

			end = strchr(start, '\n');
			if (end)
				*end = 0;
			
			newp = anubis_regex_replace(regex, start, value);

			if (newp) {
				if (!stack_level) {
					obstack_init(&stack);
					stack_level = start - msg->body;
					if (stack_level > 0) {
						obstack_grow(&stack, msg->body,
							     stack_level);
					}
					stack_level++;
				}
				len = strlen(newp);
				obstack_grow(&stack, newp, len);
				obstack_1grow(&stack, '\n');
				xfree(newp);
				stack_level += len + 1;
			} else if (stack_level) {
				len = strlen(start);
				obstack_grow(&stack, start, len);
				obstack_1grow(&stack, '\n');
				stack_level += len + 1;
			}
			if (end)
				*end++ = '\n';
			start = end;
		}
		anubis_regex_free(regex);

		if (stack_level) {
			char *p = obstack_finish(&stack);
			msg->body = xrealloc(msg->body, stack_level + 1);
			memcpy(msg->body, p, stack_level-1);
			msg->body[stack_level-1] = 0;
			obstack_free(&stack, NULL);
		}
	}	
}

void
message_modify_headers(MESSAGE *msg, char *key, char *key2, char *value)
{
	ASSOC *asc;
	ITERATOR *itr;
        RC_REGEX *regex = anubis_regex_compile(key, 0);

        itr = iterator_create(msg->header);
	for (asc = iterator_first(itr); asc; asc = iterator_next(itr)) {
		char **rv;
                int rc;

		if (asc->key
		    && anubis_regex_match(regex, asc->key, &rc, &rv)) {
			if (key2) {
				free(asc->key);
				if (rc) 
					asc->key = substitute(key2, rv);
				else
					asc->key = strdup(key2);
			}
			if (value) {
				free(asc->value);
				asc->value = strdup(value);
			}
		}
		if (rc)
			free_pptr(rv);
	}
	iterator_destroy(&itr);
	anubis_regex_free(regex);
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
	msg->header = list_create();
	msg->commands = list_create();
}

void
message_free(MESSAGE *msg)
{
	destroy_assoc_list(&msg->commands);
	destroy_assoc_list(&msg->header);
	destroy_string_list(&msg->mime_hdr);
	
	xfree(msg->body);
	xfree(msg->boundary);
}

/* EOF */

