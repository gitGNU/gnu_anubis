/*
   headers.h

   This file is part of GNU Anubis.
   Copyright (C) 2001-2014 The Anubis Team.

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

typedef struct smtp_reply *ANUBIS_SMTP_REPLY;

ANUBIS_SMTP_REPLY smtp_reply_new ();
void smtp_reply_free (ANUBIS_SMTP_REPLY reply);
void smtp_reply_set (ANUBIS_SMTP_REPLY reply, const char *input);
void smtp_reply_read (ANUBIS_SMTP_REPLY reply,
		      ssize_t (*reader) (void *, char **, size_t *),
		      void *rdata);
char const *smtp_reply_string (ANUBIS_SMTP_REPLY reply);
char const *smtp_reply_line (ANUBIS_SMTP_REPLY reply, size_t index);
size_t smtp_reply_line_count (ANUBIS_SMTP_REPLY reply);
int smtp_reply_code_eq (ANUBIS_SMTP_REPLY reply, const char *code);
int smtp_reply_has_capa (ANUBIS_SMTP_REPLY reply, const char *capa,
			 size_t *pind);
int smtp_reply_has_string (ANUBIS_SMTP_REPLY reply, size_t index,
			   const char *key, size_t *pind);
void smtp_reply_replace_line (ANUBIS_SMTP_REPLY reply, size_t index,
			      const char *str);
void smtp_reply_add_line (ANUBIS_SMTP_REPLY reply, const char *str);
void smtp_reply_remove_line (ANUBIS_SMTP_REPLY reply, size_t index);

int smtp_reply_get_line (ANUBIS_SMTP_REPLY reply, size_t index,
			 char **pstr, size_t *psize);

const char *smtp_reply_line_ptr (ANUBIS_SMTP_REPLY reply, size_t index);


