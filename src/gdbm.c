/*
   gdbm.c

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
#include <gdbm.h>

/* Format of an GDBM record:

   char *key             Username
   char *value           The colon-separated list of the following values:

                         password,username,rc-file

			 The last two items are optional */

static int
gdbm_db_open (void **dp, char *arg, enum anubis_db_mode mode)
{
	GDBM_FILE dbf;
	int flags;
	
	switch (mode) {
	case anubis_db_rdonly:
		flags = GDBM_READER;
		break;

	case anubis_db_rdwr:
		flags = GDBM_WRCREAT;
	}
	
	
	dbf = gdbm_open(arg, 0, flags, 0644, NULL);
	if (!dbf)
		return ANUBIS_DB_FAIL;
	*dp = dbf;
	return ANUBIS_DB_SUCCESS;
}

static int
gdbm_db_close (void *d)
{
	gdbm_close(d);
	return ANUBIS_DB_SUCCESS;
}

static int
gdbm_db_get (void *d, char *keystr, ANUBIS_USER *rec, int *errp)
{
	datum key, content;
	char *text, *p;
	
	key.dptr = keystr;
	key.dsize = strlen(keystr);
	content = gdbm_fetch((GDBM_FILE)d, key);
	if (content.dptr == NULL) 
		return ANUBIS_DB_NOT_FOUND;

	rec->smtp_authid = strdup(keystr);
	text = xmalloc(content.dsize + 1);
	memcpy(text, content.dptr, content.dsize);

	memset(rec, 0, sizeof *rec);
	rec->smtp_authid = strdup(keystr);
	p = strtok(text, ",");
	if (p) {
		rec->smtp_passwd = strdup(p);
		p = strtok(NULL, ",");
		if (p) {
			rec->username = strdup(p);
			p = strtok(NULL, ",");
			if (p)
				rec->rc_file_name = strdup(p);
		}
		free(text);
	} else
		rec->smtp_passwd = text;
	free(content.dptr);
	return ANUBIS_DB_SUCCESS;
}

static int
gdbm_db_put (void *d, char *keystr, ANUBIS_USER *rec, int *errp)
{
	size_t size, n;
	char *text;
	datum key, content;
	int rc;
	
	size = strlen(rec->smtp_passwd) + 1;
	if (rec->username) 
		size += strlen(rec->username) + 1;
	if (rec->rc_file_name) {
		size += strlen(rec->rc_file_name);
		if (!rec->username)
			size += strlen(rec->smtp_authid) + 1;
	}
	text = xmalloc(size+1);
	n = sprintf(text, "%s", rec->smtp_passwd);
	if (rec->username)
		n += sprintf(text + n, ",%s", rec->username);
	if (rec->rc_file_name) {
		if (!rec->username)
			n += sprintf(text + n, ",%s", rec->smtp_authid);
		n += sprintf(text + n, ",%s", rec->rc_file_name);
	}

	key.dptr = keystr;
	key.dsize = strlen(keystr);
	content.dptr = text;
	content.dsize = size;

	if (gdbm_store((GDBM_FILE)d, key, content, GDBM_REPLACE))
		rc = ANUBIS_DB_FAIL;
	else
		rc = ANUBIS_DB_SUCCESS;
	free(text);
	return rc;
}

void
gdbm_db_init()
{
	anubis_db_register("gdbm",
			   gdbm_db_open,
			   gdbm_db_close,
			   gdbm_db_get,
			   gdbm_db_put,
			   NULL);
}
