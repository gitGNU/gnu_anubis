/*
   dbtext.c

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

/* Open the plaintext database. ARG is the full pathname to the file */
static int
dbtext_open (void **dp, char *arg, enum anubis_db_mode mode)
{
	FILE *fp;
	char *tmode;

	switch (mode) {
	case anubis_db_rdonly:
		tmode = "r";
		break;

	case anubis_db_rdwr:
		tmode = "rw";
	}
	
	fp = fopen(arg, tmode);
	if (!fp)
		return errno;
	*dp = fp;
	return ANUBIS_DB_SUCCESS;
}

static int
dbtext_close (void *d)
{
	fclose((FILE*)d);
	return ANUBIS_DB_SUCCESS;
}

static int
dbtext_get (void *d, char *key, ANUBIS_USER *rec, int *errp)
{
	FILE *fp = d;
	char buf[512], *p;
	static const char delim[] = " \t\r\n";
	
	memset(rec, 0, sizeof *rec);
	fseek(fp, 0, SEEK_SET);
	while ((p = fgets(buf, sizeof buf, fp)) != NULL) {
		while (*p && isspace(*p))
			p++;
		if (*p == '#')
			continue;
		p = strtok(p, delim);
		if (!p || strcmp(p, key))
			continue;
		rec->smtp_authid = strdup(p);

		p = strtok(NULL, delim);
		if (!p) {
			free(rec->smtp_authid);
			continue;
		}
		rec->smtp_passwd = strdup(p);

		p = strtok(NULL, delim);
		if (p) {
			rec->username = strdup(p);
			p = strtok(NULL, delim);
			if (p) 
				rec->rc_file_name = strdup(p);
		}
		return ANUBIS_DB_SUCCESS;
	}
	return ferror(fp) ? ANUBIS_DB_FAIL : ANUBIS_DB_NOT_FOUND;
}

static int
dbtext_put (void *d, char *key, ANUBIS_USER *rec, int *errp)
{
	FILE *fp = d;
	fprintf(fp, "%s\t%s\t%s",
		rec->smtp_authid,
		rec->smtp_passwd,
		rec->username);
	if (rec->rc_file_name)
		fprintf(fp, "\t%s", rec->rc_file_name);
	fprintf(fp, "\n");
	return ferror(fp) ? ANUBIS_DB_FAIL : ANUBIS_DB_SUCCESS;
}

void
dbtext_init ()
{
	anubis_db_register("text",
			   dbtext_open,
			   dbtext_close,
			   dbtext_get,
			   dbtext_put,
			   NULL);
}
