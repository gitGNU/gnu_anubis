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

#if defined(WITH_GSASL)

/* Open the plaintext database. ARG is the full pathname to the file */
static int
dbtext_open (void **dp, ANUBIS_URL *url, enum anubis_db_mode mode, char **errp)
{
	FILE *fp;
	char *tmode;
	char *path;
	
	switch (mode) {
	case anubis_db_rdonly:
		tmode = "r";
		break;

	case anubis_db_rdwr:
		tmode = "a+";
	}

	path = anubis_url_full_path(url);
	fp = fopen(path, tmode);
	free(path);
	if (!fp) {
		if (errp)
			*errp = strerror(errno);
		return ANUBIS_DB_FAIL;
	}
	*dp = fp;
	return ANUBIS_DB_SUCCESS;
}

static int
dbtext_close (void *d)
{
	fclose((FILE*)d);
	return ANUBIS_DB_SUCCESS;
}

static const char delim[] = " \t\r\n";

int
dbtext_to_record(char *p, ANUBIS_USER *rec)
{
	memset(rec, 0, sizeof *rec);	
	while (*p && isspace(*p))
		p++;
	if (*p == '#')
		return ANUBIS_DB_NOT_FOUND;
	p = strtok(p, delim);
	if (!p)
		return ANUBIS_DB_NOT_FOUND;
	rec->smtp_authid = strdup(p);

	p = strtok(NULL, delim);
	if (!p) {
		free(rec->smtp_authid);
		return ANUBIS_DB_FAIL;
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

static int
dbtext_get (void *d, char *key, ANUBIS_USER *rec, int *errp)
{
	FILE *fp = d;
	char buf[512], *p;
	
	memset(rec, 0, sizeof *rec);
	fseek(fp, 0, SEEK_SET);
	while ((p = fgets(buf, sizeof buf, fp)) != NULL) {
		while (*p && isspace(*p))
			p++;
		if (*p == '#')
			continue;
		for (p = buf; *p && !strchr(delim, *p); p++)
			;
		if (!*p || memcmp(buf, key, p - buf))
			continue;
		return dbtext_to_record(buf, rec);
	}
	return ferror(fp) ? ANUBIS_DB_FAIL : ANUBIS_DB_NOT_FOUND;
}

static int
dbtext_put (void *d, char *key, ANUBIS_USER *rec, int *errp)
{
	FILE *fp = d;
	fprintf(fp, "%s\t%s",
		rec->smtp_authid,
		rec->smtp_passwd);
	if (rec->username) {
		fprintf(fp, "\t%s", rec->username);
		if (rec->rc_file_name)
			fprintf(fp, "\t%s", rec->rc_file_name);
	}
	fprintf(fp, "\n");
	return ferror(fp) ? ANUBIS_DB_FAIL : ANUBIS_DB_SUCCESS;
}

static int
dbtext_list(void *d, LIST *list, int *ecode)
{
	FILE *fp = d;
	char buf[512], *p;
	
	fseek(fp, 0, SEEK_SET);
	while ((p = fgets(buf, sizeof buf, fp)) != NULL) {
		ANUBIS_USER rec;
		if (dbtext_to_record(buf, &rec) == ANUBIS_DB_SUCCESS) {
			ANUBIS_USER *prec = xmalloc(sizeof(*prec));
			memcpy(prec, &rec, sizeof(*prec));
			list_append(list, prec);
		}
	}
	return ANUBIS_DB_SUCCESS;
}

static int
dbtext_delete(void *d, char *keystr, int *ecode)
{
	FILE *fp = d;
	char buf[512], *p;
	int rc = ANUBIS_DB_FAIL;
	
	fseek(fp, 0, SEEK_SET);
	while ((p = fgets(buf, sizeof buf, fp)) != NULL) {
		size_t len;
	
		while (*p && isspace(*p))
			p++;
		if (*p == '#')
			continue;
		p = strtok(p, delim);
		if (!p || strcmp(p, keystr))
			continue;
		len = strlen(buf);
		memset(buf, '#', len-1);
		buf[len-1] = 0;
		fseek(fp, - (off_t) len, SEEK_CUR);
		fputs(buf, fp);
		rc = ANUBIS_DB_SUCCESS;
		break;
	}

	return rc;
}

void
dbtext_init ()
{
	anubis_db_register("text",
			   dbtext_open,
			   dbtext_close,
			   dbtext_get,
			   dbtext_put,
			   dbtext_delete,
			   dbtext_list,
			   NULL);
}

#endif
