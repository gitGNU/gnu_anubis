/*
   mysql.c

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
#if defined(WITH_MYSQL)
#include <mysql/mysql.h>

/* MySQL URL:

   mysql://user:password@host/dbname;
          table=STRING;authid=STRING;passwd=STRING[;user=STRING][;rccol=STRING]
          [;port=NUMBER][;socket=STRING][;bufsize=NUMBER]

*/

struct anubis_mysql_db {
	MYSQL mysql;
	char *table;
	char *authid;
	char *passwd;
	char *user;
	char *rccol;
	char *buf;
	size_t bufsize;
};

#define ERR_MISS         0
#define ERR_BADBUFSIZE   1
#define ERR_BADPORT      2 
#define ERR_CANTCONNECT  3 

static char *open_err_tab[] = {
	N_("Required parameters are missing"), /* ERR_MISS */
	N_("Invalid buffer size"),             /* ERR_BADBUFSIZE */
	N_("Invalid port number"),             /* ERR_BADPORT */
	N_("Cannot connect to the database"),  /* ERR_CANTCONNECT */
};

#define open_error_text(s) gettext(open_err_tab[s])

/* Open the plaintext database. ARG is the full pathname to the file */
static int
mysql_db_open (void **dp, ANUBIS_URL *url, enum anubis_db_mode mode,
	       char **errp)
{
	struct anubis_mysql_db *amp = NULL;
	const char *table = anubis_url_get_arg(url, "table");
	const char *authid = anubis_url_get_arg(url, "authid");
	const char *passwd = anubis_url_get_arg(url, "passwd");
	const char *user = anubis_url_get_arg(url, "user");
	const char *rccol = anubis_url_get_arg(url, "rccol");
	const char *portstr = anubis_url_get_arg(url, "port");
	const char *s = anubis_url_get_arg(url, "bufsize");
	int port = 0;
	size_t bufsize = 1024;

	if (!table || !authid || !passwd || !user || !rccol) {
		*errp = open_error_text(ERR_MISS);
		return ANUBIS_DB_FAIL;
	}
	 
	if (s) {
		char *p;
		bufsize = strtoul(s, &p, 10);
		if (*p) {
			*errp = open_error_text(ERR_BADBUFSIZE);
			return ANUBIS_DB_FAIL;
		}
	}
		
	if (portstr) {
		char *p;
		port = strtoul(portstr, &p, 10);
		if (*p) {
			*errp = open_error_text(ERR_BADPORT);
			return ANUBIS_DB_FAIL;
		}
	}

	amp = xmalloc(sizeof(*amp));
	amp->buf = xmalloc(bufsize);
	amp->bufsize = bufsize;
        mysql_init(&amp->mysql);
	if (!mysql_real_connect(&amp->mysql, 
				url->host, url->user, url->passwd,
				url->path, port,
				anubis_url_get_arg(url, "socket"),
				0)) {
		free(amp);
		*errp = open_error_text(ERR_CANTCONNECT);
		return ANUBIS_DB_FAIL;
	}
	amp->table = strdup(table);
	amp->authid = strdup(authid);
	amp->passwd = strdup(passwd);
	amp->user = strdup(user);
	amp->rccol = strdup(rccol);

	*dp = amp;
	return ANUBIS_DB_SUCCESS;
}

static int
mysql_db_close (void *d)
{
	struct anubis_mysql_db *amp = d;
	mysql_close(&amp->mysql);
	free(amp->table);
	free(amp->authid);
	free(amp->passwd);
	free(amp->user);
	free(amp->rccol);
	free(amp->buf);
	return ANUBIS_DB_SUCCESS;
}

static int
mysql_db_get (void *d, char *key, ANUBIS_USER *rec, int *errp)
{
        MYSQL_RES *result;
        MYSQL_ROW row;
	struct anubis_mysql_db *amp = d;

	snprintf(amp->buf, amp->bufsize,
		 "SELECT %s,%s,%s,%s FROM %s WHERE %s='%s'",
		 amp->authid,
		 amp->passwd,
		 amp->user,
		 amp->rccol,
		 amp->table,
		 amp->authid,
		 key);

	*errp = mysql_query(&amp->mysql, amp->buf);
	if (*errp)
		return ANUBIS_DB_FAIL;
        if (!(result = mysql_store_result(&amp->mysql)))
		return ANUBIS_DB_FAIL;
        if (mysql_num_rows(result) == 0) {
		mysql_free_result(result);
		return ANUBIS_DB_NOT_FOUND;
	}

	row = mysql_fetch_row(result);
	
	rec->smtp_authid = strdup(row[0]);
	rec->smtp_passwd = strdup(row[1]);
	if (row[2])
		rec->username = strdup(row[2]);
	if (row[3])
		rec->rc_file_name = strdup(row[3]);
	mysql_free_result(result);
	return ANUBIS_DB_SUCCESS;
}

static int
mysql_db_list(void *d, LIST *list, int *ecode)
{
	struct anubis_mysql_db *amp = d;
        MYSQL_RES *result;
	size_t nrows, i;
	
	snprintf(amp->buf, amp->bufsize,
		 "SELECT %s,%s,%s,%s FROM %s",
		 amp->authid,
		 amp->passwd,
		 amp->user,
		 amp->rccol,
		 amp->table);
	
	*ecode = mysql_query(&amp->mysql, amp->buf);
	if (*ecode)
		return ANUBIS_DB_FAIL;
        if (!(result = mysql_store_result(&amp->mysql)))
		return ANUBIS_DB_FAIL;
        if ((nrows = mysql_num_rows(result)) == 0) {
		mysql_free_result(result);
		return ANUBIS_DB_NOT_FOUND;
	}

	for (i = 0; i < nrows; i++) {
		ANUBIS_USER *rec;
		MYSQL_ROW row = mysql_fetch_row(result);
		if (!row)
			break;
		rec = xmalloc(sizeof(*rec));
		rec->smtp_authid = strdup(row[0]);
		rec->smtp_passwd = strdup(row[1]);
		if (row[2])
			rec->username = strdup(row[2]);
		if (row[3])
			rec->rc_file_name = strdup(row[3]);
		list_append(list, rec);
	}
	
	return ANUBIS_DB_SUCCESS;
}

#define MSTR(s) ((s) ? (s) : "NULL")

static int
mysql_db_put (void *d, char *key, ANUBIS_USER *rec, int *errp)
{
	struct anubis_mysql_db *amp = d;

	snprintf(amp->buf, amp->bufsize,
		 "REPLACE INTO %s (%s,%s,%s,%s) VALUES ('%s','%s','%s','%s')",
		 amp->table,
		 amp->authid,
		 amp->passwd,
		 amp->user,
		 amp->rccol,
		 rec->smtp_authid,
		 rec->smtp_passwd,
		 MSTR(rec->username),
		 MSTR(rec->rc_file_name));
	*errp = mysql_query(&amp->mysql, amp->buf);
	if (*errp)
		return ANUBIS_DB_FAIL;
	return ANUBIS_DB_SUCCESS;
}

static int
mysql_db_delete(void *d, char *keystr, int *ecode)
{
	struct anubis_mysql_db *amp = d;

	snprintf(amp->buf, amp->bufsize,
		 "DELETE FROM %s WHERE %s='%s'",
		 amp->table,
		 amp->authid,
		 keystr);
	*ecode = mysql_query(&amp->mysql, amp->buf);
	if (*ecode)
		return ANUBIS_DB_FAIL;
	return ANUBIS_DB_SUCCESS;
}

const char *
mysql_db_strerror(void *d, int rc)
{
	struct anubis_mysql_db *amp = d;
	return mysql_error(&amp->mysql);
}

void
mysql_db_init ()
{
	anubis_db_register("mysql",
			   mysql_db_open,
			   mysql_db_close,
			   mysql_db_get,
			   mysql_db_put,
			   mysql_db_delete,
			   mysql_db_list,
			   mysql_db_strerror);
}
#endif
