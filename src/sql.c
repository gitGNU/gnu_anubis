/*
   sql.c

   This file is part of GNU Anubis.
   Copyright (C) 2003, 2004 The Anubis Team.

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

#ifdef WITH_SQL

#include "sql.h"

/* SQL URL:

   PROTO://user:password@host/dbname;
          table=STRING;authid=STRING;passwd=STRING[;account=STRING]
	  [;rcfile=STRING][;port=NUMBER][;socket=STRING][;bufsize=NUMBER]

   Where PROTO is one of
     mysql         MySQL database
     pgsql         PostgreSQL database
     postgres      Synonim for the above.
*/


static char *open_err_tab[] = {
  N_("Required parameters are missing"),	/* ERR_MISS */
  N_("Invalid buffer size"),	/* ERR_BADBUFSIZE */
  N_("Invalid port number"),	/* ERR_BADPORT */
  N_("Cannot connect to the database"),	/* ERR_CANTCONNECT */
};

char *
sql_open_error_text (int s)
{
  return gettext (open_err_tab[s]);
}

static int
sql_db_get (void *d, const char *key, ANUBIS_USER * rec, int *errp)
{
  const char *p;
  struct anubis_sql_db *amp = d;

  snprintf (amp->buf, amp->bufsize,
	    "SELECT %s,%s,%s,%s FROM %s WHERE %s='%s'",
	    amp->authid,
	    amp->passwd, amp->user, amp->rcfile, amp->table, amp->authid, key);

  *errp = amp->query (amp);
  if (*errp)
    return ANUBIS_DB_FAIL;
  if (amp->num_tuples (amp) == 0 || amp->num_columns (amp) < 2)
    {
      amp->release_result (amp);
      return ANUBIS_DB_NOT_FOUND;
    }

  if (amp->get_tuple (amp, 0))
    {
      amp->release_result (amp);
      return ANUBIS_DB_NOT_FOUND;
    }

  rec->smtp_authid = strdup (amp->get_column (amp, 0));
  rec->smtp_passwd = strdup (amp->get_column (amp, 1));

  if ((p = amp->get_column (amp, 2)))
    rec->username = strdup (p);
  if ((p = amp->get_column (amp, 3)))
    rec->rcfile_name = strdup (p);
  amp->release_result (amp);
  return ANUBIS_DB_SUCCESS;
}

static int
sql_db_list (void *d, ANUBIS_LIST * list, int *ecode)
{
  struct anubis_sql_db *amp = d;
  size_t nrows, i;

  snprintf (amp->buf, amp->bufsize,
	    "SELECT %s,%s,%s,%s FROM %s",
	    amp->authid, amp->passwd, amp->user, amp->rcfile, amp->table);

  *ecode = amp->query (amp);
  if (*ecode)
    return ANUBIS_DB_FAIL;
  nrows = amp->num_tuples (amp);
  if (nrows == 0 || amp->num_columns (amp) < 2)
    {
      amp->release_result (amp);
      return ANUBIS_DB_NOT_FOUND;
    }

  for (i = 0; i < nrows; i++)
    {
      ANUBIS_USER *rec;
      const char *p;
      if (amp->get_tuple (amp, i))
	break;
      rec = xmalloc (sizeof (*rec));
      rec->smtp_authid = strdup (amp->get_column (amp, 0));
      rec->smtp_passwd = strdup (amp->get_column (amp, 1));
      if ((p = amp->get_column (amp, 2)))
	rec->username = strdup (p);
      if ((p = amp->get_column (amp, 3)))
	rec->rcfile_name = strdup (p);
      list_append (list, rec);
    }

  return ANUBIS_DB_SUCCESS;
}

static int
sql_db_delete (void *d, const char *keystr, int *ecode)
{
  struct anubis_sql_db *amp = d;

  snprintf (amp->buf, amp->bufsize,
	    "DELETE FROM %s WHERE %s='%s'", amp->table, amp->authid, keystr);
  *ecode = amp->query (amp);
  if (*ecode)
    return ANUBIS_DB_FAIL;
  return ANUBIS_DB_SUCCESS;
}

#define MSTR(s) ((s) ? (s) : "NULL")

static int
sql_db_put (void *d, const char *key, ANUBIS_USER * rec, int *errp)
{
  struct anubis_sql_db *amp = d;

  if (sql_db_delete (d, rec->smtp_authid, errp))
    return 1;

  snprintf (amp->buf, amp->bufsize,
	    "INSERT INTO %s (%s,%s,%s,%s) VALUES ('%s','%s','%s','%s')",
	    amp->table,
	    amp->authid,
	    amp->passwd,
	    amp->user,
	    amp->rcfile,
	    rec->smtp_authid,
	    rec->smtp_passwd, MSTR (rec->username), MSTR (rec->rcfile_name));
  *errp = amp->query (amp);
  if (*errp)
    return ANUBIS_DB_FAIL;
  return ANUBIS_DB_SUCCESS;
}

void
sql_db_init (const char *proto,
	     anubis_db_open_t open,
	     anubis_db_close_t close, anubis_db_strerror_t str_error)
{
  anubis_db_register (proto,
		      open,
		      close,
		      sql_db_get,
		      sql_db_put, sql_db_delete, sql_db_list, str_error);
}

#endif /* WITH_SQL */

/* EOF */
