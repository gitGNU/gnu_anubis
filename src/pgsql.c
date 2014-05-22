/*
   pgsql.c

   This file is part of GNU Anubis.
   Copyright (C) 2004-2014 The Anubis Team.

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

#include "headers.h"
#include "extern.h"

#ifdef WITH_PGSQL

#include "sql.h"
#include <libpq-fe.h>

/* PostgreSQL URL:

   pgsql://user:password@host/dbname;
          table=STRING;authid=STRING;passwd=STRING[;account=STRING]
	  [;rcfile=STRING][;port=NUMBER][;socket=STRING][;bufsize=NUMBER]

   or

   postgres://...
*/

struct pgsql_db_data
{
  PGconn *conn;
  PGresult *res;
  size_t nfields;
  size_t ntuples;
  size_t curtuple;
};

static int
pg_sql_release_result (struct anubis_sql_db *amp)
{
  struct pgsql_db_data *pdata = amp->data;

  if (pdata->res)
    {
      PQclear (pdata->res);
      pdata->res = NULL;
      pdata->ntuples = pdata->nfields = 0;
    }
  return 0;
}

static int
pg_sql_query (struct anubis_sql_db *amp)
{
  struct pgsql_db_data *pdata = amp->data;
  ExecStatusType stat;

  pg_sql_release_result (amp);

  pdata->res = PQexec (pdata->conn, amp->buf);
  stat = PQresultStatus (pdata->res);
  switch (stat)
    {
    case PGRES_COMMAND_OK:
      return 0;

    case PGRES_TUPLES_OK:
      pdata->ntuples = PQntuples (pdata->res);
      pdata->nfields = PQnfields (pdata->res);
      return 0;

    default:
      pg_sql_release_result (amp);
    }

  return 1;
}

static size_t
pg_sql_num_tuples (struct anubis_sql_db *amp)
{
  struct pgsql_db_data *pdata = amp->data;

  if (!pdata->res)
    return 0;
  return pdata->ntuples;
}

static size_t
pg_sql_num_columns (struct anubis_sql_db *amp)
{
  struct pgsql_db_data *pdata = amp->data;

  if (!pdata->res)
    return 0;
  return pdata->nfields;
}

static int
pg_sql_get_tuple (struct anubis_sql_db *amp, size_t i)
{
  struct pgsql_db_data *pdata = amp->data;

  if (!pdata->res || i >= pdata->ntuples)
    return 1;
  pdata->curtuple = i;
  return 0;
}

static const char *
pg_sql_get_column (struct anubis_sql_db *amp, size_t i)
{
  struct pgsql_db_data *pdata = amp->data;
  char *p;

  if (!pdata->res || i >= pdata->nfields)
    return NULL;
  p = PQgetvalue (pdata->res, pdata->curtuple, i);
  if (p)
    {
      char *endp;
      for (endp = p + strlen (p); endp > p && isspace (endp[-1]); endp--)
	;
      *endp = 0;
    }
  return p;
}

/* Open the plaintext database. ARG is the full pathname to the file */
static int
pgsql_db_open (void **dp, ANUBIS_URL * url, enum anubis_db_mode mode,
	       char const **errp)
{
  struct anubis_sql_db *amp = NULL;
  const char *table = anubis_url_get_arg (url, "table");
  const char *authid = anubis_url_get_arg (url, "authid");
  const char *passwd = anubis_url_get_arg (url, "passwd");
  const char *user = anubis_url_get_arg (url, "account");
  const char *rcfile = anubis_url_get_arg (url, "rcfile");
  const char *portstr = anubis_url_get_arg (url, "port");
  const char *s = anubis_url_get_arg (url, "bufsize");
  size_t bufsize = 1024;
  struct pgsql_db_data *pdata;
  PGconn *conn;

  /* Provide reasonable defaults */
  if (!table)
    table = "users";
  if (!authid)
    authid = "authid";
  if (!passwd)
    passwd = "passwd";
  if (!user)
    user = "account";
  if (!rcfile)
    rcfile = "rcfile";

  conn = PQsetdbLogin (url->host, portstr, NULL, NULL,
		       url->path, url->user, url->passwd);

  if (PQstatus (conn) == CONNECTION_BAD)
    {
      /* PQerrorMessage(conn) */
      PQfinish (conn);
      free (amp);
      *errp = sql_open_error_text (ERR_CANTCONNECT);
      return ANUBIS_DB_FAIL;
    }

  amp = xzalloc (sizeof (*amp));
  amp->buf = xmalloc (bufsize);
  amp->bufsize = bufsize;
  pdata = xmalloc (sizeof (*pdata));
  pdata->conn = conn;
  amp->data = pdata;

  if (s)
    {
      char *p;
      bufsize = strtoul (s, &p, 10);
      if (*p)
	{
	  *errp = sql_open_error_text (ERR_BADBUFSIZE);
	  return ANUBIS_DB_FAIL;
	}
    }

  amp->query = pg_sql_query;
  amp->num_tuples = pg_sql_num_tuples;
  amp->num_columns = pg_sql_num_columns;
  amp->release_result = pg_sql_release_result;
  amp->get_tuple = pg_sql_get_tuple;
  amp->get_column = pg_sql_get_column;

  amp->table = strdup (table);
  amp->authid = strdup (authid);
  amp->passwd = strdup (passwd);
  amp->user = strdup (user);
  amp->rcfile = strdup (rcfile);

  *dp = amp;
  return ANUBIS_DB_SUCCESS;
}

static int
pgsql_db_close (void *d)
{
  struct anubis_sql_db *amp = d;
  struct pgsql_db_data *pdata = amp->data;

  pg_sql_release_result (amp);
  PQfinish (pdata->conn);

  free (amp->data);
  free (amp->table);
  free (amp->authid);
  free (amp->passwd);
  free (amp->user);
  free (amp->rcfile);
  free (amp->buf);
  return ANUBIS_DB_SUCCESS;
}

const char *
pgsql_db_strerror (void *d, int rc)
{
  struct anubis_sql_db *amp = d;
  struct pgsql_db_data *pdata = amp->data;
  return PQerrorMessage (pdata->conn);
}

void
pgsql_db_init (void)
{
  sql_db_init ("pgsql", pgsql_db_open, pgsql_db_close, pgsql_db_strerror);
  sql_db_init ("postgres", pgsql_db_open, pgsql_db_close, pgsql_db_strerror);
}

#endif /* WITH_PGSQL */

/* EOF */
