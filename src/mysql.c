/*
   mysql.c

   This file is part of GNU Anubis.
   Copyright (C) 2003-2014 The Anubis Team.

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

#ifdef WITH_MYSQL

#include "sql.h"
#include <mysql/mysql.h>

/* MySQL URL:

   mysql://user:password@host/dbname;
          table=STRING;authid=STRING;passwd=STRING[;account=STRING]
	  [;rcfile=STRING][;port=NUMBER][;socket=STRING][;bufsize=NUMBER]
*/

struct mysql_db_data
{
  MYSQL mysql;
  MYSQL_RES *result;
  MYSQL_ROW row;
};

static int
my_sql_release_result (struct anubis_sql_db *amp)
{
  struct mysql_db_data *mdata = amp->data;

  if (mdata->result)
    {
      mysql_free_result (mdata->result);
      mdata->result = NULL;
      mdata->row = NULL;
    }
  return 0;
}

static int
my_sql_query (struct anubis_sql_db *amp)
{
  struct mysql_db_data *mdata = amp->data;
  int rc;

  my_sql_release_result (amp);

  rc = mysql_query (&mdata->mysql, amp->buf);
  if (rc)
    return rc;
  mdata->result = mysql_store_result (&mdata->mysql);
  return 0;
}

static size_t
my_sql_num_tuples (struct anubis_sql_db *amp)
{
  struct mysql_db_data *mdata = amp->data;

  if (!mdata->result)
    return 0;
  return mysql_num_rows (mdata->result);
}

static size_t
my_sql_num_columns (struct anubis_sql_db *amp)
{
  struct mysql_db_data *mdata = amp->data;

  if (!mdata->result)
    return 0;
  return mysql_num_fields (mdata->result);
}

static int
my_sql_get_tuple (struct anubis_sql_db *amp, size_t i)
{
  struct mysql_db_data *mdata = amp->data;

  if (!mdata->result)
    return 1;
  mdata->row = mysql_fetch_row (mdata->result);
  if (!mdata->row)
    return 1;
  return 0;
}

static const char *
my_sql_get_column (struct anubis_sql_db *amp, size_t i)
{
  struct mysql_db_data *mdata = amp->data;

  if (!mdata->row)
    return NULL;
  return mdata->row[i];
}

/* Open the plaintext database. ARG is the full pathname to the file */
static int
mysql_db_open (void **dp, ANUBIS_URL * url, enum anubis_db_mode mode,
	       char const **errp)
{
  struct anubis_sql_db *amp = NULL;
  const char *table = anubis_url_get_arg (url, "table");
  const char *authid = anubis_url_get_arg (url, "authid");
  const char *passwd = anubis_url_get_arg (url, "passwd");
  const char *user = anubis_url_get_arg (url, "account");
  const char *rcfile = anubis_url_get_arg (url, "rcfile");
  const char *s;
  char *optfile;
  int port = 0;
  size_t bufsize = 1024;
  struct mysql_db_data *mdata;

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

  s = anubis_url_get_arg (url, "bufsize");
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

  s = anubis_url_get_arg (url, "port");
  if (s)
    {
      char *p;
      port = strtoul (s, &p, 10);
      if (*p)
	{
	  *errp = sql_open_error_text (ERR_BADPORT);
	  return ANUBIS_DB_FAIL;
	}
    }

  amp = xzalloc (sizeof (*amp));
  amp->buf = xmalloc (bufsize);
  amp->bufsize = bufsize;
  mdata = xmalloc (sizeof (*mdata));
  amp->data = mdata;
  mysql_init (&mdata->mysql);

  s = anubis_url_get_arg (url, "options-file");
  if (!s) {
	  if (access ("/etc/my.cnf", F_OK) == 0)
		  s = "/etc/my.cnf";
  }
  
  if (s && *s) {
	  mysql_options (&mdata->mysql, MYSQL_READ_DEFAULT_FILE, s);
	  mysql_options(&mdata->mysql, MYSQL_READ_DEFAULT_GROUP,
			s ? s : "anubis");
  }
  
  if (!mysql_real_connect (&mdata->mysql,
			   url->host, url->user, url->passwd,
			   url->path, port,
			   anubis_url_get_arg (url, "socket"), 0))
    {
      free (amp->data);
      free (amp);
      *errp = sql_open_error_text (ERR_CANTCONNECT);
      return ANUBIS_DB_FAIL;
    }

  amp->query = my_sql_query;
  amp->num_tuples = my_sql_num_tuples;
  amp->num_columns = my_sql_num_columns;
  amp->release_result = my_sql_release_result;
  amp->get_tuple = my_sql_get_tuple;
  amp->get_column = my_sql_get_column;

  amp->table = strdup (table);
  amp->authid = strdup (authid);
  amp->passwd = strdup (passwd);
  amp->user = strdup (user);
  amp->rcfile = strdup (rcfile);

  *dp = amp;
  return ANUBIS_DB_SUCCESS;
}

static int
mysql_db_close (void *d)
{
  struct anubis_sql_db *amp = d;
  struct mysql_db_data *mdata = amp->data;

  my_sql_release_result (amp);
  mysql_close (&mdata->mysql);

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
mysql_db_strerror (void *d, int rc)
{
  struct anubis_sql_db *amp = d;
  return mysql_error (amp->data);
}

void
mysql_db_init (void)
{
  sql_db_init ("mysql", mysql_db_open, mysql_db_close, mysql_db_strerror);
}

#endif /* WITH_MYSQL */

/* EOF */
