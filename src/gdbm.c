/*
   gdbm.c

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

#ifdef HAVE_LIBGDBM
#include <gdbm.h>

/* Format of an GDBM record:

   char *key             Username
   char *value           The colon-separated list of the following values:

                         password,username,rc-file

			 The last two items are optional */

static int
gdbm_db_open (void **dp, ANUBIS_URL * url, enum anubis_db_mode mode,
	      char const **errp)
{
  GDBM_FILE dbf;
  int flags;
  char *path;

  switch (mode)
    {
    case anubis_db_rdonly:
      flags = GDBM_READER;
      break;

    case anubis_db_rdwr:
      flags = GDBM_WRCREAT;
      break;

    default:
      flags = 0;
    }

  path = anubis_url_full_path (url);
  dbf = gdbm_open (path, 0, flags, 0644, NULL);
  free (path);
  if (!dbf)
    {
      *errp = gdbm_strerror (gdbm_errno);
      return ANUBIS_DB_FAIL;
    }
  *dp = dbf;
  return ANUBIS_DB_SUCCESS;
}

static int
gdbm_db_close (void *d)
{
  gdbm_close (d);
  return ANUBIS_DB_SUCCESS;
}

static void
gdbm_content_to_record (char *keystr, datum content, ANUBIS_USER * rec)
{
  char *p;
  char *text = xmalloc (content.dsize + 1);

  memcpy (text, content.dptr, content.dsize);
  text[content.dsize] = 0;
  rec->smtp_authid = strdup (keystr);
  p = strtok (text, ",");
  if (p)
    {
      rec->smtp_passwd = strdup (p);
      p = strtok (NULL, ",");
      if (p)
	{
	  rec->username = strdup (p);
	  p = strtok (NULL, ",");
	  if (p)
	    rec->rcfile_name = strdup (p);
	}
      free (text);
    }
  else
    rec->smtp_passwd = text;
}

static int
gdbm_db_get (void *d, const char *keystr, ANUBIS_USER * rec, int *errp)
{
  datum key, content;

  key.dptr = (char *) keystr;
  key.dsize = strlen (keystr);
  content = gdbm_fetch ((GDBM_FILE) d, key);
  if (content.dptr == NULL)
    return ANUBIS_DB_NOT_FOUND;

  memset (rec, 0, sizeof *rec);
  gdbm_content_to_record ((char *) keystr, content, rec);
  free (content.dptr);
  return ANUBIS_DB_SUCCESS;
}

static int
gdbm_db_list (void *d, ANUBIS_LIST  list, int *ecode)
{
  datum key, content;

  key = gdbm_firstkey ((GDBM_FILE) d);
  while (key.dptr)
    {
      datum nextkey;

      content = gdbm_fetch ((GDBM_FILE) d, key);
      if (content.dptr)
	{
	  ANUBIS_USER *rec = xmalloc (sizeof (*rec));
	  char *keyval = xmalloc (key.dsize + 1);
	  memcpy (keyval, key.dptr, key.dsize);
	  keyval[key.dsize] = 0;
	  gdbm_content_to_record (keyval, content, rec);
	  free (keyval);
	  list_append (list, rec);
	}

      nextkey = gdbm_nextkey ((GDBM_FILE) d, key);
      free (key.dptr);
      key = nextkey;
    }
  return ANUBIS_DB_SUCCESS;
}

static int
gdbm_db_put (void *d, const char *keystr, ANUBIS_USER * rec, int *errp)
{
  size_t size, n;
  char *text;
  datum key, content;
  int rc;

  size = strlen (rec->smtp_passwd) + 1;
  if (rec->username)
    size += strlen (rec->username) + 1;
  if (rec->rcfile_name)
    {
      size += strlen (rec->rcfile_name);
      if (!rec->username)
	size += strlen (rec->smtp_authid) + 1;
    }
  text = xmalloc (size + 1);
  n = sprintf (text, "%s", rec->smtp_passwd);
  if (rec->username)
    n += sprintf (text + n, ",%s", rec->username);
  if (rec->rcfile_name)
    {
      if (!rec->username)
	n += sprintf (text + n, ",%s", rec->smtp_authid);
      n += sprintf (text + n, ",%s", rec->rcfile_name);
    }

  key.dptr = (char *) keystr;
  key.dsize = strlen (keystr);
  content.dptr = text;
  content.dsize = size;

  if (gdbm_store ((GDBM_FILE) d, key, content, GDBM_REPLACE))
    {
      *errp = gdbm_errno;
      rc = ANUBIS_DB_FAIL;
    }
  else
    rc = ANUBIS_DB_SUCCESS;
  free (text);
  return rc;
}

static int
gdbm_db_delete (void *d, const char *keystr, int *ecode)
{
  int rc;
  datum key;

  key.dptr = (char *) keystr;
  key.dsize = strlen (keystr);
  if (gdbm_delete ((GDBM_FILE) d, key))
    {
      *ecode = gdbm_errno;
      rc = ANUBIS_DB_FAIL;
    }
  else
    rc = ANUBIS_DB_SUCCESS;
  return rc;
}

const char *
gdbm_db_strerror (void *d, int rc)
{
  return gdbm_strerror (rc);
}

void
gdbm_db_init (void)
{
  anubis_db_register ("gdbm",
		      gdbm_db_open,
		      gdbm_db_close,
		      gdbm_db_get,
		      gdbm_db_put,
		      gdbm_db_delete, gdbm_db_list, gdbm_db_strerror);
}

#endif /* HAVE_LIBGDBM */

/* EOF */
