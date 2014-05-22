/*
   dbtext.c

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

#ifdef WITH_GSASL

/* Open the plaintext database. ARG is the full pathname to the file */
static int
dbtext_open (void **dp, ANUBIS_URL * url, enum anubis_db_mode mode,
	     char const **errp)
{
  FILE *fp;
  char *tmode;
  char *path;

  switch (mode)
    {
    case anubis_db_rdonly:
      tmode = "r";
      break;

    case anubis_db_rdwr:
      tmode = "a+";
      break;

    default:
      *errp = strerror (EINVAL);
      return ANUBIS_DB_FAIL;
    }

  path = anubis_url_full_path (url);
  fp = fopen (path, tmode);
  free (path);
  if (!fp)
    {
      if (errp)
	*errp = strerror (errno);
      return ANUBIS_DB_FAIL;
    }
  *dp = fp;
  return ANUBIS_DB_SUCCESS;
}

static int
dbtext_close (void *d)
{
  fclose ((FILE *) d);
  return ANUBIS_DB_SUCCESS;
}

static char *
next_field (const char *text, const char **endp)
{
  const char *p;
  char *field;
  int length;
  int nescapes = 0;

  if (!text)
    return NULL;
  for (p = text; *p && *p != ':' && *p != '\n'; p++)
    if (*p == '\\' && p[1] == ':')
      {
	nescapes++;
	p++;
      }

  if (endp)
    *endp = p + 1;
  length = p - text - nescapes;
  if (length == 0)
    return NULL;
  field = xmalloc (length + 1);
  if (nescapes)
    {
      char *q;
      for (q = field, p = text; *p != ':'; )
	{
	  if (*p == '\\' && p[1] == ':')
	    p++;
	  *q++ = *p++;
	}
      *q = 0;
    }
  else
    {
      memcpy (field, text, length);
      field[length] = 0;
    }
  return field;
}

static void
put_field (FILE *fp, const char *text)  
{
  if (!text)
    return;
  for (; *text; text++)
    {
      if (*text == ':')
	fputc ('\\', fp);
      fputc (*text, fp);
    }
}

int
dbtext_to_record (const char *p, ANUBIS_USER *rec)
{
  memset (rec, 0, sizeof *rec);
  while (*p && isspace (*p))
    p++;
  if (*p == '#')
    return ANUBIS_DB_NOT_FOUND;
  rec->smtp_authid = next_field (p, &p); 
  if (!rec->smtp_authid)
    return ANUBIS_DB_NOT_FOUND;
  rec->smtp_passwd = next_field (p, &p); 
  if (!rec->smtp_passwd)
    {
      free (rec->smtp_authid);
      return ANUBIS_DB_FAIL;
    }
  rec->username = next_field (p, &p);
  rec->rcfile_name = next_field (p, &p); 
  return ANUBIS_DB_SUCCESS;
}

static int
dbtext_get (void *d, const char *key, ANUBIS_USER * rec, int *errp)
{
  FILE *fp = d;
  char buf[512], *p;

  memset (rec, 0, sizeof *rec);
  fseek (fp, 0, SEEK_SET);
  while ((p = fgets (buf, sizeof buf, fp)) != NULL)
    {
      char *kp;
      
      while (*p && isspace (*p))
	p++;
      if (*p == '#' || *p == 0)
	continue;
      kp = next_field (p, NULL);
      if (!kp || strcmp (kp, key))
	{
	  free (kp);
	  continue;
	}
      free (kp);
      return dbtext_to_record (buf, rec);
    }
  return ferror (fp) ? ANUBIS_DB_FAIL : ANUBIS_DB_NOT_FOUND;
}

static int
dbtext_put (void *d, const char *key, ANUBIS_USER *rec, int *errp)
{
  FILE *fp = d;
  put_field (fp, rec->smtp_authid);
  fputc (':', fp); 
  put_field (fp, rec->smtp_passwd);
  fputc (':', fp);
  put_field (fp, rec->username);
  fputc (':', fp);
  put_field (fp, rec->rcfile_name);
  fputc ('\n', fp);
  return ferror (fp) ? ANUBIS_DB_FAIL : ANUBIS_DB_SUCCESS;
}

static int
dbtext_list (void *d, ANUBIS_LIST  list, int *ecode)
{
  FILE *fp = d;
  char buf[512], *p;

  fseek (fp, 0, SEEK_SET);
  while ((p = fgets (buf, sizeof buf, fp)) != NULL)
    {
      ANUBIS_USER rec;
      if (dbtext_to_record (buf, &rec) == ANUBIS_DB_SUCCESS)
	{
	  ANUBIS_USER *prec = xmalloc (sizeof (*prec));
	  memcpy (prec, &rec, sizeof (*prec));
	  list_append (list, prec);
	}
    }
  return ANUBIS_DB_SUCCESS;
}

static int
dbtext_delete (void *d, const char *keystr, int *ecode)
{
  FILE *fp = d;
  char buf[512], *p;
  int rc = ANUBIS_DB_FAIL;

  fseek (fp, 0, SEEK_SET);
  while ((p = fgets (buf, sizeof buf, fp)) != NULL)
    {
      size_t len;
      char *kp;
      
      while (*p && isspace (*p))
	p++;
      if (*p == '#' || *p == 0)
	continue;

      kp = next_field (p, NULL);
      if (!kp || strcmp (kp, keystr))
	{
	  free (kp);
	  continue;
	}
      free (kp);
      len = strlen (buf);
      memset (buf, '#', len - 1);
      buf[len - 1] = 0;
      fseek (fp, -(off_t) len, SEEK_CUR);
      fputs (buf, fp);
      rc = ANUBIS_DB_SUCCESS;
      break;
    }

  return rc;
}

void
dbtext_init (void)
{
  anubis_db_register ("text",
		      dbtext_open,
		      dbtext_close,
		      dbtext_get,
		      dbtext_put, dbtext_delete, dbtext_list, NULL);
}

#endif /* WITH_GSASL */

/* EOF */
