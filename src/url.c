/*
   url.c

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
#include <assert.h>

/* mech://[user[:password]@][host/]path[;arg=str[;arg=str...] */

static void
alloc_string (char **sptr, char *start, char *end)
{
  size_t len = end - start;
  *sptr = xmalloc (len + 1);
  memcpy (*sptr, start, len);
  (*sptr)[len] = 0;
}

static void
url_parse_arg (ASSOC * assoc, char *p, char *q)
{
  char *s;

  for (s = p; s < q && *s != '='; s++)
    ;

  alloc_string (&assoc->key, p, s);
  if (s != q)
    alloc_string (&assoc->value, s + 1, q);
}

static int
url_get_args (ANUBIS_URL * url, char **str)
{
  char *p;
  int argc;

  if (!**str)
    return 0;

  for (p = *str, argc = 1; *p; p++)
    if (*p == ';')
      argc++;

  url->argc = argc;
  url->argv = calloc (argc, sizeof (url->argv[0]));
  assert (url->argv != NULL);

  for (argc = 0, p = *str; *p; argc++)
    {
      char *q = strchr (p, ';');
      if (q)
	{
	  url_parse_arg (&url->argv[argc], p, q);
	  p = q + 1;
	}
      else
	{
	  q = p + strlen (p);
	  url_parse_arg (&url->argv[argc], p, q);
	  p = q;
	}
    }
  return 0;
}

static int
url_get_path (ANUBIS_URL * url, char **str)
{
  char *p;

  p = strchr (*str, ';');
  if (!p)
    p = *str + strlen (*str);
  alloc_string (&url->path, *str, p);
  *str = p;
  if (*p)
    ++ * str;
  return url_get_args (url, str);

}

/* On input str points at the beginning of host part */
static int
url_get_host (ANUBIS_URL * url, char **str)
{
  char *p;

  p = strchr (*str, '/');

  if (p)
    {
      alloc_string (&url->host, *str, p);
      *str = p + 1;
    }
  return url_get_path (url, str);
}

/* On input str points past the ':' */
static int
url_get_passwd (ANUBIS_URL * url, char **str)
{
  char *p;

  p = strchr (*str, '@');

  if (p)
    {
      alloc_string (&url->passwd, *str, p);
      *str = p + 1;
    }
  return url_get_host (url, str);
}

/* On input str points past the mech:// part */
static int
url_get_user (ANUBIS_URL * url, char **str)
{
  char *p;

  for (p = *str; *p && !strchr (":@", *p); p++)
    ;

  switch (*p)
    {
    case ':':
      alloc_string (&url->user, *str, p);
      *str = p + 1;
      return url_get_passwd (url, str);
    case '@':
      alloc_string (&url->user, *str, p);
      url->passwd = NULL;
      *str = p + 1;
    }
  return url_get_host (url, str);
}

static int
url_get_mech (ANUBIS_URL * url, char *str)
{
  char *p;

  if (!str)
    return 1;

  p = strchr (str, ':');
  if (!p)
    return 1;
  alloc_string (&url->method, str, p);

  /* Skip slashes */
  for (p++; *p == '/'; p++)
    ;
  return url_get_user (url, &p);
}

void
anubis_url_destroy (ANUBIS_URL ** url)
{
  int i;

  free ((*url)->method);
  free ((*url)->host);
  free ((*url)->path);
  free ((*url)->user);
  free ((*url)->passwd);
  for (i = 0; i < (*url)->argc; i++)
    {
      free ((*url)->argv[i].key);
      free ((*url)->argv[i].value);
    }
  free ((*url)->argv);
  free (*url);
  *url = NULL;
}

int
anubis_url_parse (ANUBIS_URL ** url, char *str)
{
  int rc;

  *url = xmalloc (sizeof (**url));
  memset (*url, 0, sizeof (**url));
  rc = url_get_mech (*url, str);
  if (rc)
    anubis_url_destroy (url);
  return rc;
}

char *
anubis_url_full_path (ANUBIS_URL * url)
{
  char *path;
  size_t size = 1;

  if (url->host)
    size += strlen (url->host);
  if (url->path)
    size += strlen (url->path) + 1;
  path = xmalloc (size + 1);
  if (url->host)
    {
      strcpy (path, "/");
      strcat (path, url->host);
    }
  if (url->path)
    {
      if (path[0])
	strcat (path, "/");
      strcat (path, url->path);
    }
  return path;
}

const char *
anubis_url_get_arg (ANUBIS_URL * url, const char *argname)
{
  int i;
  for (i = 0; i < url->argc; i++)
    {
      if (strcasecmp (url->argv[i].key, argname) == 0)
	return url->argv[i].value;
    }
  return NULL;
}
