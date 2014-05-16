/*
   misc.c

   This file is part of GNU Anubis.
   Copyright (C) 2001-2014 The Anubis Team.

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

/* General-purpose function for use with list_destroy when deallocating
   simple lists */
int
anubis_free_list_item (void *item, void *data)
{
  free (item);
  return 0;
}

int
anubis_name_cmp (void *item, void *data)
{
  return strcmp (item, data);
}

/* String lists */

void
destroy_string_list (ANUBIS_LIST * plist)
{
  list_destroy (plist, anubis_free_list_item, NULL);
}

static int
_string_dup (void *item, void *data)
{
  list_append (data, xstrdup ((char*) item));
  return 0;
}

ANUBIS_LIST 
string_list_dup (ANUBIS_LIST orig)
{
  if (orig)
    {
      ANUBIS_LIST ptr = list_create ();
      list_iterate (orig, _string_dup, ptr);
      return ptr;
    }
  return NULL;
}


static int
_assoc_free (void *item, void *data)
{
  assoc_free (item);
  return 0;
}

void
destroy_assoc_list (ANUBIS_LIST *plist)
{
  list_destroy (plist, _assoc_free, NULL);
}

void
assoc_free (ASSOC * asc)
{
  free (asc->key);
  free (asc->value);
  free (asc);
}

static int
_assoc_dup (void *item, void *data)
{
  ASSOC *elt = item;
  ASSOC *newelt = xmalloc (sizeof (*newelt));

  newelt->key = xstrdup (elt->key);
  newelt->value = xstrdup (elt->value);
  list_append (data, newelt);
  return 0;
}
  
ANUBIS_LIST 
assoc_list_dup (ANUBIS_LIST orig)
{
  if (orig)
    {
      ANUBIS_LIST ptr = list_create ();
      list_iterate (orig, _assoc_dup, ptr);
      return ptr;
    }
  return NULL;
}

ASSOC *
header_assoc (char *line)
{
  char *p = strchr (line, ':');
  ASSOC *entry = xmalloc (sizeof (*entry));
  if (p)
    {
      int len = p - line;
      entry->key = xmalloc (len + 1);
      memcpy (entry->key, line, len);
      entry->key[len] = 0;
      for (p++; *p && isspace (*(u_char *) p); p++)
	;
      entry->value = strdup (p);
    }
  else
    {
      /* Malformed header. Save everything as rhs */
      entry->key = NULL;
      entry->value = strdup (line);
    }
  return entry;
}

char *
assoc_to_header (ASSOC * asc)
{
  char *buf;

  if (asc->key)
    {
      buf = xmalloc (strlen (asc->key) + strlen (asc->value) + 3);
      sprintf (buf, "%s: %s", asc->key, asc->value);
    }
  else
    buf = strdup (asc->value);
  return buf;
}

int
anubis_assoc_cmp (void *item, void *data)
{
  ASSOC *p = item;
  return strcmp (p->key, data);
}

static void
get_port_number (unsigned *port, char *str)
{
  char *p;
  unsigned short sp;
  unsigned long lp;
  
  sp = lp = strtoul (str, &p, 0);
  if (*p || sp != lp)
    anubis_error (1, 0, _("Invalid port number: %s"), str);
  *port = (unsigned) lp;
}

/****************************
 An extra port number parser
*****************************/

void
parse_mtaport (char *opt, char **host, unsigned int *port)
{
  struct servent *p;
  char *port_tmp = NULL;

  if ((port_tmp = strrchr (opt, ':')))
    {
      port_tmp++;
      if ((p = getservbyname (port_tmp, "tcp")))
	*port = ntohs (p->s_port);
      else
        get_port_number (port, port_tmp);
      assign_string_n (host, opt, port_tmp - opt - 1); 
    }
  else
    assign_string (host, opt); 
}

/**************************
 An extra host name parser
***************************/

void
parse_mtahost (char *opt, char **host, unsigned int *port)
{
  struct servent *p;
  char *port_tmp;

  if ((port_tmp = strrchr (opt, ':')))
    {
      port_tmp++;
      if ((p = getservbyname (port_tmp, "tcp")))
	*port = ntohs (p->s_port);
      else
        get_port_number (port, port_tmp);
      assign_string_n (host, opt, port_tmp - opt - 1);
    }
  else
    {				/* only port number available */
      if ((p = getservbyname (opt, "tcp")))
	*port = ntohs (p->s_port);
      else
        get_port_number (port, opt);
    }
}

/*********************
 Remove a single line
**********************/

void
remline (char *s, char *line)
{
  char *pos1 = NULL;
  char *pos2 = NULL;
  int len;

  if (!s || !line)
    return;
  pos1 = strstr (s, line);
  if (!pos1)
    return;

  pos2 = pos1;
  do
    {
      pos2++;
    }
  while (*pos2 != '\n');
  pos2++;
  len = strlen (pos2);
  pos2 = (char *) memmove (pos1, pos2, len);
  pos2[len] = '\0';
}

void
remcrlf (char *s)
{
  int len;

  if (!s)
    return;
  len = strlen (s);

  if (len >= 2 && s[len - 2] == '\r' && s[len - 1] == '\n')
    {				/* CRLF */
      s[len - 2] = '\0';
      s[len - 1] = '\0';
    }
  else if (len >= 2 && s[len - 2] != '\r' && s[len - 1] == '\n')	/* LF */
    s[len - 1] = '\0';
  else if (len >= 1 && s[len - 1] == '\r')	/* CR */
    s[len - 1] = '\0';
  else if (len >= 1 && s[len - 1] == '\n')	/* LF */
    s[len - 1] = '\0';
}

/***********************************
 Substitutions (RE back-references)
************************************/

static char *
insert (char *inbuf, char *sign, char *fill_in)
{
  int len1 = 0;
  int len2 = 0;
  int psign_len = 0;
  char *psign = NULL;
  char *outbuf = NULL;

  if (!inbuf || !sign || !fill_in)
    return NULL;

  psign = strstr (inbuf, sign);
  if (!psign)
    return NULL;

  psign_len = strlen (psign);
  len1 = strlen (inbuf);
  len1 -= psign_len;
  len2 = len1 + 1;
  len2 += strlen (fill_in);
  len2 += (psign_len - 2);

  outbuf = (char *) xmalloc (len2);
  memset (outbuf, 0, len2);
  psign += 2;

  strncpy (outbuf, inbuf, len1);
  strcat (outbuf, fill_in);
  strcat (outbuf, psign);

  if (strstr (outbuf, sign))
    {
      char *outbuf2 = insert (outbuf, sign, fill_in);
      free (outbuf);
      outbuf = outbuf2;
    }

  return outbuf;
}

char *
substitute (char *inbuf, char **subbuf)
{
  char **tmp = subbuf;
  char *tmpout = NULL;
  char *tmpbuf = NULL;
  char sign[5];
  int i = 0;

  if (!inbuf || !subbuf)
    return NULL;

  tmpbuf = xstrdup (inbuf);
  tmp++;
  while (*tmp)
    {
      snprintf (sign, 4, "\\%d", i + 1);
      tmpout = insert (tmpbuf, sign, *tmp);
      if (tmpout)
	{
	  tmpbuf = (char *) xrealloc ((char *) tmpbuf, strlen (tmpout) + 1);
	  strcpy (tmpbuf, tmpout);
	  free (tmpout);
	}
      tmp++;
      i++;
    }
  return tmpbuf;
}

/***************************
 Change the case of letters
****************************/

char *
make_lowercase (char *s)
{
  unsigned char *p;
  if (!s)
    return NULL;
  for (p = (unsigned char*) s; *p; p++)
    *p = tolower (*p);
  return s;
}

char *
make_uppercase (char *s)
{
  unsigned char *p;
  if (!s)
    return NULL;
  for (p = (unsigned char*) s; *p; p++)
    *p = toupper (*p);
  return s;
}

char *
get_localname (void)
{
  static char *localname = NULL;

  if (!localname)
    {
      char *name;
      int name_len = 256;
      int status = 1;
      struct hostent *hp;

      name = malloc (name_len);
      while (name
	     && (status = gethostname (name, name_len)) == 0
	     && !memchr (name, 0, name_len))
	{
	  name_len *= 2;
	  name = realloc (name, name_len);
	}
      if (status)
	{
	  info (NORMAL, _("Can't find out my own hostname"));
	  exit (1);
	}

      hp = gethostbyname (name);
      if (hp)
	{
	  struct in_addr inaddr;
	  inaddr.s_addr = *(unsigned int *) hp->h_addr;
	  hp = gethostbyaddr ((const char *) &inaddr,
			      sizeof (struct in_addr), AF_INET);
	  if (hp)
	    {
	      free (name);
	      name = strdup ((char *) hp->h_name);
	    }
	}
      localname = name;
    }
  return localname;
}

char *
get_localdomain (void)
{
  if (!anubis_domain)
    {
      char *localname = get_localname (), *p = strchr (localname, '.');
      if (!p)
	anubis_domain = strdup (localname);
      else
	anubis_domain = strdup (p + 1);
    }
  return anubis_domain;
}

void
assign_string (char **pstr, const char *s)
{
  free (*pstr);
  if (s)
    *pstr = xstrdup (s);
  else
    *pstr = NULL;
}

void
assign_string_n (char **pstr, const char *s, size_t length)
{
  free (*pstr);
  if (s)
    {
      *pstr = xmalloc (length + 1);
      memcpy (*pstr, s, length);
      (*pstr)[length] = 0;
    }
  else
    *pstr = NULL;
}

/* EOF */
