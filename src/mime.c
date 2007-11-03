/*
   mime.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003, 2004, 2007 The Anubis Team.

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

/*
  FIXME: Will add here further MIME support (see TODO file).
*/

static void
_append_text_file (MESSAGE * msg, char *filename, char *prefix)
{
  FILE *fptxt;
  char buf[LINEBUFFER + 1];
  unsigned long nbytes;
  unsigned long nlines = 0;
  char *p;

  fptxt = fopen (filename, "r");
  if (fptxt == 0)
    {
      anubis_error (0, errno, "%s", filename);
      return;
    }
  while (fgets (buf, LINEBUFFER, fptxt) != 0)
    nlines++;

  fseek (fptxt, 0L, SEEK_END);
  clearerr (fptxt);
  nbytes = ftell (fptxt);
  rewind (fptxt);
  nbytes = strlen (msg->body)
    + (prefix ? strlen (prefix) : 0) + nbytes + nlines + 1;

  msg->body = (char *) xrealloc ((char *) msg->body, nbytes);
  p = msg->body + strlen (msg->body);
  if (prefix)
    {
      strcpy (p, prefix);
      p += strlen (prefix);
    }
  while (fgets (buf, LINEBUFFER - 1, fptxt) != 0)
    {
      strcpy (p, buf);
      p += strlen (buf);
    }
  *p = 0;
  fclose (fptxt);
  return;
}

void
message_append_text_file (MESSAGE * msg, char *filename)
{
  _append_text_file (msg, filename, NULL);
}

void
message_append_signature_file (MESSAGE * msg)
{
  char homedir[MAXPATHLEN + 1];
  char signature_file[] = DEFAULT_SIGFILE;
  char *signature_path;
  size_t n;

  get_homedir (session.clientname, homedir, sizeof (homedir));

  n = strlen (homedir) + strlen (signature_file) + 2;
  signature_path = xmalloc (n);
  snprintf (signature_path, n - 1, "%s/%s", homedir, signature_file);

  _append_text_file (msg, signature_path, "-- \n");
  free (signature_path);
  return;
}

/* EOF */
