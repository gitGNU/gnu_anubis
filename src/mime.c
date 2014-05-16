/*
   mime.c

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

/*
  FIXME: Will add here further MIME support (see TODO file).
*/

struct append_closure
{
  const char *prefix;
  const char *filename;
};

static int
_append_proc (char **output, char *input, void *param)
{
  struct append_closure *clos = param;
  FILE *fptxt;
  char buf[LINEBUFFER + 1];
  size_t nbytes;
  size_t nlines = 0;
  char *p;

  fptxt = fopen (clos->filename, "r");
  if (fptxt == 0)
    {
      anubis_error (0, errno, "%s", clos->filename);
      return -1;
    }
  while (fgets (buf, LINEBUFFER, fptxt) != 0)
    nlines++;

  fseek (fptxt, 0L, SEEK_END);
  clearerr (fptxt);
  nbytes = ftell (fptxt);
  rewind (fptxt);
  
  nbytes = strlen (input)
            + (clos->prefix ? strlen (clos->prefix) : 0) + nbytes + nlines + 1;

  input = xrealloc (input, nbytes);
  *output = input;
  p = input + strlen (input);
  if (clos->prefix)
    {
      strcpy (p, clos->prefix);
      p += strlen (clos->prefix);
    }
  while (fgets (buf, LINEBUFFER - 1, fptxt) != 0)
    {
      strcpy (p, buf);
      p += strlen (buf);
    }
  *p = 0;
  return 0;
}

void
message_append_text_file (MESSAGE msg, char *filename, char *prefix)
{
  struct append_closure clos;
  clos.filename = filename;
  clos.prefix = prefix;
  message_proc_body (msg, _append_proc, &clos);
}

void
message_append_signature_file (MESSAGE msg)
{
  char homedir[MAXPATHLEN + 1];
  char signature_file[] = DEFAULT_SIGFILE;
  char *signature_path;
  size_t n;

  get_homedir (session.clientname, homedir, sizeof (homedir));

  n = strlen (homedir) + strlen (signature_file) + 2;
  signature_path = xmalloc (n);
  snprintf (signature_path, n - 1, "%s/%s", homedir, signature_file);

  message_append_text_file (msg, signature_path, "-- \n");
  free (signature_path);
  return;
}

/* EOF */
