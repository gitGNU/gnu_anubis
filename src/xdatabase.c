/*
   xdatabase.c

   This file is part of GNU Anubis.
   Copyright (C) 2004 The Anubis Team.

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
#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>
#include "rcfile.h"

static int xdatabase_active = 0;

void
xdatabase_enable ()
{
  xdatabase_active = 1;
}

void
xdatabase_capability (char *reply, size_t reply_size)
{
  static char capa_string[] = "250-XDATABASE\r\n";
  size_t capa_len = strlen (capa_string);
  size_t len;
  char *p;

  if (!xdatabase_active)
    return;

  if (strlen (reply) + capa_len >= reply_size)
    {
      anubis_error (SOFT,
		    _("Cannot add capability: not enough buffer space."));
      return;
    }

  p = strstr (reply, "250 ");
  if (!p)
    {
      anubis_error (SOFT,
		    _
		    ("Cannot add capability: input string missing end marker"));
      return;
    }
  len = strlen (p);
  memmove (p + capa_len, p, len);
  memmove (p, capa_string, capa_len);
}

static FILE *
make_temp_file (struct obstack *stk, char *rcname, char **name)
{
  char nbuf[64];
  struct timeval tv;
  char *p;
  FILE *fp;
  int save_umask;

  obstack_grow (stk, rcname, strlen (rcname));
  obstack_1grow (stk, '.');
  p = get_localname ();
  obstack_grow (stk, p, strlen (p));

  gettimeofday (&tv, NULL);
  snprintf (nbuf, sizeof nbuf, ".%lu.%lu.", tv.tv_sec, tv.tv_usec);
  obstack_grow (stk, nbuf, strlen (nbuf));
  snprintf (nbuf, sizeof nbuf, "%lu", (unsigned long) getpid ());
  obstack_grow (stk, nbuf, strlen (nbuf));
  obstack_grow (stk, ".tmp", 5);

  p = *name = obstack_finish (stk);

  save_umask = umask (077);
  fp = fopen (p, "w");
  umask (save_umask);
  if (!fp)
    {
      anubis_error (SOFT,
		    _("Cannot open temporary file %s: %s"),
		    p, strerror (errno));
    }
  return fp;
}

#define ERROR_PREFIX "450-anubisrc:"

static void
_xdb_error_printer (void *data,
		    const char *filename, int line,
		    const char *fmt, va_list ap)
{
  struct obstack *stk = data;
  char buf[LINEBUFFER];
  int n;

  obstack_grow (stk, ERROR_PREFIX, sizeof ERROR_PREFIX - 1);
  n = snprintf (buf, sizeof buf, "%d: ", line);
  obstack_grow (stk, buf, n);
  n = vsnprintf (buf, sizeof buf, fmt, ap);
  obstack_grow (stk, buf, n);
  obstack_grow (stk, CRLF, 2);
}

static void
xupload ()
{
  int n;
  char *tempname;
  FILE *tempfile;
  char line[LINEBUFFER + 1];
  RC_SECTION *sec;
  struct obstack stk;
  char *rcname;

  obstack_init (&stk);

  rcname = user_rcfile_name ();
  tempfile = make_temp_file (&stk, rcname, &tempname);
  if (!tempfile)
    {
      swrite (SERVER, remote_client,
	      "450 Failed to create temporary file\r\n");
      free (rcname);
      obstack_free (&stk, NULL);
      return;
    }

  swrite (SERVER, remote_client,
	  "354 Enter configuration settings, end with \".\" on a line by itself\r\n");

  while ((n = recvline (SERVER, remote_client, line, sizeof (line) - 1)) > 0)
    {
      remcrlf (line);
      if (strcmp (line, ".") == 0)	/* EOM */
	break;
      fputs (line, tempfile);
      fputc ('\n', tempfile);
    }

  fclose (tempfile);

  /* Parse it */
  sec = rc_parse_ep (tempname, _xdb_error_printer, &stk);
  if (!sec)
    {
      char *errmsg;
      obstack_1grow (&stk, 0);
      errmsg = obstack_finish (&stk);
      swrite (SERVER, remote_client, "450-Configuration update failed" CRLF);
      swrite (SERVER, remote_client, errmsg);
      swrite (SERVER, remote_client, "450 Please fix and submit again" CRLF);
      unlink (tempname);
    }
  else
    {
      rc_section_list_destroy (&sec);
      if (rename (tempname, rcname))
	{
	  anubis_error (SOFT,
			_("Cannot rename %s to %s: %s"),
			tempname, rcname, strerror (errno));
	  swrite (SERVER, remote_client, "450 Cannot rename file" CRLF);
	}
      else
	{
	  open_rcfile (CF_CLIENT);
	  process_rcfile (CF_CLIENT);

	  swrite (SERVER, remote_client,
		  "250 Configuration update accepted" CRLF);
	}
    }
  free (rcname);
  obstack_free (&stk, NULL);
}

static void
xremove ()
{
  char *rcname = user_rcfile_name ();
  if (unlink (rcname) && errno != ENOENT)
    {
      anubis_error (SOFT,
		    _("Cannot unlink %s: %s"), rcname, strerror (errno));
      swrite (SERVER, remote_client, "450 Cannot unlink file" CRLF);
    }
  swrite (SERVER, remote_client, "250 Configuration settings dropped" CRLF);
  free (rcname);
}

static void
xexamine ()
{
  char *rcname = user_rcfile_name ();
  FILE *fp;

  fp = fopen (rcname, "r");
  if (!fp && errno != ENOENT)
    {
      anubis_error (SOFT, _("Cannot open %s: %s"), rcname, strerror (errno));
      swrite (SERVER, remote_client, "450 Cannot open file" CRLF);
    }
  else
    {
      char line[LINEBUFFER + 1];

      swrite (SERVER, remote_client, "250-Configuration settings follow\r\n");
      if (fp)
	{
	  while (fgets (line, sizeof line, fp))
	    {
	      remcrlf (line);
	      swrite (SERVER, remote_client, "250-");
	      swrite (SERVER, remote_client, line);
	      swrite (SERVER, remote_client, CRLF);
	    }
	  fclose (fp);
	}
      swrite (SERVER, remote_client, "250 End of configuration listing\r\n");
    }
  free (rcname);
}

static void
xerror (char *p)
{
  swrite (SERVER, remote_client, "501 XDATABASE syntax error\r\n");
}

/* Input: command string (lowercase)
   Return value: 0 -- not processed (the command will be passed to the
                 remote SMTP server.
                 1 -- processed (successfully or not) and replied to */

int
xdatabase (char *command)
{
  char *p;

  if (!xdatabase_active)
    return 0;

  remcrlf (command);
  for (p = command; *p && isspace (*p); p++)
    ;

  if (strcmp (p, "upload") == 0)
    xupload ();
  else if (strcmp (p, "remove") == 0)
    xremove ();
  else if (strcmp (p, "examine") == 0)
    xexamine ();
  else
    xerror (p);

  return 1;
}
