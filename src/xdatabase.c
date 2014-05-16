/*
   xdatabase.c

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
xdatabase_capability (ANUBIS_SMTP_REPLY reply)
{
  if (!smtp_reply_has_capa (reply, "XDATABASE", NULL))
    smtp_reply_add_line (reply, "XDATABASE");
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
  if (!fp)
    anubis_error (0, errno, _("Cannot open temporary file %s: %s"),
		  p, strerror (errno));

  umask (save_umask);
  return fp;
}

#define ERROR_PREFIX "450-anubisrc:"

static void
_xdb_error_printer (void *data,
		    struct rc_loc *loc,
		    const char *pfx,
		    const char *fmt, va_list ap)
{
  struct obstack *stk = data;
  char buf[LINEBUFFER];
  int n;

  obstack_grow (stk, ERROR_PREFIX, sizeof ERROR_PREFIX - 1);
  /* FIXME: column? */
  n = snprintf (buf, sizeof buf, "%lu", (unsigned long)loc->line);
  obstack_grow (stk, buf, n);
  if (topt & T_LOCATION_COLUMN)
    {
      n = snprintf (buf, sizeof buf, ".%lu", (unsigned long)loc->column);
      obstack_grow (stk, buf, n);
    }
  obstack_grow (stk, ": ", 2);
  if (pfx)
    {
      obstack_grow (stk, pfx, strlen (pfx));
      obstack_grow (stk, ": ", 2);
    }
  n = vsnprintf (buf, sizeof buf, fmt, ap);
  obstack_grow (stk, buf, n);
  obstack_grow (stk, CRLF, 2);
}

static void
xupload ()
{
  char *tempname;
  FILE *tempfile;
  char *line = NULL;
  size_t size = 0;
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

  while (recvline (SERVER, remote_client, &line, &size) > 0)
    {
      remcrlf (line);
      if (strcmp (line, ".") == 0)	/* EOM */
	break;
      fputs (line, tempfile);
      fputc ('\n', tempfile);
    }
  free (line);  

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
	  anubis_error (0, errno, _("Cannot rename %s to %s"),
			tempname, rcname);
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
      anubis_error (0, errno, _("Cannot unlink %s"), rcname);
      swrite (SERVER, remote_client, "450 Cannot unlink file" CRLF);
    }
  swrite (SERVER, remote_client, "250 Configuration settings dropped" CRLF);
  free (rcname);
}

static void
xexamine ()
{
  char *rcname = user_rcfile_name ();
  int fd = open (rcname, O_RDONLY);
  if (fd == -1)
    {
      if (errno == ENOENT)
	swrite (SERVER, remote_client,
		"300 Configuration file does not exist" CRLF);
      else
	{
	  anubis_error (0, errno, _("Cannot open %s"), rcname);
	  swrite (SERVER, remote_client, "450 Cannot open file" CRLF);
	}
    }
  else
    {
      unsigned char digest[MD5_DIGEST_BYTES];
      unsigned char hex[2*MD5_DIGEST_BYTES+1];
      
      anubis_md5_file (digest, fd);
      close (fd);

      memset (hex, 0, sizeof hex); 
      string_bin_to_hex (hex, digest, sizeof digest);
      swrite (SERVER, remote_client, "250 ");
      swrite (SERVER, remote_client, (char*) hex);
      swrite (SERVER, remote_client, CRLF);
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

  if (!command || !xdatabase_active)
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
