/*
   log.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003 The Anubis Team.

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
#include "rcfile.h"

void
mprintf (const char *fmt, ...)
{
  va_list arglist;

  if (options.termlevel == SILENT)
    return;

  va_start (arglist, fmt);
  vfprintf (stderr, fmt, arglist);
  va_end (arglist);
  fputc ('\n', stderr);
}

void
info (int mode, const char *fmt, ...)
{
  va_list arglist;
  char msg[LINEBUFFER + 1];

  if (mode > options.termlevel)
    return;

  va_start (arglist, fmt);
  vsnprintf (msg, LINEBUFFER, fmt, arglist);
  va_end (arglist);

#ifdef HAVE_SYSLOG
  if ((topt & T_DAEMON) && !(topt & T_FOREGROUND))
    {
      if (!(topt & T_DISABLE_SYSLOG))
	syslog (LOG_INFO | LOG_MAIL, "%s", msg);
      if (options.ulogfile && options.uloglevel >= ALL)
	filelog (options.ulogfile, msg);
    }
  else
#endif /* HAVE_SYSLOG */
  if (topt & T_FOREGROUND)
    mprintf ("> [%d] %s", (int) getpid (), msg);
  else
    mprintf ("> %s", msg);
}

void
filelog (char *logfile, char *msg)
{
  FILE *fplog;

  fplog = fopen (logfile, "a");
  if (fplog == NULL)
    return;
  else
    {
      time_t tp;
      struct tm *timeptr;
      char timebuf[65];
      memset (timebuf, 0, sizeof (timebuf));

      time (&tp);
      timeptr = localtime (&tp);
      strftime (timebuf, sizeof (timebuf) - 1,
		"%a, %d %b %Y %H:%M:%S", timeptr);
      fprintf (fplog, "%s [%d] %s\n", timebuf, (int) getpid (), msg);
      fclose (fplog);
    }
}

void
tracefile (RC_LOC * loc, const char *fmt, ...)
{
  va_list ap;
  int n = 0;
  char msg[LINEBUFFER + 1];

  if (!(topt & (T_TRACEFILE_SYS | T_TRACEFILE_USR)))
    return;

  if (loc)
    n = snprintf (msg, LINEBUFFER, "%s:%lu: ",
		  loc->file, (unsigned long) loc->line);
  va_start (ap, fmt);
  vsnprintf (msg + n, LINEBUFFER - n, fmt, ap);
  va_end (ap);

  if ((topt & T_TRACEFILE_SYS) && options.termlevel != SILENT)
    {
#ifdef HAVE_SYSLOG
      if ((topt & T_DAEMON) && !(topt & T_FOREGROUND))
	syslog (LOG_INFO | LOG_MAIL, "%s", msg);
      else
#endif /* HAVE_SYSLOG */
      if (topt & T_FOREGROUND)
	mprintf ("> [%d] %s", (int) getpid (), msg);
      else
	mprintf ("> %s", msg);
    }

  if (topt & T_TRACEFILE_USR)
    filelog (options.tracefile, msg);
}

/* EOF */
