/*
   quit.c

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

RETSIGTYPE
sig_exit (int code)
{
  info (NORMAL, _("Signal Caught. Exiting Cleanly..."));
  quit (code);
}

RETSIGTYPE
sig_timeout (int code)
{
  info (NORMAL, _("Timeout! Exiting..."));
  quit (code);
}

void
free_mem (void)
{
#ifdef USE_GNUTLS
  xfree (secure.cafile);
  xfree (secure.cert);
  xfree (secure.key);
#endif /* USE_GNUTLS */

#ifdef HAVE_GPG
  gpg_free ();
#endif /* HAVE_GPG */

  xfree (options.ulogfile);
  xfree (options.tracefile);
  xfree (session.execpath);
  argcv_free (-1, session.execargs);
}

void
quit (int code)
{
  if ((topt & T_DAEMON) && !(topt & T_FOREGROUND))
    closelog ();
  free_mem ();
  exit (code);
}

/* EOF */
