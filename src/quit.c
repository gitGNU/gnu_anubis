/*
   quit.c

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

RETSIGTYPE
sig_exit(int code)
{
	info(NORMAL, _("Signal Caught. Exiting Cleanly..."));
	quit(code);
}

RETSIGTYPE
sig_timeout(int code)
{
	info(NORMAL, _("Timeout! Exiting..."));
	quit(code);
}

void
free_mem(void)
{
#ifdef USE_SSL
	xfree(secure.cafile);
	xfree(secure.cert);
	xfree(secure.key);
#endif /* HAVE_TLS or HAVE_SSL */

#ifdef HAVE_GPG
	gpg_free();
#endif /* HAVE_GPG */

	xfree(options.ulogfile);
	xfree(options.tracefile);
	xfree(session.execpath);
	xfree_pptr(session.execargs);
}

void
quit(int code)
{
	memset(session.mta_username, 0, sizeof(session.mta_username));
	memset(session.mta_password, 0, sizeof(session.mta_password));

#ifdef USE_SSL
	/*FIXME!!!*/
	net_close_stream(&secure.client);
	net_close_stream(&secure.server);
#endif
#ifdef HAVE_SYSLOG
	if ((topt & T_DAEMON) && !(topt & T_FOREGROUND))
		closelog();
#endif /* HAVE_SYSLOG */

	free_mem();
	exit(code);
}

/* EOF */

