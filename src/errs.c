/*
   errs.c

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

void
anubis_error(int method, char *format, ...)
{
	va_list arglist;

	switch (method) {
	case HARD:
		topt |= T_ERROR;
		break;
		
	case SOFT:
	case SYNTAX:
		topt &= ~T_ERROR;
		break;
	}

	if (topt & T_SMTP_ERROR_CODES) {
		fprintf(stdout, "451 4.0.0 ");
		va_start(arglist, format);
		vfprintf(stdout, format, arglist);
		va_end(arglist);
		fprintf(stdout, "\n");
		
	} else if (options.termlevel != SILENT) {
		char txt[LINEBUFFER+1];
	
		va_start(arglist, format);
		vsnprintf(txt, LINEBUFFER, format, arglist);
		va_end(arglist);
#ifdef HAVE_SYSLOG
		if ((topt & T_DAEMON) && !(topt & T_FOREGROUND)) {
			if (options.slogfile)
				filelog(options.slogfile, txt);
			else
				syslog(LOG_ERR | LOG_MAIL, txt);

			if (options.ulogfile && options.uloglevel >= FAILS)
				filelog(options.ulogfile, txt);
		}
		else
#endif /* HAVE_SYSLOG */
			if (topt & T_FOREGROUND)
				mprintf("%s[%d] %s",
					method == SYNTAX ? "" : ">>",
					(int)getpid(), txt);
			else
				mprintf("%s%s",
					method == SYNTAX ? "" : ">>",
					txt);
	}
	errno = 0;
	if (method != SYNTAX && !(topt & T_DAEMON) && !(topt & T_FOREGROUND))
		quit(EXIT_FAILURE);
	return;
}

void
socket_error(const char *msg)
{
	anubis_error(HARD, _("Couldn't write to socket: %s."),
		     msg ? msg : strerror(errno));
	return;
}

void
socks_error(char *txt)
{
	anubis_error(HARD, _("SOCKS proxy: %s"), txt);
	return;
}

void
hostname_error(char *host)
{
	if (h_errno == 0)
		return;

	if (h_errno == HOST_NOT_FOUND)
		anubis_error(HARD, _("Unknown host %s."), host);
	else if (h_errno == NO_ADDRESS)
		anubis_error(HARD,
		_("%s: host name is valid but does not have an IP address."), host);
	else if (h_errno == NO_RECOVERY)
		anubis_error(HARD,
		_("%s: unrecoverable name server error occured."), host);
	else if (h_errno == TRY_AGAIN)
		anubis_error(HARD,
		_("%s: a temporary name server error occured. Try again later."), host);
	else
		anubis_error(HARD, _("%s: unknown DNS error %d."), host, h_errno);

	h_errno = 0;
	return;
}

/* EOF */

