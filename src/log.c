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

void
mprintf(char *format, ...)
{
	va_list arglist;
	char txt[LINEBUFFER+1];

	if (options.termlevel == SILENT)
		return;

	va_start(arglist, format);
	#ifdef HAVE_VSNPRINTF
	vsnprintf(txt, LINEBUFFER,
	#else
	vsprintf(txt,
	#endif /* HAVE_VSNPRINTF */
		format, arglist);
	va_end(arglist);

	puts(txt);
	return;
}

void
info(int mode, char *format, ...)
{
	va_list arglist;
	char txt[LINEBUFFER+1];

	if (mode > options.termlevel)
		return;

	va_start(arglist, format);
	#ifdef HAVE_VSNPRINTF
	vsnprintf(txt, LINEBUFFER,
	#else
	vsprintf(txt,
	#endif /* HAVE_VSNPRINTF */
		format, arglist);
	va_end(arglist);

	#ifdef HAVE_SYSLOG
	if ((topt & T_DAEMON) && !(topt & T_FOREGROUND)) {
		if (options.slogfile)
			filelog(options.slogfile, txt);
		else
			syslog(LOG_INFO | LOG_MAIL, txt);

		if (options.ulogfile && options.uloglevel >= ALL)
			filelog(options.ulogfile, txt);
	}
	else
	#endif /* HAVE_SYSLOG */
		if (topt & T_FOREGROUND)
			mprintf("> [%d] %s", (int)getpid(), txt);
		else
			mprintf("> %s", txt);
	return;
}

void
filelog(char *logfile, char *txt)
{
	FILE *fplog;

	fplog = fopen(logfile, "a");
	if (fplog == 0)
		return;
	else {
		time_t tp;
		struct tm *timeptr;
		char timebuf[65];
		memset(timebuf, 0, sizeof(timebuf));

		time(&tp);
		timeptr = localtime(&tp);
		strftime(timebuf, sizeof(timebuf) - 1,
			"%a, %d %b %Y %H:%M:%S", timeptr);
		fprintf(fplog, "%s [%d] %s\n", timebuf, (int)getpid(), txt);
		fclose(fplog);
	}
	return;
}

/* EOF */

