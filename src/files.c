/*
   files.c

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

static void append_text_file(void);
static void append_signature_file(char *);

void
check_all_files(char *user)
{
	if (mopt & M_BODYAPPEND)
		append_text_file();
	if (mopt & M_SIGNATURE)
		append_signature_file(user);
	return;
}

static void
append_text_file(void)
{
	FILE *fptxt;
	char buf[LINEBUFFER+1];
	unsigned long nbytes;
	unsigned long nlines = 0;

	fptxt = fopen(message.body_append, "r");
	if (fptxt == 0) {
		anubis_error(HARD, "%s: %s.", message.body_append, strerror(errno));
		return;
	}
	while (fgets(buf, LINEBUFFER, fptxt) != 0)
		nlines++;

	fseek(fptxt, 0L, SEEK_END);
	clearerr(fptxt);
	nbytes = ftell(fptxt);
	rewind(fptxt);
	nbytes = strlen(message.body) + nbytes + nlines + 3;

	message.body = (char *)xrealloc((char *)message.body, nbytes);
	strcat(message.body, CRLF);
	nbytes -= (strlen(message.body) + 1);
	while (fgets(buf, LINEBUFFER - 2, fptxt) != 0)
	{
		remcrlf(buf);
		strcat(buf, CRLF);
		strncat(message.body, buf, nbytes);
		nbytes -= strlen(buf);
	}
	fclose(fptxt);
	return;
}

static void
append_signature_file(char *user)
{
	int n;
	FILE *fpsig;
	unsigned long nbytes;
	unsigned long nlines = 0;
	char homedir[MAXPATHLEN+1];
	char buf[LINEBUFFER+1];
	char signature_file[] = DEFAULT_SIGFILE;
	char *signature_path = 0;

	get_homedir(user, homedir, sizeof(homedir));

	n = strlen(homedir) + strlen(signature_file) + 2;
	n = n > MAXPATHLEN ? MAXPATHLEN + 1 : n + 1;
	signature_path = (char *)xmalloc(n);
	#ifdef HAVE_SNPRINTF
	snprintf(signature_path, n - 1,
	#else
	sprintf(signature_path,
	#endif /* HAVE_SNPRINTF */
		"%s/%s", homedir, signature_file);

	fpsig = fopen(signature_path, "r");
	if (fpsig == 0) {
		anubis_error(HARD, "%s: %s.", signature_path, strerror(errno));
		return;
	}
	while (fgets(buf, LINEBUFFER, fpsig) != 0)
		nlines++;

	fseek(fpsig, 0L, SEEK_END);
	clearerr(fpsig);
	nbytes = ftell(fpsig);
	rewind(fpsig);
	nbytes = strlen(message.body) + nbytes + nlines + 10;

	message.body = (char *)xrealloc((char *)message.body, nbytes);
	strcat(message.body, CRLF"-- "CRLF);
	nbytes -= (strlen(message.body) + 1);
	while (fgets(buf, LINEBUFFER - 2, fpsig) != 0)
	{
		remcrlf(buf);
		strcat(buf, CRLF);
		strncat(message.body, buf, nbytes);
		nbytes -= strlen(buf);
	}
	strncat(message.body, CRLF, nbytes);
	free(signature_path);
	fclose(fpsig);
	return;
}

/* EOF */

