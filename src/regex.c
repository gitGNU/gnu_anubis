/*
   regex.c

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

/****************************
 Regular Expressions support
*****************************/

static int posixre_match(char *, char *);
#ifdef HAVE_PCRE
static int perlre_match(char *, char *);
#endif /* HAVE_PCRE */

int
regex_match(char *regex, char *line)
{
	int rs = 0;

	#ifdef HAVE_PCRE
	if (ropt & R_PERLRE)
		rs = perlre_match(regex, line);
	else
	#endif /* HAVE_PCRE */
		rs = posixre_match(regex, line);

	ropt = 0;
	return rs;
}

static int
posixre_match(char *regex, char *line)
{
	int ret;
	int cflags = 0;
	regex_t preg;
	regmatch_t rm[10];

	if (!(ropt & R_BASIC))
		cflags |= REG_EXTENDED;
	if (!(ropt & R_SCASE)) /* case sensitive */
		cflags |= REG_ICASE;

	if ((ret = regcomp(&preg, regex, cflags))) {
		char string_error[256];
		regerror(ret, &preg, string_error, 255);
		anubis_error(SOFT, _("regcomp() failed. %s"), string_error);
		return 0;
	}
	if (preg.re_nsub > 9)
		preg.re_nsub = 9;
	ret = regexec(&preg, line, preg.re_nsub + 1, rm, 0);

	if (ret == 0 && preg.re_nsub > 0) {
		int i;
		xfree_pptr(submatch);
		submatch = xmalloc((preg.re_nsub + 2) * sizeof(*submatch));
		for (i = 0; i <= preg.re_nsub; i++)
		{
			if (rm[i].rm_so != -1) {
				size_t matchlen = rm[i].rm_eo - rm[i].rm_so;
				submatch[i] = xmalloc(matchlen + 1);
				strncpy(submatch[i], line + rm[i].rm_so, matchlen);
				remcrlf(submatch[i]);
			}
		}
	}
	regfree(&preg);

	if (ret == REG_NOMATCH)
		return 0;
	else
		return 1;
}

#ifdef HAVE_PCRE
static int
perlre_match(char *regex, char *line)
{
	pcre *re;
	const char *error;
	int cflags = 0;
	int error_offset;
	int rc;
	int offsets[45];
	int size_offsets = sizeof(offsets) / sizeof(int);

	if (!(ropt & R_SCASE)) /* case sensitive */
		cflags |= PCRE_CASELESS;

	re = pcre_compile(regex, cflags, &error, &error_offset, 0);
	if (re == 0) {
		anubis_error(SOFT, _("pcre_compile() failed at offset %d: %s."),
		error_offset, error);
		return 0;
	}
	rc = pcre_exec(re, 0, line, strlen(line), 0, 0, offsets, size_offsets);
	if (rc == 0) {
		anubis_error(SOFT, _("Matched, but too many substrings."));
		rc = size_offsets / 3;
	}
	if (rc > 1) { /* submatches */
		int i;
		int rs;
		if (rc > 9)
			rc = 9;
		xfree_pptr(submatch);
		submatch = xmalloc((rc + 2) * sizeof(*submatch));
		for (i = 0; i < rc; i++)
		{
			rs = pcre_get_substring(line, offsets, rc, i,
				(const char **)&submatch[i]);
			if (rs < 0)
				anubis_error(SOFT, _("Get substring %d failed (%d)."), i, rs);
		}
	}
	if (rc < 0) {
		switch(rc)
		{
			case PCRE_ERROR_NOMATCH:
				break;
			default:
				break;
		}
		return 0;
	}
	return 1;
}
#endif /* HAVE_PCRE */

/* EOF */

