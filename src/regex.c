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
#include "rcfile.h"

#include <regex.h>
#ifdef HAVE_PCRE
# ifdef HAVE_PCRE_H
#  include <pcre.h>
# elif defined (HAVE_PCRE_PCRE_H)
#  include <pcre/pcre.h>
# endif
#endif

/****************************
 Regular Expressions support
*****************************/

struct rc_regex {            /* Regular expression */
	char *src;           /* Raw-text representation */  
#ifdef HAVE_PCRE
	int perlre;          /* Is it Perl style? */
#endif
	union {
		regex_t re;  /* POSIX regex */
#ifdef HAVE_PCRE
		pcre *pre;   /* Perl */
#endif
	} v;
};

static int posixre_match(char *, char *);
#ifdef HAVE_PCRE
static int perlre_match(char *, char *);
#endif /* HAVE_PCRE */

static int
_posix_match(regex_t *re, char *line, int *refc, char ***refv)
{
	regmatch_t *rmp;
	int rc;
		
	rmp = xmalloc((re->re_nsub + 1) * sizeof(*rmp));
	rc = regexec(re, line, re->re_nsub + 1, rmp, 0);
	if (rc == 0 && re->re_nsub) {
		int i;
		*refv = xmalloc((re->re_nsub + 2) * sizeof(**refv));
		for (i = 0; i <= re->re_nsub; i++) {
			if (rmp[i].rm_so != -1) {
				size_t matchlen = rmp[i].rm_eo - rmp[i].rm_so;
				(*refv)[i] = xmalloc(matchlen + 1);
				memcpy((*refv)[i], line + rmp[i].rm_so,
				       matchlen);
				(*refv)[i][matchlen] = 0;
				remcrlf((*refv)[i]);
			} else
				(*refv)[i] = strdup("");
		}
		(*refv)[i] = NULL;
		*refc = re->re_nsub;
	} else
		*refc = 0;
	xfree(rmp);
	return rc;
}

static int
_posix_refcnt(regex_t *re)
{
	return re->re_nsub;
}

#ifdef HAVE_PCRE
static int
_perl_match(pcre *re, char *line, int *refc, char ***refv)
{
	int rc;
	int ovsize, count;
	int *ovector;
	
	rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &count);
	if (rc) {
		anubis_error(SOFT,
			     _("pcre_fullinfo() failed: %d."), rc);
		return rc;
	}

	/* According to pcre docs: */
	ovsize = (count + 1) * 3;
	ovector = xmalloc(ovsize * sizeof(*ovector));
	
	rc = pcre_exec(re, 0, line, strlen(line), 0, 0,
		       ovector, ovsize);
	if (rc == 0) {
		/* shouldn't happen, but still ... */
		anubis_error(SOFT, _("Matched, but too many substrings."));
		count /= 3;
	} else if (rc < 0)
		count = 0;
	else
		rc = 0; /* indiocate the string is matched */
	
	if (count) {
		/* Collect captured substrings */
		int i;
		
		*refv = xmalloc((count + 1) * sizeof(**refv));
		for (i = 0; i < count; i++) {
			rc = pcre_get_substring(line, ovector, count, i,
						(const char **)&(*refv)[i]);
			if (rc < 0)
				anubis_error(SOFT,
				     _("Get substring %d failed (%d)."),
					     i, rc);
		}
		(*refv)[i] = NULL;
		*refc = count;
	} else		
		*refc = 0;
	xfree(ovector);
	return rc;
}

static int
_perl_refcnt(pcre *re)
{
	int count = 0;
	
	pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &count);
	return count;
}
#endif

int
anubis_regex_match(RC_REGEX *re, char *line, int *refc, char ***refv)
{
#ifdef HAVE_PCRE
	if (re->perlre)
		return !_perl_match(re->v.pre, line, refc, refv);
#endif
	return !_posix_match(&re->v.re, line, refc, refv);
}

int
anubis_regex_refcnt(RC_REGEX *re)
{
#ifdef HAVE_PCRE
	if (re->perlre)
		return _perl_refcnt(re->v.pre);
#endif
	return _posix_refcnt(&re->v.re);
}

RC_REGEX *
anubis_regex_compile(char *line, int opt)
{
	RC_REGEX *re;
	int cflags = 0;
	
	re = xmalloc(sizeof(*re));
#ifdef HAVE_PCRE
	if (opt & R_PERLRE) {
		const char *error;
		int error_offset;

		re->perlre = 1;
		
                if (!(opt & R_SCASE))
			cflags |= PCRE_CASELESS;
		re->v.pre = pcre_compile(line, cflags,
					 &error, &error_offset, 0);
		if (re->v.pre == 0) {
			anubis_error(SOFT,
				     _("pcre_compile() failed at offset %d: %s."),
				     error_offset, error);
			xfree(re);
			return NULL;
		}
	} else
#endif
	{
		int rc;
		
		if (opt & R_SCASE)
			cflags |= REG_ICASE;
		if (!(opt & R_BASIC))
			cflags |= REG_EXTENDED;
		
		rc = regcomp(&re->v.re, line, cflags);
		if (rc) {
			char errbuf[512];
			regerror(rc, &re->v.re, errbuf, sizeof(errbuf));
			anubis_error(SOFT,
				     _("regcomp() failed at %s: %s."),
				     line, errbuf);
			xfree(re);
			return NULL;
		}
	}

	re->src = strdup(line);
	return re;
}

void
anubis_regex_free(RC_REGEX *re)
{
	free(re->src);
#ifdef HAVE_PCRE
	if (re->perlre)
		pcre_free(re->v.pre);
	else
#endif
		regfree(&re->v.re);
	xfree(re);
}

char *
anubis_regex_source(RC_REGEX *re)
{
	return re->src;
}

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

