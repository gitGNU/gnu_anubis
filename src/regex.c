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
#endif /* HAVE_PCRE */

/****************************
 Regular Expressions support
*****************************/

typedef int (*_match_fp) (RC_REGEX *, char *, int *, char ***, int *, int *);
typedef int (*_refcnt_fp) (RC_REGEX *);
typedef int (*_compile_fp) (RC_REGEX *, char *, int);
typedef void (*_free_fp) (RC_REGEX *);

struct regex_vtab {
 int mask;
 _match_fp  match;
 _refcnt_fp refcnt;
 _compile_fp compile;
 _free_fp free;
};

static int posix_compile(RC_REGEX *, char *, int);
static void posix_free(RC_REGEX *);
static int posix_match(RC_REGEX *, char *, int *, char ***, int *, int *);
static int posix_refcnt(RC_REGEX *);
#ifdef HAVE_PCRE
static int perl_compile(RC_REGEX *, char *, int);
static void perl_free(RC_REGEX *);
static int perl_match(RC_REGEX *, char *, int *, char ***, int *, int *);
static int perl_refcnt(RC_REGEX *);
#endif /* HAVE_PCRE */

static struct regex_vtab vtab[] = {
#ifdef HAVE_PCRE
	{ R_PERLRE, perl_match, perl_refcnt, perl_compile, perl_free },
#endif
	{ 0, posix_match, posix_refcnt, posix_compile, posix_free },
};
		
struct rc_regex {     /* Regular expression */
 char *src;           /* Raw-text representation */
 int flags;           /* Compilation flags */
 union {
  regex_t re;         /* POSIX regex */
#ifdef HAVE_PCRE
  pcre *pre;          /* Perl */
#endif
  } v;
};

static struct regex_vtab *
regex_vtab_lookup(int flags)
{
	struct regex_vtab *p;

	for (p = vtab; p->mask; p++)
		if (p->mask & flags)
			break;
	return p;
}


/* ************************** Interface Functions ************************** */
int
anubis_regex_match(RC_REGEX *re, char *line, int *refc, char ***refv)
{
	int so, eo;
	struct regex_vtab *vp = regex_vtab_lookup(re->flags);
	if (!vp)
		return -1;
	return vp->match(re, line, refc, refv, &so, &eo) == 0;
}

char *
anubis_regex_replace(RC_REGEX *re, char *line, char *repl)
{
	int so, eo;
	int refc;
	char **refv;
	struct regex_vtab *vp = regex_vtab_lookup(re->flags);
	
	if (!vp)
		return NULL;
	if (vp->match(re, line, &refc, &refv, &so, &eo) == 0) {
		char *p = substitute(repl, refv);
		int plen = strlen(p);
		int newlen = strlen(line) - (eo - so) + plen + 1;
		char *newstr = xmalloc(newlen);

		memcpy(newstr, line, so);
		memcpy(newstr + so, p, strlen(p));
		strcpy(newstr + so + plen, line + eo);

		xfree_pptr(refv);
		return newstr;
	}
	return NULL;
}

int
anubis_regex_refcnt(RC_REGEX *re)
{
	struct regex_vtab *vp = regex_vtab_lookup(re->flags);
	if (!vp)
		return 0;
	return vp->refcnt(re);
}

RC_REGEX *
anubis_regex_compile(char *line, int opt)
{
	struct regex_vtab *vp = regex_vtab_lookup(opt);
	RC_REGEX *p;
	if (!vp)
		return 0;
	p = xmalloc(sizeof(*p));
	if (vp->compile(p, line, opt)) {
		xfree(p);
		p = NULL;
	} else {
		p->src = strdup(line);
		p->flags = opt;
	}
	return p;
}

void
anubis_regex_free(RC_REGEX *re)
{
	struct regex_vtab *vp = regex_vtab_lookup(re->flags);
	free(re->src);
	if (vp)
		vp->free(re);
	xfree(re);
}

char *
anubis_regex_source(RC_REGEX *re)
{
	return re->src;
}


/* ********************* POSIX Regular Expressions ************************ */

static int
posix_compile(RC_REGEX *regex, char *line, int opt)
{
	int rc;
	int cflags = 0;
	
	if (opt & R_SCASE)
		cflags |= REG_ICASE;
	if (!(opt & R_BASIC))
		cflags |= REG_EXTENDED;
		
	rc = regcomp(&regex->v.re, line, cflags);
	if (rc) {
		char errbuf[512];
		regerror(rc, &regex->v.re, errbuf, sizeof(errbuf));
		anubis_error(SOFT,
			     _("regcomp() failed at %s: %s."),
			     line, errbuf);
	}
	return rc;
}	

static void
posix_free(RC_REGEX *regex)
{
	regfree(&regex->v.re);
}

static int
posix_match(RC_REGEX *regex, char *line, int *refc, char ***refv,
	    int *so, int *eo)
{
	regmatch_t *rmp;
	int rc;
	regex_t *re = &regex->v.re;
	
	rmp = xmalloc((re->re_nsub + 1) * sizeof(*rmp));
	rc = regexec(re, line, re->re_nsub + 1, rmp, 0);
	if (rc == 0 && re->re_nsub) {
		int i;
		*refv = xmalloc((re->re_nsub + 2) * sizeof(**refv));
		*eo = rmp[0].rm_eo;
		*so = rmp[0].rm_so;
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
posix_refcnt(RC_REGEX *regex)
{
	return regex->v.re.re_nsub;
}


/* ********************* PERL Regular Expressions ************************ */

#ifdef HAVE_PCRE

static int
perl_compile(RC_REGEX *regex, char *line, int opt)
{
	const char *error;
	int error_offset;
	int cflags = 0;
	
	if (!(opt & R_SCASE))
		cflags |= PCRE_CASELESS;
	regex->v.pre = pcre_compile(line, cflags, &error, &error_offset, 0);
	if (regex->v.pre == 0) {
		anubis_error(SOFT,
			     _("pcre_compile() failed at offset %d: %s."),
			     error_offset, error);
		return 1;
	}
	return 0;
}

static void
perl_free(RC_REGEX *regex)
{
	pcre_free(regex->v.pre);
}

static int
perl_match(RC_REGEX *regex, char *line, int *refc, char ***refv,
	   int *so, int *eo)
{
	int rc;
	int ovsize, count;
	int *ovector;
	pcre *re = regex->v.pre;
	
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
	} else if (rc > 0) {
		/* Collect captured substrings */
		int i;
		
		*refv = xmalloc((rc + 1) * sizeof(**refv));
		for (i = 0; i < rc; i++) {
			int c = pcre_get_substring(line, ovector, ovsize, i,
						   (const char **)&(*refv)[i]);
			if (c < 0)
				anubis_error(SOFT,
					  _("Get substring %d failed (%d)."),
					     i, c);
		}
		(*refv)[i] = NULL;
		*refc = count;
		*so = ovector[0];
		*eo = ovector[1];
	} else		
		*refc = 0;
	xfree(ovector);
	return rc < 0;
}

static int
perl_refcnt(RC_REGEX *regex)
{
	int count = 0;
	
	pcre_fullinfo(regex->v.pre, NULL, PCRE_INFO_CAPTURECOUNT, &count);
	return count;
}
#endif /* HAVE_PCRE */

/* EOF */

