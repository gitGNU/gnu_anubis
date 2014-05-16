/*
   regex.c

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

typedef int (*_match_fp) (RC_REGEX *, const char *,
			  int *, char ***, int *, int *);
typedef int (*_refcnt_fp) (RC_REGEX *);
typedef int (*_compile_fp) (RC_REGEX *, char *, int);
typedef void (*_free_fp) (RC_REGEX *);

struct regex_vtab
{
  int mask;
  _match_fp match;
  _refcnt_fp refcnt;
  _compile_fp compile;
  _free_fp free;
};

static int exact_compile (RC_REGEX *, char *, int);
static void exact_free (RC_REGEX *);
static int exact_match (RC_REGEX *, const char *,
			int *, char ***, int *, int *);
static int exact_refcnt (RC_REGEX *);

static int posix_compile (RC_REGEX *, char *, int);
static void posix_free (RC_REGEX *);
static int posix_match (RC_REGEX *, const char *,
			int *, char ***, int *, int *);
static int posix_refcnt (RC_REGEX *);
#ifdef HAVE_PCRE
static int perl_compile (RC_REGEX *, char *, int);
static void perl_free (RC_REGEX *);
static int perl_match (RC_REGEX *, const char *,
		       int *, char ***, int *, int *);
static int perl_refcnt (RC_REGEX *);
#endif /* HAVE_PCRE */

static struct regex_vtab vtab[] = {
  {R_EXACT, exact_match, exact_refcnt, exact_compile, exact_free},
#ifdef HAVE_PCRE
  {R_PERLRE, perl_match, perl_refcnt, perl_compile, perl_free},
#endif
  {R_POSIX, posix_match, posix_refcnt, posix_compile, posix_free},
  {0}
};

struct rc_regex
{				/* Regular expression */
  char *src;			/* Raw-text representation */
  int flags;			/* Compilation flags */
  union
  {
    regex_t re;			/* POSIX regex */
#ifdef HAVE_PCRE
    pcre *pre;			/* Perl */
#endif
  }
  v;
};

static struct regex_vtab *
regex_vtab_lookup (int flags)
{
  struct regex_vtab *p;

  for (p = vtab; p->mask; p++)
    if (p->mask & flags)
      break;
  if (p->mask == 0)
    return NULL;
  return p;
}


/* ************************** Interface Functions ************************** */
#define ASSERT_RE(re,vp) \
 if (!(re) || (vp = regex_vtab_lookup((re)->flags)) == NULL) {\
	anubis_error(EXIT_ABORT, 0,\
		    _("INTERNAL ERROR at %s:%d: missing or invalid regex"),\
                    __FILE__, __LINE__);\
 }

void
regex_print_flags (int flags)
{
  printf (":");
  if (flags & R_EXACT)
    printf ("exact");
  else if (flags & R_POSIX)
    printf ("posix");
  else if (flags & R_PERLRE)
    printf ("perl");

  if (flags & R_SCASE)
    printf (" :scase");
  if (flags & R_BASIC)
    printf (" :basic");
}

void
anubis_regex_print (RC_REGEX *re)
{
  regex_print_flags (re->flags);
  printf (" [%s]", anubis_regex_source (re));
}

int
anubis_regex_match (RC_REGEX *re, const char *line, int *refc, char ***refv)
{
  int so, eo;
  struct regex_vtab *vp;

  ASSERT_RE (re, vp);
  return vp->match (re, line, refc, refv, &so, &eo) == 0;
}

char *
anubis_regex_replace (RC_REGEX *re, char *line, char *repl)
{
  int so, eo;
  int refc;
  char **refv;
  char *newstr = NULL;
  char *savep = NULL;
  int newlen;
  int off = 0;
  int alloc = 0;
  struct regex_vtab *vp;

  ASSERT_RE (re, vp);
  while (vp->match (re, line + off, &refc, &refv, &so, &eo) == 0)
    {
      char *p;
      int plen;

      if (so == -1)
	{
	  char *q;

	  q = strstr (line + off, anubis_regex_source (re));

	  if (q)
	    {
	      alloc = 0;
	      p = repl;
	      so = (q - (line + off));
	      eo = so + strlen (anubis_regex_source (re));
	    }
	  else
	    {
	      char *x[2];

	      x[0] = line + off;
	      x[1] = NULL;

	      alloc = 1;
	      p = substitute (repl, x);
	      
	      so = 0;
	      eo = strlen (line + off);
	    }
	}
      else
	{
	  alloc = 1;
	  p = substitute (repl, refv);
	  argcv_free (-1, refv);
	}

      plen = strlen (p);
      
      savep = newstr;
      newlen = strlen (line) - (eo - so) + plen + 1;
      newstr = xmalloc (newlen);
      memcpy (newstr, line, off + so);
      memcpy (newstr + off + so, p, plen);
      strcpy (newstr + off + so + plen, line + off + eo);

      if (alloc)
	xfree (p);
      if (savep)
	xfree (savep);
      line = newstr;
      off += so;
    }
  return newstr;
}

int
anubis_regex_refcnt (RC_REGEX *re)
{
  struct regex_vtab *vp;

  ASSERT_RE (re, vp);
  return vp->refcnt (re);
}

RC_REGEX *
anubis_regex_compile (char *line, int opt)
{
  struct regex_vtab *vp = regex_vtab_lookup (opt);
  RC_REGEX *p;

  if (!vp)
    return 0;
  p = xmalloc (sizeof (*p));
  if (vp->compile (p, line, opt))
    {
      xfree (p);
    }
  else
    {
      p->src = strdup (line);
      p->flags = opt;
    }
  return p;
}

void
anubis_regex_free (RC_REGEX **pre)
{
  struct regex_vtab *vp;

  if (!*pre)
    return;
  ASSERT_RE (*pre, vp);
  free ((*pre)->src);
  vp->free (*pre);
  xfree (*pre);
}

char *
anubis_regex_source (RC_REGEX *re)
{
  if (!re)
    return NULL;
  return re->src;
}


/* **************************** Exact strings ***************************** */
static int
exact_compile (RC_REGEX *regex, char *line, int opt)
{
  return 0;
}

static void
exact_free (RC_REGEX *regex)
{
  /* nothing */
}


static int
exact_match (RC_REGEX *regex, const char *line, int *refc, char ***refv,
	     int *so, int *eo)
{
  int code;

  *eo = *so = -1;
  *refc = 0;
  *refv = NULL;

  if (regex->flags & R_SCASE)
    code = strcmp (line, regex->src);
  else
    code = strcasecmp (line, regex->src);
  return code;
}

static int
exact_refcnt (RC_REGEX *regex)
{
  return 0;
}



/* ********************* POSIX Regular Expressions ************************ */

static int
posix_compile (RC_REGEX *regex, char *line, int opt)
{
  int rc;
  int cflags = 0;

  if (!(opt & R_SCASE))
    cflags |= REG_ICASE;
  if (!(opt & R_BASIC))
    cflags |= REG_EXTENDED;

  rc = regcomp (&regex->v.re, line, cflags);
  if (rc)
    {
      char errbuf[512];
      regerror (rc, &regex->v.re, errbuf, sizeof (errbuf));
      anubis_error (0, 0, _("regcomp() failed at %s: %s."), line, errbuf);
    }
  return rc;
}

static void
posix_free (RC_REGEX *regex)
{
  regfree (&regex->v.re);
}

static int
posix_match (RC_REGEX *regex, const char *line, int *refc, char ***refv,
	     int *so, int *eo)
{
  regmatch_t *rmp;
  int rc;
  regex_t *re = &regex->v.re;

  rmp = xmalloc ((re->re_nsub + 1) * sizeof (*rmp));
  rc = regexec (re, line, re->re_nsub + 1, rmp, 0);
  if (rc == 0)
    {
      int i;
      *refv = xmalloc ((re->re_nsub + 2) * sizeof (**refv));
      *eo = rmp[0].rm_eo;
      *so = rmp[0].rm_so;
      for (i = 0; i <= re->re_nsub; i++)
	{
	  if (rmp[i].rm_so != -1)
	    {
	      size_t matchlen = rmp[i].rm_eo - rmp[i].rm_so;
	      (*refv)[i] = xmalloc (matchlen + 1);
	      memcpy ((*refv)[i], line + rmp[i].rm_so, matchlen);
	      (*refv)[i][matchlen] = 0;
	      remcrlf ((*refv)[i]);
	    }
	  else
	    (*refv)[i] = strdup ("");
	}
      (*refv)[i] = NULL;
      *refc = re->re_nsub;
    }
  else
    {
      *eo = *so = -1;
      *refc = 0;
    }
  xfree (rmp);
  return rc;
}

static int
posix_refcnt (RC_REGEX *regex)
{
  return regex->v.re.re_nsub;
}


/* ********************* PERL Regular Expressions ************************ */

#ifdef HAVE_PCRE

static int
perl_compile (RC_REGEX *regex, char *line, int opt)
{
  const char *error;
  int error_offset;
  int cflags = 0;

  if (!(opt & R_SCASE))
    cflags |= PCRE_CASELESS;
  regex->v.pre = pcre_compile (line, cflags, &error, &error_offset, 0);
  if (regex->v.pre == 0)
    {
      anubis_error (0, 0,
		    _("pcre_compile() failed at offset %d: %s."),
		    error_offset, error);
      return 1;
    }
  return 0;
}

static void
perl_free (RC_REGEX *regex)
{
    pcre_free (regex->v.pre);
}

static int
perl_match (RC_REGEX *regex, const char *line, int *refc, char ***refv,
	    int *so, int *eo)
{
  int rc;
  int ovsize, count;
  int *ovector;
  pcre *re = regex->v.pre;

  rc = pcre_fullinfo (re, NULL, PCRE_INFO_CAPTURECOUNT, &count);
  if (rc)
    {
      anubis_error (0, 0, _("pcre_fullinfo() failed: %d."), rc);
      return rc;
    }

  /* According to pcre docs: */
  ovsize = (count + 1) * 3;
  ovector = xmalloc (ovsize * sizeof (*ovector));

  rc = pcre_exec (re, 0, line, strlen (line), 0, 0, ovector, ovsize);
  if (rc == 0)
    {
      /* shouldn't happen, but still ... */
      anubis_error (0, 0, _("Matched, but too many substrings."));
      *so = *eo = -1;
      *refc = 0;
    }
  else if (rc > 0)
    {
      /* Collect captured substrings */
      int i;

      *refv = xmalloc ((rc + 1) * sizeof (**refv));
      for (i = 0; i < rc; i++)
	{
	  int c = pcre_get_substring (line, ovector, ovsize, i,
				      (const char **) &(*refv)[i]);
	  if (c < 0)
	    anubis_error (0, 0, _("Get substring %d failed (%d)."), i, c);
	}
      (*refv)[i] = NULL;
      *refc = count;
      *so = ovector[0];
      *eo = ovector[1];
    }
  else
    {
      *so = *eo = -1;
      *refc = 0;
    }
  xfree (ovector);
  return rc < 0;
}

static int
perl_refcnt (RC_REGEX *regex)
{
  int count = 0;

  pcre_fullinfo (regex->v.pre, NULL, PCRE_INFO_CAPTURECOUNT, &count);
  return count;
}
#endif /* HAVE_PCRE */

/* EOF */
