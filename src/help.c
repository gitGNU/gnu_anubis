/*
   help.c

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

static char *config_opts[] = {
#ifdef HAVE_REGEX
  "REGEX",
#endif				/* HAVE_REGEX */
#ifdef HAVE_PCRE
  "PCRE",
#endif				/* HAVE_PCRE */
#ifdef WITH_GSASL
  "GSASL",
#endif				/* WITH_GSASL */
#ifdef WITH_MYSQL
  "MYSQL",
#endif				/* WITH_MYSQL */
#ifdef WITH_PGSQL
  "POSTGRES",
#endif			        /* WITH_PGSQL */
#ifdef WITH_GUILE
  "GUILE",
#endif				/* WITH_GUILE */
#ifdef USE_GNUTLS
  "GNUTLS",
#endif				/* USE_GNUTLS */
#ifdef HAVE_GPG
  "GPG",
#endif				/* HAVE_GPG */
#ifdef HAVE_PAM
  "PAM",
#endif				/* HAVE_PAM */
#ifdef USE_LIBWRAP
  "LIBWRAP",
#endif				/* USE_LIBWRAP */
#ifdef USE_SOCKS_PROXY
  "SOCKS",
#endif				/* USE_SOCKS_PROXY */
#ifdef ENABLE_NLS
  "NLS",
#endif				/* ENABLE_NLS */
  NULL
};

void
print_config_options (void)
{
  int i;
  for (i = 0; config_opts[i]; i++)
    puts (config_opts[i]);
  exit (0);
}

/* EOF */
