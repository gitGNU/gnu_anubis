/*
   anubisusr.h
   
   Copyright (C) 2004-2014 The Anubis Team.

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
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include "headers.h"
#include "extern.h"
#include "rcfile.h"
#include <gsasl.h>
#include "getopt.h"

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

#if defined(USE_GNUTLS)
# include <gnutls/gnutls.h>
# define HAVE_TLS
#endif /* USE_GNUTLS */

extern char *tls_cafile;
extern int enable_tls;
extern char *rcfile_name;
extern char *netrc_name;
extern int verbose;

void add_mech (char *arg);
void usr_get_options (int argc, char *argv[], int *index);

