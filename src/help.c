/*
   help.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003, 2004 The Anubis Team.

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
#ifdef HAVE_TLS
  "GNUTLS",
#endif				/* HAVE_TLS */
#ifdef HAVE_SSL
  "OPENSSL",
#endif				/* HAVE_SSL */
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

void
print_version (void)
{
  printf ("\n%s\n", version);
  puts (copyright);
  puts (_("\nGNU Anubis is free software; you can redistribute it and/or modify\n"
	  "it under the terms of the GNU General Public License as published by\n"
	  "the Free Software Foundation; either version 2 of the License, or\n"
	  "(at your option) any later version."));
  puts (_("\nGNU Anubis is distributed in the hope that it will be useful,\n"
	  "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
	  "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
	  "GNU General Public License for more details."));
  puts (_("\nYou should have received a copy of the GNU General Public License\n"
	  "along with GNU Anubis; if not, write to the Free Software\n"
	  "Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA"));
  puts (_("\nGNU Anubis is released under the GPL with the additional exemption that\n"
	  "compiling, linking, and/or using OpenSSL is allowed.\n"));
  exit (0);
}

void
print_usage (void)
{
  puts (_("Usage: anubis [options]\n"));
  puts (_(" -b, --bind [HOST:]PORT       Specify the TCP port on which GNU Anubis listens\n"
	  "                              for connections. The default HOST is INADDR_ANY,\n"
	  "                              and default PORT is 24 (private mail system)."));
  puts (_(" -r, --remote-mta HOST[:PORT] Specify a remote SMTP host name or IP address.\n"
	  "                              The default PORT number is 25."));
  puts (_(" -l, --local-mta FILE         Execute a local SMTP server, which works on\n"
	  "                              standard input and output (inetd-type program).\n"
	  "                              This option excludes the '--remote-mta' option."));
  puts (_(" -m, --mode=MODE              Select operation mode."));
  puts (_("                              MODE is either \"transparent\" or \"auth\""));
  puts (_(" -f, --foreground             Foreground mode."));
  puts (_(" -i, --stdio                  Use the SMTP protocol (OMP/Tunnel) as described\n"
	  "                              in RFC 821 on standard input and output."));
  puts (_("Output options:\n"));
  puts (_(" -s, --silent                 Work silently."));
  puts (_(" -v, --verbose                Work noisily."));
  puts (_(" -D, --debug                  Debug mode."));
  puts (_("\nMiscellaneous options:\n"));
  puts (_(" -c, --check-config           Run the configuration file syntax checker."));
  puts (_(" --show-config-options        Print a list of configuration options used\n"
	  "                              to build GNU Anubis."));
  puts (_(" --relax-perm-check           Do not check user configuration file permissions."));
  puts (_(" --altrc FILE                 Specify alternate system configuration file."));
  puts (_(" --norc                       Ignore system configuration file."));
  puts (_(" --version                    Print version number and copyright."));
  puts (_(" --help                       It's obvious..."));
  printf (_("\nReport bugs to <%s>.\n"), PACKAGE_BUGREPORT);
  exit (0);
}

/* EOF */
