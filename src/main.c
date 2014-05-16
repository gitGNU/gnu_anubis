/*
   GNU Anubis -- an SMTP message submission daemon.
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

ANUBIS_MODE anubis_mode = anubis_transparent;

const char version[] = "GNU Anubis v" VERSION;

struct options_struct options;
struct session_struct session;
#if defined(USE_GNUTLS)
struct secure_struct secure;
#endif /* USE_GNUTLS */

unsigned long topt;
NET_STREAM remote_client;
NET_STREAM remote_server;

char *anubis_domain;      /* Local domain for EHLO in authentication mode */
char *incoming_mail_rule; /* Name of section for incoming mail processing */
char *outgoing_mail_rule; /* Name of section for outgoing mail processing */
char *smtp_command_rule;  /* Name of section for rewriting SMTP commands */

void
xalloc_die ()
{
  anubis_error (EXIT_FAILURE, 0, "%s", _("Not enough memory"));
  abort ();
}

int
main (int argc, char *argv[])
{
  /*
     Signal handling.
   */
  signal (SIGILL, sig_exit);
  signal (SIGINT, sig_exit);
  signal (SIGTERM, sig_exit);
  signal (SIGHUP, sig_exit);
  signal (SIGQUIT, sig_exit);
  signal (SIGPIPE, SIG_IGN);
  signal (SIGALRM, sig_timeout);

  /* Native Language Support */

#ifdef ENABLE_NLS
  /* Set locale via LC_ALL.  */
#ifdef HAVE_SETLOCALE
  setlocale (LC_ALL, "");
#endif /* HAVE_SETLOCALE */
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif /* ENABLE_NLS */

  /* default values */

  options.termlevel = NORMAL;
  options.uloglevel = FAILS;
  session.anubis_port = 24;	/* private mail system */
  session.mta_port = 25;

#ifdef USE_SOCKS_PROXY
  session.socks_port = 1080;
#endif
  /*
     Process the command line options.
   */

  SETVBUF (stderr, NULL, _IOLBF, 0);
  get_options (argc, argv);
  anubis_getlogin (&session.supervisor);
  assign_string (&incoming_mail_rule, "INCOMING");
  assign_string (&outgoing_mail_rule, "RULE");
  assign_string (&smtp_command_rule, "SMTP");
  
  /*
     Initialize various database formats
   */

#ifdef WITH_GSASL
  dbtext_init ();
# ifdef HAVE_LIBGDBM
  gdbm_db_init ();
# endif
# ifdef WITH_MYSQL
  mysql_db_init ();
# endif
# ifdef WITH_PGSQL
  pgsql_db_init ();
# endif
#endif /* WITH_GSASL */

  /*
     Initialize the rc parsing subsystem.
     Read the system configuration file (SUPERVISOR).
   */

  rc_system_init ();

  if (topt & T_CHECK_CONFIG)
    {
      open_rcfile (CF_SUPERVISOR);
      exit (0);
    }
  if (!(topt & T_NORC))
    {
      open_rcfile (CF_SUPERVISOR);
      process_rcfile (CF_INIT);
    }

  /* DEBUG */

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)
  if (options.termlevel != DEBUG)
    {
      struct rlimit corelimit;
      if (getrlimit (RLIMIT_CORE, &corelimit) == 0)
	{
	  corelimit.rlim_cur = 0;
	  setrlimit (RLIMIT_CORE, &corelimit);
	}
    }
#endif /* HAVE_GETRLIMIT and HAVE_SETRLIMIT */

  info (VERBOSE, _("UID:%d (%s), GID:%d, EUID:%d, EGID:%d"),
	(int) getuid (), session.supervisor, (int) getgid (),
	(int) geteuid (), (int) getegid ());

  /*
     Initialize GnuTLS and the PRNG.
   */

#ifdef USE_SSL
  init_ssl_libs ();
#endif /* USE_SSL */

#ifdef WITH_GUILE
  init_guile ();
#endif
  
  /*
     Enter the main core...
   */

  if (anubis_mode == anubis_mda)  /* Mail Delivery Agent */
    mda ();
  else if (topt & T_STDINOUT)     /* stdin/stdout */
    stdinout ();
  else
    {				  /* daemon */
      int sd_bind;
      sd_bind = bind_and_listen (session.anubis, session.anubis_port);
      
      if (topt & T_FOREGROUND_INIT)
	topt |= T_FOREGROUND;
      else
	daemonize ();
      loop (sd_bind);
    }
  return 0;
}


/* EOF */
