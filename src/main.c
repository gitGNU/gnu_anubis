/*
   GNU Anubis v3.9.0 -- an outgoing mail processor and the SMTP tunnel.
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

const char version[] = "GNU Anubis v"VERSION;
const char copyright[] = "Copyright (C) 2001, 2002, 2003 The Anubis Team.";

struct options_struct options;
struct session_struct session;
struct rm_struct rm;
#if defined(HAVE_TLS) || defined(HAVE_SSL)
struct secure_struct secure;
#endif /* HAVE_TLS or HAVE_SSL */

unsigned long topt;
void *remote_client;
void *remote_server;

#ifdef WITH_GUILE
void
anubis_core()
{
	char *argv[] = { "anubis", NULL };
	scm_boot_guile (1, argv, anubis_boot, NULL);
}
#else
# define anubis_core() anubis(NULL)
#endif /* WITH_GUILE */

int
main(int argc, char *argv[])
{
	/*
	   Signal handling.
	*/

	signal(SIGILL,  sig_exit);
	signal(SIGINT,  sig_exit);
	signal(SIGTERM, sig_exit);
	signal(SIGHUP,  sig_exit);
	signal(SIGQUIT, sig_exit);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, sig_timeout);

	/* Native Language Support */

#ifdef ENABLE_NLS
	 /* Set locale via LC_ALL.  */
#ifdef HAVE_SETLOCALE
	  setlocale(LC_ALL, "");
#endif /* HAVE_SETLOCALE */
	 bindtextdomain(PACKAGE, LOCALEDIR);
	 textdomain(PACKAGE);
#endif /* ENABLE_NLS */

	/* default values */

	options.termlevel = NORMAL;
	options.uloglevel = FAILS;
	session.tunnel_port = 24; /* private mail system */
	session.mta_port = 25;
	session.socks_port = 1080;

	/*
	   Process the command line options.
	*/

	get_options(argc, argv);
	anubis_getlogin(session.supervisor, sizeof(session.supervisor));

	/*
	   Initialize the rc parsing subsystem.
	   Read the system configuration file (SUPERVISOR).
	*/

	rc_system_init();

	if (topt & T_CHECK_CONFIG) {
		open_rcfile(CF_SUPERVISOR);
		exit(0);
	}
	if (!(topt & T_NORC)) {
		open_rcfile(CF_SUPERVISOR);
		process_rcfile(CF_INIT);
	}

	/* DEBUG */

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)
	if (options.termlevel != DEBUG) {
		struct rlimit corelimit;
		if (getrlimit(RLIMIT_CORE, &corelimit) == 0) {
			corelimit.rlim_cur = 0;
			setrlimit(RLIMIT_CORE, &corelimit);
		}
	}
#endif /* HAVE_GETRLIMIT and HAVE_SETRLIMIT */

	info(DEBUG, _("UID:%d, GID:%d, EUID:%d, EGID:%d"), (int)getuid(),
		(int)getgid(), (int)geteuid(), (int)getegid());

	/*
	   Initialize GnuTLS or OpenSSL library and the PRNG.
	*/

#ifdef HAVE_TLS
	init_tls_libs();
#endif /* HAVE_TLS */

#ifdef HAVE_SSL
	init_ssl_libs();
#endif /* HAVE_SSL */

	/*
	   Enter the main core...
	*/

	anubis_core();
	return 0;
}

void
anubis(char *arg)
{	
	if (topt & T_STDINOUT) { /* stdin/stdout */
		if (options.termlevel != DEBUG)
			options.termlevel = SILENT;
		topt &= ~T_SSL;
		topt |= T_FOREGROUND;
		stdinout();
	}
	else { /* daemon */
		int sd_bind;
		sd_bind = bind_and_listen(session.tunnel, session.tunnel_port);
		if (topt & T_FOREGROUND_INIT)
			topt |= T_FOREGROUND;
		else
			daemonize();
		loop(sd_bind);
	}
}

/* EOF */

