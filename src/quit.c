/*
   quit.c

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

void
sig_exit(int code)
{
	info(NORMAL, _("Signal Caught. Exiting Cleanly..."));
	quit(code);
}

void
sig_timeout(int code)
{
	info(NORMAL, _("Timeout! Exiting..."));
	quit(code);
}

void
free_mem(void)
{
	xfree(message.body);
	xfree(message.body_append);
	xfree(message.boundary);
	xfree(rm.rrt);
	xfree(rm.post);
	xfree(rm.header);
	xfree(rm.gpg_file);
	xfree(rm.latent_time);

#if defined(HAVE_TLS) || defined(HAVE_SSL)
	xfree(secure.cafile);
	xfree(secure.cert);
	xfree(secure.key);
#endif /* HAVE_TLS or HAVE_SSL */

#ifdef HAVE_GPG
	xfree(gpg.keys);
	xfree(gpg.rm_key);
	if (gpg.passphrase) {
		memset(gpg.passphrase, 0, strlen(gpg.passphrase));
		xfree(gpg.passphrase);
	}
#endif /* HAVE_GPG */

	destroy_list(&session.transmap);
	xfree(options.slogfile);
	xfree(options.ulogfile);
	xfree(session.execpath);
	xfree_pptr(session.execargs);
	xfree_pptr(submatch);
	return;
}

void
quit(int code)
{
	memset(session.mta_username, 0, sizeof(session.mta_username));
	memset(session.mta_password, 0, sizeof(session.mta_password));

#ifdef HAVE_TLS
	end_tls(CLIENT, secure.client);
	end_tls(SERVER, secure.server);
	if (secure.xcred)
		gnutls_certificate_free_credentials(secure.xcred);
	if (secure.x509_cred)
		gnutls_certificate_free_credentials(secure.x509_cred);
	gnutls_global_deinit();
#endif /* HAVE_TLS */

#ifdef HAVE_SSL
	end_ssl(CLIENT, secure.client, secure.ctx_client);
	end_ssl(SERVER, secure.server, secure.ctx_server);
#endif /* HAVE_SSL */

#ifdef HAVE_SYSLOG
	if ((topt & T_DAEMON) && !(topt & T_FOREGROUND))
		closelog();
#endif /* HAVE_SYSLOG */

	free_mem();
	exit(code);
}

/* EOF */

