/*
   daemon.c

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

/* TCP wrappers */
#ifdef USE_LIBWRAP
 #include <tcpd.h>
 int deny_severity = LOG_INFO;
 int allow_severity = LOG_INFO;
#endif /* USE_LIBWRAP */

static void sig_cld(int);
static void service_unavailable(int);
static void set_unprivileged_user(void);

static int nchild;

/************
  DAEMONIZE
*************/

void
daemonize(void)
{
	#ifdef HAVE_DAEMON
	if (daemon(0, 0) == -1)
		anubis_error(HARD, _("daemon() failed. %s."), strerror(errno));
	#else
	chdir("/");
	umask(0);
	switch(fork())
	{
		case -1: /* fork() failed */
			anubis_error(HARD, _("Can't fork. %s."), strerror(errno));
			break;
		case 0: /* child process */
			break;
		default: /* parent process */
			quit(0);
	}
	if (setsid() == -1)
		anubis_error(HARD, _("setsid() failed."));

	close(0);
	close(1);
	close(2);
	#endif /* HAVE_DAEMON */

	signal(SIGHUP, SIG_IGN);
	topt |= T_DAEMON;

	#ifdef HAVE_SYSLOG
	openlog("anubis", LOG_PID, 0);
	syslog(LOG_INFO, _("%s daemon startup succeeded."), version);
	#endif /* HAVE_SYSLOG */

	return;
}

static void
sig_cld(int code)
{
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
	{
		nchild--;
		info(VERBOSE, _("Child [%d] finished. Exit status: %s. %d client(s) left."),
			pid, WIFEXITED(status) ? _("OK") : _("ERROR"), nchild);
	}
	return;
}

/************************************
 If a service is not available,
 then close a transmission channel.
*************************************/

static void
service_unavailable(int sd_client)
{
	char buf[LINEBUFFER+1];

	#ifdef HAVE_SNPRINTF
	snprintf(buf, LINEBUFFER,
	#else
	sprintf(buf,
	#endif /* HAVE_SNPRINTF */
	"421 %s Service not available, closing transmission channel."CRLF,
		(topt & T_LOCAL_MTA) ? "localhost" : session.mta);

	swrite(SERVER, (void *)sd_client, buf);
	close_socket(sd_client);
	return;
}

/*************************
 Set an unprivileged user
 (if possible).
**************************/

static void
set_unprivileged_user(void)
{
	if (topt & T_USER_NOTPRIVIL) {
		if (check_username(session.notprivileged))
			anubis_changeowner(session.notprivileged);
	}
	else
		info(NORMAL, _("WARNING: An unprivileged user has not been specified!"));
	return;
}

/**************
  DAEMON loop
***************/

void
loop(int sd_bind)
{
	struct sockaddr_in addr;
	pid_t childpid = 0;
	int sd_client = 0;
	int sd_server = 0;
	#ifdef __socklen_t_defined
	socklen_t addrlen;
	#else
	int addrlen;
	#endif /* __socklen_t_defined */
	#ifdef USE_LIBWRAP
	struct request_info req;
	#endif /* USE_LIBWRAP */
	#ifdef HAVE_PAM
	int pam_retval;
	#endif /* HAVE_PAM */

	addrlen = sizeof(addr);
	signal(SIGCHLD, sig_cld);

	info(VERBOSE, _("GNU Anubis is running..."));

	for (;;)
	{
		sd_client = accept(sd_bind, (struct sockaddr *)&addr, &addrlen);
		if (sd_client < 0) {
			if (errno == EINTR)
				continue;
			else {
				anubis_error(SOFT, _("accept() failed: %s."), strerror(errno));
				continue;
			}
		}

		/*
		   Check the TCP wrappers settings.
		*/

		#ifdef USE_LIBWRAP
		request_init(&req, RQ_DAEMON, "anubis", RQ_FILE, sd_client, 0);
		fromhost(&req);
		if (hosts_access(&req) == 0) {
			info(NORMAL, _("TCP wrappers: connection from %s:%u rejected."),
				inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			service_unavailable(sd_client);
			continue;
		}
		#endif /* USE_LIBWRAP */

		/*
		   Read the system configuration file (SUPERVISOR).
		*/

		if (!(topt & T_NORC)) {
			open_rcfile(SUPERVISOR);
			read_rcfile(SUPERVISOR);
			close_rcfile(); /* SUPERVISOR */
		}

		nchild++;
		if (nchild > MAXCLIENTS) {
			info(NORMAL, _("Too many clients. Connection from %s:%u rejected."),
				inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			service_unavailable(sd_client);
			nchild--;
		}
		else {
			info(NORMAL, _("Connection from %s:%u"),
				inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

			childpid = fork();
			if (childpid == -1)
				anubis_error(HARD, _("daemon: Can't fork. %s."), strerror(errno));
			else if (childpid == 0) { /* a child process */
				int rs = 0;
				signal(SIGCHLD, SIG_IGN);

				rs = auth_ident(&addr, session.client, sizeof(session.client));

				if (topt & T_TRANSLATION_MAP) {
					int cs = 0;
					if (rs)
						parse_transmap(&cs, session.client, inet_ntoa(addr.sin_addr),
							session.client, sizeof(session.client));
					else
						parse_transmap(&cs, 0, inet_ntoa(addr.sin_addr),
							session.client, sizeof(session.client));

					if (cs == 1) {
						topt |= T_SUPERCLIENT;
						anubis_changeowner(session.client);
						auth_tunnel();
					}
					else if (rs && cs == -1
					&& ntohl(addr.sin_addr.s_addr) == INADDR_LOOPBACK) {
						if (check_username(session.client)) {
							topt |= T_SUPERCLIENT;
							anubis_changeowner(session.client);
							auth_tunnel();
						}
						else
							set_unprivileged_user();
					}
					else
						set_unprivileged_user();
				}
				else {
					if (rs && ntohl(addr.sin_addr.s_addr) == INADDR_LOOPBACK) {
						if (check_username(session.client)) {
							topt |= T_SUPERCLIENT;
							anubis_changeowner(session.client);
							auth_tunnel();
						}
						else
							set_unprivileged_user();
					}
					else
						set_unprivileged_user();
				}

				if (!(topt & T_LOCAL_MTA) && (strlen(session.mta) == 0)) {
					anubis_error(HARD, _("The MTA has not been specified. "
						"Set the REMOTE-MTA or LOCAL-MTA."));
					close_socket(sd_client);
					quit(EXIT_FAILURE);
				}

				/*
				   Protection against a loop connection.
				*/

				if (!(topt & T_LOCAL_MTA)) {
					unsigned long inaddr;
					struct sockaddr_in ad;

					memset(&ad, 0, sizeof(ad));
					inaddr = inet_addr(session.mta);
					if (inaddr != INADDR_NONE)
						memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
					else {
						struct hostent *hp = 0;
						hp = gethostbyname(session.mta);
						if (hp == 0) {
							hostname_error(session.mta);
							close_socket(sd_client);
							quit(EXIT_FAILURE);
						}
						else {
							if (hp->h_length != 4 && hp->h_length != 8) {
								anubis_error(HARD,
								_("Illegal address length received for host %s"), session.mta);
								close_socket(sd_client);
								quit(EXIT_FAILURE);
							}
							else {
								memcpy((char *)&ad.sin_addr.s_addr, hp->h_addr,
									hp->h_length);
							}
						}
					}
					if (ntohl(ad.sin_addr.s_addr) == INADDR_LOOPBACK
					&& session.tunnel_port == session.mta_port) {
						anubis_error(SOFT, _("Loop not allowed. Connection rejected."));
						close_socket(sd_client);
						quit(EXIT_FAILURE);
					}
				}

				alarm(300);
				if (topt & T_LOCAL_MTA) {
					sd_server = make_local_connection(session.execpath, session.execargs);
					if (sd_server == -1) {
						service_unavailable(sd_client);
						quit(EXIT_FAILURE);
					}
				}
				else {
					sd_server = make_remote_connection(session.mta, session.mta_port);
					if (sd_server == -1)
						service_unavailable(sd_client);
				}
				alarm(0);

				if (!(topt & T_ERROR)) {
					remote_client = (void *)sd_client;
					remote_server = (void *)sd_server;
					alarm(900);
					smtp_session((void *)sd_client, (void *)sd_server);
					alarm(0);

					#ifdef HAVE_TLS
					end_tls(SERVER, secure.server);
					end_tls(CLIENT, secure.client);
					secure.server = 0;
					secure.client = 0;
					#endif /* HAVE_TLS */

					#ifdef HAVE_SSL
					end_ssl(SERVER, secure.server, secure.ctx_server);
					end_ssl(CLIENT, secure.client, secure.ctx_client);
					secure.server = 0;
					secure.client = 0;
					secure.ctx_server = 0;
					secure.ctx_client = 0;
					#endif /* HAVE_SSL */
				}
				close_socket(sd_server);
				close_socket(sd_client);
				close_rcfile(); /* CLIENT */

				if (topt & T_ERROR)
					info(NORMAL, _("Connection terminated."));
				else
					info(NORMAL, _("Connection closed successfully."));
	
				#ifdef HAVE_PAM	
				pam_retval = pam_close_session(pamh, 0);
				if (pam_retval == PAM_SUCCESS)
					info(VERBOSE, _("PAM: Session closed."));
				if (pam_end(pamh, pam_retval) != PAM_SUCCESS) {
					pamh = NULL;
					info(NORMAL, _("PAM: failed to release authenticator."));
					quit(EXIT_FAILURE);
				}
				#endif /* HAVE_PAM */

				quit(0);
			}
			close_socket(sd_client);
		}
		topt &= ~T_ERROR;
	}
	return;
}

/********************************************
 Run an outgoing mail processor on standard
 input and output as described in RFC 821.
*********************************************/

void
stdinout(void)
{
	int sd_client = -1; /* stdin/stdout */
	int sd_server = 0;

	/*
	   Read the system configuration file (SUPERVISOR).
	*/

	if (!(topt & T_NORC)) {
		open_rcfile(SUPERVISOR);
		read_rcfile(SUPERVISOR);
		close_rcfile(); /* SUPERVISOR */
	}

	anubis_getlogin(session.client, sizeof(session.client));
	auth_tunnel(); /* session.client = session.supervisor */

	if (!(topt & T_LOCAL_MTA) && (strlen(session.mta) == 0)) {
		options.termlevel = NORMAL;
		anubis_error(HARD, _("The MTA has not been specified. "
			"Set the REMOTE-MTA or LOCAL-MTA."));
		close_rcfile(); /* CLIENT */
		free_mem();
		return;
	}

	alarm(300);
	if (topt & T_LOCAL_MTA)
		sd_server = make_local_connection(session.execpath, session.execargs);
	else
		sd_server = make_remote_connection(session.mta, session.mta_port);
	alarm(0);

	if (sd_server == -1) {
		service_unavailable(sd_client);
		close_rcfile(); /* CLIENT */
		free_mem();
		return;
	}
	remote_client = (void *)sd_client;
	remote_server = (void *)sd_server;
	smtp_session((void *)sd_client, (void *)sd_server);

	close_socket(sd_server);
	close_rcfile(); /* CLIENT */
	free_mem();
	return;
}

/* EOF */

