/*
   daemon.c

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

/* TCP wrappers */
#ifdef USE_LIBWRAP
# include <tcpd.h>
int deny_severity = LOG_INFO;
int allow_severity = LOG_INFO;
#endif /* USE_LIBWRAP */

static RETSIGTYPE sig_cld (int);

static int nchild;

/************
  DAEMONIZE
*************/

void
daemonize (void)
{
  signal (SIGHUP, SIG_IGN);
#ifdef HAVE_DAEMON
  if (daemon (0, 0) == -1)
    anubis_error (EXIT_FAILURE, errno, _("daemon() failed"));
#else
  chdir ("/");
  umask (0);
  switch (fork ())
    {
    case -1:			/* fork() failed */
      anubis_error (EXIT_FAILURE, errno, _("Cannot fork."));
      break;
    case 0:			/* child process */
      break;
    default:			/* parent process */
      quit (0);
    }
  if (setsid () == -1)
    anubis_error (EXIT_FAILURE, errno, _("setsid() failed"));

  close (0);
  close (1);
  close (2);
#endif /* HAVE_DAEMON */

  topt &= ~T_FOREGROUND;
  topt |= T_DAEMON;

#ifdef HAVE_SYSLOG
  openlog ("anubis", LOG_PID, 0);
  syslog (LOG_INFO, _("%s daemon startup succeeded."), version);
#endif /* HAVE_SYSLOG */
  write_pid_file ();
  return;
}

static RETSIGTYPE
sig_cld (int code)
{
  pid_t pid;
  int status;

  while ((pid = waitpid (-1, &status, WNOHANG)) > 0)
    {
      nchild--;
      info (VERBOSE,
	    ngettext
	    ("Child [%lu] finished. Exit status: %s. %d client left.",
	     "Child [%lu] finished. Exit status: %s. %d clients left.",
	     nchild), (unsigned long) pid,
	    WIFEXITED (status) ? _("OK") : _("ERROR"), nchild);
    }
  signal (code, sig_cld);
  return;
}

/************************************
 If a service is not available,
 then close a transmission channel.
*************************************/

void
service_unavailable (NET_STREAM * sd_client)
{
  char buf[LINEBUFFER + 1];

  snprintf (buf, LINEBUFFER,
	    "421 %s Service not available, closing transmission channel."
	    CRLF, (topt & T_LOCAL_MTA) ? "localhost" : session.mta);

  swrite (SERVER, *sd_client, buf);
  stream_close (*sd_client);
  stream_destroy (sd_client);
  return;
}

/*************************
 Set an unprivileged user
 (if possible).
**************************/

void
set_unprivileged_user (void)
{
  if (topt & T_USER_NOTPRIVIL)
    {
      if (check_username (session.notprivileged))
	anubis_changeowner (session.notprivileged);
    }
  else
    {
      if (check_username (DEFAULT_UNPRIVILEGED_USER))
	anubis_changeowner (DEFAULT_UNPRIVILEGED_USER);
      else
	info (NORMAL,
	      _("WARNING: An unprivileged user has not been specified!"));
    }
  return;
}

int
anubis_child_main (NET_STREAM *sd_client, struct sockaddr_in *addr)
{
  int rc;

#ifdef WITH_GSASL
  switch (anubis_mode)
    {
    case anubis_transparent:
      rc = anubis_transparent_mode (sd_client, addr);
      break;

    case anubis_authenticate:
      rc = anubis_authenticate_mode (sd_client, addr);
    }
#else
  rc = anubis_transparent_mode (sd_client, addr);
#endif /* WITH_GSASL */
  net_close_stream (sd_client);
  return rc;
}

/**************
  DAEMON loop
***************/

void
loop (int sd_bind)
{
  struct sockaddr_in addr;
  pid_t childpid = 0;
  socklen_t addrlen;
#ifdef USE_LIBWRAP
  struct request_info req;
#endif /* USE_LIBWRAP */

  addrlen = sizeof (addr);
  signal (SIGCHLD, sig_cld);

  info (VERBOSE, _("GNU Anubis is running..."));

  for (;;)
    {
      NET_STREAM sd_client = NULL;
      int fd = accept (sd_bind, (struct sockaddr *) &addr, &addrlen);
      if (fd < 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    {
	      anubis_error (0, errno, _("accept() failed"));
	      continue;
	    }
	}

      /* Create the TCP stream */
      net_create_stream (&sd_client, fd);

      /*
         Check the TCP wrappers settings.
       */

#ifdef USE_LIBWRAP
      request_init (&req, RQ_DAEMON, "anubis", RQ_FILE, fd, 0);
      fromhost (&req);
      if (hosts_access (&req) == 0)
	{
	  info (NORMAL,
		_("TCP wrappers: connection from %s:%u rejected."),
		inet_ntoa (addr.sin_addr), ntohs (addr.sin_port));
	  service_unavailable (&sd_client);
	  continue;
	}
#endif /* USE_LIBWRAP */

      /*
         Read the system configuration file (SUPERVISOR).
       */

      if (!(topt & T_NORC))
	{
	  open_rcfile (CF_SUPERVISOR);
	  process_rcfile (CF_SUPERVISOR);
	}

      nchild++;
      if (nchild > MAXCLIENTS)
	{
	  info (NORMAL,
		_("Too many clients. Connection from %s:%u rejected."),
		inet_ntoa (addr.sin_addr), ntohs (addr.sin_port));
	  service_unavailable (&sd_client);
	  nchild--;
	}
      else
	{
	  info (NORMAL, _("Connection from %s:%u"),
		inet_ntoa (addr.sin_addr), ntohs (addr.sin_port));

	  childpid = fork ();
	  if (childpid == -1)
	    anubis_error (0, errno, _("daemon: cannot fork"));
	  else if (childpid == 0)
	    {			/* a child process */
	      /* FIXME */
	      signal (SIGCHLD, SIG_IGN);
	      quit (anubis_child_main (&sd_client, &addr));
	    }

	  net_close_stream (&sd_client);
	}
      cleanup_children ();
    }
  return;
}

/********************************************
 Run an outgoing mail processor on standard
 input and output as described in RFC 821.
*********************************************/

static int
_stdio_write (void *sd, char *data, size_t size, size_t * nbytes)
{
  int rc;
  int fd = (int) sd;

  if (fd == 0)
    fd = 1;
  rc = write (fd, data, size);
  if (rc > 0)
    {
      *nbytes = rc;
      return 0;
    }
  return errno;
}

static int
_stdio_read (void *sd, char *data, size_t size, size_t * nbytes)
{
  int n;
  int fd = (int) sd;
  fd_set rds;

  errno = 0;
  FD_ZERO (&rds);
  FD_SET (fd, &rds);
  do
    n = select (fd + 1, &rds, NULL, NULL, NULL);
  while (n < 0 && errno == EINTR);
  if (n > 0)
    {
      n = read (fd, data, size);
      if (n >= 0)
	*nbytes = n;
    }
  return errno;
}

static const char *
_stdio_strerror (void *ignored_data, int rc)
{
  return strerror (rc);
}

void
stdinout (void)
{
  NET_STREAM sd_client = NULL;
  NET_STREAM sd_server = NULL;

  topt &= ~T_SSL;
  topt |= T_FOREGROUND;
  topt |= T_SMTP_ERROR_CODES;

  anubis_getlogin (session.clientname, sizeof (session.clientname));
  auth_tunnel ();		/* session.clientname = session.supervisor */

  if (!(topt & T_LOCAL_MTA) && (strlen (session.mta) == 0))
    {
      options.termlevel = NORMAL;
      anubis_error (EXIT_FAILURE, 0, _("The MTA has not been specified. "
			               "Set the REMOTE-MTA or LOCAL-MTA."));
    }

  net_create_stream (&sd_client, 0);
  stream_set_read (sd_client, _stdio_read);
  stream_set_write (sd_client, _stdio_write);
  stream_set_strerror (sd_client, _stdio_strerror);

  alarm (300);
  if (topt & T_LOCAL_MTA)
    sd_server = make_local_connection (session.execpath, session.execargs);
  else
    sd_server = make_remote_connection (session.mta, session.mta_port);
  alarm (0);

  if (sd_server == NULL)
    {
      service_unavailable (&sd_client);
      free_mem ();
      return;
    }
  stream_set_read (sd_server, _stdio_read);
  stream_set_write (sd_server, _stdio_write);
  stream_set_strerror (sd_server, _stdio_strerror);

  remote_client = sd_client;
  remote_server = sd_server;

  smtp_session_transparent ();
  cleanup_children ();

  net_close_stream (&sd_server);
  free_mem ();
  return;
}

/* EOF */
