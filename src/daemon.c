/*
   daemon.c

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

/* TCP wrappers */
#ifdef USE_LIBWRAP
# include <tcpd.h>
int deny_severity = LOG_INFO;
int allow_severity = LOG_INFO;
#endif /* USE_LIBWRAP */

char *log_tag = "anubis";
int log_facility = LOG_MAIL;

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

  openlog (log_tag, LOG_PID, log_facility);
  info (NORMAL, _("%s daemon startup succeeded."), version);
  write_pid_file ();
  return;
}

char *
format_exit_status (char *buffer, size_t buflen, int status)
{
  if (WIFEXITED(status))
    {
      if (WEXITSTATUS(status) == 0)
	snprintf(buffer, buflen, _("Exited successfully"));
      else
	snprintf(buffer, buflen, _("Failed with status %d"),
		 WEXITSTATUS(status));
    }
  else if (WIFSIGNALED(status)) 
    snprintf(buffer, buflen,
	     _("Terminated on signal %d"), WTERMSIG(status));
  else if (WIFSTOPPED(status))
    snprintf(buffer, buflen,
	     _("Stopped on signal %d"), WSTOPSIG(status));
#ifdef WCOREDUMP
  else if (WCOREDUMP(status))
    snprintf(buffer, buflen, _("Dumped core"));
#endif
  else
    snprintf(buffer, buflen, _("Terminated"));
  return buffer;
}

static void
report_process_status (size_t count, pid_t pid, int status)
{
  char buffer[LINEBUFFER];

  count--;
  info (VERBOSE,
	ngettext
	("Child [%lu] finished. %s. %d client left.",
	 "Child [%lu] finished. %s. %d clients left.",
	 count),
	(unsigned long) pid,
	format_exit_status (buffer, sizeof buffer, status), count);
}

static void
subprocess_report_status (size_t count, pid_t pid, int status)
{
  char buffer[LINEBUFFER];

  info (VERBOSE, _("Local program [%lu] finished. %s"),
	(unsigned long) pid,
	format_exit_status (buffer, sizeof buffer, status));
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
      if (check_username (session.notprivileged)) {
	anubis_changeowner (session.notprivileged);
	assign_string (&session.clientname, session.notprivileged);
      }
      else
	anubis_error (EXIT_FAILURE, 0,
		      _("WARNING: An unprivileged user cannot be resolved. Verify your settings!"));
    }
  else
    {
      if (check_username (DEFAULT_UNPRIVILEGED_USER)) {
	anubis_changeowner (DEFAULT_UNPRIVILEGED_USER);
	assign_string (&session.clientname, DEFAULT_UNPRIVILEGED_USER);
      }
      else
	info (NORMAL,
	      _("WARNING: An unprivileged user has not been specified!"));
    }
  return;
}

int
anubis_child_main (struct sockaddr_in *addr)
{
  int rc;

  proclist_init ();
  switch (anubis_mode)
    {
    case anubis_transparent:
      rc = anubis_transparent_mode (addr);
      break;

#ifdef WITH_GSASL
    case anubis_authenticate:
      rc = anubis_authenticate_mode (addr);
      break;
#endif /* WITH_GSASL */

    case anubis_proxy:
      rc = anubis_proxy_mode (addr);
      break;
      
    default:
      abort();
    }
  proclist_cleanup (subprocess_report_status);
  net_close_stream (&remote_client);
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

  proclist_init ();

  info (VERBOSE, _("GNU Anubis is running..."));

  for (;;)
    {
      int fd;
      size_t count;
      
      fd = accept (sd_bind, (struct sockaddr *) &addr, &addrlen);
      count = proclist_cleanup (report_process_status);
      
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
      net_create_stream (&remote_client, fd);
      remote_server = NULL;
      
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
	  service_unavailable (&remote_client);
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

      if (count >= MAXCLIENTS)
	{
	  info (NORMAL,
		_("Too many clients. Connection from %s:%u rejected."),
		inet_ntoa (addr.sin_addr), ntohs (addr.sin_port));
	  service_unavailable (&remote_client);
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
	      quit (anubis_child_main (&addr));
	    }
	  else /* master process */
	    proclist_register (childpid);
	  
	  net_close_stream (&remote_client);
	}
    }
  return;
}

/********************************************
 Run an outgoing mail processor on standard
 input and output as described in RFC 821.
*********************************************/

static int
_stdio_write (void *sd, const char *data, size_t size, size_t * nbytes)
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
      else
	return errno;
    }
  return 0;
}

static const char *
_stdio_strerror (void *ignored_data, int rc)
{
  return strerror (rc);
}

void
create_stdio_stream (NET_STREAM *s)
{
  net_create_stream (s, 0);
  stream_set_read (*s, _stdio_read);
  stream_set_write (*s, _stdio_write);
  stream_set_strerror (*s, _stdio_strerror);
}

void
stdinout (void)
{
  topt &= ~T_SSL;
  topt |= T_FOREGROUND;
  topt |= T_SMTP_ERROR_CODES;

  proclist_init ();
  
  anubis_getlogin (&session.clientname);
  auth_tunnel ();		/* session.clientname = session.supervisor */

  ASSERT_MTA_CONFIG ();

  create_stdio_stream (&remote_client);

  alarm (300);
  if (topt & T_LOCAL_MTA)
    remote_server = make_local_connection (session.execpath, session.execargs);
  else
    remote_server = make_remote_connection (session.mta, session.mta_port);
  alarm (0);

  if (remote_server == NULL)
    {
      service_unavailable (&remote_client);
      free_mem ();
      return;
    }
  stream_set_read (remote_server, _stdio_read);
  stream_set_write (remote_server, _stdio_write);
  stream_set_strerror (remote_server, _stdio_strerror);

  smtp_session_transparent ();
  proclist_cleanup (subprocess_report_status);
  
  net_close_stream (&remote_server);
  free_mem ();
  return;
}

/* EOF */
