/*
   mda.c

   This file is part of GNU Anubis.
   Copyright (C) 2005 The Anubis Team.

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

static void
deliver (const char *recipient, MESSAGE *msg)
{
  int status;
  pid_t pid;

  info (VERBOSE, _("Delivering to %s"), recipient);
  
  pid = fork ();

  if (pid == (pid_t)-1)
    anubis_error(EX_TEMPFAIL, errno, _("Cannot fork"));

  if (pid == 0)
    {
      /* Child */

      /* FIXME: Need a way to specify sender and recipient user names in
	 execargs, like in mailutils' mail.local */
      remote_server = make_local_connection_arg (session.execpath,
						 session.execargs,
						 recipient);
      if (!remote_server)
	{
	  service_unavailable (&remote_client);
	  exit (EXIT_FAILURE);
	}

      assign_string (&session.clientname, recipient);
      anubis_changeowner (recipient); /* FIXME: Contains PAM auth. Is it OK? */

      open_rcfile (CF_CLIENT);
      process_rcfile (CF_CLIENT);

      /* FIXME: Other sections? */ 
      rcfile_process_section (CF_CLIENT, "RULE", NULL, msg);
      
      transfer_header (msg->header);
      transfer_body (msg);
      stream_close (remote_server);
      stream_destroy (&remote_server);

      /* Wait for the real MTA to exit.
	 FIXME: We'd better wait for a specific pid */
      pid = waitpid ((pid_t) -1, &status, 0);
      if (WIFEXITED (status))
	{
	  status = WEXITSTATUS (status);
	  info (VERBOSE, _("MDA grandchild %lu exited with code %d"),
		(unsigned long)pid, status);
	  exit (status);
	}
      else if (WIFSIGNALED (status))
	{
	  anubis_error (EX_SOFTWARE, 0,
			_("MDA grandchild %lu terminated on signal %d"),
			(unsigned long) pid,
			WTERMSIG (status));
	}
      else
	{
	  anubis_error (EX_SOFTWARE, 0,
			_("MDA grandchild %lu terminated"),
			(unsigned long) pid);
	}
    }
  else
    {
      /* Master */

      info (VERBOSE, _("Started MDA child %lu"), (unsigned long)pid);

      waitpid (pid, &status, 0);
      if (WIFEXITED (status))
	{
	  status = WEXITSTATUS (status);
	  info (VERBOSE, _("MDA child %lu exited with code %d"),
		(unsigned long)pid, status);
	  if (status)
	    exit (status);
	}
      else if (WIFSIGNALED (status))
	{
	  anubis_error (EX_SOFTWARE, 0,
			_("MDA child %lu terminated on signal %d"),
			(unsigned long) pid,
			WTERMSIG (status));
	}
      else
	{
	  anubis_error (EX_SOFTWARE, 0,
			_("MDA child %lu terminated"),
			(unsigned long) pid);
	}
    }
}

void
mda ()
{
  char **p;
  MESSAGE msg;

  create_stdio_stream (&remote_client);

  message_init (&msg);
  collect_headers (&msg);
  collect_body (&msg);
  
  signal (SIGCHLD, SIG_DFL);
  for (p = x_argv; *p; p++)
    deliver (*p, &msg);

  message_free (&msg);
  
  exit (EX_OK);
}
