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
#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

char *from_address; /* Sender address */

/* Expand a meta-variable. Available meta-variables are:
   
   %sender          Replace with the sender name
   %recipient       Replace with the recipient name */

static void
expand_meta_variable (char *start, size_t size,
		      char **expansion, size_t *expansion_size)
{
  size--;
  start++;
      
  if (strncmp ("sender", start, size) == 0)
    {
      *expansion = from_address;
      *expansion_size = strlen (*expansion);
    }
  else if (strncmp ("recipient", start, size) == 0)
    {
      *expansion = session.clientname;
      *expansion_size = strlen (*expansion);
    }
  else
    {
      *expansion = start;
      *expansion_size = size;
    }	  
}


/* Expand meta-notations in arguments. */
   
static void
expand_arg (struct obstack *stk, char *arg)
{
  char *meta = 0;
  for (; *arg; arg++)
    {
      if (!meta)
	{
	  if (*arg != '%')
	    obstack_1grow (stk, *arg);
	  else
	    meta = arg;
	}
      else /* In metacharacter */
	{
	  if (!(isalnum (*arg) || *arg == '_'))
	    {
	      char *repl;
	      size_t size;
	      
	      expand_meta_variable (meta, arg - meta, &repl, &size);
	      obstack_grow (stk, repl, size);
	      obstack_1grow (stk, *arg);
	      meta = NULL;
	    }
	}
    }

  if (meta)
    {
      char *repl;
      size_t size;
	      
      expand_meta_variable (meta, arg - meta, &repl, &size);
      obstack_grow (stk, repl, size);
    }
  
  obstack_1grow (stk, 0);
}

/* Deliver message to the recipient */
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
      int i;
      char **argv;
      char *p;
      struct obstack stk;

      assign_string (&session.clientname, recipient);

      /* Create argv vector.
	 Argv will not be freed. It is no use, since we're going to
	 exit anyway. */
      obstack_init (&stk);
      for (i = 0; session.execargs[i]; i++)
	expand_arg (&stk, session.execargs[i]);
      obstack_1grow (&stk, 0);
      
      argv = xmalloc (sizeof *argv * (i + 1));
      for (i = 0, p = obstack_finish (&stk); *p; p += strlen (p) + 1, i++)
	argv[i] = p;
      argv[i] = NULL;
	
      remote_server = make_local_connection (session.execpath, argv);
      if (!remote_server)
	{
	  service_unavailable (&remote_client);
	  exit (EXIT_FAILURE);
	}

      anubis_changeowner (recipient); /* FIXME: Contains PAM auth. Is it OK? */

      open_rcfile (CF_CLIENT);
      process_rcfile (CF_CLIENT);

      rcfile_call_section (CF_CLIENT, incoming_mail_rule, NULL, msg);
      
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

/* Extract sender e-mail from the UNIX 'From ' line and save it in
   from_address */
static void
save_sender_address (char *from_line)
{
  char *p;

  from_line += 5;
  p = strchr (from_line, ' ');
  if (p)
    assign_string_n (&from_address, from_line, p - from_line);
  else
    /* Should not happen, but anyway ... */
    assign_string (&from_address, from_line); 
}

#define DEFAULT_FROM_ADDRESS "" /* FIXME: a better value?
				   postmaster@localhost? */

/* Ensure from_address is set. */
static void
ensure_sender_address (MESSAGE *msg)
{
  if (!from_address)
    {
      ASSOC *p = list_locate (msg->header, "From", anubis_assoc_cmp);
      if (p)
	{
	  /* Find the email address itself. It is a rather simplified
	     logic, but it seems to be sufficient for the purpose */
	  char *q = strchr (p->value, '@');
	  if (!q)
	    assign_string (&from_address, p->value);
	  else
	    {
	      char *start, *end;
	      
	      for (start = q; start > p->value; start--)
		{
		  if (*start == '<' || isspace (*start))
		    {
		      start++;
		      break;
		    }
		}

	      for (end = q; *end; end++)
		{
		  if (*end == '>' || isspace (*end))
		    {
		      end--;
		      break;
		    }
		}
	      assign_string_n (&from_address, start, end - start + 1);
	    }
	}
      else
	assign_string (&from_address, DEFAULT_FROM_ADDRESS);
    }
  remcrlf (from_address);
}


/* Run in MDA mode */
void
mda ()
{
  char **p;
  MESSAGE msg;
  char buf[128];
  char *line = NULL;
  
  create_stdio_stream (&remote_client);

  message_init (&msg);

  /* Read eventual From line */
  recvline (SERVER, remote_client, buf, sizeof (buf) - 1);
  if (memcmp (buf, "From ", 5) == 0)
    save_sender_address (buf);
  else
    assign_string (&line, buf);
  
  collect_headers (&msg, line);
  ensure_sender_address (&msg);
  collect_body (&msg);

  signal (SIGCHLD, SIG_DFL);
  for (p = x_argv; *p; p++)
    deliver (*p, &msg);

  message_free (&msg);
  
  exit (EX_OK);
}
