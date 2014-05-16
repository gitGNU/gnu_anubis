/*
   mda.c

   This file is part of GNU Anubis.
   Copyright (C) 2005-2014 The Anubis Team.

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


enum smtp_client_state
  {
    smtp_client_state_init,
    smtp_client_state_helo,
    /*    smtp_client_state_auth,*/
    smtp_client_state_mail,
    smtp_client_state_rcpt,
    smtp_client_state_data,
    smtp_client_state_quit,
    smtp_client_state_stop
  };

static char *smtp_client_state_descr[] =
  {
    /* smtp_client_state_init */ N_("initial greeting"),
    /* smtp_client_state_helo */ "HELO/EHLO",
    /*    smtp_client_state_auth,*/
    /* smtp_client_state_mail */ "MAIL FROM",
    /* smtp_client_state_rcpt */ "RCPT TO",
    /* smtp_client_state_data */ "DATA",
    /* smtp_client_state_quit */ "QUIT",
    /* smtp_client_state_stop */ N_("session end")
  };

struct smtp_client_context
{
  MESSAGE msg;
  enum smtp_client_state state;
  int rcpt;
  int status;
  ANUBIS_SMTP_REPLY reply;
};

void
protocol_warning (const char *msg, ANUBIS_SMTP_REPLY reply)
{
  anubis_error (0, 0, "%s", msg);
  if (smtp_reply_line_count (reply))
    {
      size_t i;
      const char *p;
      
      anubis_error (0, 0, _("server reply follows:"));
      for (i = 0; (p = smtp_reply_line (reply, i)); i++)
	anubis_error (0, 0, "%s", p);
    }
}

void
smtp_client_failure (struct smtp_client_context *ctx)
{
  anubis_error (0, 0, _("%s failed"),
		gettext (smtp_client_state_descr[ctx->state]));
  if (smtp_reply_line_count (ctx->reply))
    {
      size_t i;
      const char *p;
      
      anubis_error (0, 0, _("server reply follows:"));
      for (i = 0; (p = smtp_reply_line (ctx->reply, i)); i++)
	anubis_error (0, 0, "%s", p);
    }
  
  if (smtp_reply_code_eq (ctx->reply, "4"))
    ctx->status = EX_TEMPFAIL;
  else if (smtp_reply_code_eq (ctx->reply, "5"))
    ctx->status = EX_UNAVAILABLE;
  else
    ctx->status = EX_PROTOCOL;

  switch (ctx->state)
    {
    case smtp_client_state_init:
    case smtp_client_state_quit:
      ctx->state = smtp_client_state_stop;
      break;

    default:
      ctx->state = smtp_client_state_quit;
    }
}

void
smtp_client_greeting (struct smtp_client_context *ctx)
{
  smtp_reply_get (CLIENT, remote_server, ctx->reply);
  if (smtp_reply_code_eq (ctx->reply, "2"))
    ctx->state = smtp_client_state_helo;
  else
    {
      ctx->status = EX_PROTOCOL;
      ctx->status = smtp_client_state_stop;
      return;
    }
}

  
void
smtp_client_helo (struct smtp_client_context *ctx)
{
  swrite (CLIENT, remote_server, "EHLO ");
  swrite (CLIENT, remote_server, get_ehlo_domain ());
  swrite (CLIENT, remote_server, CRLF);
  smtp_reply_get (CLIENT, remote_server, ctx->reply);

  if (!smtp_reply_code_eq (ctx->reply, "250"))
    {
      /* Try HELO */
      swrite (CLIENT, remote_server, "HELO");
      swrite (CLIENT, remote_server, get_ehlo_domain ());
      swrite (CLIENT, remote_server, CRLF);
      smtp_reply_get (CLIENT, remote_server, ctx->reply);

      if (!smtp_reply_code_eq (ctx->reply, "250"))
	{
	  smtp_client_failure (ctx);
	  return;
	}
    }
#if 0  
  if ((topt & T_STARTTLS) && (!(topt & T_SSL) || (topt & T_SSL_ONEWAY)))
    {
      if (smtp_reply_lookup (reply, "250", "STARTTLS"))
	{
	  /* FIXME */
	}
    }
#endif
  
  ctx->state = smtp_client_state_mail;
}  

void
smtp_client_mail (struct smtp_client_context *ctx)
{
  swrite (CLIENT, remote_server, "MAIL FROM:<");
  swrite (CLIENT, remote_server, from_address);
  swrite (CLIENT, remote_server, ">"CRLF);
  smtp_reply_get (CLIENT, remote_server, ctx->reply);
  if (smtp_reply_code_eq (ctx->reply, "250"))
    ctx->state = smtp_client_state_rcpt;
  else
    {
      smtp_client_failure (ctx);
      return;
    }
}

void
smtp_client_rcpt (struct smtp_client_context *ctx)
{
  char *addr = x_argv[ctx->rcpt]; /* FIXME: normalize */
  swrite (CLIENT, remote_server, "RCPT TO:<");
  swrite (CLIENT, remote_server, addr);
  swrite (CLIENT, remote_server, ">"CRLF);
  smtp_reply_get (CLIENT, remote_server, ctx->reply);
  if (!smtp_reply_code_eq (ctx->reply, "250"))
    {
      smtp_client_failure (ctx);
      return;
    }
  ctx->state = smtp_client_state_data;
}

void
smtp_client_data (struct smtp_client_context *ctx)
{
  MESSAGE tmp;
  
  swrite (CLIENT, remote_server, "DATA"CRLF);
  smtp_reply_get (CLIENT, remote_server, ctx->reply);
  if (!smtp_reply_code_eq (ctx->reply, "354"))
    {
      smtp_client_failure (ctx);
      return;
    }

  open_rcfile (CF_CLIENT);
  process_rcfile (CF_CLIENT);
  
  tmp = message_dup (ctx->msg);
  rcfile_call_section (CF_CLIENT, incoming_mail_rule, "RULE", NULL, tmp);
      
  transfer_header (message_get_header (tmp));
  transfer_body (tmp);
  message_free (tmp);
  
  swrite (CLIENT, remote_server, "." CRLF);
  smtp_reply_get (CLIENT, remote_server, ctx->reply);
  if (!smtp_reply_code_eq (ctx->reply, "250"))
    {
      smtp_client_failure (ctx);
      return;
    }
  ctx->state = smtp_client_state_quit;
}

void
smtp_client_quit (struct smtp_client_context *ctx)
{
  if (++ctx->rcpt < x_argc)
    {
      ctx->state = smtp_client_state_mail;
    }
  else
    {
      swrite (CLIENT, remote_server, "QUIT"CRLF);
      smtp_reply_get (CLIENT, remote_server, ctx->reply);
      if (smtp_reply_code_eq (ctx->reply, "2"))
	ctx->state = smtp_client_state_stop;
      else
	smtp_client_failure (ctx);
    }
}

static int
deliver_remote (MESSAGE msg)
{
  struct smtp_client_context ctx;
  remote_server = make_remote_connection (session.mta, session.mta_port);

  ctx.msg = msg;
  ctx.state = smtp_client_state_init;
  ctx.rcpt = 0;
  ctx.status = 0;
  ctx.reply = smtp_reply_new ();

  while (ctx.state != smtp_client_state_stop)
    {
      enum smtp_client_state prev = ctx.state;
      switch (ctx.state)
	{
	case smtp_client_state_init:
	  smtp_client_greeting (&ctx);
	  break;
	  
	case smtp_client_state_helo:
	  smtp_client_helo (&ctx);
	  break;
	  
	case smtp_client_state_mail:
	  smtp_client_mail (&ctx);
	  break;
	  
	case smtp_client_state_rcpt:
	  smtp_client_rcpt (&ctx);
	  break;

	case smtp_client_state_data:
	  smtp_client_data (&ctx);
	  break;
	  
	case smtp_client_state_quit:
	  smtp_client_quit (&ctx);
	  break;
	  
	default:
	  anubis_error (EX_SOFTWARE, 0,
			_("INTERNAL ERROR at %s:%d: unhandled state %d"),
			__FILE__, __LINE__, ctx.state);
	}
      if (ctx.state == prev)
	  anubis_error (EX_SOFTWARE, 0,
			_("INTERNAL ERROR at %s:%d: state did not change: %d"),
			__FILE__, __LINE__, ctx.state);
	
    }

  net_close_stream (&remote_server);
  return ctx.status;
}


static void
deliver_local_child (const char *recipient, MESSAGE msg)
{
  int i;
  char **argv;
  char *p;
  struct obstack stk;
  int status;
  pid_t pid;

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
  
  rcfile_call_section (CF_CLIENT, incoming_mail_rule, "RULE", NULL, msg);
      
  transfer_header (message_get_header (msg));
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

/* Deliver message to the recipient */
static void
deliver_local (const char *recipient, MESSAGE msg)
{
  int status;
  pid_t pid;

  info (VERBOSE, _("Delivering to %s"), recipient);
  
  pid = fork ();

  if (pid == (pid_t)-1)
    anubis_error (EX_TEMPFAIL, errno, _("Cannot fork"));

  if (pid == 0)
    {
      /* Child */
      
      assign_string (&session.clientname, recipient);
      deliver_local_child (recipient, msg);
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
ensure_sender_address (MESSAGE msg)
{
  if (!from_address)
    {
      ASSOC *p = list_locate (message_get_header (msg),
			      "From", anubis_assoc_cmp);
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
  char *buf = NULL;
  size_t size = 0;
  char *line = NULL;
  int rc = EX_OK;
  
  ASSERT_MTA_CONFIG ();
  if (x_argc == 0)
    anubis_error (EX_USAGE, 0, _("Missing recipient addresses"));
  if (!from_address)
    anubis_error (EX_USAGE, 0, _("Missing sender address"));/*FIXME*/
  
  create_stdio_stream (&remote_client);

  msg = message_new ();

  /* Read eventual From line */
  if (recvline (SERVER, remote_client, &buf, &size) == 0)
    exit (EX_OK);
  if (memcmp (buf, "From ", 5) == 0)
    save_sender_address (buf);
  else
    assign_string (&line, buf);
  
  collect_headers (msg, line);
  free (buf);
  ensure_sender_address (msg);
  collect_body (msg);

  signal (SIGCHLD, SIG_DFL);
  if (!x_argc)
    anubis_error (EX_USAGE, 0, _("no recipient names given"));

  if (topt & T_LOCAL_MTA)
    {
      for (p = x_argv; *p; p++)
	deliver_local (*p, msg);
    }
  else
    rc = deliver_remote (msg);
  
  message_free (msg);
  
  exit (rc);
}
