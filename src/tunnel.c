/*
   tunnel.c

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

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

static int transfer_command (MESSAGE);
static int process_command (MESSAGE, char *);
static void process_data (MESSAGE);
static int handle_ehlo (ANUBIS_SMTP_REPLY );



static char *smtp_ehlo_domain_name = NULL;
static ANUBIS_SMTP_REPLY ehlo_reply = NULL;

char *
get_ehlo_domain (void)
{
  return smtp_ehlo_domain_name ? smtp_ehlo_domain_name : get_localname ();
}




/* Collect and send headers */

/* Headers spanning multiple lines are wrapped into a single line, preserving
   the newlines. When sending to the server they are split again at newlines
   and sent in multiline lines. */

static void
get_boundary (MESSAGE msg, char *line)
{
  char boundary_buf[LINEBUFFER + 1], *p;
  char *boundary;
  
  if (strncmp (line, "Content-Type:", 13))
    return;

  /* Downcase the string to help search for boundary */
  safe_strcpy (boundary_buf, line);
  make_lowercase (boundary_buf);
  p = strstr (boundary_buf, "boundary=");
  if (!p)
    return;

  /* Now use the unaltered string. P still points past the
     `boundary=' */
  safe_strcpy (boundary_buf, line);
  p += 9;
  if (*p == '"')
    {
      char *q = strchr (++p, '"');
      if (*q)
	*q = 0;
    }
  boundary = xmalloc (strlen (p) + 3);
  sprintf (boundary, "--%s", p);
  message_replace_boundary (msg, boundary);
}

static void
add_header (ANUBIS_LIST list, char *line)
{
  ASSOC *asc = header_assoc (line);
  list_append (list, asc);
  if (asc->key && strcasecmp (asc->key, "subject") == 0)
    {
      char *p = strstr (asc->value, BEGIN_TRIGGER);

      if (p)
	{
	  asc = xmalloc (sizeof (*asc));

	  *p = 0;
	  p += sizeof (BEGIN_TRIGGER) - 1;
	  asc->key = strdup (X_ANUBIS_RULE_HEADER);
	  asc->value = strdup (p);
	  list_append (list, asc);
	}
    }
}

void
collect_headers (MESSAGE msg, char *line)
{
  char *buf = NULL;
  size_t size = 0;
  
  while (recvline (SERVER, remote_client, &buf, &size))
    {
      remcrlf (buf);
      if (isspace ((u_char) buf[0]))
	{
	  if (!line)
	    /* Something wrong, assume we've got no
	       headers */
	    break;
	  line = xrealloc (line, strlen (line) + strlen (buf) + 2);
	  strcat (line, "\n");
	  strcat (line, buf);
	}
      else
	{
	  if (line)
	    {
	      if (!(topt & T_ENTIRE_BODY) && message_get_boundary (msg))
		get_boundary (msg, line);
	      add_header (message_get_header (msg), line);
	      xfree (line);
	    }
	  if (buf[0] == 0)
	    break;
	  line = strdup (buf);
	}
    }
}

static void
write_header_line (NET_STREAM sd_server, char *line)
{
  char *p;

  p = strtok (line, "\r\n");
  do
    {
      swrite (CLIENT, sd_server, p);
      send_eol (CLIENT, sd_server);
    }
  while ((p = strtok (NULL, "\r\n")));
}

static void
write_assoc (NET_STREAM sd_server, ASSOC *entry)
{
  if (entry->key)
    {
      if (strcmp (entry->key, X_ANUBIS_RULE_HEADER) == 0)
	return;
      swrite (CLIENT, sd_server, entry->key);
      swrite (CLIENT, sd_server, ": ");
    }
  write_header_line (sd_server, entry->value);
}

void
send_header (NET_STREAM sd_server, ANUBIS_LIST list)
{
  ASSOC *p;
  ITERATOR itr = iterator_create (list);

  for (p = iterator_first (itr); p; p = iterator_next (itr))
    write_assoc (sd_server, p);
  iterator_destroy (&itr);
}

void
send_string_list (NET_STREAM sd_server, ANUBIS_LIST list)
{
  char *p;
  ITERATOR itr = iterator_create (list);

  for (p = iterator_first (itr); p; p = iterator_next (itr))
    write_header_line (sd_server, p);
  iterator_destroy (&itr);
}


/* Collect and sent the message body */

/* When read each CRLF is replaced by a single newline.
   When sent, the reverse procedure is performed.

   The handling of MIME encoded messages depends on the
   setting of T_ENTIRE_BODY bit in topt. If the bit is set, the
   entire body is read into memory. Otherwise, only the first
   part is read and processed, all the rest is passed to the
   server verbatim. */

#define ST_INIT  0
#define ST_HDR   1
#define ST_BODY  2
#define ST_DONE  3

void
collect_body (MESSAGE msg)
{
  int nread;
  char *buf = NULL;
  size_t size = 0;
  struct obstack stk;
  int state = 0;
  int len;
  const char *boundary = message_get_boundary (msg);
  
  if (boundary)
    len = strlen (boundary);
  obstack_init (&stk);
  while (state != ST_DONE
	 && (nread = recvline (SERVER, remote_client, &buf, &size)))
    {
      remcrlf (buf);

      if (strcmp (buf, ".") == 0)	/* EOM */
	break;

      if (boundary)
	{
	  switch (state)
	    {
	    case ST_INIT:
	      if (strcmp (buf, boundary) == 0)
		state = ST_HDR;
	      break;

	    case ST_HDR:
	      if (buf[0] == 0)
		state = ST_BODY;
	      else
		message_append_mime_header (msg, buf);
	      break;

	    case ST_BODY:
	      if (strncmp (buf, boundary, len) == 0)
		state = ST_DONE;
	      else
		{
		  obstack_grow (&stk, buf, strlen (buf));
		  obstack_1grow (&stk, '\n');
		}
	    }
	}
      else
	{
	  obstack_grow (&stk, buf, strlen (buf));
	  obstack_1grow (&stk, '\n');
	}
    }
  free (buf);
  obstack_1grow (&stk, 0);
  /* FIXME: Use message_proc_body to avoid spurious reallocations */
  message_replace_body (msg, xstrdup (obstack_finish (&stk)));
  obstack_free (&stk, NULL);
}

void
send_body (MESSAGE msg, NET_STREAM sd_server)
{
  const char *p;
  const char *boundary = message_get_boundary (msg);
  
  if (boundary)
    {
      swrite (CLIENT, sd_server, boundary);
      send_eol (CLIENT, sd_server);
      send_string_list (sd_server, message_get_mime_header (msg));
      send_eol (CLIENT, sd_server);
    }

  for (p = message_get_body (msg); *p;)
    {
      size_t len = strcspn (p, "\n");
      
      swrite_n (CLIENT, sd_server, p, len);
      send_eol (CLIENT, sd_server);
      p += len;
      if (*p)
	p++;
      else
	break;
    }
      
  if (boundary)
    {
      swrite (CLIENT, sd_server, boundary);
      send_eol (CLIENT, sd_server);
    }
}


/******************
  The Tunnel core
*******************/

void
smtp_session_transparent (void)
{
  char *command = NULL;
  size_t size = 0;
  ANUBIS_SMTP_REPLY reply;
  MESSAGE msg;

  /*
     First of all, transfer a welcome message.
   */

  reply = smtp_reply_new ();
  info (VERBOSE, _("Transferring messages..."));
  smtp_reply_get (CLIENT, remote_server, reply);

  if (smtp_reply_code_eq (reply, "220")
      && !smtp_reply_has_string (reply, 0, version, NULL))
    {
      char *banner_copy;
      char *host;
      char *rest;
      char *str;
      
      smtp_reply_get_line (reply, 0, &banner_copy, 0);
      for (host = banner_copy + 4; *host && *host == ' '; host++);
      rest = strchr (host, ' ');
      if (rest)
	*rest++ = 0;
      else
	rest = "";
      
      str = xmalloc (4 + strlen (host) + 2 + strlen (version) + 2
		     + strlen (rest) + 1);
      sprintf (str, "%s (%s) %s", host, version, rest);
      
      smtp_reply_replace_line (reply, 0, str);
      free (str);
      free (banner_copy);
    }
  swrite (SERVER, remote_client, smtp_reply_string (reply));
  smtp_reply_free (reply);
  
  /*
     Then process the commands...
   */

  msg = message_new ();
  while (recvline (SERVER, remote_client, &command, &size))
    {
      remcrlf (command);

      if (process_command (msg, command))
	continue;

      if (transfer_command (msg) == 0)
	break;
    }
  free (command);

  message_free (msg);
}

void
smtp_begin (void)
{
  ANUBIS_SMTP_REPLY reply;
  
  /* first get an mta banner */
  reply = smtp_reply_new ();
  smtp_reply_get (CLIENT, remote_server, reply);

  /* now send the ehlo command */
  swrite (CLIENT, remote_server, "EHLO ");
  swrite (CLIENT, remote_server, get_ehlo_domain ());
  send_eol (CLIENT, remote_server);
  handle_ehlo (reply);
  smtp_reply_free (reply);
}

void
smtp_session (void)
{
  char *command = NULL;
  size_t size = 0;
  MESSAGE msg;

  info (VERBOSE, _("Starting SMTP session..."));
  smtp_begin ();
  info (VERBOSE, _("Transferring messages..."));

  msg = message_new ();
  while (recvline (SERVER, remote_client, &command, &size))
    {
      remcrlf (command);
      
      if (process_command (msg, command))
	continue;

      if (transfer_command (msg) == 0)
	break;
    }
  free (command);
  message_free (msg);
}

/********************
  THE MAIL COMMANDS
*********************/

static void
save_command (MESSAGE msg, const char *line)
{
  int i;
  ASSOC *asc = xmalloc (sizeof (*asc));

  for (i = 0; line[i] && !isspace ((u_char) line[i]); i++)
    ;

  if (i == 4)
    {
      char *expect = NULL;
      if (strncasecmp (line, "mail", 4) == 0)
	expect = " from:";
      else if (strncasecmp (line, "rcpt", 4) == 0)
	expect = " to:";
      if (expect)
	{
	  int n = strlen (expect);
	  if (strncasecmp (&line[i], expect, n) == 0)
	    i += n;
	}
    }

  asc->key = xmalloc (i + 1);
  memcpy (asc->key, line, i);
  asc->key[i] = 0;
  make_uppercase (asc->key);
  
  for (; line[i] && isspace ((u_char) line[i]); i++)
    ;

  if (line[i])
    asc->value = strdup (&line[i]);
  else
    asc->value = NULL;
  message_add_command (msg, asc);
}

static int
handle_starttls (char *command)
{
#ifdef USE_SSL
  NET_STREAM stream;
  
  if (topt & T_SSL_FINISHED)
    {
      if (topt & T_SSL_ONEWAY)
	swrite (SERVER, remote_client,
		"503 5.0.0 TLS (ONEWAY) already started" CRLF);
      else
	swrite (SERVER, remote_client, "503 5.0.0 TLS already started" CRLF);
      return 1;
    }
  else if (!(topt & T_STARTTLS) || !(topt & T_SSL))
    {
      swrite (SERVER, remote_client, "503 5.5.0 TLS not available" CRLF);
      return 1;
    }

  /*
     Make the TLS/SSL connection with ESMTP server.
   */

  info (NORMAL, _("Using the TLS/SSL encryption..."));

  if (!(topt & T_LOCAL_MTA))
    {
      NET_STREAM stream;
      ANUBIS_SMTP_REPLY reply = smtp_reply_new ();
      const char *rstr;
      
      swrite (CLIENT, remote_server, "STARTTLS" CRLF);
      smtp_reply_get (CLIENT, remote_server, reply);

      rstr = smtp_reply_string (reply);
      /* FIXME: Use smtp_reply_eq */
      if (!isdigit ((unsigned char) rstr[0])
	  || (unsigned char) rstr[0] > '3')
	{
	  /* FIXME: Display complete response */
	  info (VERBOSE, _("WARNING: %s"), smtp_reply_line (reply, 0));
	  smtp_reply_free (reply);
	  anubis_error (0, 0, _("STARTTLS command failed."));
	  return 0;
	}
      smtp_reply_free (reply);

      stream = start_ssl_client (remote_server, options.termlevel > NORMAL);
      if (!stream)
	return 0;
      remote_server = stream;
    }
  
  /*
     Make the TLS/SSL connection with SMTP client
     (client connected with the Tunnel).
   */

  if (!secure.cert)
    secure.cert = xstrdup (DEFAULT_SSL_PEM);
  if (!check_filename (secure.cert, NULL))
    {
      swrite (SERVER, remote_client,
	      "454 TLS not available due to temporary reason" CRLF);
      return 0;
    }

  if (!secure.key)
    secure.key = xstrdup (secure.cert);
  else if (!check_filename (secure.key, NULL))
    {
      swrite (SERVER, remote_client,
	      "454 TLS not available due to temporary reason" CRLF);
      return 0;
    }

  /*
     Check file permissions. Ignore if a client hasn't
     specified a private key or a certificate.
   */

  if (topt & T_SSL_CKCLIENT)
    check_filemode (secure.key);

  swrite (SERVER, remote_client, "220 2.0.0 Ready to start TLS" CRLF);
  stream = start_ssl_server (remote_client, options.termlevel > NORMAL);
  if (!stream)
    {
      swrite (SERVER, remote_client, "454 4.3.3 TLS not available" CRLF);
      return 0;
    }
  remote_client = stream;
  topt |= T_SSL_FINISHED;
#else
  swrite (SERVER, remote_client, "503 5.5.0 TLS not available" CRLF);
#endif /* USE_SSL */

  return 1;
}

static int
process_command (MESSAGE msg, char *command)
{
  save_command (msg, command);
  if (!strncasecmp (command, "starttls", 8))
    return handle_starttls (command);
  else if (!strncasecmp (command, "xdatabase", 9))
    return xdatabase (command + 9);
  return 0;
}

void
set_ehlo_domain (const char *domain, size_t len)
{
  xfree (smtp_ehlo_domain_name);
  smtp_ehlo_domain_name = xmalloc (len + 1);
  memcpy (smtp_ehlo_domain_name, domain, len);
  smtp_ehlo_domain_name[len] = 0;
}

static void
save_ehlo_domain (const char *command)
{
  const char *p, *endp;
  
  for (p = command + 5 /* length of EHLO + initial space */;
       *p && isspace (*p);
       p++)
    ;

  for (endp = p + strlen (p) - 1; endp >= p && isspace(*endp); endp--)
    ;
  set_ehlo_domain (p, endp - p + 1);
}

static int
handle_ehlo (ANUBIS_SMTP_REPLY reply)
{
  if (!smtp_ehlo_domain_name)
    save_ehlo_domain (smtp_reply_line (reply, 0));
		   
  smtp_reply_free (ehlo_reply);
  ehlo_reply = smtp_reply_new ();
  smtp_reply_get (CLIENT, remote_server, ehlo_reply);

  if (smtp_reply_has_capa (ehlo_reply, "STARTTLS", NULL))
    topt |= T_STARTTLS;		/* Yes, we can use the TLS/SSL
				   encryption. */

  xdatabase_capability (ehlo_reply);

#ifdef USE_SSL
  if ((topt & T_SSL_ONEWAY)
      && (topt & T_STARTTLS) && !(topt & T_SSL_FINISHED))
    {
      NET_STREAM stream;
      ANUBIS_SMTP_REPLY newreply = smtp_reply_new ();
      const char *rstr;
      
      /*
         The 'ONEWAY' method is used when your MUA doesn't
         support the TLS/SSL, but your MTA does.
         Make the TLS/SSL connection with ESMTP server.
	 FIXME: The diagnostic message below is not correct in
	 authmode.
       */

      info (NORMAL,
	    _("Using TLS/SSL encryption between Anubis and remote MTA only..."));
      swrite (CLIENT, remote_server, "STARTTLS" CRLF);
      smtp_reply_get (CLIENT, remote_server, newreply);

      rstr = smtp_reply_string (newreply);
      if (!isdigit ((unsigned char) rstr[0])
	  || (unsigned char) rstr[0] > '3')
	{
	  info (VERBOSE, _("WARNING: %s"), smtp_reply_line (newreply, 0));
	  smtp_reply_free (newreply);
	  anubis_error (0, 0, _("STARTTLS (ONEWAY) command failed."));
	  topt &= ~T_SSL_ONEWAY;
	  swrite (SERVER, remote_client, smtp_reply_string (ehlo_reply));
	  return 1;
	}
      smtp_reply_free (newreply);

      stream = start_ssl_client (remote_server, options.termlevel > NORMAL);
      if (!stream)
	{
	  topt &= ~T_SSL_ONEWAY;
	  swrite (SERVER, remote_client, smtp_reply_string (ehlo_reply));
	  return 1;
	}

      remote_server = stream;
      topt |= T_SSL_FINISHED;

      /*
         Send the EHLO command (after the TLS/SSL negotiation).
       */

      swrite (CLIENT, remote_server, "EHLO ");
      swrite (CLIENT, remote_server, get_ehlo_domain ());
      send_eol (CLIENT, remote_server);
      smtp_reply_get (CLIENT, remote_server, ehlo_reply);
    }
#endif /* USE_SSL */

  /*
     Remove the STARTTLS command from the EHLO list
     if no SSL is specified, the SSL is not available,
     or we're using the 'ONEWAY' TLS/SSL encryption.
   */

  if ((topt & T_STARTTLS) && (!(topt & T_SSL) || (topt & T_SSL_ONEWAY)))
    {
      size_t n;
      if (smtp_reply_has_capa (ehlo_reply, "STARTTLS", &n))
	smtp_reply_remove_line (ehlo_reply, n);
    }

  /*
     Check whether we can use the ESMTP AUTH.
   */

  if (topt & T_ESMTP_AUTH)
    {
      size_t n;
      if (smtp_reply_has_capa (ehlo_reply, "AUTH", &n))
	{
	  if (!(topt & T_ESMTP_AUTH_DELAYED))
	    {
	      const char *p = smtp_reply_line (ehlo_reply, n);
	      esmtp_auth (&remote_server, p + 9);
	      smtp_reply_remove_line (ehlo_reply, n);
	      topt &= ~T_ESMTP_AUTH;
	    }
	}
      else
	topt &= ~T_ESMTP_AUTH;
    }

  smtp_reply_set (reply, smtp_reply_string (ehlo_reply));

  return 0;
}

static int
transfer_command (MESSAGE msg)
{
  char *buf = NULL;
  int rc = 1; /* OK */
  ANUBIS_SMTP_REPLY reply = smtp_reply_new ();
  const char *rstr;
  ASSOC *asc;
  char *command;
  int len;
  
  rcfile_call_section (CF_CLIENT, smtp_command_rule, "SMTP", NULL, msg);
  asc = list_tail_item (message_get_commands (msg));
  if (!asc->value)
    command = strdup (asc->key);
  else if (strcasecmp (asc->key, "mail from:") == 0)
    {
      if (topt & T_ESMTP_AUTH)
	{
	  size_t n;
	  if (smtp_reply_has_capa (ehlo_reply, "AUTH", &n))
	    {
	      const char *p = smtp_reply_line (ehlo_reply, n);
	      esmtp_auth (&remote_server, p + 9);
	      smtp_reply_remove_line (ehlo_reply, n);
	    }
	  topt &= ~T_ESMTP_AUTH;
	}
      asprintf (&command, "%s%s", asc->key, asc->value);
    }
  else if (strcasecmp (asc->key, "rcpt to:") == 0)
    asprintf (&command, "%s%s", asc->key, asc->value);
  else
    asprintf (&command, "%s %s", asc->key, asc->value);
	    
  assign_string (&buf, command);
  make_lowercase (buf);

  swrite (CLIENT, remote_server, command);
  swrite (CLIENT, remote_server, CRLF);

  if (!strncmp (buf, "ehlo", 4))
    {
      smtp_reply_set (reply, command);
      if (handle_ehlo (reply))
	{
	  smtp_reply_free (reply);
	  free (command);
	  return 0;
	}
    }
  else
    smtp_reply_get (CLIENT, remote_server, reply);
  
  swrite (SERVER, remote_client, smtp_reply_string (reply));

  rstr = smtp_reply_line_ptr (reply, 0);
  len = strcspn (rstr, "\r\n");
  info (NORMAL, "%s: %s <=> %*.*s",
	message_id (msg), command,
	len, len, rstr);
  rstr = smtp_reply_string (reply);
  if (isdigit ((unsigned char) rstr[0]) && (unsigned char) rstr[0] < '4')
    {
      if (strncmp (buf, "quit", 4) == 0)
	rc = 0;		/* The QUIT command */
      else if (strncmp (buf, "rset", 4) == 0)
	{
	  message_reset (msg);
	}
      else if (strncmp (buf, "data", 4) == 0)
	{
	  process_data (msg);
	}
    }
  free (buf);
  free (command);
  smtp_reply_free (reply);
  return rc;
}

void
process_data (MESSAGE msg)
{
  char *buf = NULL;
  size_t size = 0;

  alarm (1800);

  collect_headers (msg, NULL);
  collect_body (msg);

  rcfile_call_section (CF_CLIENT, outgoing_mail_rule, "RULE", NULL, msg);

  transfer_header (message_get_header (msg));
  transfer_body (msg);

  if (recvline (CLIENT, remote_server, &buf, &size))
    {
      remcrlf (buf);
      
      swrite (SERVER, remote_client, buf);
      send_eol (SERVER, remote_client);

      info (NORMAL, "%s: dot <=> %s", message_id (msg), buf);
    }
  free (buf);

  message_reset (msg);
  alarm (0);
}

void
transfer_header (ANUBIS_LIST header_buf)
{
  send_header (remote_server, header_buf);
  send_eol (CLIENT, remote_server);
}

/***************
  MESSAGE BODY
****************/

static void
raw_transfer (void)
{
  size_t size = 0;
  char *buf = NULL;
  while (recvline (SERVER, remote_client, &buf, &size) > 0)
    {
      remcrlf (buf);
      if (strcmp (buf, ".") == 0)	/* EOM */
	break;
      swrite (CLIENT, remote_server, buf);
      send_eol (CLIENT, remote_server);
    }
  free (buf);
}

void
transfer_body (MESSAGE msg)
{
  if (message_get_boundary (msg))
    {
      send_body (msg, remote_server);

      /* Transfer everything else */
      raw_transfer ();
    }
  else
    send_body (msg, remote_server);
  if (anubis_mode != anubis_mda)
    swrite (CLIENT, remote_server, "." CRLF);
}

/* EOF */

