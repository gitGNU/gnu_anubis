/*
   tunnel.c

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

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

static int transfer_command (MESSAGE *, char *);
static int process_command (MESSAGE *, char *);
static void transfer_header (ANUBIS_LIST *);
static void transfer_body (MESSAGE *);
static void process_data (MESSAGE *);


/* Collect and send headers */

/* Headers spanning multiple lines are wrapped into a single line, preserving
   the newlines. When sending to the server they are split again at newlines
   snd sent in multiline lines. */

static void
get_boundary (MESSAGE * msg, char *line)
{
  char boundary_buf[LINEBUFFER + 1], *p;

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
  msg->boundary = xmalloc (strlen (p) + 3);
  sprintf (msg->boundary, "--%s", p);
}

static void
add_header (ANUBIS_LIST * list, char *line)
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

static void
collect_headers (MESSAGE * msg)
{
  char buf[LINEBUFFER + 1];
  char *line = NULL;

  while (recvline (SERVER, remote_client, buf, sizeof (buf) - 1))
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
	      if (!(topt & T_ENTIRE_BODY) && msg->boundary == NULL)
		get_boundary (msg, line);
	      add_header (msg->header, line);
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

  p = strtok (line, "\n");
  do
    {
      swrite (CLIENT, sd_server, p);
      swrite (CLIENT, sd_server, CRLF);
    }
  while ((p = strtok (NULL, "\n")));
}

static void
write_assoc (NET_STREAM sd_server, ASSOC * entry)
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
send_header (NET_STREAM sd_server, ANUBIS_LIST * list)
{
  ASSOC *p;
  ITERATOR *itr = iterator_create (list);

  for (p = iterator_first (itr); p; p = iterator_next (itr))
    write_assoc (sd_server, p);
  iterator_destroy (&itr);
}

void
send_string_list (NET_STREAM sd_server, ANUBIS_LIST * list)
{
  char *p;
  ITERATOR *itr = iterator_create (list);

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

static void
collect_body (MESSAGE * msg)
{
  int nread;
  char buf[LINEBUFFER + 1];
  struct obstack stk;
  int state = 0;
  int len;

  if (msg->boundary)
    {
      len = strlen (msg->boundary);
      msg->mime_hdr = list_create ();
    }

  obstack_init (&stk);
  while (state != ST_DONE
	 && (nread = recvline (SERVER, remote_client, buf, sizeof (buf) - 1)))
    {
      if (strncmp (buf, "." CRLF, 3) == 0)	/* EOM */
	break;

      remcrlf (buf);

      if (msg->boundary)
	{
	  switch (state)
	    {
	    case ST_INIT:
	      if (strcmp (buf, msg->boundary) == 0)
		state = ST_HDR;
	      break;

	    case ST_HDR:
	      if (buf[0] == 0)
		state = ST_BODY;
	      else
		list_append (msg->mime_hdr, strdup (buf));
	      break;

	    case ST_BODY:
	      if (strncmp (buf, msg->boundary, len) == 0)
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
  obstack_1grow (&stk, 0);
  msg->body = strdup (obstack_finish (&stk));
  obstack_free (&stk, NULL);
}

void
send_body (MESSAGE * msg, NET_STREAM sd_server)
{
  char *p;

  if (msg->boundary)
    {
      swrite (CLIENT, sd_server, msg->boundary);
      swrite (CLIENT, sd_server, CRLF);
      send_string_list (sd_server, msg->mime_hdr);
      swrite (CLIENT, sd_server, CRLF);
    }

  for (p = msg->body; *p;)
    {
      char *q = strchr (p, '\n');
      if (q)
	*q++ = 0;
      else
	q = p + strlen (p);

      swrite (CLIENT, sd_server, p);
      swrite (CLIENT, sd_server, CRLF);
      p = q;
    }

  if (msg->boundary)
    {
      swrite (CLIENT, sd_server, msg->boundary);
      swrite (CLIENT, sd_server, CRLF);
    }
}


/******************
  The Tunnel core
*******************/

void
smtp_session_transparent (void)
{
  char command[LINEBUFFER + 1];
  MESSAGE msg;

  /*
     First of all, transfer a welcome message.
   */

  info (VERBOSE, _("Transferring message(s)..."));
  get_response_smtp (CLIENT, remote_server, command, sizeof (command) - 1);

  if (strncmp (command, "220 ", 4) == 0 && strstr (command, version) == 0)
    {
      char *ptr = 0;
      char *banner_ptr = 0;
      char host[65];
      char banner_backup[LINEBUFFER + 1];

      safe_strcpy (banner_backup, command);

      if ((banner_ptr = strchr (banner_backup, ' ')))
	{
	  banner_ptr++;
	  safe_strcpy (host, banner_ptr);
	  if ((ptr = strchr (host, ' ')))
	    *ptr = '\0';
	  do
	    {
	      banner_ptr++;
	    }
	  while (*banner_ptr != ' ');
	  banner_ptr++;
	  snprintf (command, sizeof command,
		    "220 %s (%s) %s", host, version, banner_ptr);
	}
    }
  swrite (SERVER, remote_client, command);

  /*
     Then process the commands...
   */

  message_init (&msg);
  while (recvline (SERVER, remote_client, command, sizeof (command) - 1))
    {
      if (process_command (&msg, command))
	continue;

      if (topt & T_ERROR)
	break;

      if (transfer_command (&msg, command) == 0)
	break;
    }

  message_free (&msg);
  return;
}

void
smtp_begin (void)
{
  char command[LINEBUFFER + 1];

  get_response_smtp (CLIENT, remote_server, command, sizeof (command) - 1);
}

void
smtp_session (void)
{
  char command[LINEBUFFER + 1];
  MESSAGE msg;

  info (VERBOSE, _("Starting SMTP session..."));
  smtp_begin ();
  info (VERBOSE, _("Transferring message(s)..."));

  message_init (&msg);
  while (recvline (SERVER, remote_client, command, sizeof (command) - 1))
    {
      if (process_command (&msg, command))
	continue;

      if (topt & T_ERROR)
	break;

      if (transfer_command (&msg, command) == 0)
	break;
    }

  message_free (&msg);
  return;
}

/********************
  THE MAIL COMMANDS
*********************/

static void
save_command (MESSAGE * msg, char *line)
{
  int i;
  ASSOC *asc = xmalloc (sizeof (*asc));

  for (i = 0; line[i] && !isspace ((u_char) line[i]); i++)
    ;

  if (i == 4)
    {
      char *expect = NULL;
      if (memcmp (line, "mail", 4) == 0)
	expect = " from:";
      else if (memcmp (line, "rcpt", 4) == 0)
	expect = " to:";
      if (expect)
	{
	  int n = strlen (expect);
	  if (strncmp (&line[i], expect, n) == 0)
	    i += n;
	}
    }

  asc->key = xmalloc (i + 1);
  memcpy (asc->key, line, i);
  asc->key[i] = 0;
  for (; line[i] && isspace ((u_char) line[i]); i++)
    ;

  if (line[i])
    asc->value = strdup (&line[i]);
  else
    asc->value = NULL;
  list_append (msg->commands, asc);
}

static int
handle_starttls (char *command)
{
#ifdef USE_SSL
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
      char reply[LINEBUFFER + 1];
      swrite (CLIENT, remote_server, "STARTTLS" CRLF);

      get_response_smtp (CLIENT, remote_server, reply, sizeof (reply) - 1);

      if (!isdigit ((unsigned char) reply[0])
	  || (unsigned char) reply[0] > '3')
	{
	  remcrlf (reply);
	  info (VERBOSE, _("WARNING: %s"), reply);
	  anubis_error (HARD, _("STARTTLS command failed."));
	  return 0;
	}

      secure.client = start_ssl_client (remote_server,
					secure.cafile,
					options.termlevel > NORMAL);
      if (!secure.client || (topt & T_ERROR))
	return 0;
      remote_server = (void *) secure.client;
    }

  /*
     Make the TLS/SSL connection with SMTP client
     (client connected with the Tunnel).
   */

  if (secure.cert == 0)
    secure.cert = allocbuf (DEFAULT_SSL_PEM, MAXPATHLEN);
  if (check_filename (secure.cert, NULL) == 0)
    return 0;
  if (secure.key == 0)
    secure.key = allocbuf (secure.cert, MAXPATHLEN);
  else if (check_filename (secure.key, NULL) == 0)
    return 0;

  /*
     Check file permissions. Ignore if a client hasn't
     specified a private key or a certificate.
   */

  if (topt & T_SSL_CKCLIENT)
    check_filemode (secure.key);

  swrite (SERVER, remote_client, "220 2.0.0 Ready to start TLS" CRLF);
  secure.server = start_ssl_server (remote_client,
				    secure.cafile,
				    secure.cert,
				    secure.key, options.termlevel > NORMAL);
  if (!secure.server || (topt & T_ERROR))
    {
      swrite (SERVER, remote_client, "454 4.3.3 TLS not available" CRLF);
      return 0;
    }
  remote_client = secure.server;
  topt |= T_SSL_FINISHED;
#else
  swrite (SERVER, remote_client, "503 5.5.0 TLS not available" CRLF);
#endif /* USE_SSL */

  return 1;
}

static int
process_command (MESSAGE * msg, char *command)
{
  char buf[LINEBUFFER + 1];

  safe_strcpy (buf, command);	/* make a back-up */
  remcrlf (buf);
  make_lowercase (buf);
  save_command (msg, buf);

  if (strncmp (buf, "starttls", 8) == 0)
    return handle_starttls (command);
  else if (strncmp (buf, "xdatabase", 8) == 0)
    return xdatabase (buf);
  return 0;
}

static int
handle_ehlo (char *command, char *reply, size_t reply_size)
{
  get_response_smtp (CLIENT, remote_server, reply, reply_size - 1);

  if (strstr (reply, "STARTTLS"))
    topt |= T_STARTTLS;		/* Yes, we can use the TLS/SSL
				   encryption. */

  xdatabase_capability (reply, reply_size);

#ifdef USE_SSL
  if ((topt & T_SSL_ONEWAY)
      && (topt & T_STARTTLS) && !(topt & T_SSL_FINISHED))
    {

      struct sockaddr_in rclient;
      char ehlo[LINEBUFFER + 1];
      socklen_t addrlen;

      /*
         The 'ONEWAY' method is used when your MUA doesn't
         support the TLS/SSL, but your MTA does.
         Make the TLS/SSL connection with ESMTP server.
       */

      char newreply[LINEBUFFER + 1];
      info (NORMAL,
	    _
	    ("Using TLS/SSL encryption between Anubis and remote MTA only..."));
      swrite (CLIENT, remote_server, "STARTTLS" CRLF);
      get_response_smtp (CLIENT, remote_server, newreply,
			 sizeof (newreply) - 1);

      if (!isdigit ((unsigned char) newreply[0])
	  || (unsigned char) newreply[0] > '3')
	{
	  remcrlf (newreply);
	  info (VERBOSE, _("WARNING: %s"), newreply);
	  anubis_error (SOFT, _("STARTTLS (ONEWAY) command failed."));
	  topt &= ~T_SSL_ONEWAY;
	  swrite (SERVER, remote_client, reply);
	  return 1;
	}

      secure.client = start_ssl_client (remote_server,
					secure.cafile,
					options.termlevel > NORMAL);
      if (!secure.client || (topt & T_ERROR))
	{
	  topt &= ~T_ERROR;
	  topt &= ~T_SSL_ONEWAY;
	  swrite (SERVER, remote_client, reply);
	  return 1;
	}

      remote_server = (void *) secure.client;
      topt |= T_SSL_FINISHED;

      /*
         Send the EHLO command (after the TLS/SSL negotiation).
       */

      addrlen = sizeof (rclient);
      if (getpeername ((int) remote_client,
		       (struct sockaddr *) &rclient, &addrlen) == -1)
	anubis_error (HARD, _("getpeername() failed: %s."), strerror (errno));

      snprintf (ehlo, sizeof ehlo,
		"EHLO %s" CRLF,
		(topt & T_ERROR) ? "localhost" :
		inet_ntoa (rclient.sin_addr));

      topt &= ~T_ERROR;
      swrite (CLIENT, remote_server, ehlo);
      get_response_smtp (CLIENT, remote_server, reply, reply_size);
    }
#endif /* USE_SSL */

  /*
     Remove the STARTTLS command from the EHLO list
     if no SSL is specified, the SSL is not available,
     or we're using the 'ONEWAY' TLS/SSL encryption.
   */

  if ((topt & T_STARTTLS) && (!(topt & T_SSL) || (topt & T_SSL_ONEWAY)))
    {
      char *starttls1 = "250-STARTTLS";
      char *starttls2 = "STARTTLS";
      if (strstr (reply, starttls1))
	remline (reply, starttls1);
      else if (strstr (reply, starttls2))
	remline (reply, starttls2);
    }

  /*
     Check whether we can use the ESMTP AUTH.
   */

  if ((topt & T_ESMTP_AUTH) && strstr (reply, "AUTH "))
    {
      esmtp_auth (remote_server, reply);
      memset (session.mta_username, 0, sizeof (session.mta_username));
      memset (session.mta_password, 0, sizeof (session.mta_password));
    }

  return 0;
}

static int
transfer_command (MESSAGE * msg, char *command)
{
  char reply[2 * LINEBUFFER + 1];
  char buf[LINEBUFFER + 1];

  safe_strcpy (buf, command);
  make_lowercase (buf);
  swrite (CLIENT, remote_server, command);
  if (topt & T_ERROR)
    return 0;

  if (strncmp (buf, "ehlo", 4) == 0)
    {
      if (handle_ehlo (command, reply, sizeof reply))
	return 0;
    }
  else
    get_response_smtp (CLIENT, remote_server, reply, sizeof reply);

  swrite (SERVER, remote_client, reply);
  if (topt & T_ERROR)
    return 0;

  if (isdigit ((unsigned char) reply[0]) && (unsigned char) reply[0] < '4')
    {
      if (strncmp (buf, "quit", 4) == 0)
	return 0;		/* The QUIT command */
      else if (strncmp (buf, "rset", 4) == 0)
	{
	  message_free (msg);
	  message_init (msg);
	  topt &= ~T_ERROR;
	}
      else if (strncmp (buf, "data", 4) == 0)
	{
	  process_data (msg);
	  topt &= ~T_ERROR;
	}
    }
  return 1;			/* OK */
}

void
process_data (MESSAGE * msg)
{
  char buf[LINEBUFFER + 1];

  alarm (1800);

  collect_headers (msg);
  collect_body (msg);

  rcfile_process_section (CF_CLIENT, "RULE", NULL, msg);

  transfer_header (msg->header);
  transfer_body (msg);

  recvline (CLIENT, remote_server, buf, sizeof (buf) - 1);
  swrite (SERVER, remote_client, buf);

  message_free (msg);
  message_init (msg);
  alarm (0);
}

static void
transfer_header (ANUBIS_LIST * header_buf)
{
  send_header (remote_server, header_buf);
  swrite (CLIENT, remote_server, CRLF);
}

/***************
  MESSAGE BODY
****************/

static void
raw_transfer (void)
{
  int nread;
  char buf[LINEBUFFER + 1];

  while ((nread = recvline (SERVER, remote_client, buf,
			    sizeof (buf) - 1)) > 0)
    {
      if (strncmp (buf, "." CRLF, 3) == 0)	/* EOM */
	break;
      swrite (CLIENT, remote_server, buf);
    }
}

void
transfer_body (MESSAGE * msg)
{
  if (msg->boundary)
    {
      send_body (msg, remote_server);

      /* Transfer everything else */
      raw_transfer ();
    }
  else
    send_body (msg, remote_server);
  swrite (CLIENT, remote_server, "." CRLF);
}

/* EOF */
