/*
   tunnel.c

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

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

static int  transfer_command(void *, void *, char *);
static void process_command(void *, void *, char *, int);
static void transfer_header(void *, void *, struct list *list);
static void transfer_body(void *, void *);
static void process_data(void *sd_client, void *sd_server);


/* Collect and send headers */

/* Headers spanning multiple lines are wrapped into a single line, preserving
   the newlines. When sending to the server they are split again at newlines
   snd sent in multiline lines. */
   
static void
get_boundary(char *line)
{
	char boundary_buf[LINEBUFFER+1], *p;

	if (strncmp(line, "Content-Type:", 13))
		return;
	
	safe_strcpy(boundary_buf, line);
	change_to_lower(boundary_buf);
	p = strstr(boundary_buf, "boundary=");
	if (!p)
		return;
	p += 9;
	if (*p == '"') {
		char *q = strchr(++p, '"');
		if (*q)
			*q = 0;
	}
	message.boundary = xmalloc(strlen(p) + 3);
	sprintf(message.boundary, "--%s", p);
	topt |= T_BOUNDARY;
}

static void
add_header(struct list *list, char *line)
{
	ASSOC *asc = header_assoc(line);
	list_append(list, asc);
	if (asc->key && strcasecmp(asc->key, "subject") == 0) {
		char *p = strstr(asc->value, BEGIN_TRIGGER);

		if (p) {
			asc = xmalloc(sizeof(*asc));
			
			*p = 0;
			p += sizeof(BEGIN_TRIGGER) - 1;
			asc->key = strdup(X_ANUBIS_RULE_HEADER);
			asc->value = strdup(p);
			list_append(list, asc);
		}
	}
}

static void
collect_headers(void *sd_client, struct list **listp)
{
	char buf[LINEBUFFER+1];
	char *line = NULL;

	*listp = list_create();
	while (recvline(SERVER, sd_client, buf, LINEBUFFER)) {
		remcrlf(buf);
		if (isspace(buf[0])) {
			if (!line) 
				/* Something wrong, assume we've got no
				   headers */
				break;
			line = xrealloc(line,
					strlen(line) + strlen(buf) + 2);
			strcat(line, "\n");
			strcat(line, buf);
		} else {
			if (line) {
				if (!(topt & (T_BOUNDARY|T_ENTIRE_BODY)))
					get_boundary(line);
				add_header(*listp, line);
				line = NULL;
			} 
			if (buf[0] == 0)
				break;
			line = strdup(buf);
		}
	}
}

static void
write_header_line(void *sd_server, char *line)
{
	char *p;

	p = strtok(line, "\n");
	do {
		swrite(CLIENT, sd_server, p);
		swrite(CLIENT, sd_server, CRLF);
	} while (p = strtok(NULL, "\n"));
}
			
static void
write_assoc(void *sd_server, ASSOC *entry)
{
	if (entry->key) {
		if (strcmp(entry->key, X_ANUBIS_RULE_HEADER) == 0)
			return;
		swrite(CLIENT, sd_server, entry->key);
		swrite(CLIENT, sd_server, ":");
	}
	write_header_line(sd_server, entry->value);
}
			
void
send_header(void *sd_server, struct list *list)
{
	ASSOC *p;

	for (p = list_first(list); p; p = list_next(list)) 
		write_assoc(sd_server, p);
}

void
send_string_list(void *sd_server, struct list *list)
{
	char *p;

	for (p = list_first(list); p; p = list_next(list)) 
		write_header_line(sd_server, p);
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
collect_body(void *sd_client, char **retptr)
{
	int nread;
	char buf[LINEBUFFER+1];
	struct obstack stk;
	int state = 0;
	int len;

	if (topt & T_BOUNDARY) {
		len = strlen(message.boundary);
		message.mime_hdr = list_create();
	}
			
	obstack_init (&stk);
	while (state != ST_DONE
	       && (nread = recvline(SERVER, sd_client, buf, LINEBUFFER))) {
		if (strncmp(buf, "."CRLF, 3) == 0) /* EOM */
			break;
		
		remcrlf(buf);
		
		if (topt & T_BOUNDARY) {
			switch (state) {
			case ST_INIT:
				if (strcmp(buf, message.boundary) == 0) 
					state = ST_HDR;
				break;

			case ST_HDR:
				if (buf[0] == 0) 
					state = ST_BODY;
				else
					list_append(message.mime_hdr,
						    strdup(buf));
				break;

			case ST_BODY:
				if (strncmp(buf, message.boundary, len) == 0)
					state = ST_DONE;
				else {
					obstack_grow(&stk, buf, strlen(buf));
					obstack_1grow(&stk, '\n');
				}
			}
		} else {
			obstack_grow(&stk, buf, strlen(buf));
			obstack_1grow(&stk, '\n');
		}
	}
	obstack_1grow(&stk, 0);
	*retptr = strdup(obstack_finish(&stk));
	obstack_free(&stk, NULL);
}

void
send_body(void *sd_server)
{
	char *p;

	if (topt & T_BOUNDARY) {
		swrite(CLIENT, sd_server, message.boundary);
		swrite(CLIENT, sd_server, CRLF);
		send_string_list(sd_server, message.mime_hdr);
		swrite(CLIENT, sd_server, CRLF);
	}

	for (p = message.body; *p; ) {
		char *q = strchr(p, '\n');
		if (q)
			*q++ = 0;
		else
			q = p + strlen(p);
		
		swrite(CLIENT, sd_server, p);
		swrite(CLIENT, sd_server, CRLF);
		p = q;
	}

	if (topt & T_BOUNDARY) {
		swrite(CLIENT, sd_server, message.boundary);
		swrite(CLIENT, sd_server, CRLF);
	}
}


/******************
  The Tunnel core
*******************/

void
smtp_session(void *sd_client, void *sd_server)
{
	char command[LINEBUFFER+1];

	/*
	   First of all, transfer a welcome message.
	*/

	info(VERBOSE, _("Transferring message(s)..."));
	get_response_smtp(CLIENT, sd_server, command, LINEBUFFER);

	if (strncmp(command, "220 ", 4) == 0
	    && strstr(command, version) == 0) {
		char *ptr = 0;
		char *banner_ptr = 0;
		char host[65];
		char banner_backup[LINEBUFFER+1];
		safe_strcpy(banner_backup, command);

		if ((banner_ptr = strchr(banner_backup, ' '))) {
			banner_ptr++;
			safe_strcpy(host, banner_ptr);
			if ((ptr = strchr(host, ' ')))
				*ptr = '\0';
			do {
				banner_ptr++;
			} while (*banner_ptr != ' ');
			banner_ptr++;
			snprintf(command, LINEBUFFER,
				"220 %s (%s) %s", host, version, banner_ptr);
		}
	}
	swrite(SERVER, sd_client, command);

	/*
	   Then process the commands...
	*/

	while (recvline(SERVER, sd_client, command, LINEBUFFER))
	{
		process_command(sd_client, sd_server, command, LINEBUFFER);
		sd_client = remote_client;
		sd_server = remote_server;

		if (topt & T_ERROR)
			break;
		if (strlen(command) == 0)
			continue;

		if (transfer_command(sd_client, sd_server, command) == 0)
			break;
	}
	return;
}

/********************
  THE MAIL COMMANDS
*********************/

static void
save_command(char *line)
{
	int i;
	ASSOC *asc = xmalloc(sizeof(*asc));

	for (i = 0; line[i] && isspace(line[i]); i++)
		;

	asc->key = xmalloc(i + 1);
	memcpy(asc->key, line, i);
	asc->key[i] = 0;
	for (; line[i] && isspace(line[i]); i++)
		;
	if (line[i])
		asc->value = strdup(&line[i]);
	else
		asc->value = NULL;
	list_append(message.commands, asc);
}

static void
process_command(void *sd_client, void *sd_server, char *command, int size)
{
	char buf[LINEBUFFER+1];
	safe_strcpy(buf, command); /* make a back-up */
	save_command(buf);

	change_to_lower(buf);
	
	if (strncmp(buf, "starttls", 8) == 0) {

#if defined(HAVE_TLS) || defined(HAVE_SSL)

		if (topt & T_SSL_FINISHED) {
			if (topt & T_SSL_ONEWAY)
				swrite(SERVER, sd_client, "503 5.0.0 TLS (ONEWAY) already started"CRLF);
			else
				swrite(SERVER, sd_client, "503 5.0.0 TLS already started"CRLF);
			strncpy(command, "", 1);
			return;
		}
		else if (!(topt & T_STARTTLS) || !(topt & T_SSL)) {
			swrite(SERVER, sd_client, "503 5.5.0 TLS not available"CRLF);
			strncpy(command, "", 1);
			return;
		}

		/*
		   Make the TLS/SSL connection with ESMTP server.
		*/

		info(NORMAL, _("Using the TLS/SSL encryption..."));

		if (!(topt & T_LOCAL_MTA)) {
			char reply[LINEBUFFER+1];
			swrite(CLIENT, sd_server, "STARTTLS"CRLF);
			get_response_smtp(CLIENT, sd_server,
					  reply, LINEBUFFER);

			if (!isdigit((unsigned char)reply[0])
			    || (unsigned char)reply[0] > '3') {
				remcrlf(reply);
				info(VERBOSE, _("WARNING: %s"), reply);
				anubis_error(HARD, _("STARTTLS command failed."));
				return;
			}

#ifdef HAVE_TLS
			secure.client = start_tls_client((int)sd_server);
#endif /* HAVE_TLS */

#ifdef HAVE_SSL
			secure.ctx_client = init_ssl_client();
			if (topt & T_ERROR)
				return;
			secure.client = start_ssl_client((int)sd_server, secure.ctx_client);
#endif /* HAVE_SSL */

			if (topt & T_ERROR)
				return;
			sd_server = remote_server = (void *)secure.client;
		}

		/*
		   Make the TLS/SSL connection with SMTP client
		   (client connected with the Tunnel).
		*/

		if (secure.cert == 0)
			secure.cert = allocbuf(DEFAULT_SSL_PEM, MAXPATHLEN);
		if (check_filename(secure.cert, NULL) == 0)
			return;
		if (secure.key == 0)
			secure.key = allocbuf(secure.cert, MAXPATHLEN);
		else {
			if (check_filename(secure.key, NULL) == 0)
				return;
		}

		/*
		   Check file permissions. Ignore if a client hasn't
		   specified a private key or a certificate.
		*/

		if (topt & T_SSL_CKCLIENT)
			check_filemode(secure.key);

#ifdef HAVE_SSL
		secure.ctx_server = init_ssl_server();
#endif /* HAVE_SSL */

		if (topt & T_ERROR) {
			swrite(SERVER, sd_client, "454 4.3.3 TLS not available"CRLF);
			return;
		}
		swrite(SERVER, sd_client, "220 2.0.0 Ready to start TLS"CRLF);

#ifdef HAVE_TLS
		secure.server = start_tls_server((int)sd_client);
#endif /* HAVE_TLS */
#ifdef HAVE_SSL
		secure.server = start_ssl_server((int)sd_client, secure.ctx_server);
#endif /* HAVE_SSL */

		if (topt & T_ERROR)
			return;
		sd_client = remote_client = (void *)secure.server;
		topt |= T_SSL_FINISHED;

#else
		swrite(SERVER, sd_client, "503 5.5.0 TLS not available"CRLF);
#endif /* HAVE_TLS or HAVE_SSL */

		strncpy(command, "", 1);
		return;
	}
	return;
}

static int
transfer_command(void *sd_client, void *sd_server, char *command)
{
	char reply[2 * LINEBUFFER+1];
	char buf[LINEBUFFER+1];

	safe_strcpy(buf, command);
	change_to_lower(buf);
	swrite(CLIENT, sd_server, command);
	if (topt & T_ERROR)
		return 0;

	if (strncmp(buf, "ehlo", 4) == 0) {
		get_response_smtp(CLIENT, sd_server, reply, 2 * LINEBUFFER);

		if (strstr(reply, "STARTTLS"))
			topt |= T_STARTTLS; /* Yes, we can use the TLS/SSL encryption. */

#if defined(HAVE_TLS) || defined(HAVE_SSL)
		if ((topt & T_SSL_ONEWAY) && (topt & T_STARTTLS)
		&& !(topt & T_SSL_FINISHED) && !(topt & T_LOCAL_MTA)) {

			struct sockaddr_in rclient;
			char ehlo[LINEBUFFER+1];
			socklen_t addrlen;

			/*
			   The 'ONEWAY' method is used when your MUA doesn't
			   support the TLS/SSL, but your MTA does.
			   Make the TLS/SSL connection with ESMTP server.
			*/

			char newreply[LINEBUFFER+1];
			info(NORMAL, _("Using the 'ONEWAY' TLS/SSL encryption..."));
			swrite(CLIENT, sd_server, "STARTTLS"CRLF);
			get_response_smtp(CLIENT, sd_server, newreply, LINEBUFFER);

			if (!isdigit((unsigned char)newreply[0]) || (unsigned char)newreply[0] > '3') {
				remcrlf(newreply);
				info(VERBOSE, _("WARNING: %s"), newreply);
				anubis_error(SOFT, _("STARTTLS (ONEWAY) command failed."));
				topt &= ~T_SSL_ONEWAY;
				swrite(SERVER, sd_client, reply);
				return 1;
			}

#ifdef HAVE_SSL
			secure.ctx_client = init_ssl_client();
#endif /* HAVE_SSL */

			if (topt & T_ERROR) {
				topt &= ~T_ERROR;
				topt &= ~T_SSL_ONEWAY;
				swrite(SERVER, sd_client, reply);
				return 1;
			}

#ifdef HAVE_TLS
			secure.client = start_tls_client((int)sd_server);
#endif /* HAVE_TLS */
#ifdef HAVE_SSL
			secure.client = start_ssl_client((int)sd_server, secure.ctx_client);
#endif /* HAVE_SSL */

			if (topt & T_ERROR) {
				topt &= ~T_ERROR;
				topt &= ~T_SSL_ONEWAY;
				swrite(SERVER, sd_client, reply);
				return 1;
			}
			sd_server = remote_server = (void *)secure.client;
			topt |= T_SSL_FINISHED;

			/*
			   Send the EHLO command (after the TLS/SSL negotiation).
			*/

			addrlen = sizeof(rclient);
			if (getpeername((int)sd_client, (struct sockaddr *)&rclient, &addrlen) == -1)
				anubis_error(HARD, _("getpeername() failed: %s."), strerror(errno));

			snprintf(ehlo, LINEBUFFER,
				"EHLO %s"CRLF,
				(topt & T_ERROR) ? "localhost" : inet_ntoa(rclient.sin_addr));

			topt &= ~T_ERROR;
			swrite(CLIENT, sd_server, ehlo);
			get_response_smtp(CLIENT, sd_server, reply, 2 * LINEBUFFER);
		}
#endif /* HAVE_TLS or HAVE_SSL */

		/*
		   Remove the STARTTLS command from the EHLO list
		   if no SSL is specified, the SSL is not available,
		   or we're using the 'ONEWAY' TLS/SSL encryption.
		*/

		if ((topt & T_STARTTLS) && (!(topt & T_SSL) || (topt & T_SSL_ONEWAY))) {
			char *starttls1 = "250-STARTTLS";
			char *starttls2 = "STARTTLS";
			if (strstr(reply, starttls1))
				remline(reply, starttls1);
			else if (strstr(reply, starttls2))
				remline(reply, starttls2);
		}

		/*
		   Check whether we can use the ESMTP AUTH.
		*/

		if ((topt & T_ESMTP_AUTH) && strstr(reply, "AUTH ")) {
			esmtp_auth(sd_server, reply);
			memset(session.mta_username, 0, sizeof(session.mta_username));
			memset(session.mta_password, 0, sizeof(session.mta_password));
		}
	}
	else
		get_response_smtp(CLIENT, sd_server, reply, 2 * LINEBUFFER);

	swrite(SERVER, sd_client, reply);
	if (topt & T_ERROR)
		return 0;

	if (isdigit((unsigned char)reply[0]) && (unsigned char)reply[0] < '4') {
		if (strncmp(buf, "quit", 4) == 0)
			return 0; /* The QUIT command */
		else if (strncmp(buf, "rset", 4) == 0) {
			destroy_assoc_list(&message.commands);
			destroy_assoc_list(&message.header);
			destroy_string_list(&message.mime_hdr);
			xfree(message.body);
			xfree(message.boundary);
			topt &= ~T_BOUNDARY;
			topt &= ~T_ERROR;
		}
		else if (strncmp(buf, "data", 4) == 0) {
			process_data(sd_client, sd_server);
			xfree(message.body);
			xfree(message.boundary);
			topt &= ~T_BOUNDARY;
			topt &= ~T_ERROR;
		}
	}
	return 1; /* OK */
}

void
process_data(void *sd_client, void *sd_server)
{
	char buf[LINEBUFFER+1];

	alarm(1800);

	collect_headers(sd_client, &message.header);
	collect_body(sd_client, &message.body);

	rcfile_process_section(CF_CLIENT, "RULE", NULL, &message);
	
	transfer_header(sd_client, sd_server, message.header);
	transfer_body(sd_client, sd_server);

	recvline(CLIENT, sd_server, buf, LINEBUFFER);
	swrite(SERVER, sd_client, buf);

	/* FIXME: xfree(message_body); */

	alarm(0);
}
	
static void
transfer_header(void *sd_client, void *sd_server, struct list *header_buf)
{
	send_header(sd_server, header_buf);
	swrite(CLIENT, sd_server, CRLF);
}


/***************
  MESSAGE BODY
****************/

static void
raw_transfer(void *sd_client, void *sd_server)
{
	int nread;
	char buf[LINEBUFFER+1];
	
	while ((nread = recvline(SERVER, sd_client, buf, LINEBUFFER)) > 0) {
		if (strncmp(buf, "."CRLF, 3) == 0) /* EOM */
			break;
		swrite(CLIENT, sd_server, buf);
	}
}

void
transfer_body(void *sd_client, void *sd_server)
{
	if (topt & T_BOUNDARY) {
		send_body(sd_server);
		
		/* Transfer everything else */
		raw_transfer(sd_client, sd_server);
	} else
		send_body(sd_server);
	swrite(CLIENT, sd_server, "."CRLF);
}

void
message_add_header(MESSAGE *msg, char *hdr)
{
	list_append(msg->header, header_assoc(hdr));
}

void
message_remove_headers(MESSAGE *msg, char *arg)
{
	ASSOC *asc;
	RC_REGEX *regex = anubis_regex_compile(arg, 0);
	
	for (asc = list_first(msg->header); asc;
	     asc = list_next(msg->header)) {
		char **rv;
		int rc;
		char *h = assoc_to_header(asc);
		
		if (anubis_regex_match(regex, h, &rc, &rv)) {
			list_remove_current(msg->header);
			assoc_free(asc);
		}
		free(h);
		if (rc)
			free_pptr(rv);
	}
	anubis_regex_free(regex);
}

void
message_modify_headers(MESSAGE *msg, char *arg, char *modify)
{
	ASSOC *asc;
	RC_REGEX *regex = anubis_regex_compile(arg, 0);
	
	for (asc = list_first(msg->header); asc;
	     asc = list_next(msg->header)) {
		char **rv;
		int rc;
		char *h = assoc_to_header(asc);
		
		if (anubis_regex_match(regex, h, &rc, &rv)) {
			free(asc->value);
			asc->value = substitute(modify, rv);
			if (!asc->value)
				asc->value = strdup(modify);
		}
		free(h);
		free_pptr(rv);
	}
	anubis_regex_free(regex);
}

void
message_external_proc(MESSAGE *msg, char *name)
{
	int rc = 0;
	char *extbuf = 0;
	extbuf = external_program(&rc, name, message.body, 0, 0);
	if (rc != -1 && extbuf) {
		xfree(message.body);
		message.body = extbuf;
	}
}

/* EOF */

