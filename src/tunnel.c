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

typedef int (*read_fn_t)(void *data, char *buf, size_t size);

static int  transfer_command(void *, void *, char *);
static void process_command(void *, void *, char *, int);
static void transfer_header(void *, void *, read_fn_t, void *);
static void process_header_line(char *);
static void transfer_body(void *, void *, read_fn_t, void *);
static void static_body_transfer(void *, void *, read_fn_t, void *);
static void dynamic_body_transfer(void *, void *, read_fn_t, void *);
static void clear_body_transfer(void *, void *);
static void add_remailer_commands(void *);
static void transform_body(void *sd_server);
static void postprocess(void *sd_client, void *sd_server);
static void collect_body(void *sd_client, char **retptr);
static void collect_headers(void *sd_client, struct list **listp);

int
socket_reader(void *sd_client, char *buf, size_t size)
{
	return recvline(SERVER, sd_client, buf, size);
}

enum buf_state {
	state_init,
	state_end,
	state_finish
};
	
struct mem_buf {
	char *buffer;
	size_t pos;
	size_t size;
	enum buf_state state;
};

void
init_mem_buf(struct mem_buf *mb, char *buf)
{
	memset(mb, 0, sizeof(*mb));
	mb->buffer = buf;
	mb->size = strlen(buf);
	mb->pos = 0;
	mb->state = state_init;
}

int
memory_reader(void *closure, char *buf, size_t size)
{
	struct mem_buf *mb = closure;
	int i;
	int crlf;
	
	switch (mb->state) {
	case state_init:
		crlf = 0;
		size--; /* make space for terminating zero */
		for (i = 0; i < size; i++) {
			if (mb->pos == mb->size) {
				mb->state = state_end;
				break;
			}
			*buf++ = mb->buffer[mb->pos++];
			if (i > 2 && buf[-2] == '\r' && buf[-1] == '\n') {
				crlf = 1;
				break;
			}
		}

		if (!crlf) {
		        strcpy(buf, CRLF);
			i += 2;
			buf += 2;
		}
		*buf = 0;
		break;

	case state_end:
		if (size < 4)
			i = 0;
		else {
			strcpy(buf, "." CRLF);
			i = 3;
		}
		break;
		
	case state_finish:
		i = 0;
	}
	return i;
}

struct list_buf {
	struct list *list;
	enum buf_state state;
};

void
init_list_buf(struct list_buf *lb, struct list *list)
{
	lb->list = list;
	lb->state = state_init;
}

int
list_reader(void *closure, char *buf, size_t size)
{
	struct list_buf *lb = closure;

	switch (lb->state) {
	case state_init:
		if (!lb->list) {
			lb->state = state_finish;
			strncpy(buf, CRLF, size);
		} else {
			strncpy(buf, lb->list->line, size);
			lb->list = lb->list->next;
		}
		return strlen(buf);

	default:
		return 0;
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

	if (strncmp(command, "220 ", 4) == 0 && strstr(command, version) == 0) {
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
#ifdef HAVE_SNPRINTF
			snprintf(command, LINEBUFFER,
#else
			sprintf(command,
#endif /* HAVE_SNPRINTF */
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
process_command(void *sd_client, void *sd_server, char *command, int size)
{
	char buf[LINEBUFFER+1];
	safe_strcpy(buf, command); /* make a back-up */
	change_to_lower(buf);

	if (rule_position) {
		char *ptr = 0;
		char regex1[LINEBUFFER+1];
		char regex2[LINEBUFFER+1];
		unsigned long optbackup;
		fseek(fp_rcfile, rule_position, SEEK_SET);
		while (read_regex_block(COMMAND, regex1, LINEBUFFER) != 0)
		{
			if ((ptr = strstr(regex1, " != "))) {
				*ptr = '\0';
				ptr += 4;
				safe_strcpy(regex2, ptr);
			}
			optbackup = ropt;
			if (regex_match(regex1, command)) { /* TRUE */
				if (ptr) {
					ropt = optbackup; /* restore ropt settings */
					if (regex_match(regex2, command) == 0) { /* FALSE */
						while (read_action_block(command) != 0)
						{ }
					}
				}
				else {
					while (read_action_block(command) != 0)
					{ }
				}
			}
		}
	}

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
			get_response_smtp(CLIENT, sd_server, reply, LINEBUFFER);

			if (!isdigit((unsigned char)reply[0]) || (unsigned char)reply[0] > '3') {
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
		if (check_filename(secure.cert) == 0)
			return;
		if (secure.key == 0)
			secure.key = allocbuf(secure.cert, MAXPATHLEN);
		else {
			if (check_filename(secure.key) == 0)
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

#ifdef HAVE_SNPRINTF
			snprintf(ehlo, LINEBUFFER,
#else
			sprintf(ehlo,
#endif /* HAVE_SNPRINTF */
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
			xfree(message.body);
			xfree(message.boundary);
			destroy_list(&message.addlist);
			destroy_list(&message.remlist);
			destroy_list(&message.modlist);
			mopt = 0;
			topt &= ~T_BOUNDARY;
			topt &= ~T_ERROR;
			if (all_position && (topt & T_SUPERCLIENT))
				read_rcfile_allsection();
		}
		else if (strncmp(buf, "data", 4) == 0) {
			postprocess(sd_client, sd_server);
			xfree(message.body);
			xfree(message.boundary);
			mopt = 0;
			topt &= ~T_BOUNDARY;
			topt &= ~T_ERROR;
			if (all_position && (topt & T_SUPERCLIENT))
				read_rcfile_allsection();
		}
	}
	return 1; /* OK */
}

#ifdef WITH_GUILE	
static void
collect_headers(void *sd_client, struct list **listp)
{
	struct list *tail;
	char buf[LINEBUFFER+1];

	*listp = tail = NULL;
	while (recvline(SERVER, sd_client, buf, LINEBUFFER))
	{
		if (strncmp(buf, CRLF, 2) == 0)
			break;

		tail = new_element(tail, listp, buf);
	}
}
		
static void
collect_body(void *sd_client, char **retptr)
{
	int nread;
	int capacity = DATABUFFER;
	char body_line[LINEBUFFER+1];
	char *ptr;
	
	ptr = xmalloc(DATABUFFER);
	while ((nread = recvline(SERVER, sd_client, body_line, LINEBUFFER))) {
		if (strncmp(body_line, "."CRLF, 3) == 0) /* EOM */
			break;
		capacity -= nread;
		if (capacity < nread) {
			ptr = xrealloc(ptr,
				       strlen(message.body) + DATABUFFER + 1);
			capacity = DATABUFFER - nread;
		}
		strcat(ptr, body_line);
	}
	*retptr = ptr;
}
#endif

void
postprocess(void *sd_client, void *sd_server)
{
	alarm(1800);
#ifdef WITH_GUILE	
	if (options.guile_postprocess) {
		struct mem_buf mb;
		struct list_buf lb;
		struct list *hdr_list;
		char *body;

		collect_headers(sd_client, &hdr_list);
		collect_body(sd_client, &body);

		guile_postprocess_proc(options.guile_postprocess,
				       &hdr_list,
				       &body);
		init_mem_buf(&mb, body);
		init_list_buf(&lb, hdr_list);
		transfer_header(sd_client, sd_server, list_reader, &lb);
		transfer_body(sd_client, sd_server, memory_reader, &mb);
		destroy_list(&hdr_list);
		xfree(body);
	} else {
		transfer_header(sd_client, sd_server,
				socket_reader, sd_client);
		transfer_body(sd_client, sd_server,
			      socket_reader, sd_client);
	}
#else
	transfer_header(sd_client, sd_server, socket_reader, sd_client);
	transfer_body(sd_client, sd_server, socket_reader, sd_client);
#endif	
	alarm(0);
}
	
/*****************
  MESSAGE HEADER
******************/

static void
transfer_header(void *sd_client, void *sd_server,
		read_fn_t readfn, void *closure)
{
	struct list *header_buf = NULL;
	struct list *header_tail = NULL;
	struct list *p1;
	struct list *p2;
	char header_line[LINEBUFFER+1];

	while (readfn(closure, header_line, LINEBUFFER))
	{
		if (strncmp(header_line, CRLF, 2) == 0)
			break;

		process_header_line(header_line);
		header_tail = new_element(header_tail, &header_buf, header_line);
	}

	if (message.remlist) {
		struct list *h1;
		struct list *h2;
		struct list *previous;
		char hline[LINEBUFFER+1];

		p1 = message.remlist;
		do {
			p2 = p1->next;
			h1 = header_buf;
			previous = NULL;

			do {
				h2 = h1->next;
				strncpy(hline, h1->line, LINEBUFFER);
				remcrlf(hline);
				if (regex_match(p1->line, hline)) {
					if (previous)
						previous->next = h2;
					else
						header_buf = h2;
					free(h1->line);
					free(h1);
					if (h2)
						h1 = h2;
				}
				else {
					if (h2) {
						previous = h1;
						h1 = h2;
					}
				}
			} while (h2 != NULL);

			free(p1->line);
			free(p1);
			if (p2)
				p1 = p2;
		} while (p2 != NULL);
		message.remlist = NULL;
	}

	if (message.addlist) {
		p1 = message.addlist;
		do {
			p2 = p1->next;
			strncpy(header_line, p1->line, LINEBUFFER-2);
			strcat(header_line, CRLF);
			header_tail = new_element(header_tail, &header_buf, header_line);
			free(p1->line);
			free(p1);
			if (p2)
				p1 = p2;
		} while (p2 != NULL);
		message.addlist = NULL;
	}

	if (message.modlist) {
		struct list *h1;
		struct list *h2;
		char hline[LINEBUFFER+1];

		p1 = message.modlist;
		do {
			p2 = p1->next;
			h1 = header_buf;

			do {
				h2 = h1->next;
				strncpy(hline, h1->line, LINEBUFFER);
				remcrlf(hline);
				if (regex_match(p1->line, hline)) {
					char *outbuf = substitute(p1->modify, submatch);
					free(h1->line);
					if (outbuf)
						h1->line = outbuf;
					else
						h1->line = strdup(p1->modify);
				}
				if (h2)
					h1 = h2;
			} while (h2 != NULL);

			free(p1->line);
			free(p1->modify);
			free(p1);
			if (p2)
				p1 = p2;
		} while (p2 != NULL);
		message.modlist = NULL;
	}

	p1 = header_buf;
	do {
		p2 = p1->next;

		/*
		   If there are any attachments, find the BOUNDARY.
		*/

		if (strncmp(p1->line, "Content-Type:", 13) == 0) {
			if (mopt & M_BODYCLEARAPPEND) {
				message.remlist_tail = new_element(message.remlist_tail,
					&message.remlist, "^Content-Type:");
				message.remlist_tail = new_element(message.remlist_tail,
					&message.remlist, "^Content-Transfer-Encoding:");
			}
			else {
				char *ptr1 = 0;
				char *ptr2 = 0;
				char boundary_buf[LINEBUFFER+1];
				struct list *plist = p1;

				safe_strcpy(boundary_buf, plist->line);
				change_to_lower(boundary_buf);

				ptr1 = strstr(boundary_buf, "boundary=");
				if (ptr1 == 0) {
					plist = plist->next;
					safe_strcpy(boundary_buf, plist->line);
					change_to_lower(boundary_buf);
					ptr1 = strstr(boundary_buf, "boundary=");
				}

				if (ptr1) {
					topt |= T_BOUNDARY;
					safe_strcpy(boundary_buf, plist->line);

					ptr2 = parse_line_option(boundary_buf);
					message.boundary = (char *)xmalloc(strlen(ptr2) + 3);
					if (*ptr2 == '"') {
						ptr2++;
						sprintf(message.boundary, "--%s", ptr2);
						ptr2 = strstr(message.boundary, "\"");
						*ptr2 = '\0';
					}
					else
						sprintf(message.boundary, "--%s", ptr2);
				}
			}
		}

		if (mopt & M_ROT13S) {
			if (strncmp(p1->line, "Subject:", 8) == 0) {
				char *p = strchr(p1->line, ':');
				p++;
				do {
					*p = (islower((unsigned char)*p)
					? 'a'+ (*p - 'a' + 13)%26 : isupper((unsigned char)*p)
					? 'A' + (*p - 'A' + 13)%26 : *p);
					p++;
				} while (*p != '\n');
			}
		}

		swrite(CLIENT, sd_server, p1->line);
		free(p1->line);
		free(p1);
		if (p2)
			p1 = p2;
	} while (p2 != NULL);
	header_buf = NULL;

	swrite(CLIENT, sd_server, CRLF);
	return;
}

static void
process_header_line(char *header_line)
{
	char *p = 0;
	char backup[LINEBUFFER+1];

	/*
	   The Trigger.
	*/

	p = strstr(header_line, BEGIN_TRIGGER);
	if (p) {
		safe_strcpy(backup, p);
		*p++ = '\r';
		*p++ = '\n';
		*p = '\0';
		p = backup;
		p += trigger_len;
	}
	else
		p = header_line;

	if (rule_position) {
		char *ptr = 0;
		char regex1[LINEBUFFER+1];
		char regex2[LINEBUFFER+1];
		unsigned long optbackup;
		fseek(fp_rcfile, rule_position, SEEK_SET);
		while (read_regex_block(HEADER, regex1, LINEBUFFER) != 0)
		{
			if ((ptr = strstr(regex1, " != "))) {
				*ptr = '\0';
				ptr += 4;
				safe_strcpy(regex2, ptr);
			}
			optbackup = ropt;
			if (regex_match(regex1, p)) { /* TRUE */
				if (ptr) {
					ropt = optbackup; /* restore ropt settings */
					if (regex_match(regex2, p) == 0) { /* FALSE */
						while (read_action_block(header_line) != 0)
						{ }
					}
				}
				else {
					while (read_action_block(header_line) != 0)
					{ }
				}
			}
		}
	}
	return;
}

/***************
  MESSAGE BODY
****************/

static void
transfer_body(void *sd_client, void *sd_server, read_fn_t readfn, void *closure)
{
	if (mopt & M_BODYCLEARAPPEND)
		clear_body_transfer(sd_client, sd_server);
	else {
		if ((mopt & M_GPG_ENCRYPT) || (mopt & M_GPG_SIGN) || (mopt & M_ROT13B)
		|| (mopt & M_RM) || (mopt & M_SIGNATURE) || (mopt & M_BODYAPPEND)
		|| (mopt & M_EXTBODYPROC))
			static_body_transfer(sd_client, sd_server,
					     readfn, closure);
		else
			dynamic_body_transfer(sd_client, sd_server,
					      readfn, closure);
	}
	return;
}

static void
static_body_transfer(void *sd_client, void *sd_server,
		     read_fn_t readfn, void *data)
{
	int nb = 0;
	int nread;
	int capacity = DATABUFFER;
	char body_line[LINEBUFFER+1];

	message.body = (char *)xmalloc(DATABUFFER);

	/*
	   If there are some attachments...
	*/

	if (topt & T_BOUNDARY) {
		nb = strlen(message.boundary);
		while (readfn(data, body_line, LINEBUFFER)) {
			swrite(CLIENT, sd_server, body_line);
			if (strncmp(body_line, message.boundary, nb) == 0) {
				while (recvline(SERVER, sd_client, body_line, LINEBUFFER))
				{
					swrite(CLIENT, sd_server, body_line);
					if (strncmp(body_line, CRLF, 2) == 0)
						break;
				}
				break;
			}
		}

		/*
		   Now we have reached the message body...
		*/

		while ((nread = readfn(data, body_line, LINEBUFFER)))
		{
			if (strncmp(body_line, message.boundary, nb) == 0)
				break;

			capacity -= nread;
			if (capacity >= nread)
				strcat(message.body, body_line);
			else {
				message.body = (char *)xrealloc((char *)message.body,
				strlen(message.body) + DATABUFFER + 1);
				strcat(message.body, body_line);
				capacity = DATABUFFER - nread;
			}
		}

		remcrlf(message.body);
		transform_body(sd_server);
		swrite(CLIENT, sd_server, message.body);
#ifdef HAVE_GPG
		if ((mopt & M_GPG_ENCRYPT) || (mopt & M_GPG_SIGN))
			swrite(CLIENT, sd_server, CRLF);
#endif /* HAVE_GPG */
		swrite(CLIENT, sd_server, body_line);

		/*
		   Transfer everything else...
		*/

		dynamic_body_transfer(sd_client, sd_server, readfn, data);
	}

	/*
	   else... No attachments.
	*/

	else {
		while ((nread = readfn(data, body_line, LINEBUFFER))) {
			if (strncmp(body_line, "."CRLF, 3) == 0) /* EOM */
				break;

			capacity -= nread;
			if (capacity < nread) {
				message.body = (char *)xrealloc((char *)message.body,
				strlen(message.body) + DATABUFFER + 1);
				capacity = DATABUFFER - nread;
			}
			strcat(message.body, body_line);
		}
		remcrlf(message.body);
		transform_body(sd_server);
		swrite(CLIENT, sd_server, message.body);
		swrite(CLIENT, sd_server, CRLF"."CRLF);

		recvline(CLIENT, sd_server, body_line, LINEBUFFER);
		swrite(SERVER, sd_client, body_line);
	}
	return;
}

static void
dynamic_body_transfer(void *sd_client, void *sd_server,
		      read_fn_t readfn, void *data)
{
	char body_line[LINEBUFFER+1];

	while (readfn(data, body_line, LINEBUFFER))
	{
		swrite(CLIENT, sd_server, body_line);
		if (strncmp(body_line, "."CRLF, 3) == 0) /* EOM */
			break;
	}

	recvline(CLIENT, sd_server, body_line, LINEBUFFER);
	swrite(SERVER, sd_client, body_line);

	return;
}

static void
clear_body_transfer(void *sd_client, void *sd_server)
{
	char body_line[LINEBUFFER+1];
	message.body = (char *)xmalloc(1);

	while (recvline(SERVER, sd_client, body_line, LINEBUFFER))
	{
		if (strncmp(body_line, "."CRLF, 3) == 0) /* EOM */
			break;
	}

	transform_body(sd_server);
	swrite(CLIENT, sd_server, message.body);
	swrite(CLIENT, sd_server, body_line);
	recvline(CLIENT, sd_server, body_line, LINEBUFFER);
	swrite(SERVER, sd_client, body_line);

	return;
}

static void
add_remailer_commands(void *sd_server)
{
	char buf[1024];

	if (!(mopt & M_RMGPG)) {
		if (mopt & M_RMRRT) {
			sprintf(buf, "::"CRLF"Anon-To: %s"CRLF, rm.rrt);
			swrite(CLIENT, sd_server, buf);
		}
		else if (mopt & M_RMPOST) {
			sprintf(buf, "::"CRLF"Anon-Post-To: %s"CRLF, rm.post);
			swrite(CLIENT, sd_server, buf);
		}
		if ((mopt & M_RMLT) || (mopt & M_RMRLT)) {
			sprintf(buf, "Latent-Time: +%s%s"CRLF,
			rm.latent_time, (mopt & M_RMRLT) ? "r" : "");
			swrite(CLIENT, sd_server, buf);
		}
		swrite(CLIENT, sd_server, CRLF);
		if (mopt & M_RMHEADER) {
			remcrlf(rm.header);
			swrite(CLIENT, sd_server, "##"CRLF);
			swrite(CLIENT, sd_server, rm.header);
			swrite(CLIENT, sd_server, CRLF);
		}
	}
#ifdef HAVE_GPG
	else
		swrite(CLIENT, sd_server, "::"CRLF"Encrypted: PGP"CRLF CRLF);
#endif /* HAVE_GPG */

	return;
}

static void
transform_body(void *sd_server)
{
	check_all_files(session.client);
	if (!(topt & T_ERROR) && (mopt & M_EXTBODYPROC)) {
		int rs = 0;
		char *extbuf = 0;
		extbuf = external_program(&rs, message.exteditor, message.body, 0, 0);
		if (rs != -1 && extbuf) {
			xfree(message.body);
			message.body = extbuf;
		}
	}
	if (!(topt & T_ERROR))
		check_rot13();

#ifdef HAVE_GPG
	if (!(topt & T_ERROR) && ((mopt & M_GPG_ENCRYPT)
	|| (mopt & M_GPG_SIGN) || (mopt & M_RMGPG)))
		check_gpg();
#endif /* HAVE_GPG */

	if (!(topt & T_ERROR)) {
		if (mopt & M_RM)
			add_remailer_commands(sd_server);
	}
	topt &= ~T_ERROR;
	return;
}

/* EOF */

