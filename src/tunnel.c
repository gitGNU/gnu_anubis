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
static void process_header_line(char *);
static void transfer_body(void *, void *);
static void add_remailer_commands(void *);
static void transform_body(void *sd_server);
static void process_data(void *sd_client, void *sd_server);


/* Auxiliary list handling functions */ 
/* These belong to the future list.c */
typedef int (*list_iterator_t)(struct list *list, void *data);

void
list_iterate(struct list *p, list_iterator_t itr, void *data)
{
	while (p) {
		struct list *q = p->next;
		itr(p, data);
		p = q;
	};
}

void
list_append(struct list **a, struct list *b)
{
	if (!*a)
		*a = b;
	else {
		struct list *p;
		
		for (p = *a; p->next; p = p->next)
			;
		p->next = b;
	}
}


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
collect_headers(void *sd_client, struct list **listp)
{
	struct list *tail;
	char buf[LINEBUFFER+1];

	*listp = tail = NULL;
	while (recvline(SERVER, sd_client, buf, LINEBUFFER)) {
		if (strncmp(buf, CRLF, 2) == 0)
			break;
		remcrlf(buf);
		if (isspace(buf[0])) {
			if (!tail) 
				/* Something wrong, assume we've got no
				   headers */
				break;
			tail->line = xrealloc(tail->line,
					      strlen(tail->line) +
					      strlen(buf) + 2);
			strcat(tail->line, "\n");
			strcat(tail->line, buf);
		} else {
			if (!(topt & (T_BOUNDARY|T_ENTIRE_BODY)) && tail)
			    get_boundary(tail->line);
			tail = new_element(tail, listp, buf);
		}
	}
}
static void
write_header_line (void *sd_server, char *line)
{
	char *p;

	p = strtok(line, "\n");
	do {
		swrite(CLIENT, sd_server, p);
		swrite(CLIENT, sd_server, CRLF);
	} while (p = strtok(NULL, "\n"));
}
			
void
send_header (void *sd_server, struct list **plist)
{
	struct list *p;
	p = *plist;
	while (p) {
		struct list *q = p->next;
		write_header_line(sd_server, p->line);
		free(p->line);
		free(p);
		p = q;
	}
	*plist = NULL;
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
	struct list *tail = NULL;
	int len;

	if (topt & T_BOUNDARY) 
		len = strlen(message.boundary);
	
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
					tail = new_element(tail,
							   &message.mime_hdr,
							   buf);
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
		send_header(sd_server, &message.mime_hdr);
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
process_command(void *sd_client, void *sd_server, char *command, int size)
{
	char buf[LINEBUFFER+1];
	safe_strcpy(buf, command); /* make a back-up */
	change_to_lower(buf);

	rcfile_process_cond("RULE", COMMAND, command);
	
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
			xfree(message.body);
			xfree(message.boundary);
			destroy_list(&message.addlist);
			destroy_list(&message.remlist);
			destroy_list(&message.modlist);
			mopt = 0;
			topt &= ~T_BOUNDARY;
			topt &= ~T_ERROR;
			if (topt & T_SUPERCLIENT)
				rcfile_process_section(CF_CLIENT, "ALL", NULL);
		}
		else if (strncmp(buf, "data", 4) == 0) {
			process_data(sd_client, sd_server);
			xfree(message.body);
			xfree(message.boundary);
			mopt = 0;
			topt &= ~T_BOUNDARY;
			topt &= ~T_ERROR;
			if (topt & T_SUPERCLIENT)
				rcfile_process_section(CF_CLIENT, "ALL", NULL);
		}
	}
	return 1; /* OK */
}

void
process_data(void *sd_client, void *sd_server)
{
	struct list *message_hdr;
	char buf[LINEBUFFER+1];

	alarm(1800);

	collect_headers(sd_client, &message_hdr);
	collect_body(sd_client, &message.body);

	transfer_header(sd_client, sd_server, message_hdr);
	transform_body(sd_server);
	transfer_body(sd_client, sd_server);

	recvline(CLIENT, sd_server, buf, LINEBUFFER);
	swrite(SERVER, sd_client, buf);

	/* FIXME: xfree(message_body); */

	alarm(0);
}
	
/*****************
  MESSAGE HEADER
******************/

struct header_data {
	void *sd_client;
	void *sd_server;
	struct list *header;
};

struct closure {
	RC_REGEX *regex;
	char *modify;
	struct list *head, *tail;
};

int
action_remove2(struct list *p, void *data)
{
	struct closure *clos = data;
	int rc, stat;
	char **rv = NULL;
	
	stat = anubis_regex_match(clos->regex, p->line, &rc, &rv);
	free_pptr(rv);
	if (stat) {
		free(p->line);
		free(p);
	} else {
		p->next = NULL;
		if (clos->head == NULL)
			clos->head = p;
		if (clos->tail)
			clos->tail->next = p;
		clos->tail = p;
	}
	return 0;
}

int
action_remove(struct list *p, void *data)
{
	struct header_data *hp = data;
	struct closure clos;

	clos.regex = anubis_regex_compile(p->line, 0);
	clos.head = clos.tail = NULL;
	list_iterate(hp->header, action_remove2, &clos);
	hp->header = clos.head;
	anubis_regex_free(clos.regex);
	free(p->line);
	free(p);
	return 0;
}

int
action_mod2(struct list *p, void *data)
{
	struct closure *clos = data;
	int rc, stat;
	char **rv = NULL;
	
	stat = anubis_regex_match(clos->regex, p->line, &rc, &rv);
	if (stat) {
		free(p->line);
		p->line = substitute(clos->modify, rv);
		if (!p->line)
			p->line = strdup(clos->modify);
		free_pptr(rv);
	}
	return 0;
}

int
action_mod(struct list *p, void *data)
{
	struct header_data *hp = data;
	struct closure clos;

	clos.regex = anubis_regex_compile(p->line, 0);
	clos.head = clos.tail = NULL;
	clos.modify = p->modify;
	list_iterate(hp->header, action_mod2, &clos);
	anubis_regex_free(clos.regex);
	free(p->line);
	free(p);
	return 0;
}

int
action_free(struct list *p, void *data)
{
	free(p->line);
	free(p);
	return 0;
}

static void
transfer_header(void *sd_client, void *sd_server, struct list *header_buf)
{
	struct list *p;
	struct header_data hd;
	
	hd.sd_server = sd_server;
	hd.sd_client = sd_client;
	hd.header = header_buf;

	for (p = hd.header; p; p = p->next) 
		process_header_line(p->line);
	
#ifdef WITH_GUILE
	guile_process_list(&header_buf, &message.body);
#endif /* WITH_GUILE */
	
	list_iterate(message.remlist, action_remove, &hd);
	message.remlist = NULL;

	list_append(&hd.header, message.addlist);
	message.addlist = NULL;
	
	list_iterate(message.modlist, action_mod, &hd);
	message.modlist = NULL;
	
#ifdef WITH_GUILE
	guile_postprocess_list(&hd.header, &message.body);
#endif /* WITH_GUILE */

	send_header(sd_server, &hd.header);
	swrite(CLIENT, sd_server, CRLF);
	
	list_iterate(hd.header, action_free, NULL);
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
		*p = '\0';
		p = backup;
		p += sizeof(BEGIN_TRIGGER) - 1;
	} else
		p = header_line;

	rcfile_process_cond("RULE", HEADER, p); 
	return;
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
#ifdef HAVE_GPG
		if ((mopt & M_GPG_ENCRYPT) || (mopt & M_GPG_SIGN))
			swrite(CLIENT, sd_server, CRLF);
#endif /* HAVE_GPG */
		
		/* Transfer everything else */
		raw_transfer(sd_client, sd_server);
	} else
		send_body(sd_server);
	swrite(CLIENT, sd_server, "."CRLF);
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

