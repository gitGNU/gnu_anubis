/*
   authmode.c

   This file is part of GNU Anubis.
   Copyright (C) 2003 The Anubis Team.

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

#if defined(WITH_GSASL)

enum asmtp_state {
	state_init,
	state_ehlo,
	state_auth,
	state_quit
};

#define KW_EHLO      0
#define KW_HELO      1
#define KW_AUTH      2
#define KW_QUIT      3
#define KW_HELP      4
#define KW_STARTTLS  5
#define KW_MAIL      6
#define KW_RCPT      7
#define KW_RSET      8

static int
asmtp_kw (const char *name)
{
	static struct kw {
		char *name;
		int code;
	} kw[] = {
		{ "ehlo",     KW_EHLO },
		{ "helo",     KW_HELO },
		{ "auth",     KW_AUTH },
		{ "help",     KW_HELP },
		{ "quit",     KW_QUIT },
		{ "starttls", KW_STARTTLS },
		{ "mail",     KW_MAIL },
		{ "rcpt",     KW_RCPT },
		{ "rset",     KW_RSET },
		{ NULL },
	};
	int i;

	if (name) {
		for (i = 0; kw[i].name != NULL; i++)
			if (strcasecmp (name, kw[i].name) == 0)
				return kw[i].code;
	}
	return -1;
}

#define R_CONT     0x8000
#define R_CODEMASK 0xfff

void
asmtp_reply(int code, char *fmt, ...)
{
	va_list ap;
	int cont = code & R_CONT ? '-' : ' ';
	static char obuf[512];
	int n;
	
	va_start(ap, fmt);
	n = snprintf(obuf, sizeof obuf, "%d%c", code & R_CODEMASK, cont);
	n += vsnprintf(obuf + n, sizeof obuf - n, fmt, ap);
	va_end(ap);
	n += snprintf(obuf + n, sizeof obuf - n, "\r\n");
	swrite(SERVER, remote_client, obuf);
}

char *
get_command_word (char *command)
{
	return strtok (command, " \t\r\n");
}

char *
get_command_arg ()
{
	return strtok (NULL, " \t\r\n");
}

static void
asmtp_greet ()
{
	char *name = get_localname ();
	asmtp_reply(220, "%s GNU Anubis ESMTP; Identify yourself",
		    name);
}

static enum asmtp_state
asmtp_helo_reply(char *args)
{
	char *domain = get_command_arg();

	if (!domain) {
		asmtp_reply(501, "HELO requires domain address");
		return state_init;
	} else if (get_command_arg()) {
		asmtp_reply(501, "Syntax error");
		return state_init;
	}
	
	asmtp_reply(250, "Anubis is pleased to meet you.");
	return state_ehlo;
}

static LIST *asmtp_capa;

void
asmtp_capa_add(char *name)
{
	list_append (asmtp_capa, strdup(name));
}

void
asmtp_capa_add_prefix(char *prefix, char *name)
{
	char *str = malloc (strlen (prefix) + 1 + strlen (name) + 1);
	if (!str)
		abort();
	sprintf(str, "%s %s", prefix, name);
	list_append (asmtp_capa, str);
}

static int
name_cmp(void *a, void *b)
{
	return strcmp(a, b);
}

void
asmtp_capa_remove(char *name)
{
	char *p = list_remove (asmtp_capa, strdup(name), name_cmp);
	if (p)
		free(p);
}

static void
asmtp_capa_init()
{
	asmtp_capa = list_create();
#if defined(HAVE_TLS)
	asmtp_capa_add("STARTTLS");
#endif
#if defined(WITH_GSASL)
	auth_gsasl_init ();
#endif
	asmtp_capa_add("HELP");
}

static void
asmtp_capa_report()
{
	ITERATOR *itr = iterator_create(asmtp_capa);
	char *p = iterator_first(itr);

	while (p) {
		char *next = iterator_next(itr);
		asmtp_reply((next ? R_CONT : 0)|250, "%s", p);
		p = next;
	}
	iterator_destroy(&itr);
}

static enum asmtp_state
asmtp_ehlo_reply(char *args)
{
	char *domain = get_command_arg(args);

	if (!domain) {
		asmtp_reply(501, "EHLO requires domain address");
		return state_init;
	} else if (get_command_arg()) {
		asmtp_reply(501, "Syntax error");
		return state_init;
	}
	
	asmtp_reply(R_CONT|250, "Anubis is pleased to meet you.");
	asmtp_capa_report ();
	return state_ehlo;
}


static enum asmtp_state
asmtp_init(enum asmtp_state state)
{
	char *command = NULL;
	size_t s = 0;
	
	recvline_ptr(SERVER, remote_client, &command, &s);
	
	switch (asmtp_kw(get_command_word (command))) {
	case KW_EHLO:
		state = asmtp_ehlo_reply(command);
		break;
			
	case KW_HELO:
		state = asmtp_helo_reply(command);
		break;
		
	case KW_HELP:
		asmtp_reply(503, "No help available");
		break;
		
	case KW_AUTH:
	case KW_STARTTLS:
		asmtp_reply(503, "Polite people say EHLO first");
		break;
		
	case KW_QUIT:
		state = state_quit;
		break;

	case KW_MAIL:
	case KW_RCPT:
		asmtp_reply(550,
			    "Command disabled. Proper authentication required.");
		break;

	case KW_RSET:
		asmtp_reply(250, "OK"); /* FIXME: Fake RSET */
		break;

	default:
		asmtp_reply(500, "Unknown command");
	}
	free (command);
	return state;
}

static enum asmtp_state
asmtp_ehlo (enum asmtp_state state, ANUBIS_USER *usr)
{
	char *command = NULL;
	size_t s = 0;
	char *mech;
	char *init_input;
	
	recvline_ptr(SERVER, remote_client, &command, &s);

	switch (asmtp_kw(get_command_word (command))) {
	case KW_AUTH:
		mech = get_command_arg ();
		init_input = get_command_arg ();
		if (anubis_auth_gsasl (mech, init_input, usr) == 0) 
			state = state_auth;
		break;
		
	case KW_QUIT:
		state = state_quit;
		break;

	case KW_MAIL:
	case KW_RCPT:
		asmtp_reply(550,
			    "Command disabled. Proper authentication required.");
		break;

	case KW_RSET:
		asmtp_reply(250, "OK"); /* FIXME: Fake RSET */
		break;

	default:
		asmtp_reply(500, "Unknown command");
	}
	free(command);
	
	return state;
}

static int
anubis_smtp (ANUBIS_USER *usr)
{
	enum asmtp_state state;

	asmtp_capa_init();
	asmtp_greet();
	for (state = state_init; state != state_auth; ) {
		switch (state) {
		case state_init:
			state = asmtp_init (state);
			break;
			
		case state_ehlo:
			state = asmtp_ehlo (state, usr);
			break;
			
		case state_quit:
			return EXIT_FAILURE;

		case state_auth:
			break;
		}
	}
	return 0;
}


static char *anubis_dbarg;

void
anubis_set_password_db (char *arg)
{
	free(anubis_dbarg);
	anubis_dbarg = strdup(arg);
}

int
anubis_get_db_record(char *username, ANUBIS_USER *usr)
{
	void *db;
	int rc;
	char *errtext;
	
	if (!anubis_dbarg) {
		anubis_error(HARD, _("Database not specified"));
		return ANUBIS_DB_FAIL;
	}

	if (anubis_db_open(anubis_dbarg, anubis_db_rdonly,
			   &db, &errtext) != ANUBIS_DB_SUCCESS) {
		anubis_error(HARD,
			     _("Cannot open database %s: %s"),
			     anubis_dbarg, errtext);
		return ANUBIS_DB_FAIL;
	}
	
	rc = anubis_db_get_record(db, username, usr);
	switch (rc) {
	case ANUBIS_DB_SUCCESS:
		info(VERBOSE,
		     _("Found record for %s"), username);
		break;
			
	case ANUBIS_DB_FAIL:
		anubis_error(SOFT,
			 _("Cannot retrieve data from the SASL database: %s"),
			     anubis_db_strerror(db));
		break;
			
	case ANUBIS_DB_NOT_FOUND:
		info(VERBOSE, _("Record for %s not found"),
		     username);
		break;
	}
		
	anubis_db_close(&db);
	return rc;
}




int
anubis_authenticate_mode (int sd_client, struct sockaddr_in *addr)
{	
	int rc;
	ANUBIS_USER usr;
	
	remote_client = (void *)sd_client;
	remote_server = (void *)sd_client;
	alarm(900);
	if (anubis_smtp (&usr))
		return EXIT_FAILURE;

	if (usr.username)
		strncpy(session.client, usr.username, sizeof session.client);
	else
		strncpy(session.client, usr.smtp_authid, sizeof session.client);
	parse_transmap(&rc,
		       session.client,
		       inet_ntoa(addr->sin_addr),
		       session.client,
		       sizeof(session.client));
				
	if (rc == 1) {
		anubis_changeowner(session.client);
		auth_tunnel();
	} else if (rc == -1) {
		if (check_username(session.client)) {
			anubis_changeowner(session.client);
			auth_tunnel();
		} else
			set_unprivileged_user();
	} else
		set_unprivileged_user();
	
	if (!(topt & T_LOCAL_MTA)
	    && strlen(session.mta) == 0) {
		anubis_error(HARD, _("The MTA has not been specified. "
				     "Set the REMOTE-MTA or LOCAL-MTA."));
		return EXIT_FAILURE;
	}
	
	/*
	  Protection against a loop connection.
	*/
	
	if (!(topt & T_LOCAL_MTA)) {
		unsigned long inaddr;
		struct sockaddr_in ad;
		
		memset(&ad, 0, sizeof(ad));
		inaddr = inet_addr(session.mta);
		if (inaddr != INADDR_NONE)
			memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
		else {
			struct hostent *hp = 0;
			hp = gethostbyname(session.mta);
			if (hp == 0) {
				hostname_error(session.mta);
				return EXIT_FAILURE;
			} else {
				if (hp->h_length != 4 && hp->h_length != 8) {
					anubis_error(HARD,
		_("Illegal address length received for host %s"), session.mta);
					return EXIT_FAILURE;
				} else {
					memcpy((char *)&ad.sin_addr.s_addr,
					       hp->h_addr,
					       hp->h_length);
				}
			}
		}
		if (ntohl(ad.sin_addr.s_addr) == INADDR_LOOPBACK
		    && session.tunnel_port == session.mta_port) {
			anubis_error(SOFT, _("Loop not allowed. Connection rejected."));
			return EXIT_FAILURE;
		}
	}
	
	alarm(300);
	if (topt & T_LOCAL_MTA) {
		remote_server = (void*) make_local_connection(session.execpath,
							      session.execargs);
		if (remote_server == (void*)-1) {
			service_unavailable((int)remote_client);
			return EXIT_FAILURE;
		}
	} else {
		remote_server = (void*)make_remote_connection(session.mta,
							      session.mta_port);
		if (remote_server == (void*)-1)
			service_unavailable((int)remote_client);
	}
	alarm(0);
	
	if (!(topt & T_ERROR)) {
		alarm(900);
		smtp_session();
		alarm(0);
	}
	net_close(SERVER, remote_client);
	net_close(CLIENT, remote_server);
	
	if (topt & T_ERROR)
		info(NORMAL, _("Connection terminated."));
	else
		info(NORMAL, _("Connection closed successfully."));
	
#ifdef HAVE_PAM	
	pam_retval = pam_close_session(pamh, 0);
	if (pam_retval == PAM_SUCCESS)
		info(VERBOSE, _("PAM: Session closed."));
	if (pam_end(pamh, pam_retval) != PAM_SUCCESS) {
		pamh = NULL;
		info(NORMAL, _("PAM: failed to release authenticator."));
		return EXIT_FAILURE;
	}
#endif /* HAVE_PAM */
	return 0;
}

#endif
