/*
   authmode.c

   This file is part of GNU Anubis.
   Copyright (C) 2003-2014 The Anubis Team.

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
#include "rcfile.h"

#ifdef WITH_GSASL

static char *smtp_greeting_message;
static ANUBIS_LIST smtp_help_message;
static int helo_count; /* report possible SMTP attack */



void
make_help_message (char *text)
{
  char *p;

  if (smtp_help_message)
    list_destroy (&smtp_help_message, anubis_free_list_item, NULL);
  smtp_help_message = list_create ();

  p = strtok (text, "\n");
  do
    list_append (smtp_help_message, strdup (p));
  while ((p = strtok (NULL, "\n")));
}


enum asmtp_state
{
  state_init,
  state_ehlo,
  state_auth,
  state_quit,
};

#define KW_HELO      0
#define KW_EHLO      1
#define KW_XELO      2
#define KW_AUTH      3
#define KW_QUIT      4
#define KW_HELP      5
#define KW_STARTTLS  6
#define KW_MAIL      7
#define KW_RCPT      8
#define KW_XDATABASE 9

static int
asmtp_kw (const char *name)
{
  static struct anubis_keyword kw[] = {
    { "helo", KW_HELO },
    { "ehlo", KW_EHLO },
    { "xelo", KW_XELO },
    { "auth", KW_AUTH },
    { "help", KW_HELP },
    { "quit", KW_QUIT },
    { "starttls", KW_STARTTLS },
    { "mail", KW_MAIL },
    { "rcpt", KW_RCPT },
    { "xdatabase", KW_XDATABASE },
    { NULL },
  };
  struct anubis_keyword *kwp = anubis_keyword_lookup_ci (kw, name);
  if (kwp)
    return kwp->tok;
  return -1;
}

#define R_CONT     0x8000
#define R_CODEMASK 0xfff

void
asmtp_reply (int code, char *fmt, ...)
{
  va_list ap;
  int cont = code & R_CONT ? '-' : ' ';
  static char obuf[512];
  int n;

  va_start (ap, fmt);
  n = snprintf (obuf, sizeof obuf, "%d%c", code & R_CODEMASK, cont);
  n += vsnprintf (obuf + n, sizeof obuf - n, fmt, ap);
  va_end (ap);
  n += snprintf (obuf + n, sizeof obuf - n, "\r\n");
  swrite (SERVER, remote_client, obuf);
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
asmtp_greet (void)
{
  char *name = get_localname ();
  asmtp_reply (220, "%s %s", name, smtp_greeting_message);
}

static ANUBIS_LIST asmtp_capa;

void
asmtp_capa_add (char *name)
{
  list_append (asmtp_capa, strdup (name));
}

void
asmtp_capa_add_prefix (char *prefix, char *name)
{
  char *str = malloc (strlen (prefix) + 1 + strlen (name) + 1);
  if (!str)
    abort ();
  sprintf (str, "%s %s", prefix, name);
  list_append (asmtp_capa, str);
}

static int
name_cmp (void *a, void *b)
{
  return strcmp (a, b);
}

void
asmtp_capa_remove (char *name)
{
  char *p = list_remove (asmtp_capa, strdup (name), name_cmp);
  if (p)
    free (p);
}

static void
asmtp_capa_init (void)
{
  asmtp_capa = list_create ();
#ifdef USE_SSL
  asmtp_capa_add ("STARTTLS");
#endif
  auth_gsasl_init ();
  asmtp_capa_add ("HELP");
}

static void
asmtp_capa_report (void)
{
  ITERATOR itr = iterator_create (asmtp_capa);
  char *p = iterator_first (itr);

  while (p)
    {
      char *next = iterator_next (itr);
      asmtp_reply ((next ? R_CONT : 0) | 250, "%s", p);
      p = next;
    }
  iterator_destroy (&itr);
}

static enum asmtp_state
asmtp_helo_reply (char *args)
{
  char *domain = get_command_arg ();

  if (!domain)
    {
      asmtp_reply (501, "HELO requires domain address");
      return state_init;
    }
  else if (get_command_arg ())
    {
      asmtp_reply (501, "Syntax error");
      return state_init;
    }

  helo_count++;
  asmtp_reply (250, "Anubis is pleased to meet you.");
  return state_ehlo;
}

static enum asmtp_state
asmtp_ehlo_reply (char *args)
{
  char *domain = get_command_arg (args);

  if (!domain)
    {
      asmtp_reply (501, "EHLO requires domain address");
      return state_init;
    }
  else if (get_command_arg ())
    {
      asmtp_reply (501, "Syntax error");
      return state_init;
    }
  
  set_ehlo_domain (domain, strlen (domain));
  
  helo_count++;
  asmtp_reply (R_CONT | 250, "Anubis is pleased to meet you.");
  asmtp_capa_report ();
  return state_ehlo;
}

static enum asmtp_state
asmtp_xelo_reply (char *args)
{
  char *domain = get_command_arg (args);

  if (!domain)
    {
      asmtp_reply (501, "XELO requires domain address");
      return state_init;
    }
  else if (get_command_arg ())
    {
      asmtp_reply (501, "Syntax error");
      return state_init;
    }

  helo_count++;
  topt |= T_XELO;

  asmtp_reply (R_CONT | 250, "Anubis is pleased to meet you.");
  asmtp_capa_report ();
  return state_ehlo;
}

static void
asmtp_help (void)
{
  if (smtp_help_message)
    {
      char *s;
      ITERATOR itr = iterator_create (smtp_help_message);
      for (s = iterator_first (itr); s; s = iterator_next (itr))
	asmtp_reply (R_CONT | 214, "%s", s);
      iterator_destroy (&itr);
    }
  asmtp_reply (214, "End of HELP info");
}

static enum asmtp_state
asmtp_init (enum asmtp_state state)
{
  char *command = NULL;
  size_t s = 0;

  recvline (SERVER, remote_client, &command, &s);

  switch (asmtp_kw (get_command_word (command))) {
  case KW_EHLO:
    state = asmtp_ehlo_reply (command);
    break;
    
  case KW_XELO:
    state = asmtp_xelo_reply (command);
    break;
    
  case KW_HELO:
    state = asmtp_helo_reply (command);
    break;
    
  case KW_HELP:
    asmtp_help ();
    break;
    
  case KW_AUTH:
  case KW_STARTTLS:
    asmtp_reply (503, "Polite people say EHLO first");
    break;
    
  case KW_QUIT:
    asmtp_reply (221, "Closing connection");
    state = state_quit;
    break;
    
  case KW_MAIL:
  case KW_RCPT:
    asmtp_reply (550, "Command disabled. Proper authentication required.");
    break;
    
  default:
    asmtp_reply (500, "Unknown command");
  }
  free (command);
  return state;
}

static enum asmtp_state
asmtp_ehlo (enum asmtp_state state, ANUBIS_USER * usr)
{
  char *command = NULL;
  size_t s = 0;
  char *mech;
  char *init_input;

  if (recvline (SERVER, remote_client, &command, &s) <= 0)
    exit (1);

  switch (asmtp_kw (get_command_word (command))) {
  case KW_EHLO:
    state = asmtp_ehlo_reply (command);
    break;
    
#ifdef USE_SSL
  case KW_STARTTLS:
    if (topt & T_SSL_FINISHED)
      asmtp_reply(503, "TLS already started");
    else
      {
	NET_STREAM stream;
	
	if (!secure.cert)
	  secure.cert = xstrdup (DEFAULT_SSL_PEM);
	if (!check_filename (secure.cert, NULL))
	  {
	    asmtp_reply (454, "TLS not available due to temporary reason");
	    break;
	  }

	if (!secure.key)
	  secure.key = xstrdup (secure.cert);
	else if (!check_filename (secure.key, NULL))
	  {
	    asmtp_reply (454, "TLS not available due to temporary reason");
	    break;
	  }

	asmtp_reply (220, "Ready to start TLS");
	stream = start_ssl_server (remote_client, options.termlevel > NORMAL);
	if (!stream)
	  {
	    asmtp_reply (454, "TLS not available" CRLF);
	    break;
	  }
	remote_client = stream;
	asmtp_capa_remove ("STARTTLS");
	topt |= T_SSL_FINISHED;
    
	state = state_ehlo;
      }
    break;
#endif /* USE_SSL */
    
  case KW_AUTH:
    mech = get_command_arg ();
    init_input = get_command_arg ();
    if (anubis_auth_gsasl (mech, init_input, usr) == 0)
      state = state_auth;
    break;
    
  case KW_QUIT:
    asmtp_reply (221, "Closing connection");
    state = state_quit;
    break;
    
  case KW_MAIL:
  case KW_RCPT:
    asmtp_reply (550, "Command disabled. Proper authentication required.");
    break;
    
  case KW_HELP:
    asmtp_help ();
    break;
    
  default:
    asmtp_reply (500, "Unknown command");
  }

  free (command);
  return state;
}

static int
anubis_smtp (ANUBIS_USER * usr)
{
  enum asmtp_state state;

  asmtp_capa_init ();
  asmtp_greet ();

  for (state = state_init; state != state_auth;)
    {
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

  if (topt & T_SSL_FINISHED)
    {
      /* If `ssl yes' is requested, convert it to `ssl-oneway' for
	 the mechanics of tunnel.c:handle_ehlo() to work properly. */
	 
      topt &= ~T_SSL_FINISHED;
      if (topt & T_SSL)
	{
	  topt &= ~T_SSL;
	  topt |= T_SSL_ONEWAY;
	}
    }
  xdatabase_enable ();
  
  return 0;
}

static void
xdb_loop (void)
{
  char *command = NULL;
  size_t s = 0;

  info (VERBOSE, _("Entering XDB loop..."));

  asmtp_capa_add ("XDATABASE");
  while (recvline (SERVER, remote_client, &command, &s) > 0)
    {
      switch (asmtp_kw (get_command_word (command))) {
      case KW_HELP:
	asmtp_help ();
	break;
    
      case KW_QUIT:
	asmtp_reply (221, "Closing connection");
	info (VERBOSE, _("Exiting XDB loop..."));
	return;

      case KW_XDATABASE:
	xdatabase (make_lowercase (get_command_arg ()));
	break;

      case KW_EHLO:
	asmtp_ehlo_reply (command);
	break;
	
      case KW_AUTH:      
      case KW_STARTTLS:  
      case KW_MAIL:
      case KW_RCPT:
	asmtp_reply (550, "Command disabled.");
	break;
    
      default:
	asmtp_reply (500, "Unknown command");
      }
    }
  info (VERBOSE, _("Exiting XDB loop..."));
}



static char *anubis_dbarg;

void
anubis_set_password_db (char *arg)
{
  free (anubis_dbarg);
  anubis_dbarg = strdup (arg);
}

int
anubis_get_db_record (const char *username, ANUBIS_USER * usr)
{
  void *db;
  int rc;
  char const *errtext;

  if (!anubis_dbarg)
    {
      anubis_error (0, 0, _("Database not specified"));
      return ANUBIS_DB_FAIL;
    }

  if (anubis_db_open (anubis_dbarg, anubis_db_rdonly,
		      &db, &errtext) != ANUBIS_DB_SUCCESS)
    {
      anubis_error (0, 0,
		    _("Cannot open database %s: %s"), anubis_dbarg, errtext);
      return ANUBIS_DB_FAIL;
    }

  rc = anubis_db_get_record (db, username, usr);
  switch (rc) {
  case ANUBIS_DB_SUCCESS:
    info (VERBOSE, _("Found record for `%s'."), username);
    break;
    
  case ANUBIS_DB_FAIL:
    anubis_error (0, 0,
		  _("Cannot retrieve data from the SASL database: %s"),
		  anubis_db_strerror (db));
    break;
    
  case ANUBIS_DB_NOT_FOUND:
    info (VERBOSE, _("Record for `%s' not found."), username);
    break;
  }

  anubis_db_close (&db);
  return rc;
}


int
anubis_authenticate_mode (struct sockaddr_in *addr)
{
  ANUBIS_USER usr;

  remote_server = remote_client;
  alarm (900);

  if (anubis_smtp (&usr))
    return EXIT_FAILURE;

  if (usr.username)
    {
      if (check_username (usr.username))
	{
	  anubis_changeowner (usr.username);
	  assign_string (&session.clientname, usr.username);
	}
      else
	set_unprivileged_user ();
    }
  else
    set_unprivileged_user ();

  if (usr.rcfile_name)
    session.rcfile_name = usr.rcfile_name;

  open_rcfile (CF_CLIENT);
  process_rcfile (CF_CLIENT);
  
  if (topt & T_XELO)
    {
      xdb_loop ();
    }
  else
    {
      session_prologue ();
      smtp_session ();
      alarm (0);
    }
  
  net_close_stream (&remote_client);
  net_close_stream (&remote_server);
  
  info (NORMAL, _("Connection closed successfully."));

#ifdef HAVE_PAM
  if (pamh)
    {
      int pam_retval = pam_close_session (pamh, 0);
      if (pam_retval == PAM_SUCCESS)
	info (VERBOSE, _("PAM: Session closed."));
      if (pam_end (pamh, pam_retval) != PAM_SUCCESS)
	{
	  pamh = NULL;
	  info (NORMAL, _("PAM: failed to release authenticator."));
	  return EXIT_FAILURE;
	}
    }
#endif /* HAVE_PAM */
  return 0;
}

#define KW_SASL_PASSWORD_DB      1
#define KW_SASL_ALLOWED_MECH     2
#define KW_SASL_SERVICE          3
#define KW_SASL_REALM            4
#define KW_SASL_HOSTNAME         5
#define KW_SMTP_GREETING_MESSAGE 6
#define KW_SMTP_HELP_MESSAGE     7

static void
rc_parser (EVAL_ENV env, int key, ANUBIS_LIST arglist, void *inv_data)
{
  char *arg = list_item (arglist, 0);

  switch (key)
    {
    case KW_SMTP_GREETING_MESSAGE:
      if (list_count (arglist) != 1)
	eval_error (0, env, _("invalid number of arguments"));
      xfree (smtp_greeting_message);
      smtp_greeting_message = strdup (arg);
      break;
      
    case KW_SMTP_HELP_MESSAGE:
      if (list_count (arglist) != 1)
	eval_error (0, env, _("invalid number of arguments"));
      make_help_message (arg);
      break;
      
    case KW_SASL_PASSWORD_DB:
      if (list_count (arglist) != 1)
	eval_error (0, env, _("invalid number of arguments"));
      anubis_set_password_db (arg);
      break;
      
    case KW_SASL_ALLOWED_MECH:
      anubis_set_server_mech_list (arglist);
      break;
      
    case KW_SASL_SERVICE:
      if (list_count (arglist) != 1)
	eval_error (0, env, _("invalid number of arguments"));
      xfree (anubis_sasl_service);
      anubis_sasl_service = strdup (arg);
      break;
      
    case KW_SASL_REALM:
      if (list_count (arglist) != 1)
	eval_error (0, env, _("invalid number of arguments"));
      xfree (anubis_sasl_realm);
      anubis_sasl_realm = strdup (arg);
      break;
      
    case KW_SASL_HOSTNAME:
      if (list_count (arglist) != 1)
	eval_error (0, env, _("invalid number of arguments"));
      xfree (anubis_sasl_hostname);
      anubis_sasl_hostname = strdup (arg);
      break;
      
    default:
      eval_error (2, env,
		  _("INTERNAL ERROR at %s:%d: unhandled key %d; "
		    "please report"),
		  __FILE__, __LINE__,
		  key);
    }
}

static struct rc_kwdef init_authmode_kw[] = {
  { "smtp-greeting-message", KW_SMTP_GREETING_MESSAGE },
  { "smtp-help-message",     KW_SMTP_HELP_MESSAGE },
  { "sasl-password-db",      KW_SASL_PASSWORD_DB },
  { "sasl-allowed-mech",     KW_SASL_ALLOWED_MECH },
  { "sasl-service",          KW_SASL_SERVICE },
  { "sasl-hostname",         KW_SASL_HOSTNAME },
  { "sasl-realm",            KW_SASL_REALM },
  { NULL }
};

static struct rc_secdef_child init_authmode_child = {
  NULL,
  CF_INIT,
  init_authmode_kw,
  rc_parser,
  NULL
};

void
authmode_section_init (void)
{
  struct rc_secdef *sp = anubis_add_section ("AUTH");
  rc_secdef_add_child (sp, &init_authmode_child);
  smtp_greeting_message = strdup ("GNU Anubis ESMTP; Identify yourself");
  smtp_help_message = list_create ();
  list_append (smtp_help_message,
	       strdup
	       ("Run 'info anubis' or visit http://www.gnu.org/software/anubis/manual/"));
}

#endif /* WITH_GSASL */

/* EOF */

