/*
   extern.h

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

extern const char version[];
extern const char copyright[];

struct assoc
{
  char *key;
  char *value;
};

struct options_struct
{
  int termlevel;
  int uloglevel;
  char *ulogfile;
  char *tracefile;
#ifdef WITH_GUILE
  char *glogfile;
#endif
  char *altrc;
};

struct session_struct
{
  char *anubis;
  char *mta;
  char *supervisor;
  char *clientname;
  char *notprivileged;
  char *rcfile_name;
  char *execpath;
  char **execargs;
  unsigned int anubis_port;
  unsigned int mta_port;
#ifdef USE_SOCKS_PROXY
  char *socks;
  char *socks_username;
  char *socks_password;
  unsigned int socks_port;
#endif				/* USE_SOCKS_PROXY */
};

#ifdef USE_SSL
struct secure_struct
{
  char *prio;
  char *cafile;
  char *cert;
  char *key;
};
extern struct secure_struct secure;
#endif /* USE_SSL */

extern struct options_struct options;
extern struct session_struct session;

extern unsigned long topt;
extern NET_STREAM remote_client;
extern NET_STREAM remote_server;

extern char *anubis_domain;

#ifdef HAVE_PAM
extern pam_handle_t *pamh;
extern int pam_retval;
#endif /* HAVE_PAM */

extern ANUBIS_MODE anubis_mode;

extern char *anon_token;
extern char *authorization_id;
extern char *authentication_id;
extern char *auth_password;
extern char *auth_service;
extern char *auth_hostname;
extern char *generic_service_name;
extern char *auth_passcode;
extern char *auth_realm;

extern int x_argc;
extern char **x_argv;

extern char *incoming_mail_rule;
extern char *outgoing_mail_rule;
extern char *smtp_command_rule;

extern char *log_tag;
extern int log_facility;

extern char *from_address;

extern char *anubis_sasl_service;
extern char *anubis_sasl_realm;
extern char *anubis_sasl_hostname;

/* EOF */
