/*
   extern.h

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

extern const char version[];
extern const char copyright[];

struct options_struct {
 int termlevel;
 int uloglevel;
 char *slogfile;
 char *ulogfile;
#ifdef WITH_GUILE
 char *guile_logfile;
#endif /* WITH_GUILE */
 char *altrc;
};

struct session_struct {
 char tunnel[65];
 char mta[65];
 char mta_username[65];
 char mta_password[65];
 char socks[65];
 char socks_username[65];
 char socks_password[65];
 char client[65];
 char supervisor[65];
 char notprivileged[65];
 char *execpath;
 char **execargs;
 unsigned int tunnel_port;
 unsigned int mta_port;
 unsigned int socks_port;
};

#ifdef HAVE_TLS
struct secure_struct {
 gnutls_session client;
 gnutls_session server;
 gnutls_certificate_client_credentials xcred;
 gnutls_certificate_server_credentials x509_cred;
 char *cafile;
 char *cert;
 char *key;
};
#endif /* HAVE_TLS */

#ifdef HAVE_SSL
struct secure_struct {
 SSL *client;
 SSL *server;
 SSL_CTX *ctx_client;
 SSL_CTX *ctx_server;
 char *cafile;
 char *cert;
 char *key;
};
#endif /* HAVE_SSL */

extern struct options_struct options;
extern struct session_struct session;
#if defined(HAVE_TLS) || defined(HAVE_SSL)
extern struct secure_struct secure;
#endif /* HAVE_TLS or HAVE_SSL */

extern unsigned long topt;
extern void *remote_client;
extern void *remote_server;

#ifdef HAVE_PAM
 extern pam_handle_t *pamh;
 extern int pam_retval;
#endif /* HAVE_PAM */

/* EOF */

