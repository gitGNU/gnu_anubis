/*
   headers.h

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

#ifdef HAVE_CONFIG_H

#include <config.h>

# if defined(HAVE_GNUTLS_GNUTLS_H)
#  define HAVE_GNUTLS
# endif /* HAVE_GNUTLS_GNUTLS_H */
# if defined(HAVE_LIBSSL) && defined(HAVE_LIBCRYPTO)
#  if defined(HAVE_OPENSSL_SSL_H)
#   define HAVE_OPENSSL
#  endif /* HAVE_OPENSSL_SSL_H */
# endif /* HAVE_LIBSSL and HAVE_LIBCRYPTO */
# if defined(HAVE_LIBGPGME) && defined(HAVE_GPGME_H) && !defined(NOGPG)
#  define HAVE_GPG
# endif /* HAVE_LIBGPGME and HAVE_GPGME_H and not NOGPG */
# if defined(HAVE_LIBPCRE)
#  if defined(HAVE_PCRE_H) || defined(HAVE_PCRE_PCRE_H)
#   define HAVE_PCRE
#  endif /* HAVE_PCRE_H or HAVE_PCRE_PCRE_H */
# endif /* HAVE_LIBPCRE */
# if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
#  define HAVE_REGEX
# else
#  error POSIX Regular Expressions are required!
# endif /* HAVE_REGEX_H and HAVE_REGCOMP */
# if defined(HAVE_LIBPAM) && defined(HAVE_LIBPAM_MISC)
#  if defined(HAVE_SECURITY_PAM_APPL_H) && defined(HAVE_SECURITY_PAM_MISC_H)
#   define HAVE_PAM
#  endif /* HAVE_SECURITY_PAM_APPL_H and HAVE_SECURITY_PAM_MISC_H */
# endif /* HAVE_LIBPAM and HAVE_LIBPAM_MISC */
# if defined(HAVE_LIBWRAP) && defined(HAVE_TCPD_H)
#  define USE_LIBWRAP
# endif /* HAVE_LIBWRAP and HAVE_TCPD_H */

#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#include <stdarg.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif /* HAVE_MEMORY_H */
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)
# include <sys/resource.h>
#endif /* HAVE_GETRLIMIT and HAVE_SETRLIMIT */
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */
#if defined(HAVE_SYSLOG) && defined(HAVE_SYSLOG_H)
# include <syslog.h>
#endif /* HAVE_SYSLOG and HAVE_SYSLOG_H */

#if defined(USE_GNUTLS) && defined(HAVE_GNUTLS)
# include <gnutls/gnutls.h>
# define HAVE_TLS
# undef USE_OPENSSL
#endif /* USE_GNUTLS and HAVE_GNUTLS */

#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL)
# include <openssl/crypto.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>
# include <openssl/md5.h>
# define HAVE_SSL
#endif /* USE_OPENSSL and HAVE_OPENSSL */

#if defined(HAVE_TLS) || defined(HAVE_SSL)
# define USE_SSL
#else
# undef USE_SSL
#endif /* HAVE_TLS or HAVE_SSL */

#ifdef HAVE_PAM
# include <security/pam_appl.h>
# include <security/pam_misc.h>
#endif /* HAVE_PAM */

#include "gettext.h"
#ifdef ENABLE_NLS
# define _(String) gettext(String)
# ifdef HAVE_LOCALE_H
#  include <locale.h>
# endif /* HAVE_LOCALE_H */
#else
# define _(String) (String)
# define N_(String) String
#endif /* ENABLE_NLS */

#ifdef WITH_GUILE
# include <libguile.h>
#endif /* WITH_GUILE */

#include "mem.h" /* xfree(), xfree_pptr() */
#include "list.h"

#ifndef INADDR_NONE
# define INADDR_NONE (unsigned long)0xffffffff
#endif /* not INADDR_NONE */
#ifndef INADDR_ANY
# define INADDR_ANY (unsigned long)0x00000000
#endif /* not INADDR_ANY */
#ifndef INADDR_LOOPBACK
# define INADDR_LOOPBACK (unsigned long)0x7f000001
#endif /* not INADDR_LOOPBACK */

#ifndef MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# else
#  define MAXPATHLEN 1024
# endif /* PATH_MAX */
#endif /* not MAXPATHLEN */

#define MAXCLIENTS 50
#define LINEBUFFER 512
#define DATABUFFER 4096
#define DEFAULT_GLOBAL_RCFILE "/etc/anubisrc"
#define DEFAULT_LOCAL_RCFILE ".anubisrc"
#define DEFAULT_SSL_PEM "anubis.pem"
#define DEFAULT_SIGFILE ".signature"
#define BEGIN_TRIGGER "@@"
#define LF "\n"
#define CRLF "\r\n"

/* REGEX action methods */
#define NIL    -1
#define COMMAND 0
#define HEADER  1
#define BODY    2

/* Tunnel methods */
#define CLIENT 0
#define SERVER 1

/* configuration file access */
#define CF_CLIENT     0x0001
#define CF_SUPERVISOR 0x0002
#define CF_INIT       0x0004
#define CF_ALL CF_INIT|CF_SUPERVISOR|CF_CLIENT

/* output modes */
#define SILENT  0
#define NORMAL  1
#define VERBOSE 2
#define DEBUG   3

/* logging level */
#define NONE  0
#define FAILS 1
#define ALL   2

/* error types */
#define SOFT   1
#define HARD   2
#define SYNTAX 3

/* bit values for topt */
#define T_ERROR             0x00000001
#define T_SOCKS             0x00000002
#define T_SOCKS_V4          0x00000004
#define T_SOCKS_AUTH        0x00000008
#define T_FOREGROUND_INIT   0x00000010
#define T_FOREGROUND        0x00000020
#define T_DAEMON            0x00000040
#define T_STDINOUT          0x00000080
#define T_SSL               0x00000100
#define T_SSL_FINISHED      0x00000200
#define T_SSL_ONEWAY        0x00000400
#define T_SSL_CKCLIENT      0x00000800
#define T_NAMES             0x00001000
#define T_LOCAL_MTA         0x00002000
#define T_ALLOW_LOCAL_MTA   0x00004000
#define T_TRANSLATION_MAP   0x00008000
#define T_DROP_UNKNOWN_USER 0x00010000
#define T_USER_NOTPRIVIL    0x00020000
#define T_STARTTLS          0x00040000
#define T_ESMTP_AUTH        0x00080000
#define T_NORC              0x00100000
#define T_ALTRC             0x00200000
#define T_CHECK_CONFIG      0x00400000
#define T_RELAX_PERM_CHECK  0x00800000
#define T_ENTIRE_BODY       0x01000000

/* Regexp modifiers */
/* Basic types */
#define R_EXACT             0x00000001
#define R_POSIX             0x00000002
#define R_PERLRE            0x00000004
/* Other modifiers */
#define R_BASIC             0x00000010
#define R_SCASE             0x00000020

#define R_TYPEMASK          0x0000000f

#define re_set_type(m,t) ((m) = ((m) & ~R_TYPEMASK) | ((t) & R_TYPEMASK))
#define re_typeof(m) ((m) & R_TYPEMASK)
#define re_set_flag(m,f) ((m) |= (f))
#define re_clear_flag(m,f) ((m) &= ~(f))

/* A special header used by Anubis to implement rules. */
#define X_ANUBIS_RULE_HEADER "\nRULE\n"

#define safe_strcpy(s, ct) \
 (s[sizeof(s) - 1] = '\0', strncpy((char *)s, (char *)ct, sizeof(s) - 1))

typedef struct rc_regex RC_REGEX;
typedef struct assoc ASSOC;
typedef struct message_struct MESSAGE;
typedef int (*net_io_t) (void *, char *, size_t, size_t *);
typedef int (*net_close_t) (void *);
typedef const char *(*strerror_t) (int);

/* main.c */
void anubis(char *);

/* mem.c */
void *xmalloc(int);
void *xrealloc(void *, int);
char *allocbuf(char *, int);
#ifndef HAVE_STRDUP
 char *strdup(const char *);
#endif /* not HAVE_STRDUP */
void free_pptr(char **);

/* setenv.c */
#if !defined(HAVE_SETENV) && defined(HAVE_PUTENV)
 int setenv(const char *, const char *, int);
#endif

/* env.c */
void get_options(int, char *[]);
void get_homedir(char *, char *, int);
void anubis_getlogin(char *, int);
void anubis_changeowner(char *);
int  check_superuser(void);
int  check_username(char *);
int  check_filemode(char *);
int  check_filename(char *, time_t *);

/* errs.c */
void anubis_error(int, char *, ...);
void socket_error(const char *);
void socks_error(char *);
void hostname_error(char *);

/* log.c */
void mprintf(char *, ...);
void info(int, char *, ...);
void filelog(char *, char *);

/* net.c */
void net_set_io(int, net_io_t, net_io_t, net_close_t, strerror_t);
void net_close(int, void *);
int  make_remote_connection(char *, unsigned int);
int  bind_and_listen(char *, unsigned int);
void swrite(int, void *, char *);
int  recvline(int, void *, void *, int);
void get_response_smtp(int, void *, char *, int);
void close_socket(int);

/* proxy.c */
void check_all_proxies(char *, unsigned int *);
int  check_socks_proxy(int, char *, unsigned int);

/* daemon.c */
void daemonize(void);
void loop(int);
void stdinout(void);

/* auth.c */
void auth_tunnel(void);
int  auth_ident(struct sockaddr_in *, char *, int);

/* map.c */
void parse_transmap(int *, char *, char *, char *, int);
void translate_section_init(void);

/* tunnel.c */
void smtp_session(void);

/* message.c */
void message_add_body(MESSAGE *, char *, char *);
void message_add_header(MESSAGE *, char *, char *);
void message_remove_headers(MESSAGE *, RC_REGEX *);
void message_modify_headers(MESSAGE *, RC_REGEX *, char *, char *);
void message_modify_body(MESSAGE *, RC_REGEX *, char *);
void message_external_proc(MESSAGE *, char **);
void message_init(MESSAGE *);
void message_free(MESSAGE *);

/* exec.c */
char **gen_execargs(const char *);
int  make_local_connection(char *, char **);
char *external_program(int *, char *, char *, char *, int);
char *exec_argv(int *, char **, char *, char *, int);

/* esmtp.c */
void esmtp_auth(void *, char *);

/* misc.c */
void assoc_free(ASSOC *);
ASSOC *header_assoc(char *);
void destroy_assoc_list(LIST **);
void destroy_string_list(LIST **);
void parse_mtaport(char *, char *, unsigned int *);
void parse_mtahost(char *, char *, unsigned int *);
void remline(char *, char *);
void remcrlf(char *);
char *substitute(char *, char **);
void change_to_lower(char *);

/* files.c */
void message_append_text_file(MESSAGE *, char *);
void message_append_signature_file(MESSAGE *, char *);

/* regex.c */
int anubis_regex_match(RC_REGEX *, char *, int *, char ***);
RC_REGEX *anubis_regex_compile(char *, int);
void anubis_regex_free(RC_REGEX **);
char *anubis_regex_source(RC_REGEX *);
int anubis_regex_refcnt(RC_REGEX *);
char *anubis_regex_replace(RC_REGEX *, char *, char *);
void anubis_regex_print(RC_REGEX *);

/* rc.c */
void rc_system_init(void);
void open_rcfile(int);
void process_rcfile(int);
void rcfile_process_section(int, char *, void *, MESSAGE *);
void rcfile_call_section(int, char *, void *, MESSAGE *);

/* help.c */
void print_version(void);
void print_usage(void);
void print_config_options(void);

/* quit.c */
void sig_exit(int);
void sig_timeout(int);
void free_mem(void);
void quit(int);

/* tls.c or ssl.c */
#ifdef USE_SSL
void init_ssl_libs(void);
void *start_ssl_client(int);
void *start_ssl_server(int);
#endif /* USE_SSL */

/* gpg.c */
#ifdef HAVE_GPG
 void gpg_free(void);
 void gpg_section_init(void);
#endif /* HAVE_GPG */

/* guile.c */
#ifdef WITH_GUILE
void anubis_boot(void *, int, char **);
void guile_load_path_append(char *);
void guile_debug(int);
void guile_load_program(char *);
void guile_rewrite_line(char *, const char *);
void guile_postprocess_proc(char *, LIST **, char **);
void guile_section_init(void);
#endif /* WITH_GUILE */

/* EOF */

