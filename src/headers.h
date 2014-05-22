/*
   headers.h

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

#ifdef HAVE_CONFIG_H

#include <config.h>

#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __attribute__(x)
#endif

#ifndef ANUBIS_PRINTFLIKE
# define ANUBIS_PRINTFLIKE(fmt,narg) \
  __attribute__ ((__format__ (__printf__, fmt, narg)))
#endif

#ifndef ANUBIS_NORETURN
# define ANUBIS_NORETURN __attribute__((__noreturn__))
#endif

# if defined(HAVE_LIBGPGME) && defined(HAVE_GPGME_H) && !defined(NOGPG)
#  define HAVE_GPG
# endif	/* HAVE_LIBGPGME and HAVE_GPGME_H and not NOGPG */
# if defined(HAVE_LIBPCRE)
#  if defined(HAVE_PCRE_H) || defined(HAVE_PCRE_PCRE_H)
#   define HAVE_PCRE
#  endif /* HAVE_PCRE_H or HAVE_PCRE_PCRE_H */
# endif	/* HAVE_LIBPCRE */
# if defined(HAVE_LIBPAM) && defined(HAVE_LIBPAM_MISC)
#  if defined(HAVE_SECURITY_PAM_APPL_H) && defined(HAVE_SECURITY_PAM_MISC_H)
#   define HAVE_PAM
#  endif /* HAVE_SECURITY_PAM_APPL_H and HAVE_SECURITY_PAM_MISC_H */
# endif	/* HAVE_LIBPAM and HAVE_LIBPAM_MISC */
# if defined(HAVE_LIBWRAP) && defined(HAVE_TCPD_H)
#  define USE_LIBWRAP
# endif	/* HAVE_LIBWRAP and HAVE_TCPD_H */

#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stdarg.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_MEMORY_H
# include <memory.h>
#endif /* HAVE_MEMORY_H */
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)
# include <sys/resource.h>
#endif /* HAVE_GETRLIMIT and HAVE_SETRLIMIT */
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#if defined(USE_GNUTLS) 
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
# define HAVE_TLS
#endif /* USE_GNUTLS */

#if defined(HAVE_TLS) || defined(HAVE_SSL)
# define USE_SSL
#else
# undef USE_SSL
#endif /* HAVE_TLS or HAVE_SSL */

#ifdef HAVE_PAM
# include <security/pam_appl.h>
# include <security/pam_misc.h>
#endif /* HAVE_PAM */

#if defined(WITH_GSASL)
# include <gsasl.h>
#endif

#include "gettext.h"
#ifdef ENABLE_NLS
# define _(String) gettext(String)
# ifdef HAVE_LOCALE_H
#  include <locale.h>
# endif	/* HAVE_LOCALE_H */
#else
# define _(String) (String)
#endif /* ENABLE_NLS */
#define N_(String) String

#ifdef WITH_GUILE
# include <libguile.h>
#endif /* WITH_GUILE */

#include "xalloc.h"
#include <argcv.h>
#include <keyword.h>
#include "list.h"
#include "smtprepl.h"

#include <sysexits.h>

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
# endif	/* PATH_MAX */
#endif /* not MAXPATHLEN */

#define MAXCLIENTS 50
#define LINEBUFFER 512
#define DATABUFFER 4096
#define DEFAULT_GLOBAL_RCFILE "/etc/anubisrc"
#define DEFAULT_LOCAL_RCFILE ".anubisrc"
#define DEFAULT_SSL_PEM "anubis.pem"
#define DEFAULT_SIGFILE ".signature"
#define DEFAULT_PIDFILE "anubis.pid"
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

typedef enum anubis_mode
{
  anubis_transparent,
  anubis_authenticate,
  anubis_mda,
  anubis_proxy
}
ANUBIS_MODE;

/* bit values for topt */
#define T_DISABLE_SYSLOG    0x00000001
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
/* Not used (ex T_ALLOW_LOCAL_MTA)   0x00004000 */
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
#define T_SMTP_ERROR_CODES  0x02000000
#define T_TRACEFILE_SYS     0x04000000
#define T_TRACEFILE_USR     0x08000000
#define T_XELO              0x10000000
#define T_LOCATION_COLUMN   0x20000000
#define T_ESMTP_AUTH_DELAYED 0x40000000

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
typedef struct message_struct *MESSAGE;

#define xfree(p) do\
	if (p) { \
		free(p); \
		p = NULL; \
	}\
     while (0)

#define xfree_pptr(p) do\
	if (p) { \
		free_pptr(p); \
		p = NULL; \
	}\
     while (0)

#define ASSERT_MTA_CONFIG()						\
  do									\
    {									\
      if (!(topt & T_LOCAL_MTA) && !session.mta)			\
	anubis_error (EX_CONFIG, 0,					\
		      _("MTA has not been specified. "			\
			"Set the `remote-mta' or `local-mta'."));	\
    }									\
  while (0)

/* Message ID constants */
#define MSGIDLEN 14
#define MSGIDBOUND (MSGIDLEN + 1)

/* stream.c */

typedef struct net_stream *NET_STREAM;
typedef int (*stream_read_t) (void *, char *, size_t, size_t *);
typedef int (*stream_write_t) (void *, const char *, size_t, size_t *);
typedef int (*stream_close_t) (void *);
typedef int (*stream_destroy_t) (void *);
typedef const char *(*stream_strerror_t) (void *, int);

void stream_create (NET_STREAM * str);
int stream_set_io (NET_STREAM str,
		   void *data,
		   stream_read_t read, stream_write_t write,
		   stream_close_t close,
		   stream_destroy_t destroy, stream_strerror_t strerror);
int stream_set_read (struct net_stream *str, stream_read_t read);
int stream_set_write (struct net_stream *str, stream_write_t write);
int stream_set_strerror (struct net_stream *str, stream_strerror_t strerr);
int stream_close (NET_STREAM str);
const char *stream_strerror (NET_STREAM str, int errcode);
int stream_read (NET_STREAM str, char *buf, size_t size, size_t *nbytes);
int stream_write (NET_STREAM str, const char *buf, size_t size,
		  size_t *nbytes);
int stream_readline (NET_STREAM str, char *buf, size_t size, size_t *nbytes);
int stream_getline (NET_STREAM sd, char **vptr, size_t *maxlen, size_t *nread);
int stream_destroy (NET_STREAM *);

/* main.c */
void anubis (char *);

/* env.c */
void get_options (int, char *[]);
void get_homedir (char *, char *, int);
void anubis_getlogin (char **);
void anubis_changeowner (const char *);
int anubis_set_mode (char *modename);
int check_superuser (void);
int check_username (char *);
int check_filemode (char *);
int check_filename (char *, time_t *);
void write_pid_file (void);

/* errs.c */
#define EXIT_ABORT 256
void anubis_error (int, int, const char *, ...)
     ANUBIS_PRINTFLIKE(3,4);
void anubis_warning (int error_code, const char *fmt, ...)
     ANUBIS_PRINTFLIKE(2,3);
void socket_error (const char *);
void hostname_error (const char *);

/* log.c */
void mprintf (const char *, ...);
void info (int, const char *, ...);
void filelog (char *, char *);

/* net.c */
NET_STREAM make_remote_connection (char *, unsigned int);
int bind_and_listen (char *, unsigned int);
void swrite (int, NET_STREAM, const char *);
void swrite_n (int, NET_STREAM, const char *, size_t);
void send_eol (int method, NET_STREAM sd);
int recvline (int method, NET_STREAM sd, char **vptr, size_t * maxlen);
void get_response_smtp (int, NET_STREAM, char **, size_t *);
void close_socket (int sd);

void net_create_stream (NET_STREAM * str, int fd);
void net_close_stream (NET_STREAM * sd);

void smtp_reply_get (int method, NET_STREAM sd, ANUBIS_SMTP_REPLY reply);
/* daemon.c */
void daemonize (void);
void loop (int);
void stdinout (void);
void service_unavailable (NET_STREAM *);
void set_unprivileged_user (void);
void create_stdio_stream (NET_STREAM *s);

/* auth.c */
int auth_ident (struct sockaddr_in *, char **);

/* map.c */
void parse_transmap (int *, char *, char *, char **);
void translate_section_init (void);

/* tunnel.c */
void smtp_session (void);
void smtp_session_transparent (void);
void set_ehlo_domain (const char *domain, size_t len);
char *get_ehlo_domain (void);
void transfer_header (ANUBIS_LIST);
void transfer_body (MESSAGE);
void collect_headers (MESSAGE  msg, char *init_line);
void collect_body (MESSAGE  msg);

/* proclist.c */
void proclist_register (pid_t pid);
size_t proclist_cleanup (void (*fun) (size_t, pid_t, int));
void proclist_init (void);
size_t proclist_count (void);

/* message.c */
MESSAGE message_new (void);
const char *message_id (MESSAGE msg);

ANUBIS_LIST message_get_header (MESSAGE);
ANUBIS_LIST message_get_commands (MESSAGE);
const char *message_get_body (MESSAGE msg);
const char *message_get_boundary (MESSAGE msg);
ANUBIS_LIST message_get_mime_header (MESSAGE msg);

void message_replace_header (MESSAGE msg, ANUBIS_LIST list);
void message_replace_body (MESSAGE msg, char *body);
void message_replace_boundary (MESSAGE msg, char *boundary);

void message_add_body (MESSAGE, char *, char *);
void message_add_header (MESSAGE, char *, char *);
void message_add_command (MESSAGE, ASSOC *);
void message_append_mime_header (MESSAGE, const char *);

void message_remove_headers (MESSAGE, RC_REGEX *);
void message_modify_headers (MESSAGE, RC_REGEX *, char *, char *);
void message_modify_body (MESSAGE, RC_REGEX *, char *);
void message_modify_command (MESSAGE msg, RC_REGEX *regex, char *key,
			     char *value);
void message_proc_body (MESSAGE msg, int (*proc) (char **, char *, void *),
			void *param);
void message_external_proc (MESSAGE, char **);
void message_reset (MESSAGE);
void message_free (MESSAGE);
MESSAGE message_dup (MESSAGE msg);

/* exec.c */
char **gen_execargs (const char *);
NET_STREAM make_local_connection (char *, char **);
char *external_program (int *, char *, char *, char *, int);
char *exec_argv (int *, char *, char **, char *, char *, int);
void cleanup_children (void);

/* esmtp.c */
int esmtp_auth (NET_STREAM *, const char *);
void anubis_set_client_mech_list (ANUBIS_LIST list);
void anubis_set_encryption_mech_list (ANUBIS_LIST list);

/* misc.c */
int anubis_free_list_item (void *item, void *data);
void assoc_free (ASSOC *);
ASSOC *header_assoc (char *);
int anubis_assoc_cmp (void *item, void *data);
ANUBIS_LIST assoc_list_dup (ANUBIS_LIST);
void destroy_assoc_list (ANUBIS_LIST *);
ANUBIS_LIST string_list_dup (ANUBIS_LIST orig);
void destroy_string_list (ANUBIS_LIST *);
void parse_mtaport (char *, char **, unsigned int *);
void parse_mtahost (char *, char **, unsigned int *);
void remline (char *, char *);
void remcrlf (char *);
char *substitute (char *, char **);
char *make_uppercase (char *);
char *make_lowercase (char *);
char *get_localname (void);
char *get_localdomain (void);
void assign_string (char **pstr, const char *s);
void assign_string_n (char **pstr, const char *s, size_t length);

/* mime.c */
void message_append_text_file (MESSAGE, char *, char *);
void message_append_signature_file (MESSAGE);

/* regex.c */
int anubis_regex_match (RC_REGEX *, const char *, int *, char ***);
RC_REGEX *anubis_regex_compile (char *, int);
void anubis_regex_free (RC_REGEX **);
char *anubis_regex_source (RC_REGEX *);
int anubis_regex_refcnt (RC_REGEX *);
char *anubis_regex_replace (RC_REGEX *, char *, char *);
void anubis_regex_print (RC_REGEX *);

/* rcfile.c */
void rc_system_init (void);
void auth_tunnel (void);
void open_rcfile (int);
void process_rcfile (int);
void rcfile_process_section (int, char *, void *, MESSAGE);
void rcfile_call_section (int, char *, char *, void *, MESSAGE);
char *user_rcfile_name (void);

typedef struct eval_env *EVAL_ENV;
struct rc_loc const *eval_env_locus (EVAL_ENV);
int eval_env_method (EVAL_ENV);
MESSAGE eval_env_message (EVAL_ENV);
void *eval_env_data (EVAL_ENV);
void eval_error (int retcode, EVAL_ENV env, const char *fmt, ...)
  ANUBIS_PRINTFLIKE(3,4);
void eval_warning (EVAL_ENV env, const char *fmt, ...)
  ANUBIS_PRINTFLIKE(2,3);

void rc_disable_keyword (int mask, const char *kw);

/* help.c */
void print_config_options (void);

/* quit.c */
RETSIGTYPE sig_exit (int);
RETSIGTYPE sig_timeout (int);
void free_mem (void);
void quit (int);

/* socks.c */
#ifdef USE_SOCKS_PROXY
int check_socks_proxy (int, char *, unsigned int);
#endif /* USE_SOCKS_PROXY */

/* tls.c */
#ifdef USE_SSL
void init_ssl_libs (void);
NET_STREAM start_ssl_client (NET_STREAM str, int verbose);
NET_STREAM start_ssl_server (NET_STREAM str, int verbose);
#endif /* USE_SSL */

/* gpg.c */
#ifdef HAVE_GPG
void gpg_free (void);
void gpg_section_init (void);
#endif /* HAVE_GPG */

/* guile.c */
#ifdef WITH_GUILE
void init_guile (void);
void guile_debug (int);
void guile_section_init (void);
void guile_init_anubis_error_port (void);
SCM guile_make_anubis_error_port (int err);
void guile_init_anubis_info_port (void);
SCM guile_make_anubis_info_port (void);
#endif /* WITH_GUILE */

/* url.c */

typedef struct anubis_url
{
  char *method;
  char *host;
  char *path;
  char *user;
  char *passwd;
  int argc;
  ASSOC *argv;
}
ANUBIS_URL;

void anubis_url_destroy (ANUBIS_URL ** url);
int anubis_url_parse (ANUBIS_URL ** url, char *str);
char *anubis_url_full_path (ANUBIS_URL * url);
const char *anubis_url_get_arg (ANUBIS_URL * url, const char *argname);

/* anubisdb.c */

typedef struct anubis_user
{
  char *smtp_authid;		/* ESMTP authentication ID */
  char *smtp_passwd;		/* A corresponding password */
  char *username;		/* System user name to switch to */
  char *rcfile_name;		/* Optional configuration file. 
				   When NULL, defaults to
				   ~username/.anubisrc */
}
ANUBIS_USER;

enum anubis_db_mode
{
  anubis_db_rdonly,
  anubis_db_rdwr
};

#define ANUBIS_DB_SUCCESS   0	/* Operations successful */
#define ANUBIS_DB_FAIL      1	/* Operation failed */
#define ANUBIS_DB_NOT_FOUND 2	/* Record not found (for db_get_record
				   only) */

typedef int (*anubis_db_open_t) (void **d, ANUBIS_URL * url,
				 enum anubis_db_mode mode, char const **errp);
typedef int (*anubis_db_close_t) (void *d);
typedef int (*anubis_db_io_t) (void *d, const char *key, ANUBIS_USER * rec,
			       int *ecode);
typedef const char *(*anubis_db_strerror_t) (void *d, int rc);
typedef int (*anubis_db_delete_t) (void *d, const char *key, int *ecode);
typedef int (*anubis_db_get_list_t) (void *d, ANUBIS_LIST  list, int *ecode);

int anubis_db_register (const char *dbid,
			anubis_db_open_t _db_open,
			anubis_db_close_t _db_close,
			anubis_db_io_t _db_get,
			anubis_db_io_t _db_put,
			anubis_db_delete_t _db_delete,
			anubis_db_get_list_t _db_list,
			anubis_db_strerror_t _db_strerror);
int anubis_db_open (char *arg, enum anubis_db_mode mode, void **dptr,
		    char const **errp);
int anubis_db_close (void **dptr);
int anubis_db_get_record (void *dptr, const char *key, ANUBIS_USER * rec);
int anubis_db_put_record (void *dptr, const char *key, ANUBIS_USER * rec);
int anubis_db_delete_record (void *dptr, const char *key);
int anubis_db_get_list (void *dptr, ANUBIS_LIST * list);
const char *anubis_db_strerror (void *dptr);
void anubis_db_free_record (ANUBIS_USER * rec);

/* dbtext.c */
void dbtext_init (void);

/* gdbm.c */
void gdbm_db_init (void);

/* mysql.c */
void mysql_db_init (void);

/* pgsql.c */
void pgsql_db_init (void);

/* transmode.c */
int anubis_transparent_mode (struct sockaddr_in *addr);
int anubis_proxy_mode (struct sockaddr_in *addr);
void session_prologue ();

/* authmode.c */
int anubis_authenticate_mode (struct sockaddr_in *addr);
void anubis_set_password_db (char *arg);
void asmtp_reply (int code, char *fmt, ...);
void asmtp_capa_add_prefix (char *prefix, char *name);
int anubis_get_db_record (const char *username, ANUBIS_USER * usr);
void authmode_section_init (void);

/* gsasl.c */
void auth_gsasl_init (void);
int anubis_auth_gsasl (char *auth_type, char *arg, ANUBIS_USER * usr);
#ifdef WITH_GSASL
void install_gsasl_stream (Gsasl_session *sess_ctx, NET_STREAM * stream);
#endif

/* gsasl_srv.c */
int anubis_name_cmp (void *item, void *data);
ANUBIS_LIST auth_method_list (const char *input);
void anubis_set_mech_list (ANUBIS_LIST *out, ANUBIS_LIST list);
void anubis_set_server_mech_list (ANUBIS_LIST list);

/* xdatabase.c */
int xdatabase (char *command);
void xdatabase_capability (ANUBIS_SMTP_REPLY reply);
void xdatabase_enable (void);

/* md5.c */
int anubis_md5_file (unsigned char *digest, int fd);
void string_bin_to_hex (unsigned char *output, unsigned char *input, int inlen);
int string_hex_to_bin (unsigned char *output, unsigned char *input, int inlen);

#define MD5_DIGEST_BYTES 16

/* mda.c */
void mda (void);

/* EOF */
