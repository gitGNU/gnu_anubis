/*
   This file is part of GNU Anubis testsuite.
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

/* This is a "fake" mta designed for testing purposes. It imitates
   sendmail SMTP modes (daemon and stdin). It does not actually send anything,
   instead it just outputs the transcript of the SMTP session.

   Invocation:
   
   1. mta -bs [-d FILE]

   Use the SMTP protocol on standard input and output.

   2. mta -bd [-p port] [-d FILE]

   Operates as daemon. If port is given, mta will listen on that port.
   Otherwise, it will use the first free port in the range 1024-65535.
   In this case, mta prints the port number on the stdout, prior to
   starting operation. Notice, that in this mode mta does not disconnect
   itself from the controlling terminal, it always stays on the foreground.

   Option -d in both cases sets the name of the output diagnostics file.
   
   Environment variables:

   MTA_DIAG     Sets the name of the output diagnostic file. By default,
                the diagnostics goes to stderr.
   MTA_APPEND   When set to any non-empty value, directs mta to append
                to the diagnostics file, not to overwrite it. 

*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>

#include <pwd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#if defined(USE_GNUTLS) 
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

FILE *diag = NULL;		/* diagnostic output */
int port = 0;			/* Port number (for smtp mode) */

#ifdef USE_GNUTLS
char *tls_cert;			/* TLS sertificate */
char *tls_key;			/* TLS key */
char *tls_cafile;

#define DH_BITS 768
#define enable_tls() (tls_cafile != NULL || (tls_cert != NULL && tls_key != NULL))
void tls_init (void);

gnutls_dh_params_t dh_params;
static gnutls_certificate_server_credentials x509_cred;
#endif /* USE_GNUTLS */

char *progname;

int mta_daemon (int, char **);
int mta_stdio (int, char **);
void error (const char *, ...);
void smtp_reply (int, char *, ...);
void reset_capa (char *);

#define R_CONT     0x8000
#define R_CODEMASK 0xfff

int
main (int argc, char **argv)
{
  int c, status;
  int (*mta_mode) (int argc, char **argv) = NULL;
  char *diag_name = NULL;
  int append = getenv ("MTA_APPEND") != NULL;

  progname = strrchr (argv[0], '/');
  if (!progname)
    progname = argv[0];
  else
    progname++;

  while ((c = getopt (argc, argv, "ac:C:b:d:k:p:")) != EOF)
    {
      switch (c) {
      case 'a':
	append = 1;
	break;
	
      case 'b':
	switch (optarg[0]) {
	case 'd':
	  mta_mode = mta_daemon;
	  break;
	  
	case 's':
	  mta_mode = mta_stdio;
	  break;
	  
	default:
	  error ("unsupported mode");
	  exit (1);
	}
	break;

#ifdef USE_GNUTLS
      case 'c':
	tls_cert = optarg;
	break;
	
      case 'C':
	tls_cafile = optarg;
	break;
	
      case 'k':
	tls_key = optarg;
	break;
#endif
	
      case 'd':
	diag_name = optarg;
	break;
	
      case 'p':
	port = strtoul (optarg, NULL, 0);
	break;
	
      default:
	error ("unknown option: -%c", c);
	exit (1);
      }
    }
  
  if (!diag_name)
    diag_name = getenv ("MTA_DIAG");

  if (diag_name)
    {
      char *mode = append ? "a" : "w";
      diag = fopen (diag_name, mode);
      if (!diag)
	{
	  error ("can't open diagnostic output: %s", diag_name);
	  return 1;
	}
    }

  argc -= optind;
  argv += optind;

  if (!mta_mode)
    {
      error ("use either -bs or -bd");
      exit (1);
    }

#ifdef USE_GNUTLS
  tls_init ();
#endif
  status = mta_mode (argc, argv);

  if (diag)
    fclose (diag);
  smtp_reply (221, "Done");
  return status;
}

void
error (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  fprintf (stderr, "%s: ", progname);
  vfprintf (stderr, fmt, ap);
  fprintf (stderr, "\n");
  va_end (ap);
}

static void *in, *out;

static const char *
_def_strerror (int rc)
{
  return rc == -1 ? "end of file reached" : strerror (rc);
}

static int
_def_write (void *sd, char *data, size_t size, size_t * nbytes)
{
  int n = write ((int) sd, data, size);
  if (n != size)
    return errno;
  if (nbytes)
    *nbytes = n;
  return 0;
}

static int
_def_read (void *sd, char *data, size_t size, size_t * nbytes)
{
  int n = read ((int) sd, data, size);
  if (n != size)
    return errno ? errno : -1;
  if (nbytes)
    *nbytes = n;
  return 0;
}

static int
_def_close (void *sd)
{
  return close ((int) sd);
}

int (*_mta_read) (void *, char *, size_t, size_t *) = _def_read;
int (*_mta_write) (void *, char *, size_t, size_t *) = _def_write;
int (*_mta_close) (void *) = _def_close;
const char *(*_mta_strerror) (int) = _def_strerror;

#ifdef USE_GNUTLS

static void
_tls_cleanup_x509 (void)
{
  if (x509_cred)
    gnutls_certificate_free_credentials (x509_cred);
}

static void
generate_dh_params (void)
{
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, DH_BITS);
}

void
tls_init (void)
{
  if (!enable_tls ())
    return;

  gnutls_global_init ();
  atexit (gnutls_global_deinit);
  gnutls_certificate_allocate_credentials (&x509_cred);
  atexit (_tls_cleanup_x509);
  if (tls_cafile)
    {
      int rc = gnutls_certificate_set_x509_trust_file (x509_cred,
						       tls_cafile,
						       GNUTLS_X509_FMT_PEM);
      if (rc < 0)
	{
	  gnutls_perror (rc);
	  return;
	}
    }
  if (tls_cert && tls_key)
    gnutls_certificate_set_x509_key_file (x509_cred,
					  tls_cert, tls_key,
					  GNUTLS_X509_FMT_PEM);

  generate_dh_params ();
  gnutls_certificate_set_dh_params (x509_cred, dh_params);
}

static ssize_t
_tls_fd_pull (gnutls_transport_ptr_t fd, void *buf, size_t size)
{
  int rc;
  do
    {
      rc = read ((int) fd, buf, size);
    }
  while (rc == -1 && errno == EAGAIN);
  return rc;
}

static ssize_t
_tls_fd_push (gnutls_transport_ptr_t fd, const void *buf, size_t size)
{
  int rc;
  do
    {
      rc = write ((int) fd, buf, size);
    }
  while (rc == -1 && errno == EAGAIN);
  return rc;
}

static const char *
_tls_strerror (int rc)
{
  return gnutls_strerror (rc);
}

static int
_tls_write (void *sd, char *data, size_t size, size_t * nbytes)
{
  int rc;

  do
    rc = gnutls_record_send (sd, data, size);
  while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);
  if (rc >= 0)
    {
      if (nbytes)
	*nbytes = rc;
      return 0;
    }
  return rc;
}

static int
_tls_read (void *sd, char *data, size_t size, size_t * nbytes)
{
  int rc = gnutls_record_recv (sd, data, size);
  if (rc >= 0)
    {
      if (nbytes)
	*nbytes = rc;
      return 0;
    }
  return rc;
}

static int
_tls_close (void *sd)
{
  if (sd)
    {
      gnutls_bye (sd, GNUTLS_SHUT_RDWR);
      gnutls_deinit (sd);
    }
  return 0;
}

static gnutls_session_t
tls_session_init (void)
{
  gnutls_session_t session = 0;
  int rc;

  gnutls_init (&session, GNUTLS_SERVER);
  gnutls_set_default_priority (session);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
  gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);
  gnutls_dh_set_prime_bits (session, DH_BITS);

  gnutls_transport_set_pull_function (session, _tls_fd_pull);
  gnutls_transport_set_push_function (session, _tls_fd_push);

  gnutls_transport_set_ptr2 (session,
			     (gnutls_transport_ptr_t) in,
			     (gnutls_transport_ptr_t) out);
  rc = gnutls_handshake (session);
  if (rc < 0)
    {
      gnutls_deinit (session);
      gnutls_perror (rc);
      return 0;
    }

  return session;
}

void
smtp_starttls (void)
{
  gnutls_session_t session;

  smtp_reply (220, "Ready to start TLS");

  session = tls_session_init ();
  if (session)
    {
      in = out = session;
      _mta_read = _tls_read;
      _mta_write = _tls_write;
      _mta_close = _tls_close;
      _mta_strerror = _tls_strerror;
      reset_capa ("STARTTLS");
    }
  else
    smtp_reply (530, "TLS negotiation failed");
}

#endif /* USE_GNUTLS */

void
smtp_reply (int code, char *fmt, ...)
{
  va_list ap;
  int cont = code & R_CONT ? '-' : ' ';
  static char obuf[512];
  int n, rc;

  va_start (ap, fmt);
  n = snprintf (obuf, sizeof obuf, "%d%c", code & R_CODEMASK, cont);
  n += vsnprintf (obuf + n, sizeof obuf - n, fmt, ap);
  va_end (ap);
  n += snprintf (obuf + n, sizeof obuf - n, "\r\n");
  rc = _mta_write (out, obuf, n, NULL);
  if (rc)
    {
      fprintf (stderr, "Write failed: %s", _mta_strerror (rc));
      abort ();
    }
}

int
get_input_line (char *buf, size_t bufsize)
{
  int i, rc;

  for (i = 0; i < bufsize - 1; i++)
    {
      size_t n;
      rc = _mta_read (in, buf + i, 1, &n);
      if (rc)
	{
	  fprintf (stderr, "Read failed: %s", _mta_strerror (rc));
	  abort ();
	}
      if (n == 0)
	break;
      if (buf[i] == '\n')
	break;
    }
  buf[++i] = 0;
  return i;
}

#define STATE_INIT   0
#define STATE_EHLO   1
#define STATE_MAIL   2
#define STATE_RCPT   3
#define STATE_DATA   4
#define STATE_QUIT   5
#define STATE_DOT    6

#define KW_EHLO      0
#define KW_HELO      1
#define KW_MAIL      2
#define KW_RCPT      3
#define KW_DATA      4
#define KW_HELP      5
#define KW_QUIT      6
#define KW_STARTTLS  7

int
smtp_kw (const char *name)
{
  static struct kw
  {
    char *name;
    int code;
  }
  kw[] =
  {
    { "ehlo", KW_EHLO },
    { "helo", KW_HELO },
    { "mail", KW_MAIL },
    { "rcpt", KW_RCPT },
    { "data", KW_DATA },
    { "help", KW_HELP },
    { "quit", KW_QUIT },
    { "help", KW_HELP },
    { "starttls", KW_STARTTLS },
    { NULL },
  };
  int i;

  for (i = 0; kw[i].name != NULL; i++)
    if (strcasecmp (name, kw[i].name) == 0)
      return kw[i].code;
  return -1;
}

char *
skipws (char *str)
{
  while (*str && isspace (*(u_char *) str))
    str++;
  return str;
}

char *
skipword (char *str)
{
  while (*str && !isspace (*(u_char *) str))
    str++;
  return str;
}

int
argcv_split (char *buf, int *pargc, char ***pargv)
{
  char *t;
  int i, argc = 0;
  char **argv;

  t = buf;
  do
    {
      argc++;
      t = skipws (t);
    }
  while (*t && (t = skipword (t)));

  argv = calloc (argc, sizeof (*argv));
  for (i = 0, t = strtok (buf, " \t"); t; i++, t = strtok (NULL, " \t"))
    argv[i] = strdup (t);
  argv[i] = NULL;
  *pargc = argc - 1;
  *pargv = argv;
  return 0;
}

int
argcv_free (int argc, char **argv)
{
  while (--argc >= 0)
    if (argv[argc])
      free (argv[argc]);
  free (argv);
  return 1;
}

char *mta_capa[] = {
#ifdef USE_GNUTLS
  "STARTTLS",
#endif
  NULL
};

void
reset_capa (char *name)
{
  int i;
  for (i = 0; mta_capa[i]; i++)
    if (strcmp (mta_capa[i], name) == 0)
      {
	mta_capa[i] = NULL;
	break;
      }
}

void
smtp_ehlo (int extended)
{
  int i;

  if (!extended)
    {
      smtp_reply (250, "pleased to meet you");
      return;
    }

  smtp_reply (R_CONT | 250, "pleased to meet you");
  for (i = 0; mta_capa[i]; i++)
    smtp_reply (R_CONT | 250, "%s", mta_capa[i]);
  smtp_reply (250, "HELP");
}

void
smtp_help (void)
{
  smtp_reply (502, "HELP not implemented");
}

/* Check if (*PARGV)[1] begins with the string PFX, followed by ':'.
   Return 0 if so, 1 otherwise.
   If any characters follow the semicolon, reformat *PARGV so that
   [1] contains only PFX:, [2] contains the characters in question,
   and the rest of entries after [2] is properly reindexed.
*/
int
check_address_command(const char *pfx, int *pargc, char ***pargv)
{
  int argc = *pargc;
  char **argv = *pargv;
  int pfxlen = strlen (pfx);
  int arglen = strlen (argv[1]);
  
  if (argc >= 2 && arglen > pfxlen
      && strncasecmp (argv[1], pfx, pfxlen) == 0
      && argv[1][pfxlen] == ':') {

    if (arglen > pfxlen + 1)
      {
	argc++;
	argv = realloc (argv, (argc + 1) * sizeof (argv[0]));
	memmove (&argv[2], &argv[1], (argc - 1) * sizeof argv[1]);
	argv[2] = strdup (argv[1] + pfxlen + 1);
	argv[1][pfxlen + 1] = 0;

	*pargc = argc;
	*pargv = argv;
      }
    
    return 0;
  }
  return 1;
}

void
smtp (void)
{
  int state;
  char buf[128];

  smtp_reply (220, "localhost bitbucket ready");
  for (state = STATE_INIT; state != STATE_QUIT;)
    {
      int argc;
      char **argv;
      int kw, len;

      if (get_input_line (buf, sizeof buf) <= 0)
	exit (1);

      len = strlen (buf);
      while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
	len--;
      buf[len] = 0;

      if (diag)
	fprintf (diag, "%s\n", buf);

      argcv_split (buf, &argc, &argv);
      if (argc == 0)
	continue;
      kw = smtp_kw (argv[0]);
      if (kw == KW_QUIT)
	{
	  state = STATE_QUIT;
	  argcv_free (argc, argv);
	  continue;
	}
      else if (kw == KW_HELP)
	{
	  smtp_help ();
	  continue;
	}

      switch (state) {
      case STATE_INIT:
	switch (kw) {
	case KW_EHLO:
	case KW_HELO:
	  if (argc == 2)
	    {
	      smtp_ehlo (kw == KW_EHLO);
	      state = STATE_EHLO;
	    }
	  else
	    smtp_reply (501, "%s requires domain address", argv[0]);
	  break;
	  
	default:
	  smtp_reply (503, "Polite people say HELO first");
	  break;
	}
	break;
	
      case STATE_EHLO:
	switch (kw) {
	case KW_EHLO:
	  if (argc == 2)
	    {
	      smtp_ehlo (1);
	    }
	  else
	    smtp_reply (501, "%s requires domain address", argv[0]);
	  break;
	  
	case KW_MAIL:
	  if (check_address_command("from", &argc, &argv) == 0)
	    {
	      smtp_reply (250, "Sender OK");
	      state = STATE_MAIL;
	    }
	  else
	    smtp_reply (501, "Syntax error");
	  break;

#ifdef USE_GNUTLS
	case KW_STARTTLS:
	  smtp_starttls ();
	  break;
#endif
	default:
	  smtp_reply (503, "Need MAIL command");
	}
	break;
	
      case STATE_MAIL:
	switch (kw) {
	case KW_RCPT:
	  if (check_address_command("to", &argc, &argv) == 0)
	    {
	      smtp_reply (250, "Recipient OK");
	      state = STATE_RCPT;
	    }
	  else
	    smtp_reply (501, "Syntax error");
	  break;
	  
	default:
	  smtp_reply (503, "Need RCPT command");
	}
	break;
	
      case STATE_RCPT:
	switch (kw) {
	case KW_RCPT:
	  if (argc == 3 && strcasecmp (argv[1], "to:") == 0)
	    {
	      smtp_reply (250, "Recipient OK");
	    }
	  else
	    smtp_reply (501, "Syntax error");
	  break;
	  
	case KW_DATA:
	  smtp_reply (354,
		      "Enter mail, end with \".\" on a line by itself");
	  state = STATE_DATA;
	  break;
	  
	default:
	  smtp_reply (501, "Syntax error");
	}
	
      case STATE_DATA:
	if (strcmp (buf, ".") == 0)
	  {
	    smtp_reply (250, "Mail accepted for delivery");
	    state = STATE_EHLO;
	  }
	break;
      }
    }
}

int
mta_daemon (int argc, char **argv)
{
  int on = 1;
  struct sockaddr_in address;
  int fd;

  fd = socket (PF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    {
      perror ("socket");
      return 1;
    }

  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));

  memset (&address, 0, sizeof (address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;

  if (port)
    {
      address.sin_port = htons (port);
      if (bind (fd, (struct sockaddr *) &address, sizeof (address)) < 0)
	{
	  close (fd);
	  perror ("bind");
	  return 1;
	}
    }
  else
    {
      int status;

      port = 1023;
      do
	{
	  if (++port >= 65535)
	    {
	      error ("can't bind socket: all ports in use?");
	      return 1;
	    }
	  address.sin_port = htons (port);
	  status = bind (fd, (struct sockaddr *) &address, sizeof (address));
	}
      while (status < 0);
      printf ("%d\n", port);
      fclose (stdout);
    }

  listen (fd, 5);
  while (1)
    {
      fd_set rfds;
      struct sockaddr_in his_addr;
      int sfd, status;
      socklen_t len;

      FD_ZERO (&rfds);
      FD_SET (fd, &rfds);

      status = select (fd + 1, &rfds, NULL, NULL, NULL);
      if (status == -1)
	{
	  if (errno == EINTR)
	    continue;
	  perror ("select");
	  return 1;
	}

      len = sizeof (his_addr);
      if ((sfd = accept (fd, (struct sockaddr *) &his_addr, &len)) < 0)
	{
	  perror ("accept");
	  return 1;
	}

      in = out = (void *) fd;
      smtp ();
      break;
    }

  return 0;
}

int
mta_stdio (int argc, char **argv)
{
  in = (void *) fileno (stdin);
  out = (void *) fileno (stdout);
  smtp ();
  return 0;
}

/* EOF */
