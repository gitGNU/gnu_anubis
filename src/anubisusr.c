/*
   anubisusr.c
   
   Copyright (C) 2004 The Anubis Team.

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
# include <config.h>
#endif
#include "headers.h"
#include "extern.h"
#include "rcfile.h"
#include <gsasl.h>
#include <getopt.h>
#include <getline.h>

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

#if defined(USE_GNUTLS) && defined(HAVE_GNUTLS_GNUTLS_H)
# include <gnutls/gnutls.h>
# define HAVE_TLS
#endif /* USE_GNUTLS and HAVE_GNUTLS_GNUTLS_H */

#ifdef HAVE_TLS
char *tls_cafile;
int enable_tls = 1;
#endif /* HAVE_TLS */

char *progname;

char *smtp_host = "localhost";
int smtp_port = 24;
struct obstack input_stk;

int verbose;

#define VDETAIL(n,s) do { if (verbose>=(n)) printf s; } while(0)

struct smtp_reply {
	int code;        /* Reply code */
	char *base;      /* Pointer to the start of the reply string */
	int argc;        /* Number of arguments in the parsed reply */
	char **argv;     /* Parsed reply */ 
};

struct smtp_reply smtp_capa;

void error(const char *, ...);
int send_line(char *buf);
int smtp_get_reply(struct smtp_reply *repl);
void smtp_free_reply(struct smtp_reply *repl);

#define R_CONT     0x8000
#define R_CODEMASK 0xfff

void
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}


/* Basic I/O */

NET_STREAM iostream;


#ifdef HAVE_TLS

void
info(int mode, const char *fmt, ...)
{
	va_list ap;

	if (verbose == 0)
		return;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void
anubis_error(int ignored_method, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}	

void
starttls()
{
	struct smtp_reply reply;
	
	VDETAIL(1,(_("Starting TLS negotiation\n")));
	send_line("STARTTLS");
	smtp_get_reply(&reply);
	if (reply.code != 220) {
		error(_("Server rejected TLS negotiation"));
		exit(1);
	}
	iostream = start_ssl_client(iostream, tls_cafile, verbose > 2);
	if (!iostream) {
		error(_("TLS negotiation failed"));
		exit(1);
	}
}
#endif /* HAVE_TLS */


/* Auxiliary functions */
char *
skipws(char *str)
{
	while (*str && isspace(*(u_char*)str))
		str++;
	return str;
}

char *
skipword(char *str)
{
	while (*str && !isspace(*(u_char*)str))
		str++;
	return str;
}

int
argcv_split(char *buf, int *pargc, char ***pargv)
{
	char *t;
	int i, argc = 0;
	char **argv;

	t = buf;
	do {
		argc++;
		t = skipws(t);
	} while (*t && (t = skipword(t)));

	argv = calloc(argc, sizeof(*argv));
	for (i = 0, t = strtok(buf, " \t"); t; i++, t = strtok(NULL, " \t"))
		argv[i] = strdup(t);
	argv[i] = NULL;
	*pargc = argc-1;
	*pargv = argv;
	return 0;
}

void
argcv_free(int argc, char **argv)
{
	if (argc == 0 || argv == NULL)
		return;
	while (--argc >= 0)
		if (argv[argc])
			free(argv[argc]);
	free(argv);
}

/* FIXME: Move to the library and unify with hostname_error() */
const char *
h_error_string (int ec)
{
	static struct h_err_tab {
		int code;
		char *descr;
	} *ep, h_err_tab[] = {
		{ HOST_NOT_FOUND,
		  N_("No such host is known in the database.") },
		{ TRY_AGAIN,
		  N_("Temporary error. Try again later.") },
		{ NO_RECOVERY,
		  N_("Non-recoverable error") },
		{ NO_ADDRESS,
		  N_("No Internet address is associated with the name") },
		{ 0, 0 }
	};

	for (ep = h_err_tab; ep->descr; ep++)
		if (ep->code == ec)
			return gettext(ep->descr);
	return gettext ("Unknown error");
};

/* FIXME: move to the library. Modify connect_directly_to() to use it */
int
parse_host(char *host, int port, struct sockaddr_in *addr)
{
	struct hostent *hp = gethostbyname(host);
	
	if (!hp) {
		error(_("Cannot resolve %s: %s"), host,
		      h_error_string(h_errno));
		return -1;
	}
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);

	if (hp->h_length != sizeof addr->sin_addr.s_addr) {
		error(_("Cannot resolve %s: received illegal address length (%d)"),
		      host,
		      hp->h_length);
		return -1;
	}
	memcpy(&addr->sin_addr.s_addr, hp->h_addr,
	       sizeof addr->sin_addr.s_addr);
	return 0;
}


/* GSASL mechanisms */

static ANUBIS_LIST *auth_mech_list;

void
add_mech(char *arg)
{
	if (!auth_mech_list)
		auth_mech_list = list_create();
	list_append(auth_mech_list, arg);
}


/* Capability handling */

int
find_capa(struct smtp_reply *repl, const char *name, const char *value)
{
	int i;
	for (i = 0; i < repl->argc; i++) {
		char *p = skipword(repl->argv[i]);
		if (strncmp(name, repl->argv[i], p - repl->argv[i]) == 0) {
			if (value) {
				int j, argc;
				char **argv;
				int rc = 1;
				
				argcv_split(repl->argv[i], &argc, &argv);
				for (j = 0; rc == 1 && j < argc; j++)
					if (strcmp(argv[j], value) == 0) 
						rc = 0;
				argcv_free(argc, argv);
				return rc;
			} 
			return 0;
		}
	}
	return 1;
}	

static int
name_cmp(void *item, void *data)
{
	return strcmp(item, data);
}

char *
find_capa_v(struct smtp_reply *repl, const char *name, ANUBIS_LIST *list)
{
	int i;
	for (i = 0; i < repl->argc; i++) {
		char *p = skipword(repl->argv[i]);
		if (strncmp(name, repl->argv[i], p - repl->argv[i]) == 0) {
			int j, argc;
			char **argv;
			char *rv = NULL;
				
			argcv_split(repl->argv[i], &argc, &argv);
			if (!list) {
				if (argv[1])
					rv = strdup(argv[1]);
			} else {
				for (j = 0; !rv && j < argc; j++) 
					rv = list_locate(list, argv[j],
							 name_cmp);
			}
			argcv_free(argc, argv);
			return rv;
		} 
	}
	return NULL;
}	


/* I/O functions */
int
send_line(char *buf)
{
	size_t size = strlen(buf);
	size_t n;
	int rc;

	VDETAIL(2,("C: %s\n", buf));
	
	rc = stream_write(iostream, buf, size, &n);
	if (rc) {
		error(_("write failed: %s"),
		      stream_strerror(iostream, rc));
		return rc;
	}
	rc = stream_write(iostream, CRLF, 2, &n);
	if (rc) 
		error(_("write failed: %s"),
		      stream_strerror(iostream, rc));
	return rc;
}

int
smtp_get_reply(struct smtp_reply *repl)
{
	char buf[LINEBUFFER+1];
	char *p;
	int i;
	int cont = 0;
	
	memset(repl, 0, sizeof *repl);
	do {
		size_t n;
		int rc = stream_readline(iostream, buf, sizeof buf, &n);

		if (rc) {
			error(_("read failed: %s"),
			      stream_strerror(iostream, rc));
			exit(1);
		}
			
		VDETAIL(2,("S: %*.*s", (int) n, (int) n, buf));
		if (!cont) {
			int code;
			if (n < 4)
				break;
			code = strtoul(buf, &p, 0);
			if (p - buf != 3 || (*p != '-' && *p != ' ')) {
				error(_("Unexpected reply from server: %s"),
				      buf);
				abort();
			}
			if (repl->code == 0)
				repl->code = code;
			else if (repl->code != code) {
				error(_("Unexpected reply code from server: %d"),
				      code);
				abort();
			}
		}
		
		if (buf[n-1] == '\n') {
			cont = 0;
			n--;
			if (buf[n-1] == '\r')
				n--;
			buf[n++] = 0;
			if (n - 4 && buf[4])
				obstack_grow(&input_stk, buf + 4, n - 4);
			else
				obstack_grow(&input_stk, "\r", 2);
			repl->argc++;
		} else {
			cont = 1;
			obstack_grow(&input_stk, buf, n);
		}
	} while (cont || *p == '-');
	obstack_1grow(&input_stk, 0);
	repl->base = obstack_finish(&input_stk);

	repl->argv = xmalloc((repl->argc + 1) * sizeof (repl->argv[0]));
	for (i = 0, p = repl->base; p[0]; p += strlen(p) + 1, i++)
		repl->argv[i] = p[0] == '\r' ? "" : p;
	repl->argv[i] = NULL;
	return 0;
}

void
smtp_free_reply(struct smtp_reply *repl)
{
	obstack_free(&input_stk, repl->base);
	memset(repl, 0, sizeof *repl);
}

void
smtp_print_reply(FILE *fp, struct smtp_reply *repl)
{
	int i;
	for (i = 0; i < repl->argc; i++)
		fprintf(fp, "%s\n", repl->argv[i]);
	fflush(fp);
}


void
smtp_ehlo()
{
	struct smtp_reply repl;
	
	send_line("EHLO localhost");
	smtp_get_reply(&repl);
	if (repl.code != 250) {
		error(_("Server refused handshake"));
		smtp_print_reply(stderr, &repl);
		exit(1);
	}
	smtp_capa = repl;
}	


struct auth_args {
	char *anon_token;
	char *authorization_id;
	char *authentication_id;
	char *password;
	char *service;
	char *hostname;
	char *service_name;
	char *passcode;
	char *qop;
	char *realm;
};

struct auth_args auth_args;

void
assign_string(char **pstring, const char *value)
{
	if (*pstring)
		free(*pstring);
	*pstring = strdup(value);
}

/* Compare two hostnames. Return 0 if they have the same address type,
   address length *and* at least one of the addresses of A matches
   B */
int
hostcmp(const char *a, const char *b)
{
	struct hostent *hp = gethostbyname(a);
	char **addrlist;
	char *dptr;
	char **addr;
	size_t i, count;
	size_t entry_length;
	int entry_type;
	
	if (!hp)
		return 1;

	for (count = 1, addr = hp->h_addr_list; *addr; addr++)
		count++;
	addrlist = xmalloc(count * (sizeof *addrlist + hp->h_length)
			   - hp->h_length);
	dptr = (char*)(addrlist + count);
	for (i = 0; i < count - 1; i++) {
		memcpy(dptr, hp->h_addr_list[i], hp->h_length);
		addrlist[i] = dptr;
		dptr += hp->h_length;
	}
	addrlist[i] = NULL;
	entry_length = hp->h_length;
	entry_type = hp->h_addrtype;
	
	hp = gethostbyname(b);
	if (!hp
	    || entry_length != hp->h_length
	    || entry_type != hp->h_addrtype) {
		free(addrlist);
		return 1;
	}
	
	for (addr = addrlist; *addr; addr++) {
		char **p;

		for (p = hp->h_addr_list; *p; p++) {
			if (memcmp(*addr, *p, entry_length) == 0) {
				free(addrlist);
				return 0;
			}
		}
	}
	free(addrlist);
	return 1;
}

/* Parse traditional .netrc file. Set up auth_args fields in accordance with
   it. */
void
parse_netrc(const char *filename)
{
	FILE *fp;
	char *buf = NULL;
	size_t n = 0;
	int def_argc = 0;
	char **def_argv;
	char **p_argv = NULL;
	int line = 0;
	
	fp = fopen(filename, "r");
	if (!fp) {
		if (errno != ENOENT) {
			error(_("Cannot open configuration file %s: %s"),
			      filename, strerror(errno));
		}
		return;
	} else
	  VDETAIL(1, (_("Opening configuration file %s...\n"), filename));

	while (getline(&buf, &n, fp) > 0 && n > 0) {
		char *p;
		size_t len;
		int argc;
		char **argv;

		line++;
		len = strlen(buf);
		if (len > 1 && buf[len-1] == '\n')
			buf[len-1] = 0;
		p = skipws(buf);
		if (*p == 0 || *p == '#')
			continue;
		
		argcv_split(buf, &argc, &argv);

		if (strcmp(argv[0], "machine") == 0) {
			if (hostcmp(argv[1], smtp_host) == 0) {
				VDETAIL(1,
					(_("Found matching line %d\n"), line));

				if (def_argc)
					argcv_free(def_argc, def_argv);
				def_argc = argc;
				def_argv = argv;
				p_argv = argv + 2;
				break;
			}
		} else if (strcmp(argv[0], "default") == 0) {
			VDETAIL(1,(_("Found default line %d\n"), line));
			
			if (def_argc)
				argcv_free(def_argc, def_argv);
			def_argc = argc;
			def_argv = argv;
			p_argv = argv + 1;
		} else {
			VDETAIL(1,(_("Ignoring unrecognized line %d\n"), line));
			argcv_free(argc, argv);
		}
	}
	fclose(fp);
	free(buf);
	
	if (!p_argv)
		VDETAIL(1,(_("No matching line found\n")));
	else {
		while (*p_argv) {
			if (!p_argv[1]) {
				error(_("%s:%d: incomplete sentence"),
				      filename, line);
				break;
			}
			if (strcmp(*p_argv, "login") == 0) {
				assign_string(&auth_args.authentication_id,
					      p_argv[1]);
				assign_string(&auth_args.authorization_id,
					      p_argv[1]);
			} else if (strcmp(*p_argv, "password") == 0) 
				assign_string(&auth_args.password, p_argv[1]);
			p_argv += 2;
		}
		argcv_free(def_argc, def_argv);
	}
}
	

/* FIXME: Add UTF-8 conversion */
static int
utf8cpy(char *dst, size_t *dstlen, char *src, size_t srclen)
{
	size_t len = strlen(src);

	if (dst && *dstlen < len)
		return GSASL_TOO_SMALL_BUFFER;
	*dstlen = len;
	if (dst)
		strcpy(dst, src);
	return GSASL_OK;
}

char *
get_input(const char *prompt)
{
	char *buf = NULL;
	size_t n;
	
	printf("%s", prompt);
	fflush(stdout);
	getline(&buf, &n, stdin);

	n = strlen(buf);
	if (n > 1 && buf[n-1] == '\n')
		buf[n-1] = 0;
	return buf;
}

int
cb_anonymous(Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
	int rc;
	
	if (auth_args.anon_token == NULL)
		auth_args.anon_token = get_input(_("Anonymous token: "));

	if (auth_args.anon_token == NULL)
		return GSASL_AUTHENTICATION_ERROR;

	rc = utf8cpy(out, outlen, auth_args.anon_token,
		     strlen(auth_args.anon_token));
	if (rc != GSASL_OK)
		return rc;

	return GSASL_OK;
}

int
cb_authorization_id(Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
	int rc;
	
	if (auth_args.authorization_id == NULL)
		auth_args.authorization_id = get_input(_("Authorization ID: "));

	if (auth_args.authorization_id == NULL)
		return GSASL_AUTHENTICATION_ERROR;
	
	rc = utf8cpy(out, outlen, auth_args.authorization_id,
		     strlen(auth_args.authorization_id));
	if (rc != GSASL_OK)
		return rc;
	
	return GSASL_OK;
}

int
cb_authentication_id(Gsasl_session_ctx *ctx, char *out, size_t *outlen)
{
	int rc;
	
	if (auth_args.authentication_id == NULL)
		auth_args.authentication_id =
			get_input(_("Authentication ID: "));

	if (auth_args.authentication_id == NULL)
		return GSASL_AUTHENTICATION_ERROR;

	rc = utf8cpy(out, outlen, auth_args.authentication_id,
		      strlen(auth_args.authentication_id));
	if (rc != GSASL_OK)
		return rc;
	
	return GSASL_OK;
}

int
cb_password(Gsasl_session_ctx *ctx, char *out, size_t *outlen)
{
	int rc;

	if (auth_args.password == NULL)
		auth_args.password = getpass (_("Password: "));
	
	if (auth_args.password == NULL)
		return GSASL_AUTHENTICATION_ERROR;

	rc = utf8cpy(out, outlen, auth_args.password,
		      strlen(auth_args.password));
	if (rc != GSASL_OK)
		return rc;
	
	return GSASL_OK;
}

int
cb_service(Gsasl_session_ctx *ctx, char *srv, size_t *srvlen,
	   char *host, size_t *hostlen, char *srvname, size_t *srvnamelen)
{
	int rc;
  
	if (auth_args.service == NULL)
		auth_args.service = get_input(_("GSSAPI service name: "));

	if (auth_args.hostname == NULL)
		auth_args.hostname = get_input(_("Hostname of server: "));

	if (srvnamelen && auth_args.service_name == NULL)
		auth_args.service_name = get_input(_("Generic server name: "));

	if (auth_args.service == NULL)
		return GSASL_AUTHENTICATION_ERROR;

	if (auth_args.hostname == NULL)
		return GSASL_AUTHENTICATION_ERROR;

	if (srvnamelen && auth_args.service_name == NULL)
		return GSASL_AUTHENTICATION_ERROR;

	rc = utf8cpy(srv, srvlen, auth_args.service,
		     strlen(auth_args.service));
	if (rc != GSASL_OK)
		return rc;

	rc = utf8cpy(host, hostlen, auth_args.hostname,
		     strlen(auth_args.hostname));
	if (rc != GSASL_OK)
		return rc;

	if (srvnamelen) {
		rc = utf8cpy(srvname, srvnamelen, auth_args.service_name,
			     strlen(auth_args.service_name));
		if (rc != GSASL_OK)
			return rc;
	}
	
	return GSASL_OK;
}

int
cb_passcode(Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
	int rc;
	
	if (auth_args.passcode == NULL)
		auth_args.passcode = getpass (_("Passcode: "));

	if (auth_args.passcode == NULL)
		return GSASL_AUTHENTICATION_ERROR;

	rc = utf8cpy(out, outlen, auth_args.passcode,
		     strlen(auth_args.passcode));
	if (rc != GSASL_OK)
		return rc;

	return GSASL_OK;
}

int
cb_realm(Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
	int rc;

	if (auth_args.realm == NULL)
		auth_args.realm = get_input(_("Client realm: "));

	if (auth_args.realm == NULL)
		return GSASL_AUTHENTICATION_ERROR;

	rc = utf8cpy(out, outlen, auth_args.realm,
		     strlen(auth_args.realm));
	if (rc != GSASL_OK)
		return rc;
	
	return GSASL_OK;
}

void
smtp_quit()
{
	struct smtp_reply repl;
	send_line("QUIT");
	smtp_get_reply(&repl);
	smtp_free_reply(&repl); /* There's no use checking */
}


/* GSASL Authentication */

int
do_gsasl_auth(Gsasl_ctx *ctx, char *mech)
{
	char *output;
	int rc;
	Gsasl_session_ctx *sess_ctx = NULL; 
	struct smtp_reply repl;
	char buf[LINEBUFFER+1];

	snprintf(buf, sizeof buf, "AUTH %s", mech);
	send_line(buf);
	
	rc = gsasl_client_start(ctx, mech, &sess_ctx);
	if (rc != GSASL_OK) {
		error(_("SASL gsasl_client_start: %s"),
		      gsasl_strerror(rc));
		exit(1);
	}

	output = NULL;
	memset(&repl, 0, sizeof repl);
	smtp_get_reply(&repl);
	if (repl.code != 334) {
		error(_("GSASL handshake aborted"));
		smtp_print_reply(stderr, &repl);
		exit(1);
	}
	
	do {
		rc = gsasl_step64 (sess_ctx, repl.base, &output);
		if (rc != GSASL_NEEDS_MORE && rc != GSASL_OK)
			break;

		send_line(output);

		if (rc == GSASL_OK)
			break;
		smtp_free_reply(&repl);
		smtp_get_reply(&repl);
		if (repl.code != 334) {
			error(_("GSASL handshake aborted"));
			smtp_print_reply(stderr, &repl);
			exit(1);
		}
	} while (rc == GSASL_NEEDS_MORE);
	
	free (output);
	     
	if (rc != GSASL_OK) {
		error(_("GSASL error: %s"), gsasl_strerror(rc));
		exit(1);
	}

	smtp_free_reply(&repl);
	smtp_get_reply(&repl);

	if (repl.code == 334) {
		/* Additional data. Do we need it? */
		smtp_free_reply(&repl);
		smtp_get_reply(&repl);
	}

	if (repl.code != 235) {
		error(_("Authentication failed"));
		smtp_print_reply(stderr, &repl);
		exit(1);
	}
	
	VDETAIL(1, (_("GSASL authentication successful\n")));

	if (sess_ctx) 
		install_gsasl_stream (sess_ctx, &iostream);
	
	return 0;
}

void
smtp_auth()
{
	Gsasl_ctx *ctx;   
	char *mech;
	int rc;
	
	mech = find_capa_v(&smtp_capa, "AUTH", auth_mech_list);
	if (!mech) {
		error(_("No suitable authentication mechanism found"));
		smtp_quit();
		exit(1);
	}
	VDETAIL(1,(_("Selected authentication mechanism: %s\n"), mech));

	rc = gsasl_init(&ctx);
	if (rc != GSASL_OK) {
		error(_("cannot initialize libgsasl: %s"),
		      gsasl_strerror(rc));
		smtp_quit();
		exit(1);
	}

	gsasl_client_callback_anonymous_set(ctx, cb_anonymous);
	gsasl_client_callback_authentication_id_set(ctx, cb_authentication_id);
	gsasl_client_callback_authorization_id_set(ctx, cb_authorization_id);
	gsasl_client_callback_password_set(ctx, cb_password);
	gsasl_client_callback_passcode_set(ctx, cb_passcode);
	gsasl_client_callback_service_set(ctx, cb_service);
	gsasl_client_callback_realm_set(ctx, cb_realm);

	do_gsasl_auth(ctx, mech);
}


const char *
get_home_dir()
{
	static char *home;

	if (!home) {
		struct passwd *pwd = getpwuid(getuid());
		if (pwd)
			home = pwd->pw_dir;
		else 
			home = getenv("HOME");

		if (!home) {
			error(_("What is your home directory?"));
			exit(1);
		}
	}
	return home;
}

/* Auxiliary functions */
char *
rc_name()
{
	char *rc;
	const char *home = get_home_dir();
	
	rc = xmalloc(strlen(home) + 1 + sizeof DEFAULT_LOCAL_RCFILE);
	strcpy(rc, home);
	strcat(rc, "/");
	strcat(rc, DEFAULT_LOCAL_RCFILE);
	return rc;
}

#define CMP_UNCHANGED 0
#define CMP_CHANGED   1
#define CMP_ERROR     2

int
diff(char *file1, char *file2)
{
	pid_t pid;
	int i, status;
	char *args[4];

	VDETAIL(1,(_("Comparing %s and %s\n"), file1, file2));
	
	args[0] = "cmp";
	args[1] = file1;
	args[2] = file2;
	args[3] = NULL;
	
	switch (pid = fork()) {
	case -1: /* an error */
		error(_("fork() failed: %s"), strerror(errno));
		return -1;
		
	case 0: /* a child process */
		for (i = 0; i < 64; i++) /* FIXME */
			close(i);
		open("/dev/null", O_RDONLY);
		open("/dev/null", O_WRONLY);
		execvp(args[0], args);
		error(_("execvp() failed: %s"), strerror(errno));
		exit(77);
	}

	/* Master */
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		VDETAIL(1,(_("Result %d\n"), WEXITSTATUS(status)));
		switch (WEXITSTATUS(status)) {
		case 0:
			return CMP_UNCHANGED;
		case 1:
			return CMP_CHANGED;
		default:
			return CMP_ERROR;
		}
	}
	VDETAIL(1,(_("Result: Abnormal termination\n")));

	return CMP_ERROR;
}

#ifndef P_tmpdir
# define P_tmpdir "/tmp"
#endif
#define TEMPLATE "anXXXXXX"

char *
save_reply(struct smtp_reply *reply)
{
	char *filename;
	int fd;
	int i;
	char *tmpdir = getenv("TMPDIR");

	if (!tmpdir)
		tmpdir = P_tmpdir;
	
	filename = xmalloc(strlen(tmpdir) + 1 + sizeof TEMPLATE);
	sprintf(filename, "%s/%s", tmpdir, TEMPLATE);

#ifdef HAVE_MKSTEMP
	{
		int save_mask = umask(077);
		fd = mkstemp(filename);
		umask(save_mask);
	}
#else
	if (mktemp(filename))
		fd = open (filename, O_CREAT|O_EXCL|O_RDWR, 0600);
	else
		fd = -1;
#endif

	if (fd == -1) {
		error (_("Can not open temporary file: %s"), strerror(errno));
		free (filename);
		exit(1);
	}

	VDETAIL(1,(_("Saving to %s\n"), filename));
	for (i = 1; i < reply->argc-1; i++) {
		write(fd, reply->argv[i], strlen(reply->argv[i]));
		write(fd, "\n", 1);
	}
	close(fd);
	return filename;
}	

void
smtp_upload(char *rcname)
{
	FILE *fp;
	struct smtp_reply repl;
        char *buf = NULL;
	size_t n;

	fp = fopen(rcname, "r");
	if (!fp) {
		error(_("Cannot open file %s: %s"), rcname, strerror(errno));
		return;
	}
	
	VDETAIL(1,(_("Uploading %s\n"), rcname));

	send_line("XDATABASE UPLOAD");
	smtp_get_reply(&repl);
	if (repl.code != 354) {
		error(_("UPLOAD failed"));
		smtp_print_reply(stderr, &repl);
		fclose(fp);
		return;
	}
	smtp_free_reply(&repl);
	
	while (getline(&buf, &n, fp) > 0 && n > 0) {
		size_t len = strlen(buf);
		if (len && buf[len-1] == '\n')
			buf[len-1] = 0;
		send_line(buf);
	}
	send_line(".");
	
	fclose(fp);
	smtp_get_reply(&repl);
	if (repl.code != 250) {
		smtp_print_reply(stderr, &repl);
		return;
	}
	smtp_free_reply(&repl);
}
	


/* Main entry points */
int
synch()
{
	int fd;
	int rc;
	struct sockaddr_in addr;
	struct smtp_reply repl;
	char *filename;
	char *rcname;
	
	obstack_init(&input_stk);
#ifdef HAVE_TLS
	init_ssl_libs();
#endif
	
	VDETAIL(1,(_("Using remote SMTP %s:%d\n"), smtp_host, smtp_port));
	if (parse_host(smtp_host, smtp_port, &addr))
		return 1;
	
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		error(_("Cannot create socket: %s"), strerror(errno));
		return 1;
	}

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		error(_("Could not connect to %s:%u: %s."),
		      smtp_host, smtp_port, strerror(errno));
		return -1;
	}

	stream_create(&iostream);
	stream_set_io(iostream,
		      (void *)fd,
		      NULL, NULL, NULL, NULL, NULL);

	smtp_get_reply(&repl);
	if (repl.code != 220) {
		error(_("Server refused connection"));
		smtp_print_reply(stderr, &repl);
		return 1;
	}
	smtp_free_reply(&repl);

	smtp_ehlo();

#ifdef HAVE_TLS
	if (enable_tls && find_capa(&smtp_capa, "STARTTLS", NULL) == 0) {
		starttls();
		smtp_ehlo();
	}
#endif

	smtp_auth();

	/* Get the capabilities */
	smtp_ehlo();

	if (find_capa(&smtp_capa, "XDATABASE", NULL)) {
		error(_("Remote party does not reveal XDATABASE capability"));
		smtp_quit();
		return 1;
	}

	send_line("XDATABASE EXAMINE");
	smtp_get_reply(&repl);
	if (repl.code != 250) {
		error(_("EXAMINE failed"));
		smtp_print_reply(stderr, &repl);
		smtp_quit();
		return 1;
	}

	filename = save_reply(&repl);
	rcname = rc_name();

	rc = diff(filename, rcname);
	
	unlink(filename);
	free(filename);

	if (rc == CMP_CHANGED)
		smtp_upload(rcname);
	free(rcname);

	smtp_quit();
	return 0;
}


/* Main */
#define OPT_VERSION          257
#define OPT_HELP             258

static struct option gnu_options[] =
{
	{"verbose",         no_argument,       0, 'v'},
	{"version",         no_argument,       0, OPT_VERSION},
	{"help",            no_argument,       0, OPT_HELP},
#ifdef HAVE_TLS
	{"disable-tls",     no_argument,       0, 'd'},
	{"tls-cafile",      required_argument, 0, 'C'},
#endif
	{"mechanism",       required_argument, 0, 'm'},
	{0, 0, 0, 0}
};	

void
help()
{
	puts(_("anubisusr -- Synchronize local and remote copies of the user's RC file"));
	puts(_("Usage: anubisusr [OPTIONS] [URL]"));
	puts(_("OPTIONS are:"));
#ifdef HAVE_TLS
	puts(_("  -d, --disable-tls       Disable TLS encryption"));
	puts(_("  -C, --tls-cafile FILE   Use given CA file"));
#endif
	puts(_("  -m, --mechanism MECH    Restrict allowed SASL mechanisms"));
	puts(_("  -v, --verbose           Verbose output. Multiple options\n"
	       "                          increase the verbosity. Maximum is\n"
	       "                          3"));
	puts("");
        puts(_("  --version               Display program version"));
        puts(_("  --help                  Display this help list"));
	printf(_("\nReport bugs to <%s>.\n"), PACKAGE_BUGREPORT);
	exit(0);
}

#define NETRC_NAME ".netrc"
void
read_netrc()
{
	const char *home = get_home_dir();
	char *netrc = xmalloc(strlen(home) + 1 + sizeof NETRC_NAME);
	strcpy(netrc, home);
	strcat(netrc, "/");
	strcat(netrc, NETRC_NAME);
	parse_netrc(netrc);
	free(netrc);
}


int
main (int argc, char **argv)
{
	int c;
	
	progname = strrchr(argv[0], '/');
	if (!progname)
		progname = argv[0];
	else
		progname++;
		
	while ((c = getopt_long(argc, argv, "dC:m:v", gnu_options, NULL))
	       != EOF) {
		switch (c) {
#ifdef HAVE_TLS
		case 'd':
			enable_tls = 0;
			break;
			
		case 'C':
			tls_cafile = optarg;
			break;
			
#endif
		case 'm':
			add_mech(optarg);
			break;
			
		case 'v':
			verbose++;
			break;

		case OPT_VERSION:
			printf ("anubisusr (%s)\n", PACKAGE_STRING);
			break;

		case OPT_HELP:
			help();
			break;
			
		default:
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1) {
		error(_("Too many arguments. Try anubisusr --help for more info."));
		exit(1);
	}

	if (argc == 1) {
		char *p;
		
		smtp_host = argv[0];
		p = strchr (smtp_host, ':');
		if (p) {
			unsigned long n;
			*p++ = 0;
			n = strtoul(p, &p, 0);
			if (n > USHRT_MAX) {
				error(_("Port value too big"));
				exit(1);
			}
			smtp_port = n;
		}
	}

	read_netrc();
	return synch();
}

/* EOF */

