/*
   This file is part of GNU Anubis testsuite.
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

#include <pwd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

FILE *diag = NULL;       /* diagnostic output */
int port = 0;            /* Port number (for smtp mode) */

char *progname;

int mta_daemon(int argc, char **argv);
int mta_stdio(int argc, char **argv);
void error(const char *fmt, ...);

int
main (int argc, char **argv)
{
	int c, status;
	int (*mta_mode) (int argc, char **argv) = NULL;
	char *diag_name = NULL;
	int append = getenv("MTA_APPEND") != NULL;
	
	progname = strrchr(argv[0], '/');
	if (!progname)
		progname = argv[0];
	else
		progname++;
		
	while ((c = getopt(argc, argv, "ab:d:p:")) != EOF) {
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
				error("unsupported mode");
				exit(1);
			}
			break;

		case 'd':
			diag_name = optarg;
			break;
			
		case 'p':
			port = strtoul (optarg, NULL, 0);
			break;
	  
		default:
			exit(1);
		}
	}

	if (!diag_name) 
		diag_name = getenv ("MTA_DIAG");

	if (diag_name) {
		char *mode = append ? "a" : "w";
		diag = fopen(diag_name, mode);
		if (!diag) {
			error("can't open diagnostic output: %s",
			      diag_name);
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (!mta_mode) {
		error("use either -bs or -bd");
		exit(1);
	}
	status = mta_mode(argc, argv);

	if (diag)
		fclose(diag);
	return status;
}

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

static FILE *in, *out;

void
smtp_reply(int code, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(out, "%d ", code);
	vfprintf(out, fmt, ap);
	va_end(ap);
	fprintf(out, "\r\n");
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

int
smtp_kw (const char *name)
{
	static struct kw {
		char *name;
		int code;
	} kw[] = {
		{ "ehlo", KW_EHLO },      
		{ "helo", KW_HELO },       
		{ "mail", KW_MAIL },
		{ "rcpt", KW_RCPT },
		{ "data", KW_DATA },
		{ "help", KW_HELP },
		{ "quit", KW_QUIT },
		{ NULL },
	};
	int i;
	
	for (i = 0; kw[i].name != NULL; i++)
		if (strcasecmp (name, kw[i].name) == 0)
			return kw[i].code;
	return -1;
}

char *
skipws(char *str)
{
	while (*str && isspace(*str))
		str++;
	return str;
}

char *
skipword(char *str)
{
	while (*str && !isspace(*str))
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

int
argcv_free(int argc, char **argv)
{
  while (--argc >= 0)
	  if (argv[argc])
		  free(argv[argc]);
  free(argv);
  return 1;
}

void
smtp()
{
	int state;
	char buf[128];
  
	SETVBUF(in, NULL, _IOLBF, 0);
	SETVBUF(out, NULL, _IOLBF, 0);
		
	smtp_reply(220, "localhost bitbucket ready");
	for (state = STATE_INIT; state != STATE_QUIT; ) {
		int argc;
		char **argv;
		int kw, len;
      
		if (fgets(buf, sizeof buf, stdin) == NULL)
			exit (1);
		
		len = strlen (buf);
		while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r'))
			len --;
		buf[len] = 0;

		if (diag)
			fprintf(diag, "%s\n", buf);
      
		argcv_split(buf, &argc, &argv);
		if (argc == 0)
			continue;
		kw = smtp_kw(argv[0]);
		if (kw == KW_QUIT) {
			smtp_reply (221, "Done");
			state = STATE_QUIT;
			argcv_free(argc, argv);
			continue;
		}
      
		switch (state) {
		case STATE_INIT:
			switch (kw) {
			case KW_EHLO:
			case KW_HELO:
				if (argc == 2) {
					smtp_reply(250,
						   "pleased to meet you");
					state = STATE_EHLO;
				} else
					smtp_reply(501,
				    "%s requires domain address", argv[0]);
				break;

			default:
				smtp_reply(503,
					    "Polite people say HELO first");
				break;
			}
			break;
	  
		case STATE_EHLO:
			switch (kw) {
			case KW_MAIL:
				if (argc == 3
				    && strcasecmp(argv[1], "from:") == 0) {
					smtp_reply(250, "Sender OK");
					state = STATE_MAIL;
				} else
					smtp_reply(501, "Syntax error");
				break;

			default:
				smtp_reply(503, "Need MAIL command");
			}
			break;
	  
		case STATE_MAIL:
			switch (kw) {
			case KW_RCPT:
				if (argc == 3
				    && strcasecmp(argv[1], "to:") == 0) {
					smtp_reply(250, "Recipient OK");
					state = STATE_RCPT;
				}
				else
					smtp_reply(501, "Syntax error");
				break;
	      
			default:
				smtp_reply(503, "Need RCPT command");
			}
			break;
	  
		case STATE_RCPT:
			switch (kw) {
			case KW_RCPT:
				if (argc == 3
				    && strcasecmp(argv[1], "to:") == 0) {
					smtp_reply(250, "Recipient OK");
				} else
					smtp_reply(501, "Syntax error");
				break;

			case KW_DATA:
				smtp_reply(354,
			  "Enter mail, end with \".\" on a line by itself");
				state = STATE_DATA;
				break;

			default:
				smtp_reply(501, "Syntax error");
			}

		case STATE_DATA:
			if (strcmp(buf, ".") == 0) {
				smtp_reply(250, "Mail accepted for delivery");
				state = STATE_EHLO;
			}
			break;
		}
	}
}

int
mta_daemon(int argc, char **argv)
{
	int on = 1;
	struct sockaddr_in address;
	int fd;
  
	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	
	memset (&address, 0, sizeof (address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	
	if (port) {
		address.sin_port = htons(port);
		if (bind (fd, (struct sockaddr *) &address,
			  sizeof (address)) < 0) {
			close (fd);
			perror("bind");
			return 1;
		}
	} else {
		int status;
		
		port = 1023;
		do {
			if (++port >= 65535) {
				error ("can't bind socket: all ports in use?");
				return 1;
			}
			address.sin_port = htons(port);
			status = bind(fd, (struct sockaddr *) &address,
				      sizeof(address));
		} while (status < 0);
		printf("%d\n", port);
		fclose(stdout);
	}

	listen(fd, 5);
	while (1) {
		fd_set rfds;
		struct sockaddr_in his_addr;
		int sfd, len, status;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
      
		status = select(fd + 1, &rfds, NULL, NULL, NULL);
		if (status == -1) {
			if (errno == EINTR)
				continue;
			perror("select");
			return 1;
		}

		len = sizeof(his_addr);
		if ((sfd = accept(fd,
				  (struct sockaddr *)&his_addr, &len)) < 0) {
			perror("accept");
			return 1;
		}

		in = fdopen(fd, "r");
		out = fdopen (fd, "w");
		smtp();
		break;
	}
  
	return 0;
}

int
mta_stdio(int argc, char **argv)
{
	in = stdin;
	out = stdout;
	smtp();
	return 0;
}



