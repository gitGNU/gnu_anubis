/*
   net.c

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

static int connect_directly_to(char *, unsigned int);
static int mread(int, void *, char *);

static void
_debug_printer(int method, int output, unsigned long nleft, char *ptr)
{
	int len;
	char *mode = "?";

	if (strcmp(ptr, CRLF) == 0)
		return;

	switch (method) {
	case CLIENT:
		mode = _("SERVER");
		break;
	case SERVER:
		mode = _("CLIENT");
	}
		
	fprintf(stderr, "(%ld)%s %s %s", nleft, mode,
		output ? ">>>" : "<<<", ptr);
	len = strlen (ptr);
	if (len > 0 && ptr[len-1] != '\n')
		fprintf(stderr, "\n");
}

#define DPRINTF(method, output, nleft, ptr) do {\
  if (options.termlevel == DEBUG) \
     _debug_printer(method, output, nleft, ptr);\
  } while (0)

int
make_remote_connection(char *host, unsigned int port)
{
	int sd;
	char host_backup[65];
	unsigned int port_backup;
	memset(host_backup, 0, sizeof(host_backup));

	/*
	   First of all, make a copy of 'host' and 'port'.
	*/

	safe_strcpy(host_backup, host);
	port_backup = port;

	check_all_proxies(host_backup, &port_backup);
	sd = connect_directly_to(host_backup, port_backup);
	if (sd == -1) /* an error */
		return -1;
	if (check_socks_proxy(sd, host, port) == -1)
		return -1;
	return sd;
}

static int
connect_directly_to(char *host, unsigned int port)
{
	int sd = 0;
	unsigned long inaddr;
	struct sockaddr_in addr;

	/*
	   Find out the IP address.
	*/

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	info(VERBOSE, _("Getting remote host information..."));

	inaddr = inet_addr(host);
	if (inaddr != INADDR_NONE)
		memcpy(&addr.sin_addr, &inaddr, sizeof(inaddr));
	else {
		struct hostent *hp = 0;
		hp = gethostbyname(host);
		if (hp == 0) {
			hostname_error(host);
			return -1;
		}
		else {
			if (hp->h_length != 4 && hp->h_length != 8) {
				anubis_error(HARD,
				_("Illegal address length received for host %s"), host);
				return -1;
			}
			else {
				memcpy((char *)&addr.sin_addr.s_addr, hp->h_addr,
					hp->h_length);
			}
		}
	}

	/*
	   Create socket, and connect.
	*/

	info(DEBUG, _("Initializing socket..."));
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		anubis_error(HARD, _("Can't create stream socket."));
		return -1;
	}
	info(VERBOSE, _("Connecting to %s:%u..."), host, port);
	if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		anubis_error(HARD, _("Couldn't connect to %s:%u. %s."),
			host, port, strerror(errno));
		return -1;
	}
	else
		info(NORMAL, _("Connected to %s:%u"), host, port);

	return sd;
}

/*****************
 Bind and listen.
******************/

int
bind_and_listen(char *host, unsigned int port)
{
	int sd = 0;
	unsigned long inaddr;
	struct sockaddr_in addr;
	int true = 1;
	
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		anubis_error(HARD, _("Can't create stream socket."));

	if (topt & T_NAMES) {
		inaddr = inet_addr(host);
		if (inaddr != INADDR_NONE)
			memcpy(&addr.sin_addr, &inaddr, sizeof(inaddr));
		else {
			struct hostent *hp = 0;
			hp = gethostbyname(host);
			if (hp == 0)
				hostname_error(host);
			else {
				if (hp->h_length != 4 && hp->h_length != 8)
					anubis_error(HARD,
					_("Illegal address length received for host %s"), host);
				else {
					memcpy((char *)&addr.sin_addr.s_addr, hp->h_addr,
						hp->h_length);
				}
			}
		}
	}
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true));
	
	if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)))
		anubis_error(HARD, _("bind() failed: %s."), strerror(errno));
	info(VERBOSE, _("GNU Anubis bound to %s:%u"), inet_ntoa(addr.sin_addr),
		ntohs(addr.sin_port));
	if (listen(sd, 5))
		anubis_error(HARD, _("listen() failed: %s."), strerror(errno));
	return sd;
}

/**************
  Send a data
***************/

void
swrite(int method, void *sd, char *ptr)
{
	unsigned long nleft;
	unsigned long nwritten = 0;

	if (ptr == 0)
		return;

	nleft = (unsigned long)strlen(ptr);
	while (nleft > 0)
	{
		if (method == CLIENT) {

			#ifdef HAVE_TLS
			if (topt & T_SSL_CLIENT) {
				if ((nwritten = (unsigned long)gnutls_record_send(
						(gnutls_session)sd, ptr, nleft)) <= 0) {
					socket_error();
					return;
				}
			} else
			#endif /* HAVE_TLS */

			#ifdef HAVE_SSL
			if (topt & T_SSL_CLIENT) {
				if ((nwritten = (unsigned long)SSL_write((SSL *)sd,
						ptr, nleft)) <= 0) {
					socket_error();
					return;
				}
			} else
			#endif /* HAVE_SSL */

			if (!(topt & T_SSL_CLIENT)) {
				if ((nwritten = (unsigned long)send((int)sd,
						ptr, nleft, 0)) == -1) {
					socket_error();
					return;
				}
			}
		}
		else if (method == SERVER) {

			#ifdef HAVE_TLS
			if (topt & T_SSL_SERVER) {
				if ((nwritten = (unsigned long)gnutls_record_send(
						(gnutls_session)sd, ptr, nleft)) <= 0) {
					socket_error();
					return;
				}
			} else
			#endif /* HAVE_TLS */

			#ifdef HAVE_SSL
			if (topt & T_SSL_SERVER) {
				if ((nwritten = (unsigned long)SSL_write((SSL *)sd,
						ptr, nleft)) <= 0) {
					socket_error();
					return;
				}
			} else
			#endif /* HAVE_SSL */

			if ((int)sd == -1) { /* standard output */
				nwritten = (unsigned long)write(1, ptr, nleft);
			}
			else if (!(topt & T_SSL_SERVER)) {
				if ((nwritten = (unsigned long)send((int)sd,
						ptr, nleft, 0)) == -1) {
					socket_error();
					return;
				}
			}
		}
		DPRINTF(method, 1, nleft, ptr);
		if (nwritten <= 0)
			return;

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return;
}

/**************
  Read a data
***************/

static int
mread(int method, void *sd, char *ptr)
{
	static int nread = 0;
	static char *read_ptr = 0;
	static char buf[LINEBUFFER+1];

	if (nread <= 0) {
	again:
		if (method == CLIENT) {

			#ifdef HAVE_TLS
			if (topt & T_SSL_CLIENT)
				nread = gnutls_record_recv((gnutls_session)sd, buf, LINEBUFFER);
			else
			#endif /* HAVE_TLS */

			#ifdef HAVE_SSL
			if (topt & T_SSL_CLIENT)
				nread = SSL_read((SSL *)sd, buf, LINEBUFFER);
			else
			#endif /* HAVE_SSL */

			if (!(topt & T_SSL_CLIENT))
				nread = recv((int)sd, buf, LINEBUFFER, 0);
		}
		else if (method == SERVER) {

			#ifdef HAVE_TLS
			if (topt & T_SSL_SERVER)
				nread = gnutls_record_recv((gnutls_session)sd, buf, LINEBUFFER);
			else
			#endif /* HAVE_TLS */

			#ifdef HAVE_SSL
			if (topt & T_SSL_SERVER)
				nread = SSL_read((SSL *)sd, buf, LINEBUFFER);
			else
			#endif /* HAVE_SSL */

			if (!(topt & T_SSL_SERVER))
				nread = recv((int)sd, buf, LINEBUFFER, 0);
		}
		if (nread < 0) {
			if (errno == EINTR)
				goto again;
			return -1;
		}
		else if (nread == 0)
			return 0;
		read_ptr = buf;
	}
	nread--;
	*ptr = *read_ptr++;
	return 1;
}

int
recvline(int method, void *sd, void *vptr, int maxlen)
{
	int n, rc;
	char c, *ptr;

	if ((int)sd == -1 && method == SERVER) { /* standard input */
		memset(vptr, 0, maxlen);
		#ifdef HAVE_ISATTY
		if (!isatty(fileno(stdin))) {
			fgets((char *)vptr, maxlen, stdin);
			remcrlf((char *)vptr);
			strcat((char *)vptr, CRLF);
			if (vptr)
				n = strlen((char *)vptr);
			else
				n = 0;
		}
		else
		#endif /* HAVE_ISATTY */
		{
			n = read(0, (char *)vptr, maxlen - 1);
			remcrlf((char *)vptr);
			strcat((char *)vptr, CRLF);
		}
		return n;
	}

	ptr = vptr;
	for (n = 1; n < maxlen; n++)
	{
		if ((rc = mread(method, sd, &c)) == 1) {
			*ptr++ = c;
			if (c == '\n')
				break;
		}
		else if (rc == 0) {
			if (n == 1)
				return 0;
			else
				break;
		}
		else
			return -1;
	}
	*ptr = 0;
	DPRINTF(method, 0, n, (char *)vptr);
	return n;
}

/*****************
  Get a response
******************/

void
get_response_smtp(int method, void *sd, char *buf, int size)
{
	int n;
	char line[LINEBUFFER+1];

	if (buf != 0)
		memset(buf, 0, size);
	do {
		n = recvline(method, sd, line, LINEBUFFER);
		if (buf != 0) {
			strncat(buf, line, size);
			size -= n;
		}
	} while (line[3] == '-');
	return;
}

/**************************
 Close a socket descriptor
***************************/

void
close_socket(int sd)
{
	if (sd)
		close(sd);
	return;
}


/* EOF */

