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

static struct _debug_cache {
	int method;
	int output;
	int newline;
	size_t count;
} debug_cache = { -1, -1, 0, 0 };

static void
_debug_printer(int method, int output, unsigned long nleft, char *ptr)
{
	int i;
	char *mode = "?";

	switch (method) {
	case CLIENT:
		mode = _("SERVER");
		break;
	case SERVER:
		mode = _("CLIENT");
	}

	if (debug_cache.newline
	    || method != debug_cache.method || output != debug_cache.output) {
		if (!debug_cache.newline && debug_cache.count)
			fprintf(stderr, "(%lu)\n",
				(unsigned long)debug_cache.count);
		debug_cache.method = method;
		debug_cache.output = output;
		debug_cache.newline = 0;
		debug_cache.count = 0;
		fprintf(stderr, "%s %s ", mode, output ? "<<<" : ">>>");
	}

	for (i = 0; i < nleft; i++, ptr++) {
		debug_cache.count++;
		debug_cache.newline = 0;
		if (*ptr == '\r')
			continue;
		if (*ptr == '\n') {
			fprintf(stderr, "(%ld)\n",
				(unsigned long)debug_cache.count);
			debug_cache.count = 0;
			if (i != nleft-1) {
				fprintf(stderr, "%s %s ",
					mode, output ? "<<<" : ">>>");
				debug_cache.newline = 0;
			} else
				debug_cache.newline = 1;
		} else 
			fputc(*ptr, stderr);
	}
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

static const char *
_def_strerror(int rc)
{
	return strerror(rc);
}

static int
_def_write(void *sd, char *data, size_t size, size_t *nbytes)
{
	int rc = send((int)sd, data, size, 0);
	if (rc >= 0) {
		*nbytes = rc;
		return 0;
	}
	return errno;
}

static int
_def_read(void *sd, char *data, size_t size, size_t *nbytes)
{
	int rc = recv((int)sd, data, size, 0);
	if (rc >= 0) {
		*nbytes = rc;
		return 0;
	}
	return errno;
}

static int
_def_close(void *sd)
{
	close ((int) sd);
	return 0;
}

struct io_data {
	char buf[LINEBUFFER+1];          /* Input buffer */
	size_t level;                    /* Buffer fill level */
	char *read_ptr;                  /* Current buffer pointer */

	net_io_t read;
	net_io_t write;
	strerror_t strerror;
	net_close_t close;
};

struct io_data io_data[2] = {
	/* CLIENT */
	{ "", 0, NULL, _def_read, _def_write, _def_strerror, _def_close },
	/* SERVER */
	{ "", 0, NULL, _def_read, _def_write, _def_strerror, _def_close }
};

void
net_set_io(int method, net_io_t read, net_io_t write,
	   net_close_t close, strerror_t strerror)
{
	io_data[method].read = read ? read : _def_read;
	io_data[method].write = write ? write : _def_write;
	io_data[method].close = close;
	io_data[method].strerror = strerror ? strerror : _def_strerror;
}

void
net_close(int method, void *sd)
{
	if (io_data[method].close) {
		io_data[method].close(sd);
		net_set_io(method, NULL, NULL, NULL, NULL);
	}
}



struct io_descr {
	void *stream;
	
	net_io_t read;
	net_io_t write;
	strerror_t strerror;
	net_close_t close;
};

void *
net_io_get(int method, void *stream)
{
	struct io_descr *s = malloc(sizeof *s);
	s->stream = stream;
	s->read = io_data[method].read;
	s->write = io_data[method].write;
	s->close = io_data[method].close;
	return s;
}

int
net_io_read(void *iod, char *buf, size_t size, size_t *nbytes)
{
	struct io_descr *s = iod;
	return s->read(s->stream, buf, size, nbytes);
}

int
net_io_write(void *iod, char *buf, size_t size, size_t *nbytes)
{
	struct io_descr *s = iod;
	return s->write(s->stream, buf, size, nbytes);
}

int
net_io_close(void *iod)
{
	struct io_descr *s = iod;
	int rc = s->close(s->stream);
	free(iod);
	return rc;
}

/**************
  Send a data
***************/

void
swrite(int method, void *sd, char *ptr)
{
	int rc;
	size_t nleft, nwritten = 0;

	if (ptr == 0)
		return;

	nleft = (unsigned long)strlen(ptr);
	while (nleft > 0) {
		rc = io_data[method].write(sd, ptr, nleft, &nwritten);
		if (rc) {
			socket_error(io_data[method].strerror(rc));
			return;
		}
		DPRINTF(method, 1, nwritten, ptr);
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
	struct io_data *ip = &io_data[method];
	if (ip->level <= 0) {
		int rc = ip->read(sd, ip->buf, LINEBUFFER, &ip->level);
		if (rc) {
			socket_error(ip->strerror(rc));
			return -1;
		}
		if (ip->level == 0)
			return 0;
		ip->read_ptr = ip->buf;
	}
	ip->level--;
	*ptr = *ip->read_ptr++;
	return 1;
}

int
recvline(int method, void *sd, void *vptr, int maxlen)
{
	int n, rc, addc = 0;
	char c, *ptr;

	ptr = vptr;
	for (n = 1; n < maxlen; n++) {
		if ((rc = mread(method, sd, &c)) == 1) {
			if (c == '\n' && n > 1 && ptr[-1] != '\r') {
				addc++;
				*ptr++ = '\r';
			}
			*ptr++ = c;
			if (c == '\n') 
				break;
		} else if (rc == 0) {
			if (n == 1)
				return 0;
			else
				break;
		} else
			return -1;
	}
	*ptr = 0;
	DPRINTF(method, 0, n + addc, (char *)vptr);
	return n;
}

#define INIT_RECVLINE_SIZE 81

int
recvline_ptr(int method, void *sd, char **vptr, size_t *maxlen)
{
	int rc;
	char c;
	size_t i;

#define ADDC(i,c) do {\
 if (i >= *maxlen) {\
   *maxlen *= 2;\
   *vptr = realloc(*vptr, *maxlen);\
   if (!*vptr) \
       anubis_error(HARD, _("Not enough memory"));\
 }\
 (*vptr)[i++] = c;\
} while (0)
		     
	if (!*vptr || *maxlen == 0) {
		*vptr = xmalloc(INIT_RECVLINE_SIZE);
		*maxlen = INIT_RECVLINE_SIZE;
	}
	for (i = 0;;) {
		if ((rc = mread(method, sd, &c)) == 1) {
			if (c == '\n' && i > 1 && (*vptr)[i-1] != '\r') 
				ADDC(i, '\r');
			ADDC(i, c);
			if (c == '\n') 
				break;
		} else if (rc == 0) {
			if (i == 1)
				return 0;
			else
				break;
		} else
			return -1;
	}
	(*vptr)[i] = 0;
	DPRINTF(method, 0, i, *vptr);
	return i;
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

