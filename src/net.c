/*
   net.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003, 2004, 2005 The Anubis Team.

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

static int connect_directly_to (char *, unsigned int);

static struct _debug_cache
{
  int method;
  int output;
  int newline;
  size_t count;
}
debug_cache =
{
-1, -1, 0, 0};

static void
_debug_printer (int method, int output, unsigned long nleft, char *ptr)
{
  int i;
  char *mode = "?";

  switch (method)
    {
    case CLIENT:
      mode = _("SERVER");
      break;
    case SERVER:
      mode = _("CLIENT");
    }

  if (debug_cache.newline
      || method != debug_cache.method || output != debug_cache.output)
    {
      if (!debug_cache.newline && debug_cache.count)
	fprintf (stderr, "(%lu)\n", (unsigned long) debug_cache.count);
      debug_cache.method = method;
      debug_cache.output = output;
      debug_cache.newline = 0;
      debug_cache.count = 0;
      fprintf (stderr, "%s %s ", mode, output ? "<<<" : ">>>");
    }

  for (i = 0; i < nleft; i++, ptr++)
    {
      debug_cache.count++;
      debug_cache.newline = 0;
      if (*ptr == '\r')
	continue;
      if (*ptr == '\n')
	{
	  fprintf (stderr, "(%ld)\n", (unsigned long) debug_cache.count);
	  debug_cache.count = 0;
	  if (i != nleft - 1)
	    {
	      fprintf (stderr, "%s %s ", mode, output ? "<<<" : ">>>");
	      debug_cache.newline = 0;
	    }
	  else
	    debug_cache.newline = 1;
	}
      else
	fputc (*ptr, stderr);
    }
}

#define DPRINTF(method, output, nleft, ptr) do {\
  if (options.termlevel == DEBUG) \
     _debug_printer(method, output, nleft, ptr);\
  } while (0)

NET_STREAM
make_remote_connection (char *host, unsigned int port)
{
  int sd;
  NET_STREAM str;

#ifdef USE_SOCKS_PROXY
  if (topt & T_SOCKS)
    {				/* SOCKS proxy */
      host = session.socks;
      port = session.socks_port;
    }
#endif /* USE_SOCKS_PROXY */

  if ((sd = connect_directly_to (host, port)) == -1)
    return NULL;

  net_create_stream (&str, sd);
  return str;
}

static int
connect_directly_to (char *host, unsigned int port)
{
  int sd = 0;
  unsigned long inaddr;
  struct sockaddr_in addr;

  /*
     Find out the IP address.
   */

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);
  info (VERBOSE, _("Getting remote host information..."));

  inaddr = inet_addr (host);
  if (inaddr != INADDR_NONE)
    memcpy (&addr.sin_addr, &inaddr, sizeof (inaddr));
  else
    {
      struct hostent *hp = 0;
      hp = gethostbyname (host);
      if (hp == 0)
	{
	  hostname_error (host);
	  return -1;
	}
      else
	{
	  if (hp->h_length != 4 && hp->h_length != 8)
	    {
	      anubis_error (EXIT_FAILURE, 0,
			    _("Illegal address length received for host %s"),
			    host);
	      return -1;
	    }
	  else
	    {
	      memcpy ((char *) &addr.sin_addr.s_addr, hp->h_addr,
		      hp->h_length);
	    }
	}
    }

  /*
     Create socket, and connect.
   */

  if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      anubis_error (EXIT_FAILURE, errno, _("Cannot create stream socket."));
      return -1;
    }
  if (connect (sd, (struct sockaddr *) &addr, sizeof (addr)) == -1)
    {
      anubis_error (EXIT_FAILURE, errno, _("Couldn't connect to %s:%u. %s."),
		    host, port);
      return -1;
    }
  else
    info (NORMAL, _("Connected to %s:%u"), host, port);

  return sd;
}

/*****************
 Bind and listen.
******************/

int
bind_and_listen (char *host, unsigned int port)
{
  int sd = 0;
  unsigned long inaddr;
  struct sockaddr_in addr;
  int true = 1;

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);

  if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    anubis_error (EXIT_FAILURE, errno, _("Cannot create stream socket"));

  if (topt & T_NAMES)
    {
      inaddr = inet_addr (host);
      if (inaddr != INADDR_NONE)
	memcpy (&addr.sin_addr, &inaddr, sizeof (inaddr));
      else
	{
	  struct hostent *hp = 0;
	  hp = gethostbyname (host);
	  if (hp == 0)
	    hostname_error (host);
	  else
	    {
	      if (hp->h_length != 4 && hp->h_length != 8)
		anubis_error (EXIT_FAILURE, 0,
			      _("Illegal address length received for host %s"),
			      host);
	      else
		{
		  memcpy ((char *) &addr.sin_addr.s_addr, hp->h_addr,
			  hp->h_length);
		}
	    }
	}
    }
  else
    addr.sin_addr.s_addr = htonl (INADDR_ANY);

  setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof (true));

  if (bind (sd, (struct sockaddr *) &addr, sizeof (addr)))
    anubis_error (EXIT_FAILURE, errno, _("bind() failed"));
  info (VERBOSE, _("GNU Anubis bound to %s:%u"), inet_ntoa (addr.sin_addr),
	ntohs (addr.sin_port));
  if (listen (sd, 5))
    anubis_error (EXIT_FAILURE, errno, _("listen() failed"));
  return sd;
}

/**************
  Send a data
***************/

void
swrite (int method, NET_STREAM sd, char *ptr)
{
  int rc;
  size_t nleft, nwritten = 0;

  if (ptr == NULL || (nleft = strlen (ptr)) == 0)
    return;
  
  rc = stream_write (sd, ptr, nleft, &nwritten);
  if (rc)
    socket_error (stream_strerror (sd, rc));
  DPRINTF (method, 1, nwritten, ptr);
  if (nwritten != nleft)
    {
      /* Should not happen */
      anubis_error (EXIT_FAILURE, 0, _("Short write"));
    }
}

void
send_eol (int method, NET_STREAM sd)
{
  swrite (method, sd, (anubis_mode == anubis_mda) ? "\n" : CRLF);
}

/**************
  Read data
***************/

#define INIT_RECVLINE_SIZE 81

int
recvline (int method, NET_STREAM sd, char **vptr, size_t * maxlen)
{
  int rc;
  size_t off = 0;

  *vptr = NULL;
  *maxlen = 0;
  while (1)
    {
      size_t nbytes;

      if (*maxlen - off <= 1)
	{
	  *maxlen += INIT_RECVLINE_SIZE;
	  *vptr = xrealloc (*vptr, *maxlen);
	}
      rc = stream_readline (sd, *vptr + off, *maxlen - off, &nbytes);
      if (rc)
        socket_error (stream_strerror (sd, rc));
      if (nbytes == 0)
	break;
      off += nbytes;
      if ((*vptr)[off - 1] == '\n')
	break;
    }
  (*vptr)[off] = 0;
  DPRINTF (method, 0, off, *vptr);
  return off;
}

/*****************
  Get a response
******************/

void
get_response_smtp (int method, NET_STREAM sd, char **pbuf, size_t *psize)
{
  char *line = NULL;
  size_t size = 0;
  char *buf = NULL;
  
  do
    {
      if (recvline (method, sd, &line, &size) == 0)
	break;

      if (!buf)
	assign_string (&buf, line);
      else
	{
	  buf = xrealloc (buf, strlen (buf) + strlen (line) + 1);
	  strcat (buf, line);
	}
    }
  while (line[3] == '-');

  if (buf)
    {
      *pbuf = buf;
      *psize = strlen (buf) + 1;
    }
  else
    {
      assign_string (&buf, "");
      *psize = 0;
    }
}

/**************************
 Close a socket descriptor
***************************/
void
close_socket (int sd)
{
  if (sd)
    close (sd);
  return;
}

void
net_close_stream (NET_STREAM *sd)
{
  stream_close (*sd);
  stream_destroy (sd);
  return;
}


void
net_create_stream (NET_STREAM * str, int fd)
{
  stream_create (str);
  stream_set_io (*str, (void *) fd, NULL, NULL, NULL, NULL, NULL);
}


/* EOF */
