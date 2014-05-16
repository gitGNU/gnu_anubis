/*
   gsasl.c

   This file is part of GNU Anubis.
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

#include "headers.h"
#include "extern.h"

#if defined(WITH_GSASL)

#include "lbuf.h"


/* Basic I/O Functions */

struct anubis_gsasl_stream
{
  Gsasl_session *sess_ctx; /* Context */
  struct _line_buffer *lb;
  NET_STREAM stream;
};

static const char *
_gsasl_strerror (void *ignored_data, int rc)
{
  return gsasl_strerror (rc);
}

int
write_chunk (void *data, char *start, char *end)
{
  struct anubis_gsasl_stream *s = data;
  size_t chunk_size = end - start + 1;
  size_t len;
  size_t wrsize;
  char *buf = NULL;

  len = 0;
  gsasl_encode (s->sess_ctx, start, chunk_size, &buf, &len);

  wrsize = 0;
  do
    {
      size_t sz;
      int rc = stream_write (s->stream, buf + wrsize, len - wrsize,
			     &sz);
      if (rc)
	{
	  if (rc == EINTR)
	    continue;
	  free (buf);
	  return rc;
	}
      wrsize += sz;
    }
  while (wrsize < len);

  free (buf);

  return 0;
}


static int
_gsasl_write (void *sd, const char *data, size_t size, size_t * nbytes)
{
  struct anubis_gsasl_stream *s = sd;
  int rc = _auth_lb_grow (s->lb, data, size);
  if (rc)
    return rc;

  return _auth_lb_writelines (s->lb, data, size, write_chunk, s, nbytes);
}

static int
_gsasl_read (void *sd, char *data, size_t size, size_t * nbytes)
{
  struct anubis_gsasl_stream *s = sd;
  int rc;
  char *bufp = NULL;
  size_t len = 0;

  do
    {
      char buf[80];
      size_t sz;

      rc = stream_read (s->stream, buf, sizeof (buf), &sz);
      if (rc)
	{
	  if (rc == EINTR)
	    continue;
	  return rc;
	}

      rc = _auth_lb_grow (s->lb, buf, sz);
      if (rc)
	return rc;

      rc = gsasl_decode (s->sess_ctx,
			 _auth_lb_data (s->lb),
			 _auth_lb_level (s->lb), &bufp, &len);
    }
  while (rc == GSASL_NEEDS_MORE);

  if (rc != GSASL_OK)
    return rc;

  if (len > size)
    {
      memcpy (data, bufp, size);
      _auth_lb_drop (s->lb);
      _auth_lb_grow (s->lb, bufp + size, len - size);
      len = size;
    }
  else
    {
      _auth_lb_drop (s->lb);
      memcpy (data, bufp, len);
    }
  if (nbytes)
    *nbytes = len;

  free (bufp);
  return 0;
}

static int
_gsasl_close (void *sd)
{
  struct anubis_gsasl_stream *s = sd;

  stream_close (s->stream);
  return 0;
}

static int
_gsasl_destroy (void *sd)
{
  struct anubis_gsasl_stream *s = sd;
  if (s->sess_ctx)
    gsasl_finish (s->sess_ctx);
  _auth_lb_destroy (&s->lb);
  free (sd);
  return 0;
}

void
install_gsasl_stream (Gsasl_session *sess_ctx, NET_STREAM *stream)
{
  struct anubis_gsasl_stream *s = xmalloc (sizeof *s);

  s->sess_ctx = sess_ctx;
  _auth_lb_create (&s->lb);
  s->stream = *stream;

  stream_create (stream);
  stream_set_io (*stream, s,
		 _gsasl_read, _gsasl_write,
		 _gsasl_close, _gsasl_destroy, _gsasl_strerror);
}

#endif
