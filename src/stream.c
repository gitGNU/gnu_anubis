/*
   stream.c

   This file is part of GNU Anubis.
   Copyright (C) 2004-2014 The Anubis Team.

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

enum stream_state
  {
    state_open,
    state_closed
  };

struct net_stream
{
  enum stream_state state;
  stream_read_t read;
  stream_write_t write;
  stream_strerror_t strerror;
  stream_close_t close;
  stream_destroy_t destroy;

  char buf[LINEBUFFER + 1];	/* Input buffer */
  size_t level;			/* Buffer fill level */
  char *read_ptr;		/* Current buffer pointer */

  void *data;
};


static const char *
_def_strerror (void *data, int rc)
{
  return strerror (rc);
}

static int
_def_write (void *sd, const char *data, size_t size, size_t * nbytes)
{
  int rc = send ((int) sd, data, size, 0);
  if (rc >= 0)
    {
      *nbytes = rc;
      return 0;
    }
  return errno;
}

static int
_def_read (void *sd, char *data, size_t size, size_t * nbytes)
{
  int rc = recv ((int) sd, data, size, 0);
  if (rc >= 0)
    {
      *nbytes = rc;
      return 0;
    }
  return errno;
}

static int
_def_close (void *sd)
{
  close ((int) sd);
  return 0;
}

void
stream_create (struct net_stream **str)
{
  *str = xzalloc (sizeof **str);
}

int
stream_set_io (struct net_stream *str,
	       void *data,
	       stream_read_t read, stream_write_t write,
	       stream_close_t close, stream_destroy_t destroy,
	       stream_strerror_t strerror)
{
  if (!str)
    return EINVAL;
  str->state = state_open;
  str->data = data;
  str->read = read ? read : _def_read;
  str->write = write ? write : _def_write;
  str->close = close ? close : _def_close;
  str->destroy = destroy;
  str->strerror = strerror ? strerror : _def_strerror;
  return 0;
}

int
stream_set_read (struct net_stream *str, stream_read_t read)
{
  if (!str)
    return EINVAL;
  str->read = read ? read : _def_read;
  return 0;
}

int
stream_set_write (struct net_stream *str, stream_write_t write)
{
  if (!str)
    return EINVAL;
  str->write = write ? write : _def_write;
  return 0;
}

int
stream_set_strerror (struct net_stream *str, stream_strerror_t strerr)
{
  if (!str)
    return EINVAL;
  str->strerror = strerr ? strerr : _def_strerror;
  return 0;
}

int
stream_close (struct net_stream *str)
{
  if (!str)
    return EINVAL;
  if (str->state != state_open)
    return 0;
  str->state = state_closed;
  return str->close (str->data);
}

int
stream_destroy (struct net_stream **str)
{
  if (!str || !*str)
    return EINVAL;
  if ((*str)->destroy)
    (*str)->destroy ((*str)->data);
  xfree (*str);
  return 0;
}

const char *
stream_strerror (struct net_stream *str, int errcode)
{
  if (!str)
    return strerror (EINVAL);
  return str->strerror (str->data, errcode);
}

int
stream_read (struct net_stream *str, char *buf, size_t size, size_t * nbytes)
{
  if (!str)
    return EINVAL;
  return str->read (str->data, buf, size, nbytes);
}

int
stream_write (struct net_stream *str, const char *buf, size_t size,
	      size_t *nbytes)
{
  if (!str)
    return EINVAL;
  return str->write (str->data, buf, size, nbytes);
}

static int
read_char (struct net_stream *str, char *ptr, size_t * pcount)
{
  if (str->level <= 0)
    {
      int rc = str->read (str->data, str->buf, sizeof str->buf,
			  &str->level);
      if (rc)
	return rc;

      if (str->level == 0)
	{
	  *pcount = 0;
	  return 0;
	}
      str->read_ptr = str->buf;
    }
  str->level--;
  *ptr = *str->read_ptr++;
  *pcount = 1;
  return 0;
}

int
stream_readline (struct net_stream *str, char *buf, size_t size,
		 size_t *nbytes)
{
  int rc = 0;
  size_t n;
  char c, *ptr;

  if (!str)
    return EINVAL;

  ptr = buf;
  for (n = 1; n < size; n++)
    {
      size_t count;

      rc = read_char (str, &c, &count);
      if (rc)
	break;
      
      if (count == 1)
	{
	  *ptr++ = c;
	  if (c == '\n')
	    break;
	}
      else			/* if (count == 0) */
	break;
    }
  *ptr = 0;
  *nbytes = ptr - buf;
  return rc;
}

#define INIT_GETLINE_SIZE 128

int
stream_getline (NET_STREAM sd, char **vptr, size_t *maxlen, size_t *nread)
{
  int rc;
  size_t off = 0;

  while (1)
    {
      size_t nbytes;

      if (*maxlen - off <= 1)
	{
	  *maxlen += INIT_GETLINE_SIZE;
	  *vptr = xrealloc (*vptr, *maxlen);
	}
      rc = stream_readline (sd, *vptr + off, *maxlen - off, &nbytes);
      if (rc)
        return rc;
      if (nbytes == 0)
	break;
      off += nbytes;
      if ((*vptr)[off - 1] == '\n')
	break;
    }
  (*vptr)[off] = 0;
  if (nread)
    *nread = off;
  return 0;
}

