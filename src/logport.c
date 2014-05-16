/*
   Log and info output ports for Guile.

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
#include "rcfile.h"

#ifdef WITH_GUILE

#ifndef HAVE_SCM_T_OFF
typedef off_t scm_t_off;
#endif

static scm_t_bits scm_tc16_anubis_error_port;
static scm_t_bits scm_tc16_anubis_info_port;

typedef void (*log_flush_fn) (int flag, char *, size_t);

struct _anubis_error_port {
  int flag; /* For error ports: -1 if error, >=0 if warning;
	       For info ports: verbosity level */
  log_flush_fn flush;
};

#define ANUBIS_ERROR_PORT_BUFSIZE 256

static void
log_flush (int flag, char *str, size_t size)
{
  if (flag == -1)
    anubis_error (0, 0, "%*.*s", size, size, str);
  else
    anubis_warning (0, "%*.*s", size, size, str);
}

static void
info_flush (int flag, char *str, size_t size)
{
  info (flag, "%*.*s", size, size, str);
}

SCM
_make_anubis_log_port (long type, const char *descr, int flag,
		       log_flush_fn flush)
{
  struct _anubis_error_port *dp;
  SCM port;
  scm_port *pt;

  dp = scm_gc_malloc (sizeof (struct _anubis_error_port), descr);
  dp->flag = flag;
  dp->flush = flush;

  port = scm_new_port_table_entry (type);
  pt = SCM_PTAB_ENTRY(port);
  pt->rw_random = 0;
  pt->write_buf = scm_gc_malloc (ANUBIS_ERROR_PORT_BUFSIZE, "port buffer");
  pt->write_pos = pt->write_buf;
  pt->write_buf_size = ANUBIS_ERROR_PORT_BUFSIZE;
  pt->write_end = pt->write_buf + pt->write_buf_size;
  
  SCM_SET_CELL_TYPE (port, (type | SCM_OPN | SCM_WRTNG | SCM_BUFLINE));
  SCM_SETSTREAM (port, dp);
  return port;
}

SCM
guile_make_anubis_error_port (int err)
{
  return _make_anubis_log_port (scm_tc16_anubis_error_port,
				"anubis-error-port", err, log_flush);
}

SCM
guile_make_anubis_info_port (void)
{
  return _make_anubis_log_port (scm_tc16_anubis_info_port,
				"anubis-info-port", 0, info_flush);
}

#define ANUBIS_ERROR_PORT(x) ((struct _anubis_error_port *) SCM_STREAM (x))

static SCM
_anubis_error_port_mark (SCM port)
{
    return SCM_BOOL_F;
}

static void
_anubis_error_port_flush (SCM port)
{
  struct _anubis_error_port *dp = ANUBIS_ERROR_PORT (port);
  scm_port *pt = SCM_PTAB_ENTRY (port);
  size_t size = pt->write_pos - pt->write_buf;
  unsigned char *nl = memchr (pt->write_buf, '\n', size);
  int wrsize;

  if (!nl)
    return;
  
  wrsize = nl - pt->write_buf;

  dp->flush (dp->flag, (char *) pt->write_buf, wrsize);
  
  if (wrsize < size)
    {
      size_t write_start;

      nl++;
      write_start = pt->write_pos - nl;
      memmove (pt->write_buf, nl, write_start);
      pt->write_pos = pt->write_buf + write_start;
    }
  else
    pt->write_pos = pt->write_buf;
}

static int
_anubis_error_port_close (SCM port)
{
  struct _anubis_error_port *dp = ANUBIS_ERROR_PORT (port);

  if (dp)
    {
      _anubis_error_port_flush (port);
      SCM_SETSTREAM (port, NULL);
      scm_gc_free (dp, sizeof(struct _anubis_error_port),
		   "anubis-error-port");
    }
  return 0;
}

static scm_sizet
_anubis_error_port_free (SCM port)
{
  _anubis_error_port_close (port);
  return 0;
}

static int
_anubis_error_port_fill_input (SCM port)
{
  return EOF;
}

static void
_anubis_error_port_write (SCM port, const void *data, size_t size)
{
  scm_port *pt = SCM_PTAB_ENTRY (port);
  size_t space = pt->write_end - pt->write_pos;
  if (space < size)
    {
      size_t start = pt->write_pos - pt->write_buf;
      size_t new_size = pt->write_buf_size;
      
      do
	{
	  /*FIXME*/
	  new_size *= 2;
	}
      while (new_size - start < size);
      
      pt->write_buf = scm_gc_realloc (pt->write_buf,
				      pt->write_buf_size,
				      new_size, "write buffer");
      pt->write_buf_size = new_size;
      pt->write_end = pt->write_buf + pt->write_buf_size;
      pt->write_pos = pt->write_buf + start;
    }
  memcpy (pt->write_pos, data, size);
  pt->write_pos += size;

  if (memchr (data, '\n', size))
    _anubis_error_port_flush (port);
}

static scm_t_off
_anubis_error_port_seek (SCM port, scm_t_off offset, int whence)
{
  return -1;
}

static int
_anubis_error_port_print (SCM exp, SCM port, scm_print_state *pstate)
{
  scm_puts ("#<Anubis error port>", port);
  return 1;
}

static int
_anubis_info_port_print (SCM exp, SCM port, scm_print_state *pstate)
{
  scm_puts ("#<Anubis info port>", port);
  return 1;
}

void
guile_init_anubis_error_port ()
{
  scm_tc16_anubis_error_port =
    scm_make_port_type ("anubis-error-port",
			_anubis_error_port_fill_input,
			_anubis_error_port_write);
  scm_set_port_mark (scm_tc16_anubis_error_port, _anubis_error_port_mark);
  scm_set_port_free (scm_tc16_anubis_error_port, _anubis_error_port_free);
  scm_set_port_print (scm_tc16_anubis_error_port, _anubis_error_port_print);
  scm_set_port_flush (scm_tc16_anubis_error_port, _anubis_error_port_flush);
  scm_set_port_close (scm_tc16_anubis_error_port, _anubis_error_port_close);
  scm_set_port_seek (scm_tc16_anubis_error_port, _anubis_error_port_seek);
}    

void
guile_init_anubis_info_port ()
{
  scm_tc16_anubis_info_port =
    scm_make_port_type ("anubis-info-port",
			_anubis_error_port_fill_input,
			_anubis_error_port_write);
  scm_set_port_mark (scm_tc16_anubis_info_port, _anubis_error_port_mark);
  scm_set_port_free (scm_tc16_anubis_info_port, _anubis_error_port_free);
  scm_set_port_print (scm_tc16_anubis_info_port, _anubis_info_port_print);
  scm_set_port_flush (scm_tc16_anubis_info_port, _anubis_error_port_flush);
  scm_set_port_close (scm_tc16_anubis_info_port, _anubis_error_port_close);
  scm_set_port_seek (scm_tc16_anubis_info_port, _anubis_error_port_seek);
}    
#endif
