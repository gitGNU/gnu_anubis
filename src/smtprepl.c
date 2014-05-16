/* This file is part of GNU Anubis.
   Copyright (C) 2009-2014 The Anubis Team.

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

struct smtp_reply_line
{
  size_t off;
  size_t len;
};

struct smtp_reply
{
  char *buffer;
  size_t buffer_size;
  size_t reply_length;
  size_t line_count;
  size_t line_size;
  struct smtp_reply_line *line_vec;
  struct
  {
    size_t line;
    char c;
  } cursor;
};

ANUBIS_SMTP_REPLY 
smtp_reply_new ()
{
  ANUBIS_SMTP_REPLY p = xzalloc (sizeof (*p));
  p->cursor.line = -1;
  return p;
}

void
smtp_reply_free (ANUBIS_SMTP_REPLY reply)
{
  if (reply)
    {
      free (reply->buffer);
      free (reply->line_vec);
      free (reply);
    }
}

static void
smtp_reply_alloc_space (ANUBIS_SMTP_REPLY reply, size_t len)
{
  if (reply->buffer_size == 0)
    {
      reply->buffer_size = len + 1;
      reply->buffer = xmalloc (reply->buffer_size);
    }
  else
    while (reply->reply_length + len + 1 >= reply->buffer_size)
      reply->buffer = x2realloc (reply->buffer, &reply->buffer_size);
}

static void
smtp_reply_alloc_line_space (ANUBIS_SMTP_REPLY reply, size_t lc)
{
  if (lc > reply->line_size)
    {
      if (reply->line_size)
	reply->line_size = lc;
      reply->line_vec = x2nrealloc (reply->line_vec, &reply->line_size,
				    sizeof (reply->line_vec[0]));
    }
}  

static void
smtp_reply_scan (ANUBIS_SMTP_REPLY reply, size_t lc)
{
  char *line;
  size_t off;

  if (lc)
    smtp_reply_alloc_line_space (reply, lc);

  line = reply->buffer;
  lc = 0;
  off = 0;
  while (*line)
    {
      size_t len = strcspn (line, "\r\n");
      
      smtp_reply_alloc_line_space (reply, lc + 1);
      reply->line_vec[lc].off = off;
      reply->line_vec[lc].len = len;
      lc++;
      if (line[++len] == '\n')
	len++;
      line += len;
      off += len;
    }
  reply->line_count = lc;
}

void
smtp_reply_read (ANUBIS_SMTP_REPLY reply,
		 ssize_t (*reader) (void *, char **, size_t *),
		 void *rdata)
{
  char *line = NULL;
  size_t size = 0;
  size_t lc = 0;
  
  reply->reply_length = 0;
  do
    {
      size_t len;

      if (reader (rdata, &line, &size) <= 0)
	break;

      len = strlen (line);
      
      smtp_reply_alloc_space (reply, len);

      memcpy (reply->buffer + reply->reply_length, line, len);
      reply->reply_length += len;
      lc++;
    }
  while (line[3] == '-');
  free (line);

  if (reply->reply_length)
    {
      reply->buffer[reply->reply_length] = 0;
      smtp_reply_scan (reply, lc);
    }
}

void
smtp_reply_set (ANUBIS_SMTP_REPLY reply, const char *input)
{
  size_t len = strlen (input);
  
  if (len > 2 && memcmp (input + len - 2, CRLF, 2) == 0)
    len -= 2;
      
  smtp_reply_alloc_space (reply, len + 3);
  memcpy (reply->buffer, input, len);
  memcpy (reply->buffer + len, CRLF, 2);
  reply->reply_length = len + 2;
  reply->buffer[reply->reply_length] = 0;
  smtp_reply_scan (reply, 0);
}
  
#define __smtp_reply_line_ptr(r,i) ((r)->buffer + (r)->line_vec[i].off)
#define __smtp_reply_line_end(r,i) \
  ((r)->buffer + (r)->line_vec[i].off + (r)->line_vec[i].len)

size_t
smtp_reply_line_count (ANUBIS_SMTP_REPLY reply)
{
  return reply->line_count;
}

const char *
smtp_reply_line_ptr (ANUBIS_SMTP_REPLY reply, size_t index)
{
  if (index < reply->line_count)
    return __smtp_reply_line_ptr (reply, index);
  return NULL;
}

const char *
smtp_reply_line_end (ANUBIS_SMTP_REPLY reply, size_t index)
{
  if (index < reply->line_count)
    return __smtp_reply_line_end (reply, index);
  return NULL;
}

void
smtp_reply_clear_cursor (ANUBIS_SMTP_REPLY reply)
{
  if (reply->cursor.line >= 0 && reply->cursor.line < reply->line_count)
    {
      *(char*)smtp_reply_line_end (reply, reply->cursor.line) = reply->cursor.c;
      reply->cursor.line = -1;
    }
}
    
char const *
smtp_reply_line (ANUBIS_SMTP_REPLY reply, size_t index)
{
  smtp_reply_clear_cursor (reply);
  if (index < reply->line_count)
    {
      char *ptr = __smtp_reply_line_end (reply, index);
      reply->cursor.c = *ptr;
      reply->cursor.line = index;
      *ptr = 0;
      return __smtp_reply_line_ptr (reply, index);
    }
  return NULL;
}

int
smtp_reply_get_line (ANUBIS_SMTP_REPLY reply, size_t index,
		     char **pstr, size_t *psize)
{
  if (index < reply->line_count)
    {
      size_t len = reply->line_vec[index].len;
      char *p = xmalloc (len + 1);
      memcpy (p, __smtp_reply_line_ptr (reply, index), len);
      p[len] = 0;
      *pstr = p;
      if (psize)
	*psize = len;
      return 0;
    }
  return 1;
}

int
smtp_reply_code_eq (ANUBIS_SMTP_REPLY reply, const char *code)
{
  if (reply->line_count > 0)
    {
      size_t len = strlen (code);
      if (len > 3)
	len = 3;
      return strncmp (reply->buffer, code, len) == 0;
    }
  return 0;
}

int
smtp_reply_has_capa (ANUBIS_SMTP_REPLY reply, const char *capa, size_t *pind)
{
  size_t i;
  size_t capa_len = strlen (capa);
  
  for (i = 0; i < reply->line_count; i++)
    {
      char const *p = smtp_reply_line (reply, i) + 4;
      size_t len = strcspn (p, " ");
      
      if (len == capa_len
	  && memcmp (smtp_reply_line (reply, i) + 4, capa, len) == 0)
	{
	  if (pind)
	    *pind = i;
	  return 1;
	}
    }
  return 0;
}

int
smtp_reply_has_string (ANUBIS_SMTP_REPLY reply, size_t index,
		       const char *key, size_t *pind)
{
  if (index < reply->line_count)
    if (strstr (smtp_reply_line (reply, index) + 4, key) != NULL)
      {
	if (pind)
	  *pind = index;
	return 1;
      }
  return 0;
}

char const *
smtp_reply_string (ANUBIS_SMTP_REPLY reply)
{
  smtp_reply_clear_cursor (reply);
  return reply->buffer;
}

void
smtp_reply_replace_line (ANUBIS_SMTP_REPLY reply, size_t index,
			 const char *str)
{
  size_t new_len = strlen (str);
  size_t old_len = reply->line_vec[index].len;
  ssize_t delta = 4 + new_len - old_len;
  char *p;

  smtp_reply_clear_cursor (reply);

  if (delta > 0)
    smtp_reply_alloc_space (reply, delta);
  if (index != reply->line_count - 1)
    {
      size_t i;
      
      memmove (reply->buffer + reply->line_vec[index+1].off + delta,
	       reply->buffer + reply->line_vec[index+1].off,
	       reply->reply_length - reply->line_vec[index+1].off + 1);
      for (i = index + 1; i < reply->line_count; i++)
	reply->line_vec[i].off += delta;
    }
  reply->reply_length += delta;

  p = __smtp_reply_line_ptr (reply, index);
  memcpy (p, reply->buffer, 3);
  p[3] = (index != reply->line_count - 1) ? '-' : ' ';
  memcpy (p + 4, str, new_len);
  reply->line_vec[index].len = 4 + new_len;
  memcpy (__smtp_reply_line_end (reply, index), CRLF, 3);
}

void
smtp_reply_add_line (ANUBIS_SMTP_REPLY reply, const char *str)
{
  size_t new_len = strlen (str);
  struct smtp_reply_line *lp;
  char *p;

  smtp_reply_clear_cursor (reply);
  
  p = __smtp_reply_line_ptr (reply, reply->line_count - 1);
  p[3] = '-';
  
  smtp_reply_alloc_space (reply, new_len + 7);
  reply->line_count++; 
  smtp_reply_alloc_line_space (reply, reply->line_count);
  lp = reply->line_vec + reply->line_count - 1;
  lp->off = reply->reply_length;
  lp->len = 4 + new_len;
  p = reply->buffer + lp->off;
  memcpy (p, reply->buffer, 3);
  p[3] = ' ';
  memcpy (p + 4, str, new_len);
  memcpy (p + 4 + new_len, CRLF, 2);
  p[4 + new_len + 2] = 0;
  reply->reply_length += new_len + 6;
}

void
smtp_reply_remove_line (ANUBIS_SMTP_REPLY reply, size_t index)
{
  size_t len;

  smtp_reply_clear_cursor (reply);

  len = reply->line_vec[index].len + 2;
  if (index == reply->line_count - 1)
    {
      __smtp_reply_line_ptr (reply, index)[0] = 0;
      if (index > 0)
	__smtp_reply_line_ptr (reply, index - 1)[3] = ' ';
    }
  else
    {
      memmove (__smtp_reply_line_ptr (reply, index),
	       __smtp_reply_line_ptr (reply, index + 1),
	       reply->reply_length - reply->line_vec[index+1].off + 1);
      memmove (reply->line_vec + index,
	       reply->line_vec + index + 1,
	       (reply->line_count - index - 1) * sizeof reply->line_vec[0]);
      for (; index < reply->line_count; index++)
	reply->line_vec[index].off -= len;
    }
  reply->reply_length -= len;
  reply->line_count--;
}


