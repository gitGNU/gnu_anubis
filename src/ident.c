/*
   ident.c

   This file is part of GNU Anubis.
   Copyright (C) 2001-2014 The Anubis Team.

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

/***********************
 IDENT protocol support
************************/

#define USERNAME_C "USERID :"

/* If the reply matches sscanf expression
   
      "%*[^:]: USERID :%*[^:]:%s"

   and the length of "%s" part does not exceed size-1 bytes,
   copies this part to USERNAME and returns 0. Otherwise,
   returns 1 */

static int
ident_extract_username (char *reply, char **pusername)
{
  char *p;

  p = strchr (reply, ':');
  if (!p)
    return 1;
  if (p[1] != ' ' || strncmp (p + 2, USERNAME_C, sizeof (USERNAME_C) - 1))
    return 1;
  p += 2 + sizeof (USERNAME_C) - 1;
  p = strchr (p, ':');
  if (!p)
    return 1;
  do
    p++;
  while (*p == ' ');
  assign_string (pusername, p);
  return 0;
}

/* If the reply matches sscanf expression

      "%*[^ ] %*[^ ] %*[^ ] %*[^ ] %*[^ ] %s"

   and the length of "%s" part does not exceed size-1 bytes,
   copies this part to USERNAME and returns 0. Otherwise,
   returns 1 */

static int
crypt_extract_username (char *reply, char **pusername)
{
  int i;
  char *p = reply;
#define skip_word(c) while (*c && (*c) != ' ') c++

  /* Skip five words */
  for (i = 0; i < 5; i++)
    {
      skip_word (p);
      if (!*p++)
	return 1;
    }

  assign_string (pusername, p);
  return 0;
}

int
auth_ident (struct sockaddr_in *addr, char **user)
{
  struct servent *sp;
  struct sockaddr_in ident;
  char *buf = NULL;
  char inetd_buf[LINEBUFFER];
  size_t size = 0;
  int sd = 0;
  int rc;
  NET_STREAM str;
  size_t nbytes;

  if ((sd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      anubis_error (0, errno, _("IDENT: socket() failed"));
      return 0;
    }
  memcpy (&ident, addr, sizeof (ident));
  sp = getservbyname ("auth", "tcp");
  if (sp)
    ident.sin_port = sp->s_port;
  else
    ident.sin_port = htons (113);	/* default IDENT port number */

  if (connect (sd, (struct sockaddr *) &ident, sizeof (ident)) < 0)
    {
      anubis_error (0, errno, _("IDENT: connect() failed"));
      close_socket (sd);
      return 0;
    }
  net_create_stream (&str, sd);

  info (VERBOSE, _("IDENT: connected to %s:%u"),
	inet_ntoa (ident.sin_addr), ntohs (ident.sin_port));

  snprintf (inetd_buf, sizeof inetd_buf,
	    "%u , %u" CRLF, ntohs (addr->sin_port), session.anubis_port);

  if ((rc = stream_write (str, inetd_buf, strlen (inetd_buf), &nbytes)))
    {
      anubis_error (0, 0,
		    _("IDENT: stream_write() failed: %s."),
		    stream_strerror (str, rc));
      net_close_stream (&str);
      return 0;
    }
  if (recvline (CLIENT, str, &buf, &size) == 0)
    {
      anubis_error (0, 0,
		    _("IDENT: recvline() failed: %s."),
		    stream_strerror (str, rc));
      net_close_stream (&str);
      return 0;
    }
  net_close_stream (&str);

  remcrlf (buf);
  if (ident_extract_username (buf, user))
    {
      info (VERBOSE, _("IDENT: incorrect data."));
      free (buf);
      return 0;
    }
  free (buf);

  /******************************
   IDENTD DES decryption support
  *******************************/

  if (strstr (*user, "[") && strstr (*user, "]"))
    {
      int rs = 0;
      info (VERBOSE, _("IDENT: data probably encrypted with DES..."));
      external_program (&rs, IDECRYPT_PATH, *user, buf, LINEBUFFER);
      if (rs == -1)
	return 0;

      remcrlf (buf);
      if (crypt_extract_username (buf, user))
	{
	  info (VERBOSE, _("IDENT: incorrect data (DES deciphered)."));
	  return 0;
	}
      else
	{			/* UID deciphered */
	  if (ntohl (ident.sin_addr.s_addr) == INADDR_LOOPBACK)
	    {
	      struct passwd *pwd;
	      int uid = atoi (*user);
	      pwd = getpwuid (uid);
	      if (pwd != 0)
		assign_string (user, pwd->pw_name);
	      else
		return 0;
	    }
	}
    }

  info (VERBOSE, _("IDENT: resolved remote user to %s."), *user);
  return 1;			/* success */
}

/* EOF */
