/*
   transmode.c

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

static unsigned long 
string_to_ipaddr (const char *str)
{
  unsigned long inaddr;
  struct sockaddr_in ad;

  memset (&ad, 0, sizeof (ad));
  inaddr = inet_addr (str);
  if (inaddr != INADDR_NONE)
    memcpy (&ad.sin_addr, &inaddr, sizeof (inaddr));
  else
    {
      struct hostent *hp = 0;
      hp = gethostbyname (str);
      if (hp == 0)
	hostname_error (str);
      else
	{
	  if (hp->h_length != 4 && hp->h_length != 8)
	    {
	      anubis_error (EXIT_FAILURE, 0,
			    _("Illegal address length received for host %s"),
			    str);
	    }
	  else
	    memcpy ((char *) &ad.sin_addr.s_addr, hp->h_addr, hp->h_length);
	}
    }

  return inaddr;
}

void
session_prologue ()
{
  ASSERT_MTA_CONFIG ();
  if (!(topt & T_LOCAL_MTA)
      && session.anubis 
      && string_to_ipaddr (session.mta) == string_to_ipaddr (session.anubis)
      && session.anubis_port == session.mta_port)
    anubis_error (EXIT_FAILURE, 0, _("remote-mta loops back to Anubis"));
  
  alarm (300);
  if (topt & T_LOCAL_MTA)
    {
      remote_server = make_local_connection (session.execpath,
					     session.execargs);
      if (!remote_server)
	{
	  service_unavailable (&remote_client);
	  return;
	}
    }
  else
    {
      remote_server = make_remote_connection (session.mta, session.mta_port);
      if (!remote_server)
	service_unavailable (&remote_client);
    }
  
  alarm (900);
}

int
anubis_transparent_mode (struct sockaddr_in *addr)
{
  int rs = 0;
  int cs = 0;

  rs = auth_ident (addr, &session.clientname);

  if ((topt & T_DROP_UNKNOWN_USER) && !rs)
    {
      service_unavailable (&remote_client);
      return 0;
    }

  parse_transmap (&cs,
		  rs ? session.clientname : 0,
		  inet_ntoa (addr->sin_addr),
		  &session.clientname);

  if (cs == 1)
    {
      anubis_changeowner (session.clientname);
    }
  else if (rs && cs == -1 && ntohl (addr->sin_addr.s_addr) == INADDR_LOOPBACK)
    {
      if (check_username (session.clientname))
	anubis_changeowner (session.clientname);
      else
	set_unprivileged_user ();
    }
  else
    set_unprivileged_user ();

  auth_tunnel ();

  session_prologue ();
  smtp_session_transparent ();
  alarm (0);

  net_close_stream (&remote_server);
  net_close_stream (&remote_client);

  info (NORMAL, _("Connection closed successfully."));

#ifdef HAVE_PAM
  if (pamh)
    {
      int pam_retval = pam_close_session (pamh, 0);
      if (pam_retval == PAM_SUCCESS)
	info (VERBOSE, _("PAM: Session closed."));
      if (pam_end (pamh, pam_retval) != PAM_SUCCESS)
	{
	  pamh = NULL;
	  info (NORMAL, _("PAM: failed to release authenticator."));
	  return EXIT_FAILURE;
	}
    }
#endif /* HAVE_PAM */
  return 0;
}

int
anubis_proxy_mode (struct sockaddr_in *addr)
{
  ASSERT_MTA_CONFIG ();

  set_unprivileged_user ();

  info (NORMAL, _("Initiated proxy mode."));
  session_prologue ();
  smtp_session_transparent ();
  alarm (0);

  net_close_stream (&remote_server);
  net_close_stream (&remote_client);

  info (NORMAL, _("Connection closed successfully."));
  return 0;
}

/* EOF */
