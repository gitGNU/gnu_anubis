/*
   transmode.c

   This file is part of GNU Anubis.
   Copyright (C) 2003, 2004, 2005 The Anubis Team.

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

int
anubis_transparent_mode (NET_STREAM * psd_client, struct sockaddr_in *addr)
{
  int rs = 0;
  int cs = 0;
  NET_STREAM sd_server = NULL;

  rs = auth_ident (addr, &session.clientname);

  if ((topt & T_DROP_UNKNOWN_USER) && !rs)
    {
      service_unavailable (psd_client);
      return 0;
    }

  parse_transmap (&cs,
		  rs ? session.clientname : 0,
		  inet_ntoa (addr->sin_addr),
		  &session.clientname);

  if (cs == 1)
    {
      anubis_changeowner (session.clientname);
      auth_tunnel ();
    }
  else if (rs && cs == -1 && ntohl (addr->sin_addr.s_addr) == INADDR_LOOPBACK)
    {
      if (check_username (session.clientname))
	{
	  anubis_changeowner (session.clientname);
	  auth_tunnel ();
	}
      else
	set_unprivileged_user ();
    }
  else
    set_unprivileged_user ();

  if (!(topt & T_LOCAL_MTA) && !session.mta)
    {
      anubis_error (EXIT_FAILURE, 0, _("The MTA has not been specified. "
			               "Set the REMOTE-MTA or LOCAL-MTA."));
    }

  /*
     Protection against a loop connection.
   */

  if (!(topt & T_LOCAL_MTA))
    {
      unsigned long inaddr;
      struct sockaddr_in ad;

      memset (&ad, 0, sizeof (ad));
      inaddr = inet_addr (session.mta);
      if (inaddr != INADDR_NONE)
	memcpy (&ad.sin_addr, &inaddr, sizeof (inaddr));
      else
	{
	  struct hostent *hp = 0;
	  hp = gethostbyname (session.mta);
	  if (hp == 0)
	    {
	      hostname_error (session.mta);
	    }
	  else
	    {
	      if (hp->h_length != 4 && hp->h_length != 8)
		{
		  anubis_error (EXIT_FAILURE, 0,
				_("Illegal address length received for host %s"),
				session.mta);
		}
	      else
		{
		  memcpy ((char *) &ad.sin_addr.s_addr,
			  hp->h_addr, hp->h_length);
		}
	    }
	}
      if (ntohl (ad.sin_addr.s_addr) == INADDR_LOOPBACK
	  && session.anubis_port == session.mta_port)
	{
	  anubis_error (EXIT_FAILURE, 0,
                        _("Loop not allowed. Connection rejected."));
	}
    }

  alarm (300);
  if (topt & T_LOCAL_MTA)
    {
      sd_server = make_local_connection (session.execpath, session.execargs);
      if (!sd_server)
	{
	  service_unavailable (psd_client);
	  return EXIT_FAILURE;
	}
    }
  else
    {
      sd_server = make_remote_connection (session.mta, session.mta_port);
      if (!sd_server)
	service_unavailable (psd_client);
    }

  remote_client = *psd_client;
  remote_server = sd_server;
  alarm (900);
  smtp_session_transparent ();
  alarm (0);

  net_close_stream (&sd_server);
  net_close_stream (psd_client);
  *psd_client = NULL;

  info (NORMAL, _("Connection closed successfully."));

#ifdef HAVE_PAM
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

/* EOF */
