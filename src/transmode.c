/*
   transmode.c

   This file is part of GNU Anubis.
   Copyright (C) 2003 The Anubis Team.

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
anubis_transparent_mode (int sd_client, struct sockaddr_in *addr)
{
	int rs = 0;
	int cs = 0;
	int sd_server = 0;
		
	rs = auth_ident(addr,
			session.client,
			sizeof(session.client));

	if ((topt & T_DROP_UNKNOWN_USER) && !rs) {
		service_unavailable(sd_client);
		return 0;
	}
	
	parse_transmap(&cs,
		       rs ? session.client : 0,
		       inet_ntoa(addr->sin_addr),
		       session.client,
		       sizeof(session.client));
				
	if (cs == 1) {
		anubis_changeowner(session.client);
		auth_tunnel();
	} else if (rs
		   && cs == -1
		   && ntohl(addr->sin_addr.s_addr) == INADDR_LOOPBACK) {
		if (check_username(session.client)) {
			anubis_changeowner(session.client);
			auth_tunnel();
		} else
			set_unprivileged_user();
	} else
		set_unprivileged_user();
	
	if (!(topt & T_LOCAL_MTA)
	    && strlen(session.mta) == 0) {
		anubis_error(HARD, _("The MTA has not been specified. "
				     "Set the REMOTE-MTA or LOCAL-MTA."));
		return EXIT_FAILURE;
	}
	
	/*
	  Protection against a loop connection.
	*/
	
	if (!(topt & T_LOCAL_MTA)) {
		unsigned long inaddr;
		struct sockaddr_in ad;
		
		memset(&ad, 0, sizeof(ad));
		inaddr = inet_addr(session.mta);
		if (inaddr != INADDR_NONE)
			memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
		else {
			struct hostent *hp = 0;
			hp = gethostbyname(session.mta);
			if (hp == 0) {
				hostname_error(session.mta);
				return EXIT_FAILURE;
			} else {
				if (hp->h_length != 4 && hp->h_length != 8) {
					anubis_error(HARD,
		_("Illegal address length received for host %s"), session.mta);
					return EXIT_FAILURE;
				} else {
					memcpy((char *)&ad.sin_addr.s_addr,
					       hp->h_addr,
					       hp->h_length);
				}
			}
		}
		if (ntohl(ad.sin_addr.s_addr) == INADDR_LOOPBACK
		    && session.tunnel_port == session.mta_port) {
			anubis_error(SOFT, _("Loop not allowed. Connection rejected."));
			return EXIT_FAILURE;
		}
	}
	
	alarm(300);
	if (topt & T_LOCAL_MTA) {
		sd_server = make_local_connection(session.execpath, session.execargs);
		if (sd_server == -1) {
			service_unavailable(sd_client);
			return EXIT_FAILURE;
		}
	} else {
		sd_server = make_remote_connection(session.mta, session.mta_port);
		if (sd_server == -1)
			service_unavailable(sd_client);
	}
	alarm(0);
	
	if (!(topt & T_ERROR)) {
		remote_client = (void *)sd_client;
		remote_server = (void *)sd_server;
		alarm(900);
		smtp_session_transparent();
		alarm(0);
		
#ifdef USE_SSL
		net_close(CLIENT, secure.client);
		net_close(SERVER, secure.server);
		secure.server = 0;
		secure.client = 0;
#endif
	}
	close_socket(sd_server);
	close_socket(sd_client);
	
	if (topt & T_ERROR)
		info(NORMAL, _("Connection terminated."));
	else
		info(NORMAL, _("Connection closed successfully."));
	
#ifdef HAVE_PAM	
	pam_retval = pam_close_session(pamh, 0);
	if (pam_retval == PAM_SUCCESS)
		info(VERBOSE, _("PAM: Session closed."));
	if (pam_end(pamh, pam_retval) != PAM_SUCCESS) {
		pamh = NULL;
		info(NORMAL, _("PAM: failed to release authenticator."));
		return EXIT_FAILURE;
	}
#endif /* HAVE_PAM */
	return 0;
}