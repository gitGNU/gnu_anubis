/*
   proxy.c

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

/*
   Based on Request For Comments: 1928 ("SOCKS Protocol Version 5")
*/

#define SOCKS_VERSION       0x05  /* SOCKS PROTOCOL VERSION 5 */
#define SOCKS_PASS_VERSION  0x01  /* SOCKS PASS VERSION 5 */
#define SOCKS_NOAUTH        0x00  /* NO AUTHENTICATION REQUIRED */
#define SOCKS_USERPASS      0x02  /* USER NAME/PASSWORD */
#define SOCKS_NAM           0xFF  /* NO ACCEPTABLE METHODS */
#define SOCKS_USERPASS_OK   0x00  /* USER NAME/PASSWORD is OK */
#define SOCKS_CMD_CONNECT   0x01  /* CONNECT COMMAND */
#define ATYP_IPv4           0x01  /* IPv4 */
#define ATYP_DOMAINNAME     0x03  /* DOMAIN NAME */
#ifdef IPV6
# define ATYP_IPv6          0x04  /* IPv6 */
#endif /* IPV6 */

static int connect_through_socks_proxy(int, char *, unsigned int);

void
check_all_proxies(char *host_backup, unsigned int *port_backup)
{
	if (topt & T_SOCKS) { /* SOCKS proxy */
		strncpy(host_backup, session.socks, 64);
		*port_backup = session.socks_port;
	}
	return;
}

/********************
 SOCKS Proxy support
*********************/

int
check_socks_proxy(int sd, char *host, unsigned int port)
{
	if (!(topt & T_SOCKS)) /* SOCKS Proxy */
		return 0;

	info(VERBOSE, _("Using SOCKS Proxy..."));
	if (connect_through_socks_proxy(sd, host, port) == -1)
		return -1;
	return 0;
}

#ifdef IPV6
static int
value_of(char what)
{
	switch (what)
	{
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'A': return 10;
		case 'a': return 10;
		case 'B': return 11;
		case 'b': return 11;
		case 'C': return 12;
		case 'c': return 12;
		case 'D': return 13;
		case 'd': return 13;
		case 'E': return 14;
		case 'e': return 14;
		case 'F': return 15;
		case 'f': return 15;
		default: return -1;
	}
}
#endif /* IPV6 */

static int
memcopy_offset(char *dst, char *what, int offset)
{
	int i;
	for (i = offset; what[i - offset] != '\0'; i++)
		dst[i] = what[i - offset];
	return i;
}

static int
connect_through_socks_proxy(int sd, char *host, unsigned int port)
{
	unsigned char request[1024];
	unsigned char reply[1024];
	int i = 0;
	int ip = 0;
	int offset = 0;

	if (topt & T_SOCKS_V4) { /* SOCKS v4 */

		/*
		   Prepare a request.
		*/

		memset(request, 0, sizeof(request));
		request[offset++] = 4;
		request[offset++] = 1;

		/* htons - special edition for SOCKS v4 :-) */
		{
			unsigned char st, nd;
			st = port >> 8;
			nd = (port << 8) >> 8;
			request[offset++] = st;
			request[offset++] = nd;
		}

		for (i = 0; host[i] != '\0'; i++)
		{
			if (isdigit((u_char)host[i]) || host[i] == '.')
				ip = 1;
			else
				ip = 0;
		}

		if (ip) {
			unsigned char ip[5];
			unsigned char tmp[5];
			int j = 0, z = 0;

			memset(ip,  0, sizeof(ip));
			memset(tmp, 0, sizeof(tmp));
	
			strcat(host, ".");
			for (i = 0; host[i] != '\0'; i++)
			{
				if (host[i] != '.') {
					tmp[j++] = host[i];
				}
				else {
					j = 0;
					ip[z++] = atoi((char *)tmp);
					memset(tmp, 0, sizeof(tmp));
				}
			}
	
			z = 0;
			for (i = 0; i < 4; i++)
				request[offset++] = ip[z++];
		}
		else {
			socks_error(_("Address must be an IP, not a domain name."));
			return -1;
		}

		/*
		   User name ended with...
		*/

		offset = memcopy_offset((char *)request, session.socks_username, offset);
		request[offset++] = 0x00; /* null */

		/*
		   Send a request.
		*/

		if (send(sd, request, offset, 0) == -1) {
			socket_error(NULL);
			return -1;
		}

		/*
		   Get a reply.
		*/

		sleep(1);
		memset(reply, 0, sizeof(reply));
		recv(sd, reply, 8, 0);
    
		/*
		   Process a reply.
		*/

		switch (reply[1])
		{
			case 90:
				info(VERBOSE, _("SOCKS Proxy Connection: succeeded."));
				break;
			case 91:
				socks_error(_("Request rejected or failed."));
				return -1;
			case 92:
				socks_error(_("Request rejected."));
				return -1;
			case 93:
				socks_error(_("Request rejected, because "
				"the client program and identd reported different User-IDs."));
				return -1;
			default:
				socks_error(_("Server reply is not valid."));
				return -1;
		}
	}
	else { /* SOCKS v5 */

		/*
		   Prepare an AUTH request.
		*/

		memset(request, 0, sizeof(request));
		request[offset++] = SOCKS_VERSION;
		request[offset++] = 2;
		request[offset++] = SOCKS_NOAUTH;
		request[offset++] = SOCKS_USERPASS;

		/*
		   Send an AUTH request.
		*/

		if (send(sd, request, offset, 0) == -1) {
			socket_error(NULL);
			return -1;
		}

		/*
		   Get a reply.
		*/

		sleep(1);
		memset(reply, 0, sizeof(reply));
		recv(sd, reply, 2, 0);

		/*
		   Check a reply VERSION.
		*/

		if (reply[0] != SOCKS_VERSION) {
			socks_error(_("Possibly not a SOCKS proxy service."));
			return -1;
		}

		/*
		   Process an AUTH reply.
		*/

		switch (reply[1])
		{
			case SOCKS_NOAUTH:
				info(VERBOSE,
				_("SOCKS Proxy AUTH method: NO AUTHENTICATION REQUIRED"));
				break;
			case SOCKS_USERPASS:
				info(VERBOSE,
				_("SOCKS Proxy AUTH method: USER NAME/PASSWORD"));

				if (!(topt & T_SOCKS_AUTH)) {
					socks_error(_("Cannot send null user name or password."));
					return -1;
				}

				/*
				   Prepare User/Pass request.
				*/

				memset(request, 0, sizeof(request));
				offset = 0;
				request[offset++] = SOCKS_PASS_VERSION;
				request[offset++] = strlen(session.socks_username);
				offset = memcopy_offset((char *)request, session.socks_username, offset);
				request[offset++] = strlen(session.socks_password);
				offset = memcopy_offset((char *)request, session.socks_password, offset);

				/*
				   Send User/Pass request.
				*/

				if (send(sd, request, offset, 0) == -1) {
					socket_error(NULL);
					return -1;
				}

				/*
				   Get a reply.
				*/

				sleep(1);
				memset(reply, 0, sizeof (reply));
				recv(sd, reply, 2, 0);

				/*
				   Check a reply.
				*/

				if (reply[1] != SOCKS_USERPASS_OK) {
					socks_error(_("Bad user name or password."));
					return -1;
				}
				else
					info(VERBOSE, _("SOCKS Proxy AUTH: succeeded."));
				break;
			case SOCKS_NAM:
				socks_error(_("Server does not accept any method."));
				return -1;
			default:
				socks_error(_("Server does not accept an AUTH method."));
				return -1;
		}

		/*
		   Prepare a connection request
		*/

		memset(request, 0, sizeof(request));
		offset = 0;
		request[offset++] = SOCKS_VERSION;
		request[offset++] = SOCKS_CMD_CONNECT;
		request[offset++] = 0;

		for (i = 0; host[i] != '\0'; i++)
		{
			if (isdigit((u_char)host[i]) || host[i] == '.') {
				ip = 1; /* IPv4 */
			}
			else
				ip = 0; /* a domain name */

#ifdef IPV6
			if (host[i] == ':') {
				ip = 2;
				break;
			}
#endif /* IPV6 */
		}

		if (ip == 1) { /* IPv4 */
			unsigned char ip[5];
			unsigned char tmp[5];
			int j = 0, z = 0;

			memset(ip,  0, sizeof(ip));
			memset(tmp, 0, sizeof(tmp));
			request[offset++] = ATYP_IPv4; /* it`s an IPv4 */

			strcat(host, ".");
			for (i = 0; host[i] != '\0'; i++)
			{
				if (host[i] != '.') {
					tmp[j++] = host[i];
				}
				else {
					j = 0;
					ip[z++] = atoi((char *)tmp);
					memset(tmp, 0, sizeof(tmp));
				}
			}
	
			z = 0;
			for (i = 0; i < 4; i++)
				request[offset++] = ip[z++];

#ifdef IPV6
		}
		else if (ip == 2) { /* IPv6 */
			char tmp[5];
			int i = 0;

			strncpy(tmp, "0000", 4);
			strcat(host, ":");
			request[offset++] = ATYP_IPv6; /* it`s an IPv6 */

			for (i = 0; host[i] != '\0'; i++)
			{
				if (host[i] != ':') {
					tmp[0] = tmp[1];
					tmp[1] = tmp[2];
					tmp[2] = tmp[3];
					tmp[3] = host[i];
				}
				else {
					request[offset++] = value_of(tmp[0]) * 16 + value_of(tmp[1]);
					request[offset++] = value_of(tmp[2]) * 16 + value_of(tmp[3]);
					strncpy(tmp, "0000", 4);
				}
			}
#endif /* IPV6 */

		}
		else { /* a domain name */
			request[offset++] = ATYP_DOMAINNAME; /* it`s a domain name */
			request[offset++] = strlen(host);
			offset = memcopy_offset((char *)request, host, offset);
		}

		/* htons - special edition for v5 :-) */
		{
			unsigned char st, nd;
			st = port >> 8;
			nd = (port << 8) >> 8;
			request[offset++] = st;
			request[offset++] = nd;
		}

		/*
		   Send a connection request.
		*/

		if (send(sd, request, offset, 0) == -1) {
			socket_error(NULL);
			return -1;
		}

		/*
		   Get a reply.
		*/

		sleep(1);
		memset(reply, 0, sizeof(reply));
		recv(sd, reply, 4, 0); /* We don`t know how long is a reply. */

		/*
		   Process a connection reply.
		*/

		switch (reply[1])
		{
			case 0x00:
				info(VERBOSE, _("SOCKS Proxy Connection: succeeded."));
				break;
			case 0x01:
				socks_error(_("General SOCKS server failure."));
				return -1;
			case 0x02:
				socks_error(_("Connection not allowed by a ruleset."));
				return -1;
			case 0x03:
				socks_error(_("Network unreachable."));
				return -1;
			case 0x04:
				socks_error(_("Host unreachable."));
				return -1;
			case 0x05:
				socks_error(_("Connection refused."));
				return -1;
			case 0x06:
				socks_error(_("TTL expired."));
				return -1;
			case 0x07:
				socks_error(_("Command not supported."));
				return -1;
			case 0x08:
				socks_error(_("Address type not supported."));
				return -1;
			default:
				socks_error(_("Server reply is not valid."));
				return -1;
		}

		switch (reply[3])
		{
			case ATYP_IPv4:
				memset(reply, 0, sizeof(reply));
				/*
				   6 = IPv4 (4) + port number (2)
				*/
				recv(sd, reply, 6, 0);
				break;
			case ATYP_DOMAINNAME:
				{
					int length = 0;
					memset(reply, 0, sizeof(reply));
					recv(sd, reply, 1, 0);
					length = reply[1];
					memset(reply, 0, sizeof(reply));
					recv(sd, reply, length + 2, 0);
				}
				break;

#ifdef IPV6
			case ATYP_IPv6:
				memset(reply, 0, sizeof(reply));
				/*
				   18 = IPv6 (16) + port number (2)
				*/
				recv(sd, reply, 18, 0);
				break;
#endif /* IPV6 */
		}
	}
	return 0;
}

/* EOF */

