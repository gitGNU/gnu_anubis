/*
   auth.c

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

void
auth_tunnel(void)
{
	info(NORMAL, _("Welcome user %s !"), session.client);
	open_rcfile(CLIENT);
	read_rcfile(CLIENT);
	read_rcfile_allsection();
	rule_position = get_position(BEGIN_RULE);
	if (rule_position)
		info(DEBUG, _("The %s section has been found. Processing..."), "RULE");
	return;
}

/***********************
 IDENT protocol support
************************/

int
auth_ident(struct sockaddr_in *addr, char *user, int size)
{
	struct servent *sp;
	struct sockaddr_in ident;
	char buf[LINEBUFFER+1];
	int sd = 0;

	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		anubis_error(SOFT, _("IDENT: socket() failed: %s."), strerror(errno));
		return 0;
	}
	memcpy(&ident, addr, sizeof(ident));
	sp = getservbyname("auth", "tcp");
	if (sp)
		ident.sin_port = sp->s_port;
	else
		ident.sin_port = htons(113); /* default IDENT port number */

	if (connect(sd, (struct sockaddr *)&ident, sizeof(ident)) < 0) {
		anubis_error(SOFT, _("IDENT: connect() failed: %s."), strerror(errno));
		close_socket(sd);
		return 0;
	}
	info(VERBOSE, _("IDENT: connected to %s:%u"),
	inet_ntoa(ident.sin_addr), ntohs(ident.sin_port));

	#ifdef HAVE_SNPRINTF
	snprintf(buf, LINEBUFFER,
	#else
	sprintf(buf,
	#endif /* HAVE_SNPRINTF */
		"%u , %u"CRLF, ntohs(addr->sin_port), session.tunnel_port);

	if (send(sd, buf, strlen(buf), 0) == -1) {
		anubis_error(SOFT, _("IDENT: send() failed: %s."), strerror(errno));
		close_socket(sd);
		return 0;
	}
	if (recvline(CLIENT, (void *)sd, buf, LINEBUFFER) == -1) {
		anubis_error(SOFT, _("IDENT: recvline() failed: %s."), strerror(errno));
		close_socket(sd);
		return 0;
	}
	close_socket(sd);
	memset(user, 0, size);

	if (sscanf(buf, "%*[^:]: USERID :%*[^:]:%s", user) != 1) {
		info(VERBOSE, _("IDENT: incorrect data."));
		return 0;
	}

	/******************************
         IDENTD DES decryption support
	*******************************/

	if (strstr(user, "[") && strstr(user, "]")) {
		int rs = 0;
		info(VERBOSE, _("IDENT: data probably encrypted with DES..."));
		external_program(&rs, IDECRYPT_PATH, user, buf, LINEBUFFER);
		if (rs == -1)
			return 0;

		if (sscanf(buf, "%*[^ ] %*[^ ] %*[^ ] %*[^ ] %*[^ ] %s", user) != 1) {
			info(VERBOSE, _("IDENT: incorrect data (DES deciphered)."));
			return 0;
		}
		else { /* UID deciphered */
			if (ntohl(ident.sin_addr.s_addr) == INADDR_LOOPBACK) {
				struct passwd *pwd;
				int uid = atoi(user);
				pwd = getpwuid(uid);
				if (pwd != 0)
					strncpy(user, (char *)pwd->pw_name, size - 1);
				else
					return 0;
			}
		}
	}

	info(VERBOSE, _("IDENT: resolved remote user to %s."), user);
	return 1; /* success */
}

/* EOF */

