/*
   main.h

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

const char version[] = "GNU Anubis v"VERSION;
const char copyright[] = "Copyright (C) 2001, 2002, 2003 The Anubis Team.";

struct options_struct options;
struct session_struct session;
struct message_struct message;
struct rm_struct rm;

#if defined(HAVE_TLS) || defined(HAVE_SSL)
 struct secure_struct secure;
#endif /* HAVE_TLS or HAVE_SSL */

unsigned long topt;
unsigned long ropt;

void *remote_client;
void *remote_server;

/* EOF */

