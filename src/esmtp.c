/*
   esmtp.c

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

#ifdef HAVE_TLS
 #include <gcrypt.h>
#endif /* HAVE_TLS */

static char *b64encode(char *);
static int  b64decode(char *, char **);
#if defined(HAVE_TLS) || defined(HAVE_SSL)
static void cram_md5(char *, char *, unsigned char *);
#endif /* HAVE_TLS or HAVE_SSL */

/*********************
 ESMTP Authentication
**********************/

void
esmtp_auth(void *sd_server, char *reply)
{
	char *p = 0;
	char *b64buf = 0;
	char tmp[LINEBUFFER+1];
	memset(tmp, 0, LINEBUFFER + 1);

	#if defined(HAVE_TLS) || defined(HAVE_SSL)
	if (strstr(reply, "CRAM-MD5")) {
		int i;
		unsigned char digest[16];
		static char ascii_digest[33];
		memset(digest, 0, 16);

		info(VERBOSE, _("Using the ESMTP CRAM-MD5 authentication..."));
		swrite(CLIENT, sd_server, "AUTH CRAM-MD5"CRLF);
		get_response_smtp(CLIENT, sd_server, tmp, LINEBUFFER);

		if (strncmp(tmp, "334 ", 4)) {
			swrite(CLIENT, sd_server, "*"CRLF);
			anubis_error(SOFT, _("Server rejected the AUTH command."));
			get_response_smtp(CLIENT, sd_server, 0, 0);
			return;
		}

		p = strchr(tmp, ' ');
		p++;
		b64decode(p, &b64buf);
		info(DEBUG, _("Challenge decoded: %s"), b64buf);

		cram_md5(session.mta_password, b64buf, digest);
		xfree(b64buf);

		for (i = 0; i < 16; i++)
			sprintf(ascii_digest + 2 * i, "%02x", digest[i]);

		#ifdef HAVE_SNPRINTF
		snprintf(tmp, LINEBUFFER,
		#else
		sprintf(tmp,
		#endif /* HAVE_SNPRINTF */
			"%s %s", session.mta_username, ascii_digest);

		p = b64encode(tmp);
		#ifdef HAVE_SNPRINTF
		snprintf(tmp, LINEBUFFER,
		#else
		sprintf(tmp,
		#endif /* HAVE_SNPRINTF */
			"%s"CRLF, p);
		xfree(p);

		swrite(CLIENT, sd_server, tmp);
		get_response_smtp(CLIENT, sd_server, tmp, LINEBUFFER);
		if (!isdigit((unsigned char)tmp[0]) || (unsigned char)tmp[0] > '3') {
			remcrlf(tmp);
			anubis_error(SOFT, _("ESMTP AUTH: %s."), tmp);
		}
	}
	else
	#endif /* HAVE_TLS or HAVE_SSL */
	if (strstr(reply, "LOGIN") && (topt & T_SSL_FINISHED)) {
		info(VERBOSE, _("Using the ESMTP LOGIN authentication..."));
		swrite(CLIENT, sd_server, "AUTH LOGIN"CRLF);
		get_response_smtp(CLIENT, sd_server, tmp, LINEBUFFER);

		if (strncmp(tmp, "334 ", 4)) {
			swrite(CLIENT, sd_server, "*"CRLF);
			info(VERBOSE, _("Server rejected the AUTH command."));
			get_response_smtp(CLIENT, sd_server, 0, 0);
			return;
		}

		p = strchr(tmp, ' ');
		p++;
		b64decode(p, &b64buf);
		info(DEBUG, _("Challenge decoded: %s"), b64buf);

		p = b64encode(session.mta_username);
		#ifdef HAVE_SNPRINTF
		snprintf(tmp, LINEBUFFER,
		#else
		sprintf(tmp,
		#endif /* HAVE_SNPRINTF */
			"%s"CRLF, p);
		xfree(p);
		swrite(CLIENT, sd_server, tmp);
		get_response_smtp(CLIENT, sd_server, tmp, LINEBUFFER);

		p = strchr(tmp, ' ');
		p++;
		b64decode(p, &b64buf);
		info(DEBUG, _("Challenge decoded: %s"), b64buf);

		p = b64encode(session.mta_password);
		#ifdef HAVE_SNPRINTF
		snprintf(tmp, LINEBUFFER,
		#else
		sprintf(tmp,
		#endif /* HAVE_SNPRINTF */
			"%s"CRLF, p);
		xfree(p);
		swrite(CLIENT, sd_server, tmp);

		get_response_smtp(CLIENT, sd_server, tmp, LINEBUFFER);
		if (!isdigit((unsigned char)tmp[0]) || (unsigned char)tmp[0] > '3') {
			remcrlf(tmp);
			anubis_error(SOFT, _("ESMTP AUTH: %s."), tmp);
		}
	}
	return;
}

/************************************
 Base64 encoding/decoding functions.
*************************************/

static char *
b64encode(char *in)
{
	int len;
	char *out = 0;
	char *p = 0;

	const char uu_base64[64] =
	{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '+', '/'
	};

	if (in == 0)
		return 0;

	len = strlen(in);
	out = (char *)xmalloc(4 * ((len + 2) / 3) + 1);
	p = out;

	while (len-- > 0)
	{
		int x, y;
		x = *in++;
		*p++ = uu_base64[(x >> 2) & 63];

		if (len-- <= 0) {
			*p++ = uu_base64[(x << 4) & 63];
			*p++ = '=';
			*p++ = '=';
			break;
		}
		y = *in++;
		*p++ = uu_base64[((x << 4) | ((y >> 4) & 15)) & 63];

		if (len-- <= 0) {
			*p++ = uu_base64[(y << 2) & 63];
			*p++ = '=';
			break;
		}
		x = *in++;
		*p++ = uu_base64[((y << 2) | ((x >> 6) & 3)) & 63];
		*p++ = uu_base64[x & 63];
	}
	*p = 0;
	return out;
}

static int
b64decode(char *in, char **ptr)
{
	int x, y;
	char *result = 0;

	unsigned char uu_base64_decode[] =
	{
		255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
		255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
		255,255,255,255,255,255,255,255,255,255,255,62,255,255,255,63,
		52,53,54,55,56,57,58,59,60,61,255,255,255,255,255,255,
		255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
		15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,
		255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
		41,42,43,44,45,46,47,48,49,50,51,255,255,255,255,255
	};

	result = (char *)xmalloc(3 * (strlen(in) / 4) + 1);
	*ptr = result;

	while ((x = (unsigned char)(*in++)) != 0)
	{
		if (x > 127 || (x = uu_base64_decode[x]) == 255)
			return -1;
		if ((y = (unsigned char)(*in++)) == 0
		|| (y = uu_base64_decode[y]) == 255)
			return -1;
		*result++ = (x << 2) | (y >> 4);

		if ((x = (unsigned char)(*in++)) == '=') {
			if (*in++ != '=' || *in != 0)
				return -1;
		}
		else {
			if (x > 127 || (x = uu_base64_decode[x]) == 255)
				return -1;
			*result++ = (y << 4) | (x >> 2);
			if ((y = (unsigned char)(*in++)) == '=') {
				if (*in != 0)
					return -1;
			}
			else {
				if (y > 127 || (y = uu_base64_decode[y]) == 255)
					return -1;
				*result++ = (x << 6) | y;
			}
		}
	}
	*result = 0;
	return result - *ptr;
}

/***********
  CRAM-MD5
************/

#ifdef HAVE_TLS

static void
cram_md5(char *secret, char *challenge, unsigned char *digest)
{
	GCRY_MD_HD context;
	unsigned char ipad[64];
	unsigned char opad[64];
	int secret_len;
	int challenge_len;
	int i;

	if (secret == 0 || challenge == 0)
		return;

	secret_len = strlen(secret);
	challenge_len = strlen(challenge);
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));

	if (secret_len > 64) {
		context = gcry_md_open(GCRY_MD_MD5, 0);
		gcry_md_write(context, (unsigned char *)secret, secret_len);
		gcry_md_final(context);
		memcpy(ipad, gcry_md_read(context, 0), 64);
		memcpy(opad, gcry_md_read(context, 0), 64);
		gcry_md_close(context);
	}
	else {
		memcpy(ipad, secret, secret_len);
		memcpy(opad, secret, secret_len);
	}

	for (i = 0; i < 64; i++)
	{
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	context = gcry_md_open(GCRY_MD_MD5, 0);
	gcry_md_write(context, ipad, 64);
	gcry_md_write(context, (unsigned char *)challenge, challenge_len);
	gcry_md_final(context);
	memcpy(digest, gcry_md_read(context, 0), 16);
	gcry_md_close(context);

	context = gcry_md_open(GCRY_MD_MD5, 0);
	gcry_md_write(context, opad, 64);
	gcry_md_write(context, digest, 16);
	gcry_md_final(context);
	memcpy(digest, gcry_md_read(context, 0), 16);
	gcry_md_close(context);

	return;
}

#else
#ifdef HAVE_SSL

static void
cram_md5(char *secret, char *challenge, unsigned char *digest)
{
	MD5_CTX	context;
	unsigned char ipad[64];
	unsigned char opad[64];
	int secret_len;
	int challenge_len;
	int i;

	if (secret == 0 || challenge == 0)
		return;

	secret_len = strlen(secret);
	challenge_len = strlen(challenge);
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));

	if (secret_len > 64) {
		MD5_Init(&context);
		MD5_Update(&context, (unsigned char *)secret, secret_len);
		MD5_Final(ipad, &context);
		MD5_Final(opad, &context);
	}
	else {
		memcpy(ipad, secret, secret_len);
		memcpy(opad, secret, secret_len);
	}

	for (i = 0; i < 64; i++)
	{
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	MD5_Init(&context);
	MD5_Update(&context, ipad, 64);
	MD5_Update(&context, (unsigned char *)challenge, challenge_len);
	MD5_Final(digest, &context);

	MD5_Init(&context);
	MD5_Update(&context, opad, 64);
	MD5_Update(&context, digest, 16);
	MD5_Final(digest, &context);

	return;
}

#endif /* HAVE_SSL */
#endif /* HAVE_TLS */

/* EOF */

