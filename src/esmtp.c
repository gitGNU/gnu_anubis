/*
   esmtp.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003, 2004 The Anubis Team.

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

#if defined(WITH_GSASL)
/* FIXME: Duplicated in anubisusr.c */
static int
utf8cpy (char *dst, size_t * dstlen, char *src, size_t srclen)
{
  size_t len = strlen (src);

  if (dst && *dstlen < len)
    return GSASL_TOO_SMALL_BUFFER;
  *dstlen = len;
  if (dst)
    strcpy (dst, src);
  return GSASL_OK;
}

ANUBIS_LIST *anubis_client_mech_list;     /* List of auth methods allowed by
					     the client */
ANUBIS_LIST *anubis_encryption_mech_list; /* List of auth methods that require
					     using encrypted channel */
char *anon_token;                         /* Anonymous token */
char *authorization_id;       
char *authentication_id;
char *auth_password;
char *auth_service;
char *auth_hostname;
char *generic_service_name;
char *auth_passcode;
char *auth_realm;

void
anubis_set_client_mech_list (ANUBIS_LIST *list)
{
  anubis_set_mech_list (&anubis_client_mech_list, list);
}

void
anubis_set_encryption_mech_list (ANUBIS_LIST *list)
{
  anubis_set_mech_list (&anubis_encryption_mech_list, list);
}

static int
cb_anonymous (Gsasl_session_ctx *ctx, char *out, size_t *outlen)
{
  if (anon_token == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  return utf8cpy (out, outlen, anon_token, strlen (anon_token));
}

static int
cb_authorization_id (Gsasl_session_ctx *ctx, char *out, size_t *outlen)
{
  if (authorization_id == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  return utf8cpy (out, outlen, authorization_id, strlen (authorization_id));
}

static int
cb_authentication_id (Gsasl_session_ctx *ctx, char *out, size_t *outlen)
{
  if (authentication_id == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  return utf8cpy (out, outlen, authentication_id, strlen (authentication_id));
}

static int
cb_password (Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
  if (auth_password == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  return utf8cpy (out, outlen, auth_password, strlen (auth_password));
}

static int
cb_service (Gsasl_session_ctx * ctx, char *srv, size_t * srvlen,
	    char *host, size_t * hostlen, char *srvname, size_t * srvnamelen)
{
  int rc;
  
  if (auth_service == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  if (auth_hostname == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  if (srvnamelen && generic_service_name == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (srv, srvlen, auth_service, strlen (auth_service));
  if (rc != GSASL_OK)
    return rc;

  rc = utf8cpy (host, hostlen, auth_hostname, strlen (auth_hostname));
  if (rc != GSASL_OK)
    return rc;

  if (srvnamelen)
    rc = utf8cpy (srvname, srvnamelen, generic_service_name,
		  strlen (generic_service_name));

  return rc;
}

static int
cb_passcode (Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
  if (auth_passcode == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  return utf8cpy (out, outlen, auth_passcode, strlen (auth_passcode));
}

static int
cb_realm (Gsasl_session_ctx *ctx, char *out, size_t *outlen)
{
  if (auth_realm == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  return utf8cpy (out, outlen, auth_realm, strlen (auth_realm));
}

static char *
get_reply (NET_STREAM str, int *code, char *buf, size_t size)
{
  char *p;
  get_response_smtp (CLIENT, str, buf, size);
  remcrlf (buf);
  *code = strtoul (buf, &p, 10);
  if (*p == 0 || *p == '\r')
    return p;

  if (!isspace (*p))
    {
      anubis_error (1, 0, _("Malformed or unexpected reply"));
    }

  while (*p && isspace (*p))
    p++;
  return p;
}

int
do_gsasl_auth (NET_STREAM *pstr, Gsasl_ctx * ctx, char *mech)
{
  char *output;
  int rc;
  Gsasl_session_ctx *sess_ctx = NULL;
  char buf[LINEBUFFER + 1];
  char *p;
  int code;
  
  snprintf (buf, sizeof buf, "AUTH %s" CRLF, mech);
  swrite (CLIENT, *pstr, buf);

  rc = gsasl_client_start (ctx, mech, &sess_ctx);
  if (rc != GSASL_OK)
    {
      anubis_error (1, 0, _("SASL gsasl_client_start: %s"),
		    gsasl_strerror (rc));
    }

  output = NULL;

  p = get_reply (*pstr, &code, buf, sizeof buf);
  if (code != 334)
    {
      anubis_error (0, 0, _("GSASL handshake aborted: %d %s"), code, p);
      return 1;
    }

  do
    {
      rc = gsasl_step64 (sess_ctx, p, &output);
      if (rc != GSASL_NEEDS_MORE && rc != GSASL_OK)
	break;

      swrite (CLIENT, *pstr, output);
      swrite (CLIENT, *pstr, CRLF);

      if (rc == GSASL_OK)
	break;
      p = get_reply (*pstr, &code, buf, sizeof buf);
      if (code != 334)
	{
	  anubis_error (0, 0, _("GSASL handshake aborted: %d %s"), code, p);
	  free (output);
	  return 1;
	}
    }
  while (rc == GSASL_NEEDS_MORE);

  free (output);

  if (rc != GSASL_OK)
    {
      anubis_error (0, 0, _("GSASL error: %s"), gsasl_strerror (rc));
      exit (1);
    }

  p = get_reply (*pstr, &code, buf, sizeof buf);
  
  if (code == 334)
    {
      /* Additional data. Do we need it? */
      p = get_reply (*pstr, &code, buf, sizeof buf);
    }

  if (code != 235)
    {
      anubis_error (1, 0, _("Authentication failed: %d %s"), code, p);
    }

  info (VERBOSE, _("Authentication successful."));

  if (sess_ctx)
    install_gsasl_stream (sess_ctx, pstr);

  return 0;
}

int
esmtp_auth (NET_STREAM *pstr, char *input)
{
  Gsasl_ctx *ctx;
  int rc;
  ANUBIS_LIST *isect;
  ANUBIS_LIST *mech_list = auth_method_list (input);
  char *mech;
  
  if (list_count (mech_list) == 0)
    {
      anubis_warning (0, _("Got empty list of authentication methods"));
      list_destroy (&mech_list, anubis_free_list_item, NULL);
      return 1;
    }

  /* Provide reasonable defaults */
  if (!anubis_client_mech_list)
    {
      char *p = strdup ("CRAM-MD5 LOGIN PLAIN");
      anubis_client_mech_list = auth_method_list (p);
      free (p);
    }
  if (!anubis_encryption_mech_list)
    {
      char *p = strdup ("LOGIN PLAIN");
      anubis_encryption_mech_list = auth_method_list (p);
      free (p);
    }
  /* End of backward compatibility hack */
  
  isect = list_intersect (anubis_client_mech_list, mech_list, anubis_name_cmp);

  if (list_count (isect) == 0)
    {
      anubis_warning (0,
	      _("Server did not offer any feasible authentication mechanism"));
      list_destroy (&isect, NULL, NULL);
      list_destroy (&mech_list, anubis_free_list_item, NULL);
      return 1;
    }
  
  mech = list_item (isect, 0);
  if (!mech) /* Just in case...*/
    {
      anubis_error(1, 0,
		   "%s %s:%d", _("INTERNAL ERROR"), __FILE__, __LINE__);
    }

  if (list_locate (anubis_encryption_mech_list, mech, anubis_name_cmp))
    {
      if (!(topt & T_SSL_FINISHED))
	{
	  anubis_warning (0,
			  _("Selected authentication mechanism %s requires TLS encryption. Not using ESMTP authentication"),
			  mech);
	  list_destroy (&mech_list, anubis_free_list_item, NULL);
	  return 1;
	}
    }
  
  info (VERBOSE, _("Selected authentication mechanism %s"), mech);

  rc = gsasl_init (&ctx);
  
  if (rc != GSASL_OK)
    {
      anubis_error (0, 0, _("Cannot initialize libgsasl: %s"),
		    gsasl_strerror (rc));
      return 1;
    }

  gsasl_client_callback_anonymous_set (ctx, cb_anonymous);
  gsasl_client_callback_authentication_id_set (ctx, cb_authentication_id);
  gsasl_client_callback_authorization_id_set (ctx, cb_authorization_id);
  gsasl_client_callback_password_set (ctx, cb_password);
  gsasl_client_callback_passcode_set (ctx, cb_passcode);
  gsasl_client_callback_service_set (ctx, cb_service);
  gsasl_client_callback_realm_set (ctx, cb_realm);

  rc = do_gsasl_auth (pstr, ctx, mech);
  list_destroy (&mech_list, anubis_free_list_item, NULL);
  return rc;
}
#else
int
esmtp_auth (NET_STREAM *pstr, char *input)
{
  anubis_warning (0, _("ESMTP AUTH is not supported"));
  return 1;
}
#endif

