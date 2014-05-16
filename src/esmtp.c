/*
   esmtp.c

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

#if defined(WITH_GSASL)

ANUBIS_LIST anubis_client_mech_list;     /* List of auth methods allowed by
					     the client */
ANUBIS_LIST anubis_encryption_mech_list; /* List of auth methods that require
					     using encrypted channel */
char *anon_token;                         /* Anonymous token */
char *authorization_id;       
char *authentication_id;
char *auth_password;
char *auth_service;
char *auth_hostname;
/* FIXME: Not used: */
char *generic_service_name;
char *auth_passcode;
char *auth_realm;

void
anubis_set_client_mech_list (ANUBIS_LIST list)
{
  anubis_set_mech_list (&anubis_client_mech_list, list);
}

void
anubis_set_encryption_mech_list (ANUBIS_LIST list)
{
  anubis_set_mech_list (&anubis_encryption_mech_list, list);
}

static int
callback (Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop)
{
  int rc = GSASL_OK;
  
  switch (prop)
    {
    case GSASL_AUTHID:
      if (authentication_id == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, authentication_id);
      break;

    case GSASL_AUTHZID:
      if (authorization_id == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, authorization_id);
      break;

    case GSASL_PASSWORD:
      if (auth_password == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_password);
      break;

    case GSASL_ANONYMOUS_TOKEN:
      if (anon_token == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, anon_token);
      break;

    case GSASL_SERVICE:
      if (auth_service == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_service);
      break;

    case GSASL_HOSTNAME:
      if (auth_hostname == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_hostname);
      break;

    case GSASL_PASSCODE:
      if (auth_passcode == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_passcode);
      break;

    case GSASL_REALM:
      if (auth_realm == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_realm);
      break;

    default:
      rc = GSASL_NO_CALLBACK;
      anubis_error (0, 0, _("Unsupported callback property %d"), prop);
      break;
    }

  return rc;
}
      


static char *
get_reply (NET_STREAM str, int *code, char **buf, size_t *psize)
{
  char *p;

  if (recvline (CLIENT, str, buf, psize) == 0)
    {
      anubis_error (1, 0, _("unexpected eof in input"));
    }
      
  remcrlf (*buf);
  *code = strtoul (*buf, &p, 10);
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
do_gsasl_auth (NET_STREAM *pstr, Gsasl *ctx, char *mech)
{
  char *output;
  int rc;
  Gsasl_session *sess_ctx = NULL;
  char sbuf[LINEBUFFER + 1];
  char *buf = NULL;
  size_t size = 0;
  char *p;
  int code;
  
  snprintf (sbuf, sizeof sbuf, "AUTH %s" CRLF, mech);
  swrite (CLIENT, *pstr, sbuf);

  rc = gsasl_client_start (ctx, mech, &sess_ctx);
  if (rc != GSASL_OK)
    {
      anubis_error (1, 0, _("SASL gsasl_client_start: %s"),
		    gsasl_strerror (rc));
    }

  output = NULL;

  p = get_reply (*pstr, &code, &buf, &size);
  if (code != 334)
    {
      anubis_error (0, 0, _("GSASL handshake aborted: %d %s"), code, p);
      free (buf);
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
      p = get_reply (*pstr, &code, &buf, &size);
      if (code != 334)
	{
	  anubis_error (0, 0, _("GSASL handshake aborted: %d %s"), code, p);
	  free (output);
	  free (buf);
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

  p = get_reply (*pstr, &code, &buf, &size);
  
  if (code == 334)
    {
      /* Additional data. Do we need it? */
      p = get_reply (*pstr, &code, &buf, &size);
    }

  if (code != 235)
    {
      anubis_error (1, 0, _("Authentication failed: %d %s"), code, p);
    }

  info (VERBOSE, _("Authentication successful."));

  if (sess_ctx)
    install_gsasl_stream (sess_ctx, pstr);

  free (buf);
  
  return 0;
}

int
esmtp_auth (NET_STREAM *pstr, const char *input)
{
  Gsasl *ctx;
  int rc;
  ANUBIS_LIST isect;
  ANUBIS_LIST mech_list = auth_method_list (input);
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

  gsasl_callback_set (ctx, callback);

  rc = do_gsasl_auth (pstr, ctx, mech);
  list_destroy (&mech_list, anubis_free_list_item, NULL);
  return rc;
}
#else
int
esmtp_auth (NET_STREAM *pstr, const char *input)
{
  anubis_warning (0, _("ESMTP AUTH is not supported"));
  return 1;
}
#endif

