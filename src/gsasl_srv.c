/*
   gsasl_srv.c

   This file is part of GNU Anubis.
   Copyright (C) 2003,2004 The Anubis Team.

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

static Gsasl_ctx *ctx;
static ANUBIS_LIST *anubis_mech_list;

/* Converts the auth method list from a textual representation to
   a ANUBIS_LIST of string values */
ANUBIS_LIST *
auth_method_list (char *input)
{
  char *p;
  ANUBIS_LIST *list = list_create ();

  for (p = strtok (input, " \t"); p; p = strtok (NULL, " \t"))
    list_append (list, strdup (p));
  return list;
}

/* Converts the authentication method ANUBIS_LIST to its textual representation. */
static void
auth_list_to_string (ANUBIS_LIST * list, char *buf, size_t bufsize)
{
  ITERATOR *itr = iterator_create (list);
  char *p;

  if (!itr)
    return;
  for (p = iterator_first (itr); p; p = iterator_next (itr))
    {
      size_t len = strlen (p);
      if (len + 1 >= bufsize)
	break;
      strcpy (buf, p);
      buf += len;
      *buf++ = ' ';
      bufsize -= len + 1;
    }
  iterator_destroy (&itr);
  *buf = 0;
}

/* Sets the list of allowed authentication mechanisms from its
   argument */
void
anubis_set_mech_list (ANUBIS_LIST **out, ANUBIS_LIST *list)
{
  ITERATOR *itr = iterator_create (list);
  char *p;

  if (!itr)
    return;
  *out = list_create ();
  for (p = iterator_first (itr); p; p = iterator_next (itr))
    list_append (*out, make_uppercase (strdup (p)));
  iterator_destroy (&itr);
}

void
anubis_set_server_mech_list (ANUBIS_LIST *list)
{
  anubis_set_mech_list (&anubis_mech_list, list);
}

/* Capability list handling */

static void
auth_gsasl_capa_init ()
{
  int rc;
  char *listmech;

  rc = gsasl_server_mechlist (ctx, &listmech);
  if (rc != GSASL_OK)
    {
      anubis_error (0, 0, "%s", gsasl_strerror (rc));
      return;
    }

  if (anubis_mech_list)
    {
      size_t size = strlen (listmech);
      ANUBIS_LIST *mech = auth_method_list (listmech);
      ANUBIS_LIST *p = list_intersect (mech, anubis_mech_list,
				       anubis_name_cmp);
      auth_list_to_string (p, listmech, size);
      list_destroy (&p, NULL, NULL);
      list_destroy (&mech, anubis_free_list_item, NULL);
    }
  if (listmech[0])
    asmtp_capa_add_prefix ("AUTH", listmech);

  free (listmech);
}



/* GSASL Authentication */

#define SP(x) ((x)?(x):"NULL")

int
anubis_auth_gsasl (char *auth_type, char *arg, ANUBIS_USER * usr,
		   NET_STREAM * stream)
{
  char *input = arg;
  size_t input_size = 0;
  char *output;
  int rc;
  Gsasl_session_ctx *sess_ctx = NULL;

  if (options.termlevel == DEBUG)
    fprintf (stderr, "SASL mech=%s, inp=%s\n", SP(auth_type), SP(arg));

  memset (usr, 0, sizeof (*usr));
  rc = gsasl_server_start (ctx, auth_type, &sess_ctx);
  if (rc != GSASL_OK)
    {
      info (NORMAL, _("SASL gsasl_server_start: %s"), gsasl_strerror (rc));
      asmtp_reply (504, "%s", gsasl_strerror (rc));
      return 1;
    }

  gsasl_server_application_data_set (sess_ctx, usr);

  output = NULL;
  /* RFC 2554 4.:
     Unlike a zero-length client answer to a 334 reply, a zero-
     length initial response is sent as a single equals sign */
  if (input && strcmp (input, "=") == 0)
    input = "";

  while ((rc = gsasl_step64 (sess_ctx, input, &output)) == GSASL_NEEDS_MORE)
    {
      asmtp_reply (334, "%s", output);
      recvline (SERVER, remote_client, &input, &input_size);
      remcrlf (input);
      if (strcmp (input, "*") == 0)
	{
	  asmtp_reply (501, "AUTH aborted");
	  return 1;
	}
    }

  if (input_size)
    free (input);

  if (rc != GSASL_OK)
    {
      info (NORMAL, _("GSASL error: %s"), gsasl_strerror (rc));
      free (output);
      asmtp_reply (501, "Authentication failed");
      return 1;
    }

  /* Some SASL mechanisms output data when GSASL_OK is returned */
  if (output[0])
    asmtp_reply (334, "%s", output);

  free (output);

  if (usr->smtp_authid == NULL)
    {
      info (NORMAL, _("GSASL %s: cannot get username"), auth_type);
      asmtp_reply (535, "Authentication failed");	/* FIXME */
      return 1;
    }

  info (NORMAL, "Authentication passed. User name %s, Local user %s. Welcome!",
	usr->smtp_authid, usr->username ? usr->username : "NONE");

  if (sess_ctx)
    install_gsasl_stream (sess_ctx, stream);

  asmtp_reply (235, "Authentication successful.");
  return 0;
}



/* Various callback functions */

/* This is for DIGEST-MD5 */
static int
cb_realm (Gsasl_session_ctx * ctx, char *out, size_t * outlen, size_t nth)
{
  char *realm = get_localname ();

  if (nth > 0)
    return GSASL_NO_MORE_REALMS;

  if (out)
    {
      if (*outlen < strlen (realm))
	return GSASL_TOO_SMALL_BUFFER;
      memcpy (out, realm, strlen (realm));
    }

  *outlen = strlen (realm);

  return GSASL_OK;
}

static int
cb_validate (Gsasl_session_ctx * ctx,
	     const char *authorization_id,
	     const char *authentication_id, const char *password)
{
  ANUBIS_USER *usr = gsasl_server_application_data_get (ctx);

  if (usr->smtp_authid == NULL
      && anubis_get_db_record (authentication_id, usr) != ANUBIS_DB_SUCCESS)
    return GSASL_AUTHENTICATION_ERROR;
  
  if (usr->smtp_authid == NULL
      || strcmp (usr->smtp_authid, authentication_id)
      || strcmp (usr->smtp_passwd, password))
    return GSASL_AUTHENTICATION_ERROR;
  return GSASL_OK;
}

#define GSSAPI_SERVICE "anubis"

static int
cb_service (Gsasl_session_ctx * ctx, char *srv, size_t * srvlen,
	    char *host, size_t * hostlen)
{
  char *hostname = get_localname ();

  if (srv)
    {
      if (*srvlen < strlen (GSSAPI_SERVICE))
	return GSASL_TOO_SMALL_BUFFER;

      memcpy (srv, GSSAPI_SERVICE, strlen (GSSAPI_SERVICE));
    }

  if (srvlen)
    *srvlen = strlen (GSSAPI_SERVICE);

  if (host)
    {
      if (*hostlen < strlen (hostname))
	return GSASL_TOO_SMALL_BUFFER;

      memcpy (host, hostname, strlen (hostname));
    }

  if (hostlen)
    *hostlen = strlen (hostname);

  return GSASL_OK;
}

/* This gets called when SASL mechanism EXTERNAL is invoked */
static int
cb_external (Gsasl_session_ctx * ctx)
{
  return GSASL_AUTHENTICATION_ERROR;
}

/* This gets called when SASL mechanism CRAM-MD5 or DIGEST-MD5 is invoked */

static int
cb_retrieve (Gsasl_session_ctx * ctx,
	     const char *authentication_id,
	     const char *authorization_id,
	     const char *realm, char *key, size_t * keylen)
{
  ANUBIS_USER *usr = gsasl_server_application_data_get (ctx);
  
  if (usr->smtp_authid == NULL
      && anubis_get_db_record (authentication_id, usr) != ANUBIS_DB_SUCCESS)
    return GSASL_AUTHENTICATION_ERROR;

  if (key)
    {
      if (*keylen < strlen (usr->smtp_passwd))
	return GSASL_TOO_SMALL_BUFFER;
      strncpy (key, usr->smtp_passwd, *keylen);
    }
  else
    *keylen = strlen (usr->smtp_passwd);
  return GSASL_OK;
}


/* Initialization function */
void
auth_gsasl_init ()
{
  int rc;

  rc = gsasl_init (&ctx);
  if (rc != GSASL_OK)
    {
      info (NORMAL, _("cannot initialize libgsasl: %s"), gsasl_strerror (rc));
    }

  gsasl_server_callback_realm_set (ctx, cb_realm);
  gsasl_server_callback_external_set (ctx, cb_external);
  gsasl_server_callback_validate_set (ctx, cb_validate);
  gsasl_server_callback_service_set (ctx, cb_service);
  gsasl_server_callback_retrieve_set (ctx, cb_retrieve);

  auth_gsasl_capa_init ();
}

#endif
