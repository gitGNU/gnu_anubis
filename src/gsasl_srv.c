/*
   gsasl_srv.c

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

#define ANUBIS_SERVICE "anubis"

char *anubis_sasl_service;
char *anubis_sasl_realm;
char *anubis_sasl_hostname;

#if defined(WITH_GSASL)

static Gsasl *ctx;
static ANUBIS_LIST anubis_mech_list;

/* Converts the auth method list from a textual representation to
   a ANUBIS_LIST of string values */
ANUBIS_LIST 
auth_method_list (const char *input)
{
  ANUBIS_LIST list = list_create ();

  while (*input)
    {
      size_t len = strcspn (input, " \t");
      char *p = xmalloc (len + 1);
      memcpy (p, input, len);
      p[len] = 0;
      list_append (list, p);
      
      input += len;
      while (*input && (*input == ' ' || *input == '\t'))
	input++;
    }
  return list;
}

/* Converts the authentication method ANUBIS_LIST to its textual
   representation. */
static void
auth_list_to_string (ANUBIS_LIST  list, char *buf, size_t bufsize)
{
  ITERATOR itr = iterator_create (list);
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
anubis_set_mech_list (ANUBIS_LIST *out, ANUBIS_LIST list)
{
  ITERATOR itr = iterator_create (list);
  char *p;

  if (!itr)
    return;
  *out = list_create ();
  for (p = iterator_first (itr); p; p = iterator_next (itr))
    list_append (*out, make_uppercase (strdup (p)));
  iterator_destroy (&itr);
}

void
anubis_set_server_mech_list (ANUBIS_LIST list)
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
      ANUBIS_LIST mech = auth_method_list (listmech);

      /* Compute intersection of both lists. Make sure we compute
	 (anubis_mech_list X mech), not (mech X anubis_mech_list),
	 so that the resulting list preserves the ordering of
	 anubis_mech_list */
      ANUBIS_LIST p = list_intersect (anubis_mech_list, mech,
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
anubis_auth_gsasl (char *auth_type, char *arg, ANUBIS_USER * usr)
{
  char *input = NULL;
  size_t input_size = 0;
  char *output;
  int rc;
  Gsasl_session *sess_ctx = NULL;

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

  gsasl_callback_hook_set (ctx, usr);

  output = NULL;
  /* RFC 2554 4.:
     Unlike a zero-length client answer to a 334 reply, a zero-
     length initial response is sent as a single equals sign */
  if (arg)
    {
      if (strcmp (arg, "=") == 0)
	arg = "";
      
      input = xstrdup (arg);
      input_size = strlen (input) + 1;
    }
  
  while ((rc = gsasl_step64 (sess_ctx, input, &output)) == GSASL_NEEDS_MORE)
    {
      asmtp_reply (334, "%s", output);
      recvline (SERVER, remote_client, &input, &input_size);
      remcrlf (input);
      if (strcmp (input, "*") == 0)
	{
	  asmtp_reply (501, "AUTH aborted");
	  free (input);
	  return 1;
	}
    }

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
    install_gsasl_stream (sess_ctx, &remote_client);

  asmtp_reply (235, "Authentication successful.");
  return 0;
}


static int
retrieve_password (Gsasl *ctx, Gsasl_session *sctx)
{
  ANUBIS_USER *usr = gsasl_callback_hook_get (ctx);
  const char *authid = gsasl_property_get (sctx, GSASL_AUTHID);

  if (usr->smtp_authid == NULL
      && anubis_get_db_record (authid, usr) != ANUBIS_DB_SUCCESS)
    return GSASL_AUTHENTICATION_ERROR;

  gsasl_property_set (sctx, GSASL_PASSWORD, usr->smtp_passwd);
  return GSASL_OK;
}

static int
cb_validate (Gsasl *ctx, Gsasl_session *sctx)
{
  ANUBIS_USER *usr = gsasl_callback_hook_get (ctx);
  const char *authid = gsasl_property_get (sctx, GSASL_AUTHID);
  const char *pass = gsasl_property_get (sctx, GSASL_PASSWORD);

  if (!authid)
    return GSASL_NO_AUTHID;
  if (!pass)
    return GSASL_NO_PASSWORD;

  if (usr->smtp_authid == NULL
        && anubis_get_db_record (authid, usr) != ANUBIS_DB_SUCCESS)
    return GSASL_AUTHENTICATION_ERROR;

  if (usr->smtp_authid == NULL
      || strcmp (usr->smtp_authid, authid)
      || strcmp (usr->smtp_passwd, pass))
    return GSASL_AUTHENTICATION_ERROR;
  return GSASL_OK;
}

static int
callback (Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop)
{
  int rc = GSASL_OK;
  
  switch (prop)
    {
    case GSASL_PASSWORD:
      rc = retrieve_password (ctx, sctx);
      break;

    case GSASL_SERVICE:
      gsasl_property_set (sctx, prop,
			  anubis_sasl_service ?
			    anubis_sasl_service : ANUBIS_SERVICE);
      break;

    case GSASL_REALM:
      gsasl_property_set (sctx, prop,
			  anubis_sasl_realm ?
			    anubis_sasl_realm : get_localdomain ());
      break;

    case GSASL_HOSTNAME:
      gsasl_property_set (sctx, prop,
			  anubis_sasl_hostname ?
			    anubis_sasl_hostname : get_localname ());
      break;

#if 0
    FIXME:
    case GSASL_VALIDATE_EXTERNAL:
    case GSASL_VALIDATE_SECURID:
#endif

    case GSASL_VALIDATE_SIMPLE:
      rc = cb_validate (ctx, sctx);
      break;

    case GSASL_VALIDATE_ANONYMOUS:
      /* FIXME: */
      info (NORMAL, _("Anonymous access not supported"));
      rc = GSASL_AUTHENTICATION_ERROR;
      break;

    case GSASL_VALIDATE_GSSAPI:
      {
	ANUBIS_USER *usr = gsasl_callback_hook_get (ctx);
	/* FIXME: Free? */
	usr->smtp_authid = strdup (gsasl_property_get(sctx, GSASL_AUTHZID));
	break;
      }
      
    default:
      rc = GSASL_NO_CALLBACK;
      anubis_error (0, 0, _("Unsupported callback property %d"), prop);
      break;
    }

  return rc;
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

  gsasl_callback_set (ctx, callback);

  auth_gsasl_capa_init ();
}

#endif
