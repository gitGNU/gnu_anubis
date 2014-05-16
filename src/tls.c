/*
   tls.c

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

/***********************
 GnuTLS package support
************************/

#include "headers.h"
#include "extern.h"

static gnutls_session_t initialize_tls_session (void);
static void generate_dh_params (void);
static void verify_certificate (gnutls_session_t);
static void print_x509_certificate_info (gnutls_session_t);
static int cipher_info (gnutls_session_t);

#define DH_BITS 768
gnutls_dh_params_t dh_params;

static gnutls_certificate_client_credentials xcred;
static gnutls_certificate_server_credentials x509_cred;

static const char *
_tls_strerror (void *unused_data, int rc)
{
  return gnutls_strerror (rc);
}

static int
_tls_write (void *sd, const char *data, size_t size, size_t * nbytes)
{
  int rc;

  /* gnutls_record_send() docs say:
     If the EINTR is returned by the internal push function (write())
     then GNUTLS_E_INTERRUPTED, will be returned. If
     GNUTLS_E_INTERRUPTED or GNUTLS_E_AGAIN is returned you must call
     this function again, with the same parameters. Otherwise the write
     operation will be corrupted and the connection will be
     terminated. */

  do
    rc = gnutls_record_send (sd, data, size);
  while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);
  if (rc >= 0)
    {
      *nbytes = rc;
      return 0;
    }
  return rc;
}

static int
_tls_read (void *sd, char *data, size_t size, size_t * nbytes)
{
  int rc = gnutls_record_recv (sd, data, size);
  if (rc >= 0)
    {
      *nbytes = rc;
      return 0;
    }
  return rc;
}

static int
_tls_close (void *sd)
{
  if (sd)
    {
      gnutls_bye (sd, GNUTLS_SHUT_RDWR);
      gnutls_deinit (sd);
    }
  return 0;
}

static void
_tls_cleanup_xcred ()
{
  if (xcred)
    gnutls_certificate_free_credentials (xcred);
}

static void
_tls_cleanup_x509 ()
{
  if (x509_cred)
    gnutls_certificate_free_credentials (x509_cred);
}

static ssize_t
_tls_fd_pull (gnutls_transport_ptr_t fd, void *buf, size_t size)
{
  NET_STREAM stream = fd;
  int rc;
  size_t rdbytes;

  do
    {
      rc = stream_read (stream, buf, size, &rdbytes);
    }
  while (rc != 0 && errno == EAGAIN);
  if (rc)
    return -1;
  return rdbytes;
}

static ssize_t
_tls_fd_push (gnutls_transport_ptr_t fd, const void *buf, size_t size)
{
  NET_STREAM stream = fd;

  int rc;
  size_t wrbytes;
  do
    {
      rc = stream_write (stream, buf, size, &wrbytes);
    }
  while (rc != 0 && errno == EAGAIN);
  if (rc)
    return -1;
  return wrbytes;
}

void
init_ssl_libs (void)
{
  gnutls_global_init ();
  atexit (gnutls_global_deinit);
}

static char *default_priority_string = "NORMAL";

NET_STREAM
start_ssl_client (NET_STREAM sd_server, int verbose)
{
  NET_STREAM stream;
  int rs;
  gnutls_session_t session = 0;

  info (VERBOSE, _("Initializing TLS/SSL connection with MTA..."));

  gnutls_init (&session, GNUTLS_CLIENT);
  gnutls_priority_set_direct (session,
			      secure.prio
			        ? secure.prio
			        : default_priority_string,
			      NULL);
  

  gnutls_certificate_allocate_credentials (&xcred);
  if (secure.cafile)
    {
      rs = gnutls_certificate_set_x509_trust_file (xcred,
						   secure.cafile,
						   GNUTLS_X509_FMT_PEM);
      if (rs < 0)
	{
	  anubis_error (0, 0, _("TLS error reading `%s': %s"),
			secure.cafile, gnutls_strerror (rs));
	  return 0;
	}
    }

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  atexit (_tls_cleanup_xcred);

  gnutls_transport_set_pull_function (session, _tls_fd_pull);
  gnutls_transport_set_push_function (session, _tls_fd_push);
  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd_server);

  rs = gnutls_handshake (session);
  if (rs < 0)
    {
      gnutls_deinit (session);
      anubis_error (0, 0, _("TLS/SSL handshake failed: %s"),
		    gnutls_strerror (rs));
      return NULL;
    }

  if (secure.cafile)
    verify_certificate (session);
  if (verbose)
    cipher_info (session);

  stream_create (&stream);
  stream_set_io (stream,
		 session,
		 _tls_read, _tls_write, _tls_close, NULL, _tls_strerror);
  return stream;
}

/***********************
 TLS/SSL SERVER support
************************/

static void
generate_dh_params (void)
{
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, DH_BITS);
}

static gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session = 0;

  gnutls_init (&session, GNUTLS_SERVER);
  gnutls_set_default_priority (session);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
  gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);
  gnutls_dh_set_prime_bits (session, DH_BITS);

  return (gnutls_session_t) session;
}

NET_STREAM
start_ssl_server (NET_STREAM sd_client, int verbose)
{
  NET_STREAM stream;
  int rs;
  gnutls_session_t session = 0;

  info (VERBOSE, _("Initializing the TLS/SSL connection with MUA..."));

  gnutls_certificate_allocate_credentials (&x509_cred);
  atexit (_tls_cleanup_x509);
  if (secure.cafile)
    {
      rs = gnutls_certificate_set_x509_trust_file (x509_cred,
						   secure.cafile,
						   GNUTLS_X509_FMT_PEM);
      if (rs < 0)
	{
	  anubis_error (0, 0, _("TLS error reading `%s': %s"),
			secure.cafile, gnutls_strerror (rs));
	  return 0;
	}
    }
  gnutls_certificate_set_x509_key_file (x509_cred,
					secure.cert, secure.key,
					GNUTLS_X509_FMT_PEM);

  generate_dh_params ();
  gnutls_certificate_set_dh_params (x509_cred, dh_params);

  session = initialize_tls_session ();

  gnutls_transport_set_pull_function (session, _tls_fd_pull);
  gnutls_transport_set_push_function (session, _tls_fd_push);

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd_client);
  rs = gnutls_handshake (session);
  if (rs < 0)
    {
      gnutls_deinit (session);
      anubis_error (0, 0, _("TLS/SSL handshake failed!"));
      gnutls_perror (rs);
      return 0;
    }
  if (verbose)
    cipher_info (session);

  stream_create (&stream);
  stream_set_io (stream,
		 session,
		 _tls_read, _tls_write, _tls_close, NULL, _tls_strerror);
  return stream;
}

static void
verify_certificate (gnutls_session_t session)
{
  int status, rc;

  rc = gnutls_certificate_verify_peers2 (session, &status);
  if (rc)
    {
      info (VERBOSE, "gnutls_certificate_verify_peers2: %s",
	    gnutls_strerror (rc));
      return;
    }

  if (status & GNUTLS_CERT_INVALID || status & GNUTLS_CERT_REVOKED)
    {
      info (VERBOSE, _("The certificate is not trusted."));
      return;
    }
  if (gnutls_certificate_expiration_time_peers (session) < time (0))
    {
      info (VERBOSE, _("The certificate has expired."));
      return;
    }
  if (gnutls_certificate_activation_time_peers (session) > time (0))
    {
      info (VERBOSE, _("The certificate is not yet activated."));
      return;
    }
  if (gnutls_certificate_type_get (session) == GNUTLS_CRT_X509)
    {
      const gnutls_datum_t *cert_list;
      unsigned int cert_list_size;
      cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
      if (cert_list == 0)
	{
	  info (VERBOSE, _("No certificate was found!"));
	  return;
	}
    }

  info (VERBOSE, _("The certificate is trusted."));
}

#define PRINTX(x,y) if (y[0]!=0) fprintf(stderr, " -   %s %s\n", x, y);
#define PRINT_DN(X) PRINTX( "CN:", X.common_name); \
	PRINTX( "OU:", X.organizational_unit_name); \
	PRINTX( "O:", X.organization); \
	PRINTX( "L:", X.locality_name); \
	PRINTX( "S:", X.state_or_province_name); \
	PRINTX( "C:", X.country); \
	PRINTX( "E:", X.email)

static int
cipher_info (gnutls_session_t session)
{
  const char *tmp;
  gnutls_credentials_type_t cred;
  gnutls_kx_algorithm_t kx;
  int bits;

  kx = gnutls_kx_get (session);
  tmp = gnutls_kx_get_name (kx);
  fprintf (stderr, "- Key Exchange: %s\n", tmp);

  cred = gnutls_auth_get_type (session);
  switch (cred)
    {
    case GNUTLS_CRD_ANON:	/* anonymous authentication */
      bits = gnutls_dh_get_prime_bits (session);
      fprintf (stderr,
	    ngettext ("- Anonymous DH using prime of %d bit.\n",
		      "- Anonymous DH using prime of %d bits.\n", bits), bits);
      break;

    case GNUTLS_CRD_CERTIFICATE:	/* certificate authentication */
      if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS)
	{
	  bits = gnutls_dh_get_prime_bits (session);
	  fprintf (stderr,
		ngettext ("- Ephemeral DH using prime of %d bit.\n",
			  "- Ephemeral DH using prime of %d bits.\n",
			  bits), bits);
	}
      print_x509_certificate_info (session);
      break;

    default:
      break;
    }

  tmp = gnutls_protocol_get_name (gnutls_protocol_get_version (session));
  fprintf (stderr, _("- Protocol: %s\n"), tmp);

  tmp =
    gnutls_certificate_type_get_name (gnutls_certificate_type_get (session));
  fprintf (stderr, _("- Certificate Type: %s\n"), tmp);

  tmp = gnutls_compression_get_name (gnutls_compression_get (session));
  fprintf (stderr, _("- Compression: %s\n"), tmp);

  tmp = gnutls_cipher_get_name (gnutls_cipher_get (session));
  fprintf (stderr, _("- Cipher: %s\n"), tmp);

  tmp = gnutls_mac_get_name (gnutls_mac_get (session));
  fprintf (stderr, _("- MAC: %s\n"), tmp);
  return 0;
}

static void
print_x509_certificate_info (gnutls_session_t session)
{
  char dn[128];
  char digest[20];
  char serial[40];
  size_t dn_size = sizeof (dn);
  size_t digest_size = sizeof (digest);
  size_t serial_size = sizeof (serial);
  time_t expiret, activet;
  int algo;
  unsigned i;
  unsigned bits;
  unsigned cert_list_size = 0;
  const gnutls_datum_t *cert_list;
  gnutls_x509_crt_t cert;

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);

  if (cert_list_size > 0
      && gnutls_certificate_type_get (session) == GNUTLS_CRT_X509)
    {

      gnutls_x509_crt_init (&cert);
      gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_PEM);

      fprintf (stderr, _("- Certificate info:\n"));

      expiret = gnutls_x509_crt_get_expiration_time (cert);
      activet = gnutls_x509_crt_get_activation_time (cert);
      fprintf (stderr, _("- Certificate is valid since: %s"),
	       ctime (&activet));
      fprintf (stderr, _("- Certificate expires: %s"), ctime (&expiret));

      if (gnutls_fingerprint (GNUTLS_DIG_MD5,
				   &cert_list[0], digest, &digest_size) >= 0)
	{
	  fprintf (stderr, _("- Certificate fingerprint: "));
	  for (i = 0; i < digest_size; i++)
	    {
	      fprintf (stderr, "%.2x ", (unsigned char) digest[i]);
	    }
	  fprintf (stderr, "\n");
	}

      if (gnutls_x509_crt_get_serial (cert, serial, &serial_size) >= 0)
	{
	  fprintf (stderr, _("- Certificate serial number: "));
	  for (i = 0; i < serial_size; i++)
	    {
	      fprintf (stderr, "%.2x ", (unsigned char) serial[i]);
	    }
	  fprintf (stderr, "\n");
	}
      algo = gnutls_x509_crt_get_pk_algorithm (cert, &bits);

      fprintf (stderr, _("- Certificate public key: "));
      if (algo == GNUTLS_PK_RSA)
	{
	  fprintf (stderr, _("RSA\n"));
	  fprintf (stderr, ngettext ("- Modulus: %d bit\n",
				     "- Modulus: %d bits\n", bits), bits);
	}
      else if (algo == GNUTLS_PK_DSA)
	{
	  fprintf (stderr, _("DSA\n"));
	  fprintf (stderr, ngettext ("- Exponent: %d bit\n",
				     "- Exponent: %d bits\n", bits), bits);
	}
      else
	fprintf (stderr, _("UNKNOWN\n"));

      fprintf (stderr, _("- Certificate version: #%d\n"),
	       gnutls_x509_crt_get_version (cert));

      gnutls_x509_crt_get_dn (cert, dn, &dn_size);
      fprintf (stderr, "- DN: %s\n", dn);

      gnutls_x509_crt_get_issuer_dn (cert, dn, &dn_size);
      fprintf (stderr, _("- Certificate Issuer's DN: %s\n"), dn);

      gnutls_x509_crt_deinit (cert);
    }
}

/* EOF */
