/*
   tls.c

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

/***********************
 GnuTLS package support
************************/

#include "headers.h"
#include "extern.h"

#ifdef HAVE_TLS
static gnutls_session initialize_tls_session(void);
static void generate_dh_params(void);
static void verify_certificate(gnutls_session);
static void print_x509_certificate_info(gnutls_session);
static int cipher_info(gnutls_session);

#define DH_BITS 768
gnutls_dh_params dh_params;

/* FIXME: should they belong to struct secure_struct? */
static gnutls_certificate_client_credentials xcred;
static gnutls_certificate_server_credentials x509_cred;

static const char *
_tls_strerror(int rc)
{
	return gnutls_strerror(rc);
}

static int
_tls_write(void *sd, char *data, size_t size, size_t *nbytes)
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
		rc = gnutls_record_send(sd, data, size);
	while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);
	if (rc >= 0) {
		*nbytes = rc;
		return 0;
	} 
	return rc;
}

static int
_tls_read(void *sd, char *data, size_t size, size_t *nbytes)
{
	int rc = gnutls_record_recv(sd, data, size);
	if (rc >= 0) {
		*nbytes = rc;
		return 0;
 	} 
	return rc;
}

static int
_tls_close(void *sd)
{
	if (sd) {
		gnutls_bye(sd, GNUTLS_SHUT_RDWR);
		gnutls_deinit(sd);
	}
	return 0;
}

static void
_tls_cleanup_xcred()
{
	if (xcred)
		gnutls_certificate_free_credentials(xcred);
}

static void
_tls_cleanup_x509()
{
	if (x509_cred)
		gnutls_certificate_free_credentials(x509_cred);
}

static ssize_t
_tls_fd_pull(gnutls_transport_ptr fd, void *buf, size_t size)
{
	int rc;
	do {
		rc = read(fd, buf, size);
	} while (rc == -1 && errno == EAGAIN);
	return rc;
}

static ssize_t
_tls_fd_push(gnutls_transport_ptr fd, const void *buf, size_t size)
{
	int rc;
	do {
		rc = write(fd, buf, size);
	} while (rc == -1 && errno == EAGAIN);
	return rc;
}

void
init_ssl_libs(void)
{
	gnutls_global_init();
	atexit(gnutls_global_deinit);
	return;
}

void *
start_ssl_client(int sd_server)
{
	int rs;
	gnutls_session session = 0;
	const int protocol_priority[] = {GNUTLS_TLS1, GNUTLS_SSL3, 0};
	const int kx_priority[] = {GNUTLS_KX_RSA, 0};
	const int cipher_priority[] = {GNUTLS_CIPHER_3DES_CBC,
				       GNUTLS_CIPHER_ARCFOUR_128,
				       0};
	const int comp_priority[] = {GNUTLS_COMP_NULL, 0};
	const int mac_priority[] = {GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0};

	info(VERBOSE, _("Initializing the TLS/SSL connection with MTA..."));

	gnutls_init(&session, GNUTLS_CLIENT);
	gnutls_protocol_set_priority(session, protocol_priority);
	gnutls_cipher_set_priority(session, cipher_priority);
	gnutls_compression_set_priority(session, comp_priority);
	gnutls_kx_set_priority(session, kx_priority);
	gnutls_mac_set_priority(session, mac_priority);

	gnutls_certificate_allocate_credentials(&xcred);
	if (secure.cafile) {
		rs = gnutls_certificate_set_x509_trust_file(xcred,
							    secure.cafile,
							    GNUTLS_X509_FMT_PEM);
		if (rs < 0) {
			anubis_error(HARD, _("TLS Error reading `%s': %s"),
				     secure.cafile,
				     gnutls_strerror(rs));
			return 0;
		}
	}
	
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	atexit(_tls_cleanup_xcred);

	if (topt & T_LOCAL_MTA) {
		gnutls_transport_set_pull_function(session, _tls_fd_pull);
		gnutls_transport_set_push_function(session, _tls_fd_push);
	}
	gnutls_transport_set_ptr(session, sd_server);

	rs = gnutls_handshake(session);
	if (rs < 0) {
		gnutls_deinit(session);
		anubis_error(HARD, _("TLS/SSL handshake failed: %s"),
			     gnutls_strerror(rs));
		return 0;
	}

	if (secure.cafile)
		verify_certificate(session);
	if (options.termlevel > NORMAL)
		cipher_info(session);

	net_set_io(CLIENT, _tls_read, _tls_write, _tls_close, _tls_strerror);
	return session;
}

/***********************
 TLS/SSL SERVER support
************************/

static void
generate_dh_params(void)
{
	gnutls_datum prime, generator;

	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate(&prime, &generator, DH_BITS);
	gnutls_dh_params_set(dh_params, prime, generator, DH_BITS);

	free(prime.data);
	free(generator.data);
	return;
}

static gnutls_session
initialize_tls_session(void)
{
	gnutls_session session = 0;

	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_set_default_priority(session);   
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);
	gnutls_dh_set_prime_bits(session, DH_BITS);

	return (gnutls_session)session;
}

void *
start_ssl_server(int sd_client)
{
	int rs;
	gnutls_session session = 0;

	info(VERBOSE, _("Initializing the TLS/SSL connection with MUA..."));

	gnutls_certificate_allocate_credentials(&x509_cred);
	atexit(_tls_cleanup_x509);
	if (secure.cafile) {
		rs = gnutls_certificate_set_x509_trust_file(x509_cred,
							    secure.cafile,
							    GNUTLS_X509_FMT_PEM);
		if (rs < 0) {
			anubis_error(HARD, _("TLS Error reading `%s': %s"),
				     secure.cafile,
				     gnutls_strerror(rs));
			return 0;
		}
	}
	gnutls_certificate_set_x509_key_file(x509_cred,
					     secure.cert, secure.key,
					     GNUTLS_X509_FMT_PEM);

	generate_dh_params();
	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	session = initialize_tls_session();

	if (topt & T_STDINOUT) {
		gnutls_transport_set_pull_function(session, _tls_fd_pull);
		gnutls_transport_set_push_function(session, _tls_fd_push);
	}
	gnutls_transport_set_ptr(session, sd_client);
	rs = gnutls_handshake(session);
	if (rs < 0) {
		gnutls_deinit(session);
		anubis_error(HARD, _("TLS/SSL handshake failed!"));
		gnutls_perror(rs);
		return 0;
	}
	if (options.termlevel > NORMAL)
		cipher_info(session);

	net_set_io(SERVER, _tls_read, _tls_write, _tls_close, _tls_strerror);
	return session;
}

static void
verify_certificate(gnutls_session session)
{
	int status = gnutls_certificate_verify_peers(session);

	if (status == GNUTLS_E_NO_CERTIFICATE_FOUND) {
		info(VERBOSE, _("No certificate was sent."));
		return;
	}
	if (status & GNUTLS_CERT_INVALID || status & GNUTLS_CERT_NOT_TRUSTED
	|| status & GNUTLS_CERT_CORRUPTED || status & GNUTLS_CERT_REVOKED) {
		info(VERBOSE, _("The certificate is not trusted."));
		return;
	}
	if (gnutls_certificate_expiration_time_peers(session) < time(0)) {
		info(VERBOSE, _("The certificate has expired."));
		return;
	}
	if (gnutls_certificate_activation_time_peers(session) > time(0)) {
		info(VERBOSE, _("The certificate is not yet activated."));
		return;
	}
	if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509) {
		const gnutls_datum *cert_list;
		int cert_list_size;
		cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
		if (cert_list == 0) {
			info(VERBOSE, _("No certificate was found!"));
			return;
		}
	}
	info(VERBOSE, _("The certificate is trusted."));
	return;
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
cipher_info(gnutls_session session)
{
	const char *tmp;
	gnutls_credentials_type cred;
	gnutls_kx_algorithm kx;
	int bits;

	kx = gnutls_kx_get(session);
	tmp = gnutls_kx_get_name(kx);
	fprintf(stderr, "- Key Exchange: %s\n", tmp);

	cred = gnutls_auth_get_type(session);
	switch (cred)
	{
		case GNUTLS_CRD_ANON: /* anonymous authentication */
			bits = gnutls_dh_get_prime_bits(session);
			info(VERBOSE,
			     ngettext("Anonymous DH using prime of %d bit.",
				      "Anonymous DH using prime of %d bits.",
				      bits),
			     bits);
			break;
		case GNUTLS_CRD_CERTIFICATE: /* certificate authentication */
			if (kx == GNUTLS_KX_DHE_RSA
			    || kx == GNUTLS_KX_DHE_DSS) {
				bits = gnutls_dh_get_prime_bits(session);
				info(VERBOSE,
				     ngettext("Ephemeral DH using prime of %d bit.",
					      "Ephemeral DH using prime of %d bits.",
					      bits),
				     bits);
			}
			print_x509_certificate_info(session);
			break;
		case GNUTLS_CRD_SRP:
			break;
	}

	tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
	fprintf(stderr, _("- Protocol: %s\n"), tmp);

	tmp = gnutls_certificate_type_get_name(gnutls_certificate_type_get(session));
	fprintf(stderr, _("- Certificate Type: %s\n"), tmp);

	tmp = gnutls_compression_get_name( gnutls_compression_get(session));
	fprintf(stderr, _("- Compression: %s\n"), tmp);

	tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
	fprintf(stderr, _("- Cipher: %s\n"), tmp);

	tmp = gnutls_mac_get_name(gnutls_mac_get(session));
	fprintf(stderr, _("- MAC: %s\n"), tmp);
	return 0;
}

static void
print_x509_certificate_info(gnutls_session session)
{
	char digest[20];
	char serial[40];
	size_t digest_size = sizeof(digest);
	int serial_size = sizeof(serial);
	time_t expiret = gnutls_certificate_expiration_time_peers(session);
	time_t activet = gnutls_certificate_activation_time_peers(session);
	const gnutls_datum *cert_list;
	int algo, bits, i;
	int cert_list_size = 0;
	gnutls_x509_dn dn;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list_size > 0
	    && gnutls_certificate_type_get(session) == GNUTLS_CRT_X509) {
		fprintf(stderr, _(" - Certificate info:\n"));
		fprintf(stderr, _(" - Certificate is valid since: %s"),
			ctime(&activet));
		fprintf(stderr, _(" - Certificate expires: %s"),
			ctime(&expiret));

		if (gnutls_x509_fingerprint(GNUTLS_DIG_MD5,
					    &cert_list[0], digest,
					    &digest_size) >= 0) {
			fprintf(stderr, _(" - Certificate fingerprint: "));
			for (i = 0; i < digest_size; i++) {
				fprintf(stderr, "%.2x ",
					(unsigned char) digest[i]);
			}
			fprintf(stderr, "\n");
		}

		if (gnutls_x509_extract_certificate_serial(&cert_list[0],
							   serial,
							   &serial_size) >= 0) {
			fprintf(stderr,
				_(" - Certificate serial number: "));
			for (i = 0; i < serial_size; i++) {
				fprintf(stderr, "%.2x ",
					(unsigned char) serial[i]);
			}
			fprintf(stderr, "\n");
		}
		algo = gnutls_x509_extract_certificate_pk_algorithm(&cert_list[0], &bits);

		fprintf(stderr, _("Certificate public key: "));
		if (algo == GNUTLS_PK_RSA) {
			fprintf(stderr, _("RSA\n"));
			fprintf(stderr, ngettext(" Modulus: %d bit\n",
						 " Modulus: %d bits\n", bits),
				bits);
		}
		else if (algo == GNUTLS_PK_DSA) {
			fprintf(stderr, _("DSA\n"));
			fprintf(stderr, ngettext(" Exponent: %d bit\n",
						 " Exponent: %d bits\n", bits),
				bits);
		}
		else
			fprintf(stderr, _("UNKNOWN\n"));

		fprintf(stderr, _(" - Certificate version: #%d\n"),
			gnutls_x509_extract_certificate_version(&cert_list[0]));

		gnutls_x509_extract_certificate_dn(&cert_list[0], &dn);
		PRINT_DN(dn);

		gnutls_x509_extract_certificate_issuer_dn(&cert_list[0], &dn);
		fprintf(stderr, _(" - Certificate Issuer's info:\n"));
		PRINT_DN(dn);
	}
}

#endif /* HAVE_TLS */

/* EOF */
