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

void
init_tls_libs(void)
{
	gnutls_global_init();
	return;
}

gnutls_session
start_tls_client(int sd_server)
{
	int rs;
	gnutls_session session = 0;
	const int protocol_priority[] = {GNUTLS_TLS1, GNUTLS_SSL3, 0};
	const int kx_priority[] = {GNUTLS_KX_RSA, 0};
	const int cipher_priority[] = {GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR_128, 0};
	const int comp_priority[] = {GNUTLS_COMP_NULL, 0};
	const int mac_priority[] = {GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0};

	info(VERBOSE, _("Initializing the TLS/SSL connection with MTA..."));

	gnutls_init(&session, GNUTLS_CLIENT);
	gnutls_protocol_set_priority(session, protocol_priority);
	gnutls_cipher_set_priority(session, cipher_priority);
	gnutls_compression_set_priority(session, comp_priority);
	gnutls_kx_set_priority(session, kx_priority);
	gnutls_mac_set_priority(session, mac_priority);

	gnutls_certificate_allocate_credentials(&secure.xcred);
	if (secure.cafile)
		gnutls_certificate_set_x509_trust_file(secure.xcred,
			secure.cafile, GNUTLS_X509_FMT_PEM);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, secure.xcred);
	gnutls_transport_set_ptr(session, sd_server);

	rs = gnutls_handshake(session);
	if (rs < 0) {
		gnutls_deinit(session);
		anubis_error(HARD, _("TLS/SSL handshake failed!"));
		gnutls_perror(rs);
		return 0;
	}
	topt |= T_SSL_CLIENT;

	if (secure.cafile)
		verify_certificate(session);
	if (options.termlevel > NORMAL)
		cipher_info(session);

	return (gnutls_session)session;
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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, secure.x509_cred);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);
	gnutls_dh_set_prime_bits(session, DH_BITS);

	return (gnutls_session)session;
}

gnutls_session
start_tls_server(int sd_client)
{
	int rs;
	gnutls_session session = 0;

	info(VERBOSE, _("Initializing the TLS/SSL connection with MUA..."));

	gnutls_certificate_allocate_credentials(&secure.x509_cred);
	if (secure.cafile) {
		gnutls_certificate_set_x509_trust_file(secure.x509_cred,
			secure.cafile, GNUTLS_X509_FMT_PEM);
	}
	gnutls_certificate_set_x509_key_file(secure.x509_cred,
		secure.cert, secure.key, GNUTLS_X509_FMT_PEM);

	generate_dh_params();
	gnutls_certificate_set_dh_params(secure.x509_cred, dh_params);

	session = initialize_tls_session();
	gnutls_transport_set_ptr(session, sd_client);
	rs = gnutls_handshake(session);
	if (rs < 0) {
		gnutls_deinit(session);
		anubis_error(HARD, _("TLS/SSL handshake failed!"));
		gnutls_perror(rs);
		return 0;
	}
	topt |= T_SSL_SERVER;
	if (options.termlevel > NORMAL)
		cipher_info(session);

	return (gnutls_session)session;
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

#define PRINTX(x,y) if (y[0]!=0) printf(" -   %s %s\n", x, y)
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
	printf("- Key Exchange: %s\n", tmp);

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
	printf(_("- Protocol: %s\n"), tmp);

	tmp = gnutls_certificate_type_get_name(gnutls_certificate_type_get(session));
	printf(_("- Certificate Type: %s\n"), tmp);

	tmp = gnutls_compression_get_name( gnutls_compression_get(session));
	printf(_("- Compression: %s\n"), tmp);

	tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
	printf(_("- Cipher: %s\n"), tmp);

	tmp = gnutls_mac_get_name(gnutls_mac_get(session));
	printf(_("- MAC: %s\n"), tmp);
	return 0;
}

static void
print_x509_certificate_info(gnutls_session session)
{
	char digest[20];
	char serial[40];
	size_t digest_size = sizeof(digest);
	int serial_size = sizeof(serial);
	char printable[120];
	char *print;
	time_t expiret = gnutls_certificate_expiration_time_peers(session);
	time_t activet = gnutls_certificate_activation_time_peers(session);
	const gnutls_datum *cert_list;
	int algo, bits, i;
	int cert_list_size = 0;
	gnutls_x509_dn dn;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list_size > 0 && gnutls_certificate_type_get(session)
	== GNUTLS_CRT_X509) {
		printf(_(" - Certificate info:\n"));
		printf(_(" - Certificate is valid since: %s"), ctime(&activet));
		printf(_(" - Certificate expires: %s"), ctime(&expiret));

		if (gnutls_x509_fingerprint(GNUTLS_DIG_MD5,
		&cert_list[0], digest, &digest_size) >= 0) {
			print = printable;
			for (i = 0; i < digest_size; i++) {
				sprintf(print, "%.2x ", (unsigned char) digest[i]);
				print += 3;
			}
			printf(_(" - Certificate fingerprint: %s\n"), printable);
		}

		if (gnutls_x509_extract_certificate_serial(&cert_list[0],
		serial, &serial_size) >= 0) {
			print = printable;
			for (i = 0; i < serial_size; i++) {
				sprintf(print, "%.2x ", (unsigned char) serial[i]);
				print += 3;
			}
			printf(_(" - Certificate serial number: %s\n"), printable);
		}
		algo = gnutls_x509_extract_certificate_pk_algorithm(&cert_list[0], &bits);

		printf(_("Certificate public key: "));
		if (algo == GNUTLS_PK_RSA) {
			printf(_("RSA\n"));
			printf(ngettext(" Modulus: %d bit\n",
					" Modulus: %d bits\n", bits), bits);
		}
		else if (algo == GNUTLS_PK_DSA) {
			printf(_("DSA\n"));
			printf(ngettext(" Exponent: %d bit\n",
					" Exponent: %d bits\n", bits), bits);
		}
		else
			printf(_("UNKNOWN\n"));

		printf(_(" - Certificate version: #%d\n"),
			gnutls_x509_extract_certificate_version(&cert_list[0]));

		gnutls_x509_extract_certificate_dn(&cert_list[0], &dn);
		PRINT_DN(dn);

		gnutls_x509_extract_certificate_issuer_dn(&cert_list[0], &dn);
		printf(_(" - Certificate Issuer's info:\n"));
		PRINT_DN(dn);
	}
}

void
end_tls(int method, gnutls_session session)
{
	if ((topt & T_SSL_CLIENT) || (topt & T_SSL_SERVER)) {
		if (session) {
			gnutls_bye(session, GNUTLS_SHUT_RDWR);
			gnutls_deinit(session);
		}
		if (method == CLIENT)
			topt &= ~T_SSL_CLIENT;
		else if (method == SERVER)
			topt &= ~T_SSL_SERVER;
	}
	return;
}

#endif /* HAVE_TLS */

/* EOF */

