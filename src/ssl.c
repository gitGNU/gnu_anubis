/*
   ssl.c

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

/************************
 OpenSSL package support
*************************/

#include "headers.h"
#include "extern.h"

#ifdef HAVE_SSL
#define X509BUFSIZE 1024

static void ssl_error(char *);
static void cipher_info(SSL *);
static int  rand_int(int);
static char *rand_md5(void);

void
init_ssl_libs(void)
{
	SSL_library_init();
	SSL_load_error_strings();

	if (!(RAND_status())) {
		char md5[33];
		info(VERBOSE, _("Seeding random number generator..."));
		safe_strcpy(md5, rand_md5());
		RAND_seed(md5, strlen(md5));
		if (!(RAND_status()))
			info(VERBOSE, _("Unable to seed random number generator."));
	}
	return;
}

static void
ssl_error(char *txt)
{
	char string_error[256];
	memset(string_error, 0, sizeof(string_error));
	ERR_error_string(ERR_get_error(), string_error);

	if (options.termlevel != SILENT) {
#ifdef HAVE_SYSLOG
		if ((topt & T_DAEMON) && !(topt & T_FOREGROUND))
			syslog(LOG_ERR | LOG_MAIL, string_error);
		else
#endif /* HAVE_SYSLOG */
			mprintf(">>%s", string_error);
	}
	anubis_error(HARD, txt);
	return;
}

SSL_CTX *
init_ssl_client(void)
{
	SSL_CTX *ctx_local = 0;
	SSL_METHOD *method = 0;

	if (!(method = SSLv23_client_method())) {
		ssl_error(_("SSLv23_client_method() failed."));
		return 0;
	}
	if (!(ctx_local = SSL_CTX_new(method))) {
		ssl_error(_("Can't create SSL_CTX object."));
		return 0;
	}
	SSL_CTX_set_default_verify_paths(ctx_local);
	if (!(SSL_CTX_set_cipher_list(ctx_local, "DEFAULT"))) {
		ssl_error(_("SSL_CTX_set_cipher_list() failed."));
		return 0;
	}
	SSL_CTX_set_verify(ctx_local, SSL_VERIFY_NONE, 0);

	return (SSL_CTX *)ctx_local;
}

SSL *
start_ssl_client(int sd_server, SSL_CTX *ctx_ptr)
{
	SSL *ssl_local = 0;
	info(VERBOSE, _("Initializing the TLS/SSL connection with MTA..."));

	if (!(ssl_local = SSL_new(ctx_ptr))) {
		ssl_error(_("Can't create a new SSL structure for a connection."));
		return 0;
	}
	if (!(SSL_set_fd(ssl_local, sd_server))) {
		ssl_error(_("SSL_set_fd() failed."));
		return 0;
	}
	SSL_set_connect_state(ssl_local);
	if (SSL_connect(ssl_local) <= 0) {
		ssl_error(_("TLS/SSL handshake failed!"));
		return 0;
	}
	topt |= T_SSL_CLIENT;

	if (options.termlevel > NORMAL)
		cipher_info(ssl_local);

	return (SSL *)ssl_local;
}

/***********************
 TLS/SSL SERVER support
************************/

SSL_CTX *
init_ssl_server(void)
{
	SSL_CTX *ctx_local = 0;
	SSL_METHOD *method = 0;

	if (!(method = SSLv23_server_method())) {
		ssl_error(_("SSLv23_server_method() failed."));
		return 0;
	}
	if (!(ctx_local = SSL_CTX_new(method))) {
		ssl_error(_("Can't create SSL_CTX object."));
		return 0;
	}
	if (SSL_CTX_use_certificate_file(ctx_local, secure.cert, SSL_FILETYPE_PEM) <= 0) {
		ssl_error(_("SSL_CTX_use_certificate_file() failed."));
		return 0;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx_local, secure.key, SSL_FILETYPE_PEM) <= 0) {
		ssl_error(_("SSL_CTX_use_PrivateKey_file() failed."));
		return 0;
	}
	if (!(SSL_CTX_check_private_key(ctx_local))) {
		ssl_error(_("Private key does not match the certificate public key."));
		return 0;
	}
	if (!(SSL_CTX_set_cipher_list(ctx_local, "DEFAULT"))) {
		ssl_error(_("SSL_CTX_set_cipher_list() failed."));
		return 0;
	}
	return (SSL_CTX *)ctx_local;
}

SSL *
start_ssl_server(int sd_client, SSL_CTX *ctx_ptr)
{
	SSL *ssl_local = 0;
	info(VERBOSE, _("Initializing the TLS/SSL connection with MUA..."));

	if (!(ssl_local = SSL_new(ctx_ptr))) {
		ssl_error(_("Can't create a new SSL structure for a connection."));
		return 0;
	}
	if (!(SSL_set_fd(ssl_local, sd_client))) {
		ssl_error(_("SSL_set_fd() failed."));
		return 0;
	}
	SSL_set_accept_state(ssl_local);
	if (SSL_accept(ssl_local) <= 0) {
		ssl_error(_("TLS/SSL handshake failed!"));
		return 0;
	}
	topt |= T_SSL_SERVER;

	if (options.termlevel > NORMAL)
		cipher_info(ssl_local);

	return (SSL *)ssl_local;
}

/*****************
 Certificate info
******************/

static void
cipher_info(SSL *ssl_local)
{
	X509 *cert = 0;
	char *x509buf = 0;
	int bits;

	SSL_CIPHER *cipher = SSL_get_current_cipher(ssl_local);

	if (cipher) {
		SSL_CIPHER_get_bits(cipher, &bits);
		info(VERBOSE,
		     ngettext("%s connection using %s (%u bit)",
			      "%s connection using %s (%u bits)"
			      bits),
		     SSL_CIPHER_get_version(cipher),
		     SSL_CIPHER_get_name(cipher), bits);
	}
	cert = SSL_get_peer_certificate(ssl_local);
	if (cert == 0)
		return;

	bits = EVP_PKEY_bits(X509_get_pubkey(cert));
	info(VERBOSE,
	     ngettext("Server public key is %d bit",
		      "Server public key is %d bits", bits),
	     bits);

	x509buf = (char *)xmalloc(X509BUFSIZE + 1);

	info(VERBOSE, _("Certificate:"));
	if (!(X509_NAME_oneline(X509_get_subject_name(cert), x509buf, X509BUFSIZE))) {
		ssl_error(_("X509_NAME_oneline [subject] failed!"));
		return;
	}
	info(VERBOSE, _("Subject: %s"), x509buf);
	if (!(X509_NAME_oneline(X509_get_issuer_name(cert), x509buf, X509BUFSIZE))) {
		ssl_error(_("X509_NAME_oneline [issuer] failed!"));
		return;
	}
	info(VERBOSE, _("Issuer:  %s"), x509buf);

	/*
	   Free unused memory.
	*/

	free(x509buf);
	X509_free(cert);
	return;
}

void
end_ssl(int method, SSL *ssl_ptr, SSL_CTX *ctx_ptr)
{
	if ((topt & T_SSL_CLIENT) || (topt & T_SSL_SERVER)) {
		if (ssl_ptr) {
			SSL_shutdown(ssl_ptr);
			SSL_free(ssl_ptr);
		}
		if (ctx_ptr)
			SSL_CTX_free(ctx_ptr);

		if (method == CLIENT)
			topt &= ~T_SSL_CLIENT;
		else if (method == SERVER)
			topt &= ~T_SSL_SERVER;
	}
	return;
}

static int
rand_int(int i)
{
	int seed;
	struct timeval tv;
	gettimeofday(&tv, 0);
	seed = (int)tv.tv_usec;
	seed = seed * 1103515245 + 12345;
	i = abs((int)((seed / 65536)%(i + 1)));
	return i;
}

static char *
rand_md5(void)
{
	int c;
	char buf[LINEBUFFER+1];
	unsigned char digest[16];
	static char ascii_digest[33];
	MD5_CTX context;

	snprintf(buf, LINEBUFFER,
		"%d%d%s", rand_int(32768), (int)getpid(), (char *)getlogin());

	MD5_Init(&context);
	MD5_Update(&context, (unsigned char *)buf, strlen(buf));
	MD5_Final(digest, &context);

	for (c = 0; c < 16; c++)
		sprintf(ascii_digest + 2 * c, "%02x", digest[c]);
	return (char *)ascii_digest;
}

#endif /* HAVE_SSL */

/* EOF */

