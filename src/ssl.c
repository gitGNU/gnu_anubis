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

struct ssl_session {
	SSL *ssl;
	SSL_CTX *ctx;
};

typedef struct ssl_session SESS;

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

static const char *
_ssl_strerror(int rc)
{
	return ERR_error_string(rc, NULL);
}

static int
_ssl_write(void *sd, char *data, size_t size, size_t *nbytes)
{
	SESS *sess = sd;
	int rc, ec;

	do {
		rc = SSL_write(sess->ssl, data, size);
	} while (rc <= 0
		 && (ec = SSL_get_error(sess->ssl, rc))
		                     == SSL_ERROR_WANT_WRITE);
	if (rc > 0) {
		*nbytes = rc;
		return 0;
	}
	return ec;
}

static int
_ssl_read(void *sd, char *data, size_t size, size_t *nbytes)
{
	SESS *sess = sd;
	int rc, ec;

	do {
		rc = SSL_read(sess->ssl, data, size);
	} while (rc <= 0
		 && (ec = SSL_get_error(sess->ssl, rc))
		                     == SSL_ERROR_WANT_READ);
	if (rc > 0) {
		*nbytes = rc;
		return 0;
	}
	return ec;
}

static int
_ssl_close(void *sd)
{
	SESS *sess = sd;
	if (sess && sess->ssl) {
		SSL_shutdown(sess->ssl);
		SSL_free(sess->ssl);
	}
	if (sess->ctx)
		SSL_CTX_free(sess->ctx);
	free(sd);
	return 0;
}

static void
ssl_error(char *txt)
{
	char *string_error = ERR_error_string(ERR_get_error(), NULL);

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

void *
start_ssl_client(int sd_server)
{
	SESS *sd;
	SSL *ssl = 0;
	SSL_CTX *ctx = init_ssl_client();
		
	info(VERBOSE, _("Initializing the TLS/SSL connection with MTA..."));

	if (!(ssl = SSL_new(ctx))) {
		ssl_error(_("Can't create a new SSL structure for a connection."));
		return 0;
	}
	if (!(SSL_set_fd(ssl, sd_server))) {
		ssl_error(_("SSL_set_fd() failed."));
		return 0;
	}
	SSL_set_connect_state(ssl);
	if (SSL_connect(ssl) <= 0) {
		ssl_error(_("TLS/SSL handshake failed!"));
		return 0;
	}

	if (options.termlevel > NORMAL)
		cipher_info(ssl);

	sd = xmalloc(sizeof(*sd));
	sd->ssl = ssl;
	sd->ctx = ctx;
	net_set_io(CLIENT, _ssl_read, _ssl_write, _ssl_close, _ssl_strerror);
	return sd;
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

void *
start_ssl_server(int sd_client)
{
	SESS *sd;
	SSL *ssl = 0;
	SSL_CTX *ctx = init_ssl_server();
	
	info(VERBOSE, _("Initializing the TLS/SSL connection with MUA..."));

	if (!(ssl = SSL_new(ctx))) {
		ssl_error(_("Can't create a new SSL structure for a connection."));
		return 0;
	}
	if (!(SSL_set_fd(ssl, sd_client))) {
		ssl_error(_("SSL_set_fd() failed."));
		return 0;
	}
	SSL_set_accept_state(ssl);
	if (SSL_accept(ssl) <= 0) {
		ssl_error(_("TLS/SSL handshake failed!"));
		return 0;
	}

	if (options.termlevel > NORMAL)
		cipher_info(ssl);

	sd = xmalloc(sizeof(*sd));
	sd->ssl = ssl;
	sd->ctx = ctx;
	net_set_io(SERVER, _ssl_read, _ssl_write, _ssl_close, _ssl_strerror);
	return sd;
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
			      "%s connection using %s (%u bits)",
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

