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
#include <openssl/bio.h>

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


/* SSL BIO Support */
static int
net_stream_write(BIO *bio, const char *buf, int size)
{
	if (bio->init && buf) {
		size_t wrsize;
		int rc = stream_write(bio->ptr, buf, size, &wrsize);
		if (rc) {
			anubis_error(HARD,
				     _("Write error: %s"),
				     stream_strerror(bio->ptr, rc));
			return -1;
		}
		return wrsize;
	}
	return 0;
}

static int
net_stream_read(BIO *bio, char *buf, int size)
{
	if (bio->init && buf) {
		size_t rdsize;
		int rc = stream_read(bio->ptr, buf, size, &rdsize);
		if (rc) {
			anubis_error(HARD,
				     _("Read error: %s"),
				     stream_strerror(bio->ptr, rc));
			return -1;
		}
		return rdsize;
	}
	return 0;
}

static int
net_stream_puts(BIO *bio, const char *str)
{
	return net_stream_write(bio, str, strlen(str));
}

static long
net_stream_ctrl(BIO *bio, int cmd, long arg1, void *arg2)
{
	long rc = 1;
	switch (cmd) {
	case BIO_CTRL_PUSH:
	case BIO_CTRL_FLUSH:
		break;
		
	case BIO_C_SET_FILE_PTR:
		bio->init = 1;
		bio->ptr = arg2;
		bio->shutdown = (int) arg1 & BIO_CLOSE;
		return 1;
		
        case BIO_CTRL_GET_CLOSE:
		rc = (long) bio->shutdown;
		break;
		
	case BIO_CTRL_SET_CLOSE:
		bio->shutdown = (int) arg1;
		break;
		
	default:
		/*info(VERBOSE, "net_stream_ctrl: cmd=%d, arg1=%d, arg2=%p",
		       cmd, arg1, arg2);*/
		rc = 0;
		break;
	}
	return rc;
}

static int
net_stream_new(BIO *bio)
{
        bio->init = 0;
	bio->num = 0;
	bio->ptr = NULL;
	return(1);
}

static int
net_stream_free(BIO *bio)
{
        if (!bio)
		return 0;
	if (bio->shutdown) {
		if (bio->init && bio->ptr) {
			stream_close((NET_STREAM) bio->ptr);
			bio->ptr = NULL;
		}
		bio->init = 0;
	}
	return 1;
}


static BIO_METHOD method_net_stream =
{
	BIO_TYPE_SOURCE_SINK,      /* type */
	"ANUBIS NET_STREAM",       /* name */
	net_stream_write,          /* bwrite */
	net_stream_read,           /* bread */
	net_stream_puts,           /* bputs */
	NULL,                      /* bgets */
	net_stream_ctrl,           /* ctrl */
	net_stream_new,            /* create */
	net_stream_free,           /* destroy */
	NULL,                      /* callback */
};

BIO *
BIO_new_net_stream(NET_STREAM stream)
{
	BIO *bio;

	if ((bio = BIO_new(&method_net_stream)) == NULL)
		return NULL;
	BIO_set_fp(bio, stream, BIO_CLOSE);
	return bio;
}	


/* NET_STREAM I/O Support */

static const char *
_ssl_strerror(void *unused_data, int rc)
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
			syslog(LOG_ERR | LOG_MAIL, "%s", string_error);
		else
#endif /* HAVE_SYSLOG */
			mprintf(">>%s", string_error);
	}
	anubis_error(HARD, "%s", txt);
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



/* FIXME: cafile is not used */
NET_STREAM
start_ssl_client(NET_STREAM sd_server, const char *cafile, int verbose)
{
	NET_STREAM stream;
	SESS *sd;
	SSL *ssl = 0;
	SSL_CTX *ctx = init_ssl_client(); 
	BIO *rbio, *wbio;
	int rc;
	
	info(VERBOSE, _("Initializing the TLS/SSL connection with MTA..."));

	if (!(ssl = SSL_new(ctx))) {
		ssl_error(_("Can't create a new SSL structure for a connection."));
		return 0;
	}

	rbio = BIO_new_net_stream(sd_server);
	wbio = BIO_new_net_stream(sd_server);
	
	/* Set up BIOs */
	SSL_set_bio(ssl, rbio, wbio);

	SSL_set_connect_state(ssl);
	rc = SSL_connect(ssl);
	
	if (rc <= 0) {
		anubis_error(HARD,
			     _("TLS/SSL handshake failed: %s"),
			     ERR_error_string(SSL_get_error(ssl, rc), NULL));
		return 0;
	}

	if (verbose)
		cipher_info(ssl);

	sd = xmalloc(sizeof(*sd));
	sd->ssl = ssl;
	sd->ctx = ctx;
	stream_create(&stream);
	stream_set_io(stream,
		      sd,
		      _ssl_read, _ssl_write,
		      _ssl_close, NULL, _ssl_strerror);
	return stream;
}

/***********************
 TLS/SSL SERVER support
************************/

SSL_CTX *
init_ssl_server(const char *cert, const char *key)
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
	if (SSL_CTX_use_certificate_file(ctx_local, cert, SSL_FILETYPE_PEM) <= 0) {
		ssl_error(_("SSL_CTX_use_certificate_file() failed."));
		return 0;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx_local, key, SSL_FILETYPE_PEM) <= 0) {
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

/* FIXME: cafile is not used */
NET_STREAM
start_ssl_server(NET_STREAM sd_client, const char *cafile, const char *cert,
		 const char *key, int verbose)
{
	NET_STREAM stream;
	SESS *sd;
	SSL *ssl = 0;
	SSL_CTX *ctx = init_ssl_server(cert, key);
	BIO *rbio, *wbio;
	
	info(VERBOSE, _("Initializing the TLS/SSL connection with MUA..."));

	if (!(ssl = SSL_new(ctx))) {
		ssl_error(_("Can't create a new SSL structure for a connection."));
		return 0;
	}

	rbio = BIO_new_net_stream(sd_client);
	wbio = BIO_new_net_stream(sd_client);
	
	/* Set up BIOs */
	SSL_set_bio(ssl, rbio, wbio);

	SSL_set_accept_state(ssl);
	if (SSL_accept(ssl) <= 0) {
		ssl_error(_("TLS/SSL handshake failed!"));
		return 0;
	}

	if (verbose)
		cipher_info(ssl);

	sd = xmalloc(sizeof(*sd));
	sd->ssl = ssl;
	sd->ctx = ctx;
	stream_create(&stream);
	stream_set_io(stream,
		      sd,
		      _ssl_read, _ssl_write,
		      _ssl_close, NULL, _ssl_strerror);
	return stream;
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
