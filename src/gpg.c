/*
   gpg.c

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

#include "headers.h"
#include "extern.h"
#include "rcfile.h"

#ifdef HAVE_GPG
#include <gpgme.h>

static int gpgme_init(void);
static char *gpg_sign(char *);
static char *gpg_encrypt_to_users(char *);
static char *gpg_encrypt_to_remailer(char *);
static void gpgme_debug_info(GpgmeCtx);

#define EXTRA_GPG_BUF 4096
#define fail_if_err(a) do { \
		if (a) { \
			anubis_error(HARD, _("GPGME: %s."), \
			gpgme_strerror(a)); \
		} \
	} while(0)

static void
gpgme_debug_info(GpgmeCtx ctx)
{
	char *s = gpgme_get_op_info(ctx, 0);
	if (s) {
		puts(s);
		free(s);
	}
	return;
}

#define GPGME_REQ_VERSION "0.3.12" /* GPGME 0.3.12 or later */

static int
gpgme_init(void)
{
	GpgmeError err;

	if ((gpgme_check_version(GPGME_REQ_VERSION)) == 0) {
		anubis_error(HARD, _("Install GPGME version %s or later."),
			GPGME_REQ_VERSION);
		return -1;
	}
	if ((err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP))) {
		anubis_error(HARD, _("GPGME: failed. %s."), gpgme_strerror(err));
		return -1;
	}
	if (options.termlevel == DEBUG)
		puts(gpgme_get_engine_info());
	return 0;
}

static const char *
passphrase_cb(void *hook, const char *desc, void **r_hd)
{
	if (!desc)
		return 0;
	return gpg.passphrase;
}

static char *
gpg_sign(char *gpg_data)
{
	GpgmeCtx ctx;
	GpgmeError err = 0;
	GpgmeData in, out;
	char buf[256];
	char *signed_data;
	int size;
	size_t nread;

	size = strlen(gpg_data) + EXTRA_GPG_BUF;
	signed_data = (char *)xmalloc(size);
	memset(buf, 0, sizeof(buf));
	fail_if_err(gpgme_new(&ctx));
	gpgme_set_passphrase_cb(ctx, (GpgmePassphraseCb)passphrase_cb, 0);
	gpgme_set_textmode(ctx, 1);
	gpgme_set_armor(ctx, 1);

	fail_if_err(gpgme_data_new_from_mem(&in, gpg_data, strlen(gpg_data), 0));
	fail_if_err(gpgme_data_new(&out));
	fail_if_err(gpgme_op_sign(ctx, in, out, GPGME_SIG_MODE_CLEAR));
	fail_if_err(gpgme_data_rewind(out));

	if (options.termlevel == DEBUG)
		gpgme_debug_info(ctx);

	if (topt & T_ERROR) {
		gpgme_release(ctx);
		free(signed_data);
		return 0;
	}

	while (!(err = gpgme_data_read(out, buf, sizeof(buf), &nread)))
	{
		if (size > nread) {
			strncat(signed_data, buf, nread);
			size -= nread;
		}
		else {
			size = EXTRA_GPG_BUF;
			signed_data = (char *)xrealloc((char *)signed_data,
				strlen(signed_data) + size);
			strncat(signed_data, buf, nread);
			size -= nread;
		}
		memset(buf, 0, sizeof(buf));
	}
	if (err != GPGME_EOF)
		fail_if_err(err);

	gpgme_data_release(in);
	gpgme_data_release(out);
	gpgme_release(ctx);
	return signed_data;
}

static char *
gpg_encrypt_to_users(char *gpg_data)
{
	GpgmeCtx ctx;
	GpgmeError err = 0;
	GpgmeData in, out;
	GpgmeRecipients rset;
	char current_key[100];
	char buf[256];
	char *encrypted_data;
	int i, j = 0;
	int len, size;
	size_t nread;

	size = strlen(gpg_data) + EXTRA_GPG_BUF;
	encrypted_data = (char *)xmalloc(size);
	memset(buf, 0, sizeof(buf));
	memset(current_key, 0, sizeof(current_key));

	fail_if_err(gpgme_new(&ctx));
	gpgme_set_armor(ctx, 1);
	fail_if_err(gpgme_data_new_from_mem(&in, gpg_data, strlen(gpg_data), 0));
	fail_if_err(gpgme_data_new(&out));
	fail_if_err(gpgme_recipients_new(&rset));

	len = strlen(gpg.keys);
	for (i = 0; i <= len; i++)
	{
		if (gpg.keys[i] == ',') { /* comma found, so add KEY-ID */
			fail_if_err(gpgme_recipients_add_name_with_validity(rset,
				current_key, GPGME_VALIDITY_FULL));
			memset(current_key, 0, sizeof(current_key));
			j = 0;
		}
		else /* it is not a comma, so add char to KEY_ID string */
			current_key[j++] = gpg.keys[i];
	}
	fail_if_err(gpgme_op_encrypt(ctx, rset, in, out));
	fail_if_err(gpgme_data_rewind(out));

	if (options.termlevel == DEBUG)
		gpgme_debug_info(ctx);

	if (topt & T_ERROR) {
		gpgme_recipients_release(rset);
		gpgme_release(ctx);
		free(encrypted_data);
		return 0;
	}

	while (!(err = gpgme_data_read(out, buf, sizeof(buf), &nread)))
	{
		if (size > nread) {
			strncat(encrypted_data, buf, nread);
			size -= nread;
		}
		else {
			size = EXTRA_GPG_BUF;
			encrypted_data = (char *)xrealloc((char *)encrypted_data,
				strlen(encrypted_data) + size);
			strncat(encrypted_data, buf, nread);
			size -= nread;
		}
		memset(buf, 0, sizeof(buf));
	}
	if (err != GPGME_EOF)
		fail_if_err(err);

	gpgme_recipients_release(rset);
	gpgme_data_release(in);
	gpgme_data_release(out);
	gpgme_release(ctx);
	return encrypted_data;
}

static char *
gpg_encrypt_to_remailer(char *gpg_data)
{
	GpgmeCtx ctx;
	GpgmeError err = 0;
	GpgmeData in, out;
	GpgmeRecipients rset;
	char buf[256];
	char *data_to_encrypt;
	int size;
	size_t nread;

	size = strlen(gpg_data) + EXTRA_GPG_BUF;
	data_to_encrypt = (char *)xmalloc(size);
	memset(buf, 0, sizeof(buf));
	fail_if_err(gpgme_new(&ctx));
	gpgme_set_armor(ctx, 1);

	/*
	   Remailer Type-I support (with GPG encryption).
	*/

	if (mopt & M_RMRRT)
		sprintf(data_to_encrypt, CRLF"::"CRLF"Anon-To: %s"CRLF, rm.rrt);
	else if (mopt & M_RMPOST)
		sprintf(data_to_encrypt, CRLF"::"CRLF"Anon-Post-To: %s"CRLF, rm.post);
	if ((mopt & M_RMLT) || (mopt & M_RMRLT)) {
		char mailbuf[LINEBUFFER];
		sprintf(mailbuf, "Latent-Time: +%s%s"CRLF,
			rm.latent_time, (mopt & M_RMRLT) ? "r" : "");
		strcat(data_to_encrypt, mailbuf);
	}
	strcat(data_to_encrypt, CRLF);
	if (mopt & M_RMHEADER) {
		remcrlf(rm.header);
		strcat(data_to_encrypt, "##"CRLF);
		strcat(data_to_encrypt, rm.header);
		strcat(data_to_encrypt, CRLF);
	}
	strcat(data_to_encrypt, gpg_data);
	memset(buf, 0, sizeof(buf));

	fail_if_err(gpgme_data_new_from_mem(&in, data_to_encrypt,
		strlen(data_to_encrypt), 0));
	fail_if_err(gpgme_data_new(&out));
	fail_if_err(gpgme_recipients_new(&rset));
	fail_if_err(gpgme_recipients_add_name_with_validity(rset, gpg.rm_key,
		GPGME_VALIDITY_FULL));
	fail_if_err(gpgme_op_encrypt(ctx, rset, in, out));
	fail_if_err(gpgme_data_rewind(out));

	if (options.termlevel == DEBUG)
		gpgme_debug_info(ctx);

	if (topt & T_ERROR) {
		gpgme_recipients_release(rset);
		gpgme_release(ctx);
		free(data_to_encrypt);
		return 0;
	}

	memset(data_to_encrypt, 0, size);
	while (!(err = gpgme_data_read(out, buf, sizeof(buf), &nread)))
	{
		if (size > nread) {
			strncat(data_to_encrypt, buf, nread);
			size -= nread;
		}
		else {
			size = EXTRA_GPG_BUF;
			data_to_encrypt = (char *)xrealloc((char *)data_to_encrypt,
				strlen(data_to_encrypt) + size);
			strncat(data_to_encrypt, buf, nread);
			size -= nread;
		}
		memset(buf, 0, sizeof(buf));
	}
	if (err != GPGME_EOF)
		fail_if_err(err);

	gpgme_recipients_release(rset);
	gpgme_data_release(in);
	gpgme_data_release(out);
	gpgme_release(ctx);
	return data_to_encrypt;
}

void
check_gpg(void)
{
	#if defined(HAVE_SETENV) || defined(HAVE_PUTENV)
	char homedir_s[MAXPATHLEN+1]; /* SUPERVISOR */
	char homedir_c[MAXPATHLEN+1]; /* CLIENT */

	get_homedir(session.supervisor, homedir_s, sizeof(homedir_s));
	get_homedir(session.client, homedir_c, sizeof(homedir_c));
	setenv("HOME", homedir_c, 1);
	#endif /* HAVE_SETENV or HAVE_PUTENV */

	if (gpgme_init() == -1) {
		if (gpg.passphrase) {
			memset(gpg.passphrase, 0, strlen(gpg.passphrase));
			xfree(gpg.passphrase);
		}
		return;
	}

	if (mopt & M_GPG_SIGN) { /* Sign a message */
		char *buf = gpg_sign(message.body);
		if (topt & T_ERROR)
			return;
		xfree(message.body);
		message.body = buf;
	}
	if (mopt & M_GPG_ENCRYPT) { /* Encrypt a message body */
		char *buf = gpg_encrypt_to_users(message.body);
		if (topt & T_ERROR)
			return;
		xfree(message.body);
		message.body = buf;
	}
	if (mopt & M_RMGPG) { /* Remailer Type-I */
		char *buf = gpg_encrypt_to_remailer(message.body);
		if (topt & T_ERROR)
			return;
		xfree(message.body);
		message.body = buf;
	}

	#if defined(HAVE_SETENV) || defined(HAVE_PUTENV)
	setenv("HOME", homedir_s, 1);
	#endif /* HAVE_SETENV or HAVE_PUTENV */

	if (gpg.passphrase) {
		memset(gpg.passphrase, 0, strlen(gpg.passphrase));
		xfree(gpg.passphrase);
	}
	return;
}

#define KW_GPG_PASSPHRASE         1
#define KW_GPG_ENCRYPT            2
#define KW_GPG_SIGN               3
#define KW_RM_GPG                 4
#define KW_GPG_HOME               5

int
gpg_parser(int method, int key, char *arg,
	   void *inv_data, void *func_data, char *line)
{
	switch (key) {
	case KW_GPG_PASSPHRASE:
		if (gpg.passphrase) {
			memset(gpg.passphrase, 0, strlen(gpg.passphrase));
			xfree(gpg.passphrase);
		}
		gpg.passphrase = allocbuf(arg, 0);
		mopt |= M_GPG_PASSPHRASE;
		break;
		
	case KW_GPG_ENCRYPT:
		xfree(gpg.keys);
		gpg.keys = allocbuf(arg, 0);
		gpg.keys = xrealloc(gpg.keys, strlen(gpg.keys) + 2);
		strcat(gpg.keys, ",");
		mopt |= M_GPG_ENCRYPT;
		break;
		
	case KW_GPG_SIGN:              
		if (strcmp(arg, "yes")
		    || !(mopt & M_GPG_PASSPHRASE)) {
			if (gpg.passphrase) {
				memset(gpg.passphrase, 0,
				       strlen(gpg.passphrase));
				xfree(gpg.passphrase);
			}
			gpg.passphrase = allocbuf(arg, 0);
		}
		mopt |= M_GPG_SIGN;
		break;
		
	case KW_RM_GPG:
		xfree(gpg.rm_key);
		gpg.rm_key = allocbuf(arg, 0);
		mopt |= M_RMGPG;
		break;

	case KW_GPG_HOME:
		setenv("GNUPGHOME", arg, 1);
		break;
		
	default:
		return RC_KW_UNKNOWN;
	}
	return RC_KW_HANDLED;
}


struct rc_kwdef gpg_kw[] = {
	{ "gpg-passphrase", 	     KW_GPG_PASSPHRASE },          
	{ "gpg-encrypt", 	     KW_GPG_ENCRYPT },             
	{ "gpg-sign", 		     KW_GPG_SIGN },                
	{ "rm-gpg", 		     KW_RM_GPG },
	{ "gpg-home",                KW_GPG_HOME },
	{ NULL },
};

static struct rc_secdef_child gpg_sect_child = {
	NULL,
	CF_CLIENT,
	gpg_kw,
	gpg_parser,
	NULL
};

void
gpg_section_init()
{
	struct rc_secdef *sp = anubis_add_section("ALL");

	rc_secdef_add_child(sp, &gpg_sect_child);

	sp = anubis_add_section("RULE");
	rc_secdef_add_child(sp, &gpg_sect_child);
}	

#endif /* HAVE_GPG */

/* EOF */

