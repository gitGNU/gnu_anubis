/*
   gpg.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003, 2004 The Anubis Team.

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

struct gpg_struct
{
  int inited;
  char *sign_keys;
  char *encryption_keys;
  char *passphrase;
};

static struct gpg_struct gpg;

static int gpgme_init (void);
static char *gpg_sign (char *);
static char *gpg_encrypt (char *);
static char *gpg_sign_encrypt (char *);
static void gpgme_debug_info (GpgmeCtx);

#define EXTRA_GPG_BUF 4096
#define fail_if_err(a) do { \
		if (a) { \
			anubis_error(HARD, _("GPGME: %s."), \
			gpgme_strerror(a)); \
		} \
	} while(0)

static void
gpgme_debug_info (GpgmeCtx ctx)
{
  char *s = gpgme_get_op_info (ctx, 0);
  if (s)
    {
      fputs (s, stderr);
      free (s);
    }
}

#define GPGME_REQ_VERSION "0.3.15"	/* GPGME 0.3.15 or later */

static int
gpgme_init (void)
{
  GpgmeError err;

  if ((gpgme_check_version (GPGME_REQ_VERSION)) == 0)
    {
      anubis_error (HARD, _("Install GPGME version %s or later."),
		    GPGME_REQ_VERSION);
      return -1;
    }
  if ((err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP)))
    {
      anubis_error (HARD, _("GPGME: failed. %s."), gpgme_strerror (err));
      return -1;
    }
  gpg.inited = 1;
  if (options.termlevel == DEBUG)
    fputs (gpgme_get_engine_info (), stderr);
  return 0;
}

static const char *
passphrase_cb (void *hook, const char *desc, void **r_hd)
{
  if (!desc)
    return 0;
  return gpg.passphrase;
}

static char *
gpg_sign (char *gpg_data)
{
  GpgmeCtx ctx;
  GpgmeError err = 0;
  GpgmeData in, out;
  GpgmeKey key;
  char buf[256];
  char *p, *signed_data;
  int size;
  size_t nread;

  size = strlen (gpg_data) + EXTRA_GPG_BUF;
  signed_data = (char *) xmalloc (size);
  memset (buf, 0, sizeof (buf));
  fail_if_err (gpgme_new (&ctx));

  if (gpg.sign_keys)
    {
      err = gpgme_op_keylist_start (ctx, gpg.sign_keys, 0);
      if (!err)
	{
	  while ((err = gpgme_op_keylist_next (ctx, &key)) == 0)
	    {
	      err = gpgme_signers_add (ctx, key);
	      gpgme_key_release (key);
	    }
	}
      if (err && err != GPGME_EOF)
	{
	  anubis_error (HARD, _("GPGME: Cannot list keys: %s"),
			gpgme_strerror (err));
	  topt |= T_ERROR;
	}
    }

  p = getenv ("GPG_AGENT_INFO");
  if (!(p && strchr (p, ':')))
    gpgme_set_passphrase_cb (ctx, (GpgmePassphraseCb) passphrase_cb, 0);
  gpgme_set_textmode (ctx, 1);
  gpgme_set_armor (ctx, 1);

  fail_if_err (gpgme_data_new_from_mem (&in, gpg_data, strlen (gpg_data), 0));
  fail_if_err (gpgme_data_new (&out));
  fail_if_err (gpgme_op_sign (ctx, in, out, GPGME_SIG_MODE_CLEAR));
  fail_if_err (gpgme_data_rewind (out));

  if (options.termlevel == DEBUG)
    gpgme_debug_info (ctx);

  if (topt & T_ERROR)
    {
      gpgme_release (ctx);
      free (signed_data);
      return 0;
    }

  while (!(err = gpgme_data_read (out, buf, sizeof (buf), &nread)))
    {
      if (size > nread)
	{
	  strncat (signed_data, buf, nread);
	  size -= nread;
	}
      else
	{
	  size = EXTRA_GPG_BUF;
	  signed_data = (char *) xrealloc ((char *) signed_data,
					   strlen (signed_data) + size);
	  strncat (signed_data, buf, nread);
	  size -= nread;
	}
      memset (buf, 0, sizeof (buf));
    }
  if (err != GPGME_EOF)
    fail_if_err (err);

  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return signed_data;
}

static char *
gpg_encrypt (char *gpg_data)
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

  size = strlen (gpg_data) + EXTRA_GPG_BUF;
  encrypted_data = (char *) xmalloc (size);
  memset (buf, 0, sizeof (buf));
  memset (current_key, 0, sizeof (current_key));

  fail_if_err (gpgme_new (&ctx));
  gpgme_set_armor (ctx, 1);

  fail_if_err (gpgme_data_new_from_mem (&in, gpg_data, strlen (gpg_data), 0));
  fail_if_err (gpgme_data_new (&out));
  fail_if_err (gpgme_recipients_new (&rset));

  len = strlen (gpg.encryption_keys);
  for (i = 0; i <= len; i++)
    {
      if (gpg.encryption_keys[i] == ',' || gpg.encryption_keys[i] == '\0')
	{
	  fail_if_err (gpgme_recipients_add_name_with_validity (rset,
								current_key,
								GPGME_VALIDITY_FULL));
	  memset (current_key, 0, sizeof (current_key));
	  j = 0;
	}
      else
	current_key[j++] = gpg.encryption_keys[i];
    }
  fail_if_err (gpgme_op_encrypt (ctx, rset, in, out));
  fail_if_err (gpgme_data_rewind (out));

  if (options.termlevel == DEBUG)
    gpgme_debug_info (ctx);

  if (topt & T_ERROR)
    {
      gpgme_recipients_release (rset);
      gpgme_release (ctx);
      free (encrypted_data);
      return 0;
    }

  while (!(err = gpgme_data_read (out, buf, sizeof (buf), &nread)))
    {
      if (size > nread)
	{
	  strncat (encrypted_data, buf, nread);
	  size -= nread;
	}
      else
	{
	  size = EXTRA_GPG_BUF;
	  encrypted_data = (char *) xrealloc ((char *) encrypted_data,
					      strlen (encrypted_data) + size);
	  strncat (encrypted_data, buf, nread);
	  size -= nread;
	}
      memset (buf, 0, sizeof (buf));
    }
  if (err != GPGME_EOF)
    fail_if_err (err);

  gpgme_recipients_release (rset);
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return encrypted_data;
}

static char *
gpg_sign_encrypt (char *gpg_data)
{
  GpgmeCtx ctx;
  GpgmeError err = 0;
  GpgmeData in, out;
  GpgmeKey key;
  GpgmeRecipients rset;
  char current_key[100];
  char buf[256];
  char *p, *se_data;		/* Signed-Encrypted Data */
  int i, j = 0;
  int len, size;
  size_t nread;

  size = strlen (gpg_data) + EXTRA_GPG_BUF;
  se_data = (char *) xmalloc (size);
  memset (buf, 0, sizeof (buf));
  memset (current_key, 0, sizeof (current_key));

  fail_if_err (gpgme_new (&ctx));

  if (gpg.sign_keys)
    {
      err = gpgme_op_keylist_start (ctx, gpg.sign_keys, 0);
      if (!err)
	{
	  while ((err = gpgme_op_keylist_next (ctx, &key)) == 0)
	    {
	      err = gpgme_signers_add (ctx, key);
	      gpgme_key_release (key);
	    }
	}
      if (err && err != GPGME_EOF)
	{
	  anubis_error (HARD, _("GPGME: Cannot list keys: %s"),
			gpgme_strerror (err));
	  topt |= T_ERROR;
	}
    }

  p = getenv ("GPG_AGENT_INFO");
  if (!(p && strchr (p, ':')))
    gpgme_set_passphrase_cb (ctx, (GpgmePassphraseCb) passphrase_cb, 0);
  gpgme_set_armor (ctx, 1);

  fail_if_err (gpgme_data_new_from_mem (&in, gpg_data, strlen (gpg_data), 0));
  fail_if_err (gpgme_data_new (&out));
  fail_if_err (gpgme_recipients_new (&rset));

  len = strlen (gpg.encryption_keys);
  for (i = 0; i <= len; i++)
    {
      if (gpg.encryption_keys[i] == ',' || gpg.encryption_keys[i] == '\0')
	{
	  fail_if_err (gpgme_recipients_add_name_with_validity (rset,
								current_key,
								GPGME_VALIDITY_FULL));
	  memset (current_key, 0, sizeof (current_key));
	  j = 0;
	}
      else
	current_key[j++] = gpg.encryption_keys[i];
    }
  fail_if_err (gpgme_op_encrypt_sign (ctx, rset, in, out));
  fail_if_err (gpgme_data_rewind (out));

  if (options.termlevel == DEBUG)
    gpgme_debug_info (ctx);

  if (topt & T_ERROR)
    {
      gpgme_recipients_release (rset);
      gpgme_release (ctx);
      free (se_data);
      return 0;
    }

  while (!(err = gpgme_data_read (out, buf, sizeof (buf), &nread)))
    {
      if (size > nread)
	{
	  strncat (se_data, buf, nread);
	  size -= nread;
	}
      else
	{
	  size = EXTRA_GPG_BUF;
	  se_data = (char *) xrealloc ((char *) se_data,
				       strlen (se_data) + size);
	  strncat (se_data, buf, nread);
	  size -= nread;
	}
      memset (buf, 0, sizeof (buf));
    }
  if (err != GPGME_EOF)
    fail_if_err (err);

  gpgme_recipients_release (rset);
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return se_data;
}

void
gpg_proc (MESSAGE * msg, char *(*proc) (char *input))
{
  char *buf;
#if defined(HAVE_SETENV) || defined(HAVE_PUTENV)
  char homedir_s[MAXPATHLEN + 1];	/* SUPERVISOR */
  char homedir_c[MAXPATHLEN + 1];	/* CLIENT */

  get_homedir (session.supervisor, homedir_s, sizeof (homedir_s));
  get_homedir (session.clientname, homedir_c, sizeof (homedir_c));
  setenv ("HOME", homedir_c, 1);
#endif /* HAVE_SETENV or HAVE_PUTENV */

  buf = proc (msg->body);

  if (topt & T_ERROR)
    return;

  xfree (msg->body);
  msg->body = buf;

#if defined(HAVE_SETENV) || defined(HAVE_PUTENV)
  setenv ("HOME", homedir_s, 1);
#endif /* HAVE_SETENV or HAVE_PUTENV */
}

void
gpg_free (void)
{
  if (gpg.passphrase)
    {
      memset (gpg.passphrase, 0, strlen (gpg.passphrase));
      xfree (gpg.passphrase);
    }
  xfree (gpg.sign_keys);
  xfree (gpg.encryption_keys);
}

#define KW_GPG_PASSPHRASE         1
#define KW_GPG_ENCRYPT            2
#define KW_GPG_SIGN               3
#define KW_GPG_SIGN_ENCRYPT       4
#define KW_GPG_HOME               5

int
gpg_parser (int method, int key, ANUBIS_LIST * arglist,
	    void *inv_data, void *func_data, MESSAGE * msg)
{
  char *arg = list_item (arglist, 0);
  switch (key)
    {
    case KW_GPG_PASSPHRASE:
      if (gpg.passphrase)
	{
	  memset (gpg.passphrase, 0, strlen (gpg.passphrase));
	  xfree (gpg.passphrase);
	}
      gpg.passphrase = strdup (arg);
      arg = NULL;
      break;

    case KW_GPG_ENCRYPT:
      xfree (gpg.encryption_keys);
      gpg.encryption_keys = allocbuf (arg, 0);
      if (gpg.inited == 0 && gpgme_init ())
	break;
      gpg_proc (msg, gpg_encrypt);
      break;

    case KW_GPG_SIGN:
      if (strcasecmp (arg, "no"))
	{
	  xfree (gpg.sign_keys);
	  if (strcasecmp (arg, "default") && strcasecmp (arg, "yes"))
	    gpg.sign_keys = strdup (arg);
	  if (gpg.inited == 0 && gpgme_init ())
	    break;
	  gpg_proc (msg, gpg_sign);
	}
      break;

    case KW_GPG_SIGN_ENCRYPT:
      {
	char *p = strchr (arg, ':');
	xfree (gpg.encryption_keys);
	if (p)
	  {
	    p++;
	    if (strcasecmp (p, "default") && strcasecmp (p, "yes"))
	      {
		xfree (gpg.sign_keys);
		gpg.sign_keys = allocbuf (p, 0);
	      }
	    *--p = '\0';
	    gpg.encryption_keys = allocbuf (arg, 0);
	  }
	else
	  gpg.encryption_keys = allocbuf (arg, 0);

	if (gpg.inited == 0 && gpgme_init ())
	  break;
	gpg_proc (msg, gpg_sign_encrypt);
      }
      break;

    case KW_GPG_HOME:
      setenv ("GNUPGHOME", arg, 1);
      break;

    default:
      return RC_KW_UNKNOWN;
    }
  return RC_KW_HANDLED;
}


struct rc_kwdef gpg_kw[] = {
  {"gpg-passphrase", KW_GPG_PASSPHRASE, KWF_HIDDEN},
  {"gpg-encrypt", KW_GPG_ENCRYPT},
  {"gpg-sign", KW_GPG_SIGN},
  {"gpg-sign-encrypt", KW_GPG_SIGN_ENCRYPT},
  {"gpg-se", KW_GPG_SIGN_ENCRYPT},
  {"gpg-home", KW_GPG_HOME},
  {NULL},
};

static struct rc_secdef_child gpg_sect_child = {
  NULL,
  CF_CLIENT,
  gpg_kw,
  gpg_parser,
  NULL
};

void
gpg_section_init (void)
{
  struct rc_secdef *sp = anubis_add_section ("RULE");
  rc_secdef_add_child (sp, &gpg_sect_child);
}

#endif /* HAVE_GPG */

/* EOF */
