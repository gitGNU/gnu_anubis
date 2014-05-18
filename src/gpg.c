/*
   gpg.c

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

#include "headers.h"
#include "extern.h"
#include "rcfile.h"

#ifdef HAVE_GPG
#include <gpgme.h>
#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

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
static void gpgme_debug_info (gpgme_ctx_t);

#define EXTRA_GPG_BUF 4096
#define fail_if_err(code) do { \
		int a = code;\
		if (a) { \
			anubis_error(EXIT_FAILURE, 0, _("GPGME: %s."), \
			             gpgme_strerror(a)); \
		} \
	} while(0)

/* A replacement for the deprecated gpgme_data_rewind function. */
static gpgme_error_t
rewind_gpgme_data (gpgme_data_t dh)
{
  return (gpgme_data_seek (dh, 0, SEEK_SET) == -1)
	   ? gpg_error_from_errno (errno) : 0;
}


static void
gpgme_debug_info (gpgme_ctx_t ctx)
{
  /* FIXME: Current version of GPGMe does not provide any ways for
     getting this info */
}

static void
print_engine_info (gpgme_engine_info_t info)
{
  for (; info; info = info->next)
    {
      fprintf (stderr, "Protocol: %s\n",
	       gpgme_get_protocol_name (info->protocol));
      fprintf (stderr, "Executable: %s\n",
	       info->file_name ? info->file_name : "none");
      fprintf (stderr, "Version: %s\n",
	       info->version ? info->version : "N/A");
      fprintf (stderr, "Required Version: %s\n",
	       info->req_version ? info->req_version : "N/A");
    }
}

#define GPGME_REQ_VERSION "0.9.0"	/* GPGME 0.9.0 or later */

static int
gpgme_init (void)
{
  gpgme_error_t err;
  
  if ((gpgme_check_version (GPGME_REQ_VERSION)) == 0)
    {
      anubis_error (0, 0, _("Install GPGME version %s or later."),
		    GPGME_REQ_VERSION);
      return -1;
    }

  if ((err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP)))
    {
      anubis_error (0, 0, _("GPGME: failed. %s."), gpgme_strerror (err));
      return -1;
    }

  gpg.inited = 1;
  if (options.termlevel == DEBUG)
    {
      gpgme_engine_info_t info;
      if (gpgme_get_engine_info (&info) == 0)
	print_engine_info (info);
    }
  return 0;
}

gpgme_error_t
passphrase_cb (void *hook, const char *uid_hint, const char *passphrase_info, 
	       int prev_was_bad, int fd)
{
  if (passphrase_info)
    {
      size_t len = strlen(gpg.passphrase);
      if (write (fd, gpg.passphrase, len) != len)
	return gpg_error(GPG_ERR_CANCELED);
      if (write (fd, "\n", 1) != 1)
	return gpg_error(GPG_ERR_CANCELED);
    }
  return 0;
}

static int
anubis_gpg_read (gpgme_data_t dh, size_t size, char **pdata)
{
  char buf[256];
  char *data;
  size_t pos;
  size_t nread;
  
  pos = 0;
  size += EXTRA_GPG_BUF;
  data = xmalloc (size);
  while ((nread = gpgme_data_read (dh, buf, sizeof (buf))) > 0)
    {
      if (size - pos < nread)
	{
	  size += sizeof (buf);
	  data = xrealloc (data, size);
	}
      memcpy (data + pos, buf, nread);
      pos += nread;
    }
  if (size - pos == 0)
    {
      size++;
      data = xrealloc (data, size);
    }
  data[pos] = 0;
  if (nread == -1)
    fail_if_err (errno);
  *pdata = data;
  return pos ;
}

static char *
gpg_sign (char *gpg_data)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err = 0;
  gpgme_data_t in, out;
  gpgme_key_t key;
  char *p, *signed_data;

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
      if (err && gpg_err_code (err) != GPG_ERR_EOF)
	{
	  anubis_error (0, 0, _("GPGME: Cannot list keys: %s"),
			gpgme_strerror (err));
          gpgme_release (ctx);
          return NULL;
	}
    }

  p = getenv ("GPG_AGENT_INFO");
  if (!(p && strchr (p, ':')))
    gpgme_set_passphrase_cb (ctx, passphrase_cb, 0);
  gpgme_set_textmode (ctx, 1);
  gpgme_set_armor (ctx, 1);

  fail_if_err (gpgme_data_new_from_mem (&in, gpg_data, strlen (gpg_data), 0));
  fail_if_err (gpgme_data_new (&out));
  fail_if_err (gpgme_op_sign (ctx, in, out, GPGME_SIG_MODE_CLEAR));
  fail_if_err (rewind_gpgme_data (out));

  if (options.termlevel == DEBUG)
    gpgme_debug_info (ctx);

  anubis_gpg_read (out, strlen (gpg_data), &signed_data);
  
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return signed_data;
}

static gpgme_key_t *
create_key_array(gpgme_ctx_t ctx, struct obstack *stk)
{
  gpgme_key_t tmpkey;
  char *current_key;
  int i, j, len = strlen (gpg.encryption_keys);

  current_key = xmalloc (len+1);
  for (i = j = 0; i <= len; i++)
    {
      if (gpg.encryption_keys[i] == ',' || gpg.encryption_keys[i] == '\0')
	{
	  gpgme_error_t err;
	  current_key[j] = 0;
	  err = gpgme_op_keylist_start (ctx, current_key, 0);
	  while (!err)
	    {
	      err = gpgme_op_keylist_next (ctx, &tmpkey);
	      if (err)
		break;

	      gpgme_get_key (ctx, current_key, &tmpkey, 0);
	      obstack_grow (stk, &tmpkey, sizeof (tmpkey));
	      if (options.termlevel == DEBUG)
		{
		  gpgme_user_id_t uid;

		  for (uid = tmpkey->uids; uid; uid = uid->next)
		    fprintf (stderr, "Using key %s: %s <%s>\n",
			     uid->uid, uid->name, uid->email);
		}
	    }
	  if (gpg_err_code (err) != GPG_ERR_EOF)
	    {
	      fprintf (stderr, "cannot list keys: %s\n",
		       gpgme_strerror (err));
	      exit (1);
	    }
	  
	  memset (current_key, 0, sizeof (current_key));
	  j = 0;
	}
      else
	current_key[j++] = gpg.encryption_keys[i];
    }
  xfree (current_key);
  tmpkey = NULL;
  obstack_grow (stk, &tmpkey, sizeof (tmpkey));
  return obstack_finish (stk);
}

static char *
gpg_encrypt (char *gpg_data)
{
  gpgme_ctx_t ctx;
  gpgme_data_t in, out;
  char *encrypted_data;
  gpgme_key_t *keyptr;
  struct obstack stk;
  gpgme_encrypt_result_t result;
  
  fail_if_err (gpgme_new (&ctx));
  gpgme_set_armor (ctx, 1);

  fail_if_err (gpgme_data_new_from_mem (&in, gpg_data, strlen (gpg_data), 0));
  fail_if_err (gpgme_data_new (&out));

  obstack_init (&stk);
  keyptr = create_key_array (ctx, &stk);
  
  fail_if_err (gpgme_op_encrypt (ctx, keyptr, GPGME_ENCRYPT_ALWAYS_TRUST,
				 in, out));
  result = gpgme_op_encrypt_result (ctx);
  if (result->invalid_recipients)
    anubis_error(0, 0, _("GPGME: Invalid recipient encountered: %s"),
		 result->invalid_recipients->fpr);

  fail_if_err (rewind_gpgme_data (out));

  if (options.termlevel == DEBUG)
    gpgme_debug_info (ctx);

  anubis_gpg_read (out, strlen (gpg_data), &encrypted_data);
  for (; *keyptr; keyptr++)
    gpgme_key_unref (*keyptr);
  obstack_free (&stk, NULL);

  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return encrypted_data;
}

static int
check_result (gpgme_sign_result_t result, gpgme_sig_mode_t type)
{
  int errcnt = 0;

  if (result->invalid_signers)
    {
      anubis_error (0, 0, _("GPGME: Invalid signer found: %s"),
  		    result->invalid_signers->fpr);
      errcnt++;
    } 

  if (!result->signatures || result->signatures->next)
    {
      anubis_error (0, 0, _("GPGME: Unexpected number of signatures created"));
      errcnt++;
    }

  if (result->signatures->type != type)
    {
      errcnt++;
      anubis_error (0, 0, _("GPGME: Wrong type of signature created"));
    }

  if (result->signatures->pubkey_algo != GPGME_PK_DSA)
    {
      anubis_error (0, 0, _("GPGME: Wrong pubkey algorithm reported: %i"),
		    result->signatures->pubkey_algo);
      errcnt++;
    }

  if (result->signatures->hash_algo != GPGME_MD_SHA1)
    {
      anubis_error (0, 0, _("GPGME: Wrong hash algorithm reported: %i"),
		    result->signatures->hash_algo);
      errcnt++;
    }

  if (result->signatures->sig_class != 0)
    {
      anubis_error (0, 0, _("GPGME: Wrong signature class reported: %u"),
 		    result->signatures->sig_class);
      errcnt++;
    }
  /* FIXME: fingerprint? */
  return 0;
}

static char *
gpg_sign_encrypt (char *gpg_data)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err = 0;
  gpgme_data_t in, out;
  gpgme_key_t *keyptr, key;
  char *p, *se_data;		/* Signed-Encrypted Data */
  gpgme_encrypt_result_t result;
  gpgme_sign_result_t sign_result;
  struct obstack stk;
  
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
      if (err && gpg_err_code (err) != GPG_ERR_EOF)
	{
	  anubis_error (0, 0, _("GPGME: Cannot list keys: %s"),
			gpgme_strerror (err));
          
          gpgme_release (ctx);
          xfree (se_data); 
          return NULL;
	}
    }

  p = getenv ("GPG_AGENT_INFO");
  if (!(p && strchr (p, ':')))
    gpgme_set_passphrase_cb (ctx, (gpgme_passphrase_cb_t) passphrase_cb, 0);
  gpgme_set_armor (ctx, 1);

  fail_if_err (gpgme_data_new_from_mem (&in, gpg_data, strlen (gpg_data), 0));
  fail_if_err (gpgme_data_new (&out));

  obstack_init (&stk);
  keyptr = create_key_array (ctx, &stk);
  fail_if_err (gpgme_op_encrypt_sign (ctx, keyptr, GPGME_ENCRYPT_ALWAYS_TRUST,
				      in, out));
  result = gpgme_op_encrypt_result (ctx);
  if (result->invalid_recipients)
    anubis_error(0, 0, _("GPGME: Invalid recipient encountered: %s"),
		 result->invalid_recipients->fpr);
  sign_result = gpgme_op_sign_result (ctx);
  if (check_result (sign_result, GPGME_SIG_MODE_NORMAL) == 0)
    {
      fail_if_err (rewind_gpgme_data (out));

      if (options.termlevel == DEBUG)
        gpgme_debug_info (ctx);

      anubis_gpg_read (out, strlen (gpg_data), &se_data);
    }
  else 
    xfree (se_data);

  for (; *keyptr; keyptr++)
    gpgme_key_unref (*keyptr);
  obstack_free (&stk, NULL);
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return se_data;
}

static int
_gpg_funcall (char **output, char *input, void *param)
{
  char *(*fun) (char *input) = param;
  *output = fun (input);
  return 1;
}

void
gpg_proc (MESSAGE msg, char *(*fun) (char *input))
{
  char homedir_s[MAXPATHLEN + 1];	/* SUPERVISOR */
  char homedir_c[MAXPATHLEN + 1];	/* CLIENT */

  get_homedir (session.supervisor, homedir_s, sizeof (homedir_s));
  get_homedir (session.clientname, homedir_c, sizeof (homedir_c));
  setenv ("HOME", homedir_c, 1);

  message_proc_body (msg, _gpg_funcall, fun);

  setenv ("HOME", homedir_s, 1);
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

void
gpg_parser (EVAL_ENV env, int key, ANUBIS_LIST arglist, void *inv_data)
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
      gpg.encryption_keys = xstrdup (arg);
      if (gpg.inited == 0 && gpgme_init ())
	break;
      gpg_proc (eval_env_message (env), gpg_encrypt);
      break;

    case KW_GPG_SIGN:
      if (strcasecmp (arg, "no"))
	{
	  xfree (gpg.sign_keys);
	  if (strcasecmp (arg, "default") && strcasecmp (arg, "yes"))
	    gpg.sign_keys = strdup (arg);
	  if (gpg.inited == 0 && gpgme_init ())
	    break;
	  gpg_proc (eval_env_message (env), gpg_sign);
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
		gpg.sign_keys = xstrdup (p);
	      }
	    *--p = '\0';
	    gpg.encryption_keys = xstrdup (arg);
	  }
	else
	  gpg.encryption_keys = xstrdup (arg);

	if (gpg.inited == 0 && gpgme_init ())
	  break;
	gpg_proc (eval_env_message (env), gpg_sign_encrypt);
      }
      break;

    case KW_GPG_HOME:
      setenv ("GNUPGHOME", arg, 1);
      break;

    default:
      eval_error (2, env,
		  _("INTERNAL ERROR at %s:%d: unhandled key %d; "
		    "please report"),
		  __FILE__, __LINE__,
		  key);
    }
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
