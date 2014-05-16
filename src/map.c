/*
   map.c

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

/***************************
 The translation map parser
****************************/

char *
parse_line_option (char *ptr)
{
  while (isspace (*(u_char *) ptr))
    ptr++;

  remcrlf (ptr);
  return ptr;
}

struct translate_env
{
  int stop;
  int cs;
  char *extuser;
  char *extaddr;
  char translate[65];
  char into[65];
};

void
parse_transmap (int *cs, char *extuser, char *extaddr, char **dst)
{
  struct translate_env env;

  env.stop = 0;
  env.cs = -1;			/* failed by default: unmatched */
  env.extuser = extuser;
  env.extaddr = extaddr;

  rcfile_process_section (CF_SUPERVISOR, "TRANSLATION", &env, NULL);
  *cs = env.cs;
  if (*cs == 1)
    {				/* success */
      if (check_username (env.into))
	{
	  info (NORMAL, _("%s remapped to %s@localhost."),
		env.translate, env.into);
	  assign_string (dst, env.into);
	}
      else
	*cs = 0;		/* failed: invalid user name */
    }
}


/* ******************** Configuration file settings ********************** */
#define KW_TRANSLATE           1

struct rc_kwdef translate_kw[] = {
  {"translate", KW_TRANSLATE},
  {NULL}
};


void
translate_parser (EVAL_ENV env, int key, ANUBIS_LIST arglist, void *inv_data)
{
  struct translate_env *xlat_env = eval_env_data (env);
  char *p = 0;
  int cu = 0;			/* check a user name */
  char a1[65];
  char a2[65];
  char user[65];
  char address[65];
  unsigned long inaddr;
  struct sockaddr_in addr;
  size_t argc;

  if (!xlat_env || xlat_env->stop)
    return;

  switch (key)
    {
    case KW_TRANSLATE:
      /* translate [=] [USER@]ADDRESS into [=] USERNAME
         argv[0] = [USER@]ADDRESS
         argv[1] = "into"
         argv[2] = USERNAME */

      safe_strcpy (a1, xlat_env->extaddr);
      memset (&addr, 0, sizeof (addr));

      argc = list_count (arglist);
      if (argc < 3 || argc > 4 || strcmp (list_item (arglist, 1), "into"))
	{
	  /* FIXME: Merge the two functions? */
	  eval_error (0, env, _("invalid syntax"));
	  info (VERBOSE, _("Translation map: incorrect syntax."));
	  break;
	}

      safe_strcpy (xlat_env->translate, list_item (arglist, 0));
      p = list_item (arglist, 2);
      if (p[0] == '=')
	p = list_item (arglist, 3);
      safe_strcpy (xlat_env->into, p);

      if (strchr (xlat_env->translate, '@'))
	{
	  if (xlat_env->extuser == 0)
	    break;		/* failed */
	  safe_strcpy (user, xlat_env->translate);
	  p = strchr (user, '@');
	  *p++ = '\0';
	  safe_strcpy (address, p);
	  cu = 1;
	}
      else
	safe_strcpy (address, xlat_env->translate);

      inaddr = inet_addr (address);
      if (inaddr != INADDR_NONE)
	memcpy (&addr.sin_addr, &inaddr, sizeof (inaddr));
      else
	{
	  struct hostent *hp = 0;
	  hp = gethostbyname (address);
	  if (hp == 0)
	    {
	      cu = 0;
	      hostname_error (address);
	      break;		/* failed */
	    }
	  else
	    {
	      if (hp->h_length != 4 && hp->h_length != 8)
		{
		  eval_error (0, env,
			      _("Illegal address length received for host %s"),
			      address);
		  cu = 0;
		  break;	/* failed */
		}
	      else
		{
		  memcpy (&addr.sin_addr.s_addr, hp->h_addr, hp->h_length);
		}
	    }
	}

      safe_strcpy (a2, inet_ntoa (addr.sin_addr));
      if (cu)
	{
	  if (strcmp (xlat_env->extuser, user) == 0)
	    {
	      /* a temporary solution */
	      if (strcmp (a2, "0.0.0.0") == 0)
		{
		  xlat_env->cs = 1;	/* success */
		  xlat_env->stop = 1;
		  break;
		}
	      if (strcmp (a1, a2) == 0)
		{
		  xlat_env->cs = 1;	/* success */
		  xlat_env->stop = 1;
		  break;
		}
	    }
	}
      else if (cu == 0)
	{
	  /* a temporary solution */
	  if (strcmp (a2, "0.0.0.0") == 0)
	    {
	      xlat_env->cs = 1;	/* success */
	      xlat_env->stop = 1;
	      break;
	    }
	  if (strcmp (a1, a2) == 0)
	    {
	      xlat_env->cs = 1;	/* success */
	      xlat_env->stop = 1;
	      break;
	    }
	}
      break;

    default:
      eval_error (2, env,
		  _("INTERNAL ERROR at %s:%d: unhandled key %d; "
		    "please report"),
		  __FILE__, __LINE__,
		  key);
    }
}

static struct rc_secdef_child translate_secdef_child = {
  NULL,
  CF_SUPERVISOR,
  translate_kw,
  translate_parser,
  NULL
};

void
translate_section_init (void)
{
  struct rc_secdef *sp = anubis_add_section ("TRANSLATION");
  rc_secdef_add_child (sp, &translate_secdef_child);
}

/* EOF */
