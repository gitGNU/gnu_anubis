/*
   map.c

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
  int size;
};

void
parse_transmap (int *cs, char *extuser, char *extaddr, char *dst, int size)
{
  struct translate_env env;

  env.stop = 0;
  env.cs = -1;			/* failed by default: unmatched */
  env.extuser = extuser;
  env.extaddr = extaddr;
  env.size = size;

  rcfile_process_section (CF_SUPERVISOR, "TRANSLATION", &env, NULL);
  *cs = env.cs;
  if (*cs == 1)
    {				/* success */
      if (check_username (env.into))
	{
	  info (NORMAL, _("%s remapped to %s@localhost."),
		env.translate, env.into);
	  memset (dst, 0, size);
	  strncpy (dst, env.into, size - 1);
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


int
translate_parser (int method, int key, ANUBIS_LIST * arglist, void *inv_data,
		  void *func_data, MESSAGE * msg)
{
  struct translate_env *env = func_data;
  char *p = 0;
  int cu = 0;			/* check a user name */
  char a1[65];
  char a2[65];
  char user[65];
  char address[65];
  unsigned long inaddr;
  struct sockaddr_in addr;
  size_t argc;

  if (!env || env->stop)
    return RC_KW_HANDLED;

  switch (key)
    {
    case KW_TRANSLATE:
      /* translate [=] [USER@]ADDRESS into [=] USERNAME
         argv[0] = [USER@]ADDRESS
         argv[1] = "into"
         argv[2] = USERNAME */

      safe_strcpy (a1, env->extaddr);
      memset (&addr, 0, sizeof (addr));

      argc = list_count (arglist);
      if (argc < 3 || argc > 4 || strcmp (list_item (arglist, 1), "into"))
	{
	  info (VERBOSE, _("Translation map: incorrect syntax."));
	  break;
	}

      safe_strcpy (env->translate, list_item (arglist, 0));
      p = list_item (arglist, 2);
      if (p[0] == '=')
	p = list_item (arglist, 3);
      safe_strcpy (env->into, p);

      if (strchr (env->translate, '@'))
	{
	  if (env->extuser == 0)
	    break;		/* failed */
	  safe_strcpy (user, env->translate);
	  p = strchr (user, '@');
	  *p++ = '\0';
	  safe_strcpy (address, p);
	  cu = 1;
	}
      else
	safe_strcpy (address, env->translate);

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
		  anubis_error (0, 0,
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
	  if (strcmp (env->extuser, user) == 0)
	    {
	      /* a temporary solution */
	      if (strcmp (a2, "0.0.0.0") == 0)
		{
		  env->cs = 1;	/* success */
		  env->stop = 1;
		  break;
		}
	      if (strcmp (a1, a2) == 0)
		{
		  env->cs = 1;	/* success */
		  env->stop = 1;
		  break;
		}
	    }
	}
      else if (cu == 0)
	{
	  /* a temporary solution */
	  if (strcmp (a2, "0.0.0.0") == 0)
	    {
	      env->cs = 1;	/* success */
	      env->stop = 1;
	      break;
	    }
	  if (strcmp (a1, a2) == 0)
	    {
	      env->cs = 1;	/* success */
	      env->stop = 1;
	      break;
	    }
	}
      break;

    default:
      return RC_KW_UNKNOWN;
    }
  return RC_KW_HANDLED;
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
