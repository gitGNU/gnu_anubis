/*
   env.c

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
#include <grp.h>
#include <getopt.h>
#include "extern.h"
#include "rcfile.h"

#ifdef HAVE_PAM
pam_handle_t *pamh;
static struct pam_conv conv = {
  misc_conv,
  NULL
};
#endif /* HAVE_PAM */

static char **
argv_dup (int argc, char **argv)
{
  char **xargv = xmalloc ((argc + 1) * sizeof (*xargv));
  int i;

  for (i = 0; i < argc; i++)
    xargv[i] = strdup (argv[i]);
  xargv[i] = NULL;
  return xargv;
}

static int gindex = 0;

static char *pidfile;

#define OPT_VERSION          257
#define OPT_HELP             258
#define OPT_ALTRC            259
#define OPT_NORC             260
#define OPT_SHOW_CONFIG      261
#define OPT_RELAX_PERM_CHECK 262
#define OPT_PIDFILE          263

static struct option gopt[] = {
  {"bind", required_argument, 0, 'b'},
  {"remote-mta", required_argument, 0, 'r'},
  {"local-mta", required_argument, 0, 'l'},
  {"foreground", no_argument, 0, 'f'},
  {"stdio", no_argument, 0, 'i'},
  {"silent", no_argument, 0, 's'},
  {"verbose", no_argument, 0, 'v'},
  {"debug", no_argument, 0, 'D'},
  {"version", no_argument, 0, OPT_VERSION},
  {"help", no_argument, 0, OPT_HELP},
  {"altrc", required_argument, 0, OPT_ALTRC},
  {"norc", no_argument, 0, OPT_NORC},
  {"check-config", optional_argument, 0, 'c'},
  {"show-config-options", no_argument, 0, OPT_SHOW_CONFIG},
  {"relax-perm-check", no_argument, 0, OPT_RELAX_PERM_CHECK},
  {"pid-file", required_argument, 0, OPT_PIDFILE},
#ifdef WITH_GSASL
  {"mode", required_argument, 0, 'm'},
#endif
  {0, 0, 0, 0}
};

void
get_options (int argc, char *argv[])
{
  int c;

  while ((c = getopt_long (argc, argv, "m:b:r:l:fisvDc::?",
			   gopt, &gindex)) != EOF)
    {
      switch (c)
	{
	case OPT_HELP:
	  print_usage ();
	  break;

	case OPT_VERSION:
	  print_version ();
	  break;

	case OPT_NORC:
	  topt |= T_NORC;
	  break;

	case OPT_ALTRC:
	  options.altrc = optarg;
	  topt |= T_ALTRC;
	  break;

	case OPT_SHOW_CONFIG:
	  print_config_options ();
	  break;

	case OPT_RELAX_PERM_CHECK:
	  topt |= T_RELAX_PERM_CHECK;
	  break;

	case OPT_PIDFILE:
	  pidfile = optarg;
	  break;
	    
	case 'c':
	  rc_set_debug_level (optarg);
	  topt |= T_CHECK_CONFIG;
	  break;

	case 'b':		/* daemon's port number, host name */
	  parse_mtahost (optarg, session.anubis, &session.anubis_port);
	  if (strlen (session.anubis) != 0)
	    topt |= T_NAMES;
	  break;

	case 'r':		/* a remote SMTP host name or IP address */
	  parse_mtaport (optarg, session.mta, &session.mta_port);
	  break;

	case 'l':		/* a local SMTP mode */
	  session.execpath = allocbuf (optarg, MAXPATHLEN);
	  topt |= T_LOCAL_MTA;
	  break;

	case 'f':		/* foreground mode */
	  topt |= T_FOREGROUND_INIT;
	  break;

	case 'i':		/* stdin/stdout */
	  topt |= T_STDINOUT;
	  break;

	case 'v':		/* verbose */
	  options.termlevel = VERBOSE;
	  break;

	case 'D':		/* debug */
	  options.termlevel = DEBUG;
	  break;

	case 's':		/* silent */
	  options.termlevel = SILENT;
	  break;

	case 'm':
	  if (anubis_set_mode (optarg))
	    exit (1);
	  break;

	case '?':
	default:
	  mprintf (_("Try '%s --help' for more information."), argv[0]);
	  quit (0);
	}
    }

  if (topt & T_LOCAL_MTA)
    {
      if (optind == argc)
	{			/* No extra arguments specified. */
	  if (session.execpath)
	    {
	      char *ptr = strrchr (session.execpath, '/');
	      if (ptr)
		ptr++;
	      else
		ptr = session.execpath;
	      session.execargs = gen_execargs (ptr);
	    }
	}
      else
	session.execargs = argv_dup (argc - optind, argv + optind);
    }
  return;
}

/*********************
 Get a home directory
**********************/

void
get_homedir (char *user, char *buf, int maxsize)
{
  struct passwd *pwd;
  memset (buf, 0, maxsize);

  if (user == 0)
    return;

  pwd = getpwnam (user);
  if (pwd)
    strncpy (buf, (char *) pwd->pw_dir, maxsize - 1);
  else
    {
      char *p = getenv ("HOME");
      if (p)
	strncpy (buf, p, maxsize - 1);
      else
	strncpy (buf, "", 1);
    }
  return;
}

/*****************************
 Get a real user name (login)
******************************/

void
anubis_getlogin (char *buf, int maxsize)
{
  struct passwd *pwd;
  memset (buf, 0, maxsize);

  pwd = getpwuid (getuid ());
  if (pwd)
    strncpy (buf, (char *) pwd->pw_name, maxsize - 1);
  else
    strncpy (buf, (char *) getlogin (), maxsize - 1);
  return;
}

/*******************
 Check current RUID
********************/

int
check_superuser (void)
{
  if (getuid () == 0)
    return 1;			/* a super-user */
  return 0;
}

/*******************************************
 Set USER's RGID, RUID, and home directory.
********************************************/

/* Change to the given uid/gid. Clear the supplementary group list.
   On success returns 0.
   On failure returns 1 (or exits, depending on topt settings. See
   anubis_error) */
static int
change_privs (uid_t uid, gid_t gid)
{
  int rc = 0;
  gid_t emptygidset[1];

  /* Reset group permissions */
  emptygidset[0] = gid ? gid : getegid();
  if (geteuid() == 0 && setgroups(1, emptygidset))
    {
      anubis_error (SOFT,
		    _("setgroups(1, %lu) failed"),
		    (u_long) emptygidset[0]);
      rc = 1;
    }

  /* Switch to the user's gid. On some OSes the effective gid must
     be reset first */

#if defined(HAVE_SETEGID)
  if ((rc = setegid(gid)) < 0)
    anubis_error (SOFT, _("setegid(%lu) failed"), (u_long) gid);
#elif defined(HAVE_SETREGID)
  if ((rc = setregid(gid, gid)) < 0)
    anubis_error (SOFT, _("setregid(%lu,%lu) failed"),
		  (u_long) gid, (u_long) gid);
#elif defined(HAVE_SETRESGID)
  if ((rc = setresgid(gid, gid, gid)) < 0)
    anubis_error (SOFT, _("setresgid(%lu,%lu,%lu) failed"),
		  (u_long) gid,
		  (u_long) gid,
		  (u_long) gid);
#endif

  if (rc == 0 && gid != 0)
    {
      if ((rc = setgid(gid)) < 0 && getegid() != gid) 
	anubis_error (SOFT, _("setgid(%lu) failed"), (u_long) gid);
      if (rc == 0 && getegid() != gid)
	{
	  anubis_error (SOFT, _("cannot set effective gid to %lu"),
			(u_long) gid);
	  rc = 1;
	}
    }

  /* Now reset uid */
  if (rc == 0 && uid != 0)
    {
      uid_t euid;

      if (setuid(uid)
	  || geteuid() != uid
	  || (getuid() != uid
	      && (geteuid() == 0 || getuid() == 0)))
	{
			
#if defined(HAVE_SETREUID)
	  if (geteuid() != uid)
	    {
	      if (setreuid(uid, -1) < 0)
		{
		  anubis_error (SOFT, _("setreuid(%lu,-1) failed"),
				(u_long) uid);
		  rc = 1;
		}
	      if (setuid(uid) < 0)
		{
		  anubis_error (SOFT, _("second setuid(%lu) failed"),
				(u_long) uid);
		  rc = 1;
		}
	    }
	  else
#endif
	    {
	      anubis_error (SOFT, _("setuid(%lu) failed"), (u_long) uid);
	      rc = 1;
	    }
	}
	

      euid = geteuid();
      if (uid != 0 && setuid(0) == 0)
	{
	  anubis_error (HARD, _("seteuid(0) succeeded when it should not"));
	  rc = 1;
	}
      else if (uid != euid && setuid(euid) == 0)
	{
	  anubis_error (HARD, _("cannot drop non-root setuid privileges"));
	  rc = 1;
	}
    }
  return rc;
}

void
anubis_changeowner (char *user)
{
#ifdef HAVE_PAM
  int pam_retval;
#endif
  struct passwd *pwd;

  if (user == 0 || check_superuser () == 0)
    return;

#ifdef HAVE_PAM
  pam_retval = pam_start ("anubis", user, &conv, &pamh);
  if (pam_retval == PAM_SUCCESS)
    pam_retval = pam_authenticate (pamh, 0);
  if (pam_retval == PAM_SUCCESS)
    pam_retval = pam_acct_mgmt (pamh, 0);
  if (pam_retval == PAM_SUCCESS)
    pam_retval = pam_open_session (pamh, 0);
  if (pam_retval == PAM_SUCCESS)
    info (VERBOSE, _("PAM: Session opened (restrictions applied)."));
  else
    {
      info (NORMAL, _("PAM: Not authenticated to use GNU Anubis."));
      quit (EXIT_FAILURE);
    }
#endif /* HAVE_PAM */

  pwd = getpwnam (user);
  if (pwd)
    {
      if (change_privs (pwd->pw_uid, pwd->pw_gid))
	quit (EXIT_FAILURE);
	
      chdir (pwd->pw_dir);
      info (VERBOSE, _("UID:%d (%s), GID:%d, EUID:%d, EGID:%d"),
	    (int) getuid (), pwd->pw_name, (int) getgid (),
	    (int) geteuid (), (int) getegid ());
    }
  return;
}

int
check_username (char *user)
{
  struct passwd *pwd;

  if (user == 0)
    return 0;

  pwd = getpwnam (user);
  if (pwd == 0)
    {
      int i = 0;
      int digits = 0;
      int len = strlen (user);

      for (i = len - 1; i >= 0; i--)
	{
	  if (isdigit ((u_char) user[i]))
	    digits++;
	}
      if (digits == len)
	{
	  int uid = atoi (user);
	  pwd = getpwuid (uid);
	  if (pwd != 0)
	    strncpy (user, (char *) pwd->pw_name, 64);
	  else
	    {
	      info (NORMAL, _("Invalid user ID: %s"), user);
	      return 0;		/* FALSE */
	    }
	}
      else
	{
	  info (NORMAL, _("Invalid user name: %s"), user);
	  return 0;		/* FALSE */
	}
    }
  return 1;			/* TRUE */
}

/*************************
 Check a file permissions
**************************/

int
check_filemode (char *path)
{
  struct stat st;

  if (path == 0)
    return 0;

  if (stat (path, &st) == -1)
    return 0;
  if ((st.st_mode & S_IRWXG) || (st.st_mode & S_IRWXO))
    {
      anubis_error (SOFT, _("Wrong permissions on %s. Set 0600."), path);
      return 0;			/* FALSE */
    }
  return 1;			/* TRUE */
}

/*************************
 Check does a file exist?
**************************/

int
check_filename (char *path, time_t *timep)
{
  struct stat st;

  if (path == NULL)
    return 0;

  if (stat (path, &st) == -1)
    {
      anubis_error (HARD, "%s: %s.", path, strerror (errno));
      return 0;			/* FALSE */
    }
  if (!(st.st_mode & S_IFREG) || !(st.st_mode & S_IFLNK))
    {
      anubis_error (HARD,
		    _("%s is not a regular file or a symbolic link."), path);
      return 0;			/* FALSE */
    }

  if (timep)
    {
      time_t mtime = *timep;
      *timep = st.st_mtime;
      return st.st_mtime > mtime;
    }
  return 1;			/* TRUE */
}

/* Select working mode */
int
anubis_set_mode (char *modename)
{
  if (strcmp (modename, "transparent") == 0)
    anubis_mode = anubis_transparent;
  else if (strcmp (modename, "auth") == 0)
    anubis_mode = anubis_authenticate;
  else
    {
      mprintf (_("Unknown mode: %s"), modename);
      return 1;
    }
  return 0;
}

void
write_pid_file (void)
{
  FILE *fp;
  
  if (!pidfile)
    pidfile = "/var/run/" DEFAULT_PIDFILE;
  fp = fopen (pidfile, "w");
  if (!fp)
    anubis_error (SOFT, _("Cannot open pid file '%s': %s"),
		  pidfile, strerror (errno));
  fprintf (fp, "%ld\n", (unsigned long) getpid ());
  fclose (fp);
}
/* EOF */
