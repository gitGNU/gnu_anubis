/*
   env.c

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
argv_dup(int argc, char **argv)
{
	char **xargv = xmalloc((argc + 1) * sizeof(*xargv));
	int i;

	for (i = 0; i < argc; i++)
		xargv[i] = strdup(argv[i]);
	xargv[i] = NULL;
	return xargv;
}

static int gindex = 0;

#define OPT_VERSION          257
#define OPT_HELP             258
#define OPT_ALTRC            259
#define OPT_NORC             260
#define OPT_SHOW_CONFIG      261
#define OPT_RELAX_PERM_CHECK 262

static struct option gopt[] =
{
	{"bind",        required_argument, 0, 'b'},
	{"remote-mta",  required_argument, 0, 'r'},
	{"local-mta",   required_argument, 0, 'l'},
	{"foreground",  no_argument,       0, 'f'},
	{"stdio",       no_argument,       0, 'i'},
	{"silent",      no_argument,       0, 's'},
	{"verbose",     no_argument,       0, 'v'},
	{"debug",       no_argument,       0, 'D'},
	{"version",     no_argument,       0, OPT_VERSION},
	{"help",        no_argument,       0, OPT_HELP},
	{"altrc",       required_argument, 0, OPT_ALTRC},
	{"norc",        no_argument,       0, OPT_NORC},
	{"check-config",optional_argument, 0, 'c'},
	{"show-config-options", no_argument, 0, OPT_SHOW_CONFIG },
	{"relax-perm-check", no_argument,  0, OPT_RELAX_PERM_CHECK },
#if defined(WITH_GSASL)
	{"mode",        required_argument, 0, 'm'},
#endif
	{0, 0, 0, 0}
};

void
get_options(int argc, char *argv[])
{
	int c;

	while ((c = getopt_long(argc, argv, "b:r:l:fisvDc::?",
				gopt, &gindex)) != EOF) {
		switch (c) {
		case OPT_HELP:
			print_usage();
			break;
			       
		case OPT_VERSION:
			print_version();
			break;

		case OPT_NORC:
			topt |= T_NORC;
			break;

		case OPT_ALTRC:
			options.altrc = optarg;
			topt |= T_ALTRC;
			break;

		case OPT_SHOW_CONFIG:
			print_config_options();
			break;

		case OPT_RELAX_PERM_CHECK:
			topt |= T_RELAX_PERM_CHECK;
			break;
			
		case 'c':
			rc_set_debug_level(optarg);
			topt |= T_CHECK_CONFIG;
			break;
			
		case 'b': /* daemon's port number, host name */
			parse_mtahost(optarg, session.tunnel,
				      &session.tunnel_port);
			if (strlen(session.tunnel) != 0)
				topt |= T_NAMES;
			break;

		case 'r': /* a remote SMTP host name or IP address */
			parse_mtaport(optarg, session.mta, &session.mta_port);
			break;
			
		case 'l': /* a local SMTP mode */
			session.execpath = allocbuf(optarg, MAXPATHLEN);
			topt |= T_LOCAL_MTA;
			break;
			
		case 'f': /* foreground mode */
			topt |= T_FOREGROUND_INIT;
			break;
			
		case 'i': /* stdin/stdout */
			topt |= T_STDINOUT;
			break;
			
		case 'v': /* verbose */
			options.termlevel = VERBOSE;
			break;
			
		case 'D': /* debug */
			options.termlevel = DEBUG;
			break;

		case 's': /* silent */
			options.termlevel = SILENT;
			break;

		case 'm':
			if (strcmp (optarg, "transparent") == 0)
				anubis_mode = anubis_transparent;
			else if (strcmp (optarg, "auth") == 0)
				anubis_mode = anubis_authenticate;
			else {
				mprintf(_("%s: Unknown mode: %s"),
					argv[0], optarg);
				exit (1);
			}
			break;
			
		case '?':
		default:
			mprintf(_("Try '%s --help' for more information."), argv[0]);
			quit(0);
		}
	}
	
	if (topt & T_LOCAL_MTA) {
		if (optind == argc) { /* No extra arguments specified. */
			if (session.execpath) {
				char *ptr = strrchr(session.execpath, '/');
				if (ptr)
					ptr++;
				else
					ptr = session.execpath;
				session.execargs = gen_execargs(ptr);
			}
		}
		else
			session.execargs = argv_dup(argc - optind, argv + optind);
	}
	return;
}

/*********************
 Get a home directory
**********************/

void
get_homedir(char *user, char *buf, int maxsize)
{
	struct passwd *pwd;
	memset(buf, 0, maxsize);

	if (user == 0)
		return;

	pwd = getpwnam(user);
	if (pwd)
		strncpy(buf, (char *)pwd->pw_dir, maxsize - 1);
	else {
		char *p = getenv("HOME");
		if (p)
			strncpy(buf, p, maxsize - 1);
		else
			strncpy(buf, "", 1);
	}
	return;
}

/*****************************
 Get a real user name (login)
******************************/

void
anubis_getlogin(char *buf, int maxsize)
{
	struct passwd *pwd;
	memset(buf, 0, maxsize);

	pwd = getpwuid(getuid());
	if (pwd)
		strncpy(buf, (char *)pwd->pw_name, maxsize - 1);
	else
		strncpy(buf, (char *)getlogin(), maxsize - 1);
	return;
}

/*******************
 Check current RUID
********************/

int
check_superuser(void)
{
	if (getuid() == 0)
		return 1; /* a super-user */
	return 0;
}

/*******************************************
 Set USER's RGID, RUID, and home directory.
********************************************/

void
anubis_changeowner(char *user)
{
#ifdef HAVE_PAM
	int pam_retval;
#endif /* HAVE_PAM */
	struct passwd *pwd;

	if (user == 0 || check_superuser() == 0)
		return;

#ifdef HAVE_PAM
	pam_retval = pam_start("anubis", user, &conv, &pamh);
	if (pam_retval == PAM_SUCCESS)
		pam_retval = pam_authenticate(pamh, 0);
	if (pam_retval == PAM_SUCCESS)
		pam_retval = pam_acct_mgmt(pamh, 0);
	if (pam_retval == PAM_SUCCESS)
		pam_retval = pam_open_session(pamh, 0);
	if (pam_retval == PAM_SUCCESS)
		info(VERBOSE, _("PAM: Session opened (restrictions applied)."));
	else {
		info(NORMAL, _("PAM: Not authenticated to use GNU Anubis."));
		quit(EXIT_FAILURE);
	}
#endif /* HAVE_PAM */

	pwd = getpwnam(user);
	if (pwd) {
		setgid(pwd->pw_gid);
		setuid(pwd->pw_uid);
		chdir(pwd->pw_dir);
		info(VERBOSE, _("UID:%d, GID:%d, EUID:%d, EGID:%d"), (int)getuid(),
			(int)getgid(), (int)geteuid(), (int)getegid());
	}
	return;
}

int
check_username(char *user)
{
	struct passwd *pwd;

	if (user == 0)
		return 0;

	pwd = getpwnam(user);
	if (pwd == 0) {
		int i = 0;
		int digits = 0;
		int len = strlen(user);

		for (i = len - 1; i >= 0; i--)
		{
			if (isdigit((u_char) user[i]))
				digits++;
		}
		if (digits == len) {
			int uid = atoi(user);
			pwd = getpwuid(uid);
			if (pwd != 0)
				strncpy(user, (char *)pwd->pw_name, 64);
			else {
				info(NORMAL, _("Invalid user ID: %s"), user);
				return 0; /* FALSE */
			}
		}
		else {
			info(NORMAL, _("Invalid user name: %s"), user);
			return 0; /* FALSE */
		}
	}
	return 1; /* TRUE */
}

/*************************
 Check a file permissions
**************************/

int
check_filemode(char *path)
{
	struct stat st;

	if (path == 0)
		return 0;

	if (stat(path, &st) == -1)
		return 0;
	if ((st.st_mode & S_IRWXG) || (st.st_mode & S_IRWXO)) {
		anubis_error(SOFT, _("Wrong permissions on %s. Set 0600."), path);
		return 0; /* FALSE */
	}
	return 1; /* TRUE */
}

/*************************
 Check does a file exist?
**************************/

int
check_filename(char *path, time_t *timep)
{
	struct stat st;

	if (path == 0)
		return 0;

	if (stat(path, &st) == -1) {
		anubis_error(HARD, "%s -- %s.", path, strerror(errno));
		return 0; /* FALSE */
	}
	if (!(st.st_mode & S_IFREG) || !(st.st_mode & S_IFLNK)) {
		anubis_error(HARD,
			_("%s is not a regular file or a symbolic link."), path);
		return 0; /* FALSE */
	}

	if (timep) {
		time_t mtime = *timep;
		*timep = st.st_mtime;
		return st.st_mtime > mtime;
	}
	return 1; /* TRUE */
}

/* EOF */

