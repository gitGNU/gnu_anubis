/*
   rc.c

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

static int  optlength(char *);
static void match_options_common(int, char *);
static int  get_regex(int, char *, char *, int);
static char *parse_line_regex(char *);
static void get_action_line(char *);
static void match_action(char *, const char *);

static time_t global_mtime;

#define set(a, b, c) \
	if ((optlen = strlen((char *)a)) == 0) \
		return; \
	if (strncmp("yes", (char *)a, optlen) == 0) \
		b |= c; \
	else if (strncmp("no", (char *)a, optlen) == 0) \
		b &= ~c; \
	return;

#define if_empty_quit(a) \
	if (strlen((char *)a) == 0) \
		return;

#define if_empty_set(a, b, c) \
	if (strlen((char *)a) == 0) { \
		b &= ~c; \
		return; \
	} \
	else if (strlen((char *)a) != 0) { \
		b |= c; \
		return; \
	}

void
open_rcfile(int method)
{
	int n;
	char homedir[MAXPATHLEN+1];
	char local_rcfile[] = DEFAULT_LOCAL_RCFILE;
	char *rcfile = 0;
	char *user = 0;

	if (method == SUPERVISOR)
		user = session.supervisor;
	else if (method == CLIENT)
		user = session.client;

	get_homedir(user, homedir, sizeof(homedir));
	n = strlen(homedir) + strlen(local_rcfile) + 2;
	n = n > MAXPATHLEN ? MAXPATHLEN + 1 : n + 1;

	if (method == SUPERVISOR) {
		if (topt & T_ALTRC) {
			if (check_filename(options.altrc) == 0)
				return;
			rcfile = allocbuf(options.altrc, MAXPATHLEN);
		}
		else {
			if (check_superuser())
				rcfile = allocbuf(DEFAULT_GLOBAL_RCFILE, MAXPATHLEN);
			else {
				rcfile = (char *)xmalloc(n);
#ifdef HAVE_SNPRINTF
				snprintf(rcfile, n - 1,
#else
				sprintf(rcfile,
#endif /* HAVE_SNPRINTF */
					"%s/%s", homedir, local_rcfile);
			}
		}
	}
	else if (method == CLIENT) {
		rcfile = (char *)xmalloc(n);
#ifdef HAVE_SNPRINTF
		snprintf(rcfile, n - 1,
#else
		sprintf(rcfile,
#endif /* HAVE_SNPRINTF */
			"%s/%s", homedir, local_rcfile);
	}

	if (check_filemode(rcfile) == 0) { /* Wrong permissions... */
		free(rcfile);
		return;
	}

	if (method == SUPERVISOR) {
		struct stat st;
		if (stat(rcfile, &st) == 0) {
			if (global_mtime != st.st_mtime)
				global_mtime = st.st_mtime;
			else {
				free(rcfile);
				return;
			}
		}
	}
	fp_rcfile = fopen(rcfile, "r");
	if (fp_rcfile == 0) {
		if (options.termlevel == DEBUG)
			anubis_error(SOFT, _("Anubis RC file error: %s."), strerror(errno));
	}
	else {
		if (method == SUPERVISOR)
			info(DEBUG, _("Reading system configuration file %s..."), rcfile);
		else if (method == CLIENT)
			info(DEBUG, _("Reading user configuration file %s..."), rcfile);
	}
	free(rcfile);
	return;
}

void
read_rcfile(int method)
{
	char rcline[LINEBUFFER+1];
	unsigned long rcfile_position = 0;

	if (fp_rcfile == 0)
		return;

	rcfile_position = get_position(BEGIN_CONTROL);
	if (rcfile_position == 0)
		return;
	else
		info(DEBUG, _("The %s section has been found. Processing..."), "CONTROL");

	fseek(fp_rcfile, rcfile_position, SEEK_SET);
	while (fgets(rcline, LINEBUFFER, fp_rcfile) != 0)
	{
		if (strncmp(rcline, "#", 1) == 0 || strncmp(rcline, LF, 1) == 0)
			continue; /* skip: an empty line, comment (#) */
		else if (strncmp(rcline, END_SECTION, endsection_len) == 0)
			break; /* THE END */
		else
			match_options_common(method, rcline);
	}
	if (!(topt & T_ALLOW_LOCAL_MTA))
		topt &= ~T_LOCAL_MTA;

	if (method >= SUPERVISOR) {
		rcfile_position = get_position(BEGIN_TRANSLATION);
		if (rcfile_position == 0) {
			topt &= ~T_TRANSLATION_MAP;
			return;
		}
		else
			info(DEBUG, _("The %s section has been found. Processing..."), "TRANSLATION");

		destroy_list(&session.transmap);
		topt |= T_TRANSLATION_MAP;

		fseek(fp_rcfile, rcfile_position, SEEK_SET);
		while (fgets(rcline, LINEBUFFER, fp_rcfile) != 0)
		{
			if (strncmp(rcline, "#", 1) == 0 || strncmp(rcline, LF, 1) == 0)
				continue; /* skip: an empty line, comment (#) */
			else if (strncmp(rcline, END_SECTION, endsection_len) == 0)
				break; /* THE END */
			else {
				remcrlf(rcline);
				session.transmap_tail = new_element(session.transmap_tail,
					&session.transmap, rcline);
			}
		}
	}
	return;
}

void
read_rcfile_allsection(void)
{
	char rcline[LINEBUFFER+1];

	if (fp_rcfile == 0)
		return;

	if (all_position == 0) {
		all_position = get_position(BEGIN_ALL);
		if (all_position == 0)
			return;
		else
			info(DEBUG, _("The %s section has been found. Processing..."), "ALL");
	}

	fseek(fp_rcfile, all_position, SEEK_SET);
	while (fgets(rcline, LINEBUFFER, fp_rcfile) != 0)
	{
		if (strncmp(rcline, "#", 1) == 0 || strncmp(rcline, LF, 1) == 0)
			continue; /* skip: an empty line, comment (#) */
		else if (strncmp(rcline, END_SECTION, endsection_len) == 0)
			break; /* THE END */
		else {
			get_action_line(rcline);
			match_action(rcline, NULL);
		}
	}
	return;
}

#ifdef WITH_GUILE
static void
match_action_guile(char *buf)
{
	char *ptr = 0;
	int optlen;
	
	optlen = optlength(buf);
	if (optlen == 0)
		return;

	/*
	    Guile
	*/
	if (strncmp("guile-output", buf, optlen) == 0) {
		ptr = parse_line_option(buf);
		if_empty_quit(ptr);

		xfree(options.guile_logfile);
		options.guile_logfile = allocbuf(ptr, MAXPATHLEN);
	}
	if (strncmp("guile-debug", buf, optlen) == 0) {
		ptr = parse_line_option(buf);
		if_empty_quit(ptr);

		guile_debug(strncmp("yes", ptr, 3) == 0);
	}	
	if (strncmp("guile-load-path-append", buf, optlen) == 0) {
		ptr = parse_line_option(buf);
		if_empty_quit(ptr);
		guile_load_path_append(ptr);
		return;
	}
	if (strncmp("guile-load-program", buf, optlen) == 0) {
		ptr = parse_line_option(buf);
		if_empty_quit(ptr);
		guile_load_program(ptr);
		return;
	}
	if (strncmp("guile-postprocess", buf, optlen) == 0) {
		ptr = parse_line_option(buf);
		if_empty_quit(ptr);

		xfree(options.guile_postprocess);
		options.guile_postprocess = allocbuf(ptr, MAXPATHLEN);
		return;
	}
}

void
read_rcfile_guile(void)
{
	char rcline[LINEBUFFER+1];

	if (fp_rcfile == 0)
		return;

	if (guile_position == 0) {
		guile_position = get_position(BEGIN_GUILE);
		if (guile_position == 0)
			return;
		else
			info(DEBUG, _("The %s section has been found. Processing..."), "GUILE");
	}

	fseek(fp_rcfile, guile_position, SEEK_SET);
	while (fgets(rcline, LINEBUFFER, fp_rcfile) != 0)
	{
		if (strncmp(rcline, "#", 1) == 0
		    || strncmp(rcline, LF, 1) == 0)
			continue; /* skip: an empty line, comment (#) */
		else if (strncmp(rcline, END_SECTION, endsection_len) == 0)
			break; /* THE END */
		else {
			get_action_line(rcline);
			match_action_guile(rcline);
		}
	}
	return;
}
#endif /* WITH_GUILE */

void
close_rcfile(void)
{
	if (fp_rcfile == 0)
		return;
	if (fclose(fp_rcfile) != 0)
		anubis_error(SOFT, _("Fatal fclose() error. %s."), strerror(errno));
	fp_rcfile = 0;
	return;
}

char *
parse_line_option(char *line)
{
	char *ptr = 0;
	ptr = strchr(line, '=');

	if (ptr == 0)
		return line;
	do {
		ptr++;
	} while (*ptr == ' ' || *ptr == '\t');

	remcrlf(ptr);
	return ptr;
}

static int
optlength(char *p)
{
	register int n = 0;
	while (*p != ' ' && *p != '\t' && *p != '=')
	{
		n++;
		p++;
	}
	return n;
}

static void
match_options_common(int method, char *rcline)
{
	char *ptr = 0;
	char buf[LINEBUFFER+1];
	int optlen;

	safe_strcpy(buf, rcline);
	change_to_lower(buf);
	optlen = optlength(buf);
	if (optlen == 0)
		return;

	if (method == INIT) {
		if (strncmp("bind", buf, optlen) == 0) {
			ptr = parse_line_option(rcline);
			if_empty_quit(ptr);
			parse_mtahost(ptr, session.tunnel, &session.tunnel_port);
			if (strlen(session.tunnel) != 0)
				topt |= T_NAMES;
			return;
		}
	}
	if (method >= SUPERVISOR) {
		if (strncmp("termlevel", buf, optlen) == 0) {
			ptr = parse_line_option(buf);
			if ((optlen = strlen(ptr)) == 0)
				return;
			if (strncmp("silent", ptr, optlen) == 0)
				options.termlevel = SILENT;
			else if (strncmp("normal", ptr, optlen) == 0)
				options.termlevel = NORMAL;
			else if (strncmp("verbose", ptr, optlen) == 0)
				options.termlevel = VERBOSE;
			else if (strncmp("debug", ptr, optlen) == 0)
				options.termlevel = DEBUG;
			return;
		}
		if (strncmp("allow-local-mta", buf, optlen) == 0) {
			set(parse_line_option(buf), topt, T_ALLOW_LOCAL_MTA);
		}
		if (strncmp("user-notprivileged", buf, optlen) == 0) {
			safe_strcpy(session.notprivileged, parse_line_option(rcline));
			if_empty_set(session.notprivileged, topt, T_USER_NOTPRIVIL);
		}
	}
	if (strncmp("logfile", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);

		if (method >= SUPERVISOR) {
			xfree(options.slogfile);
			options.slogfile = allocbuf(ptr, MAXPATHLEN);
			return;
		}
		if (method == CLIENT) {
			xfree(options.ulogfile);
			options.ulogfile = allocbuf(ptr, MAXPATHLEN);
			return;
		}
		return;
	}
	if (method == CLIENT) {
		if (strncmp("loglevel", buf, optlen) == 0) {
			ptr = parse_line_option(buf);
			if ((optlen = strlen(ptr)) == 0)
				return;
			if (strncmp("none", ptr, optlen) == 0)
				options.uloglevel = NONE;
			else if (strncmp("all", ptr, optlen) == 0)
				options.uloglevel = ALL;
			else if (strncmp("fails", ptr, optlen) == 0)
				options.uloglevel = FAILS;
			return;
		}
	}
	if (strncmp("remote-mta", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		parse_mtaport(ptr, session.mta, &session.mta_port);
		return;
	}
	if (strncmp("local-mta", buf, optlen) == 0) {
		char *a = 0;
		char *p = 0;
		char tmp[LINEBUFFER+1];
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);

		a = strchr(ptr, ' '); /* an extra arguments */
		if (a) {
			*a++ = '\0';
			p = strrchr(ptr, '/');
			if (p)
				p++;
			else
				p = ptr;
#ifdef HAVE_SNPRINTF
			snprintf(tmp, LINEBUFFER,
#else
			sprintf(tmp,
#endif /* HAVE_SNPRINTF */
				"%s %s", p, a);
			p = ptr;
			a = tmp;
		}
		else { /* no arguments */
			p = ptr;
			a = strrchr(ptr, '/');
			if (a)
				a++;
			else
				a = ptr;
		}
		xfree(session.execpath);
		session.execpath = allocbuf(p, MAXPATHLEN);
		topt |= T_LOCAL_MTA;
		if (topt & T_RCEXECARGS) {
			xfree_pptr(session.execargs);
			topt &= ~T_RCEXECARGS;
		}
		session.execargs = gen_execargs(a);
		topt |= T_RCEXECARGS;
		return;
	}
	if (strncmp("esmtp-auth", buf, optlen) == 0) {
		char *p = 0;
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		p = strchr(ptr, ':');
		if (p) {
			safe_strcpy(session.mta_password, ++p);
			*--p = '\0';
			safe_strcpy(session.mta_username, ptr);
			topt |= T_ESMTP_AUTH;
		}
		return;
	}

	/*
	   Proxies.
	*/

	if (strncmp("socks-proxy", buf, optlen) == 0) {
		parse_mtaport(parse_line_option(rcline), session.socks,
		&session.socks_port);
		if_empty_set(session.socks, topt, T_SOCKS);
	}
	if (strncmp("socks-v4", buf, optlen) == 0) {
		set(parse_line_option(buf), topt, T_SOCKS_V4);
	}
	if (strncmp("socks-auth", buf, optlen) == 0) {
		char *p = 0;
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		p = strchr(ptr, ':');
		if (p) {
			safe_strcpy(session.socks_password, ++p);
			*--p = '\0';
			safe_strcpy(session.socks_username, ptr);
			topt |= T_SOCKS_AUTH;
		}
		return;
	}

	/*
	   TLS/SSL.
	*/

#if defined(HAVE_TLS) || defined(HAVE_SSL)
	if (strncmp("ssl", buf, optlen) == 0) {
		set(parse_line_option(buf), topt, T_SSL);
	}
	if (strncmp("oneway-ssl", buf, optlen) == 0) {
		set(parse_line_option(buf), topt, T_SSL_ONEWAY);
	}
	if (strncmp("cert", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(secure.cert);
		secure.cert = allocbuf(ptr, MAXPATHLEN);
		if (method == CLIENT)
			topt |= T_SSL_CKCLIENT;
		return;
	}
	if (strncmp("key", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(secure.key);
		secure.key = allocbuf(ptr, MAXPATHLEN);
		if (method == CLIENT)
			topt |= T_SSL_CKCLIENT;
		return;
	}
	if (strncmp("cafile", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(secure.cafile);
		secure.cafile = allocbuf(ptr, MAXPATHLEN);
		return;
	}
#endif /* HAVE_TLS or HAVE_SSL */

	return;
}

int
read_regex_block(int method, char *regex, int size)
{
	char rcline[LINEBUFFER+1];

	if (fp_rcfile == 0)
		return 0;

	while (fgets(rcline, LINEBUFFER, fp_rcfile) != 0)
	{
		if (strncmp(rcline, "#", 1) == 0 || strncmp(rcline, LF, 1) == 0)
			continue; /* skip: an empty line, comment (#) */
		else if (strncmp(rcline, END_SECTION, endsection_len) == 0)
			break; /* END OF REGEX BLOCK */
		else {
			if (get_regex(method, rcline, regex, size) == 0)
				continue;
			else
				return 1;
		}
	}
	return 0;
}

static int
get_regex(int method, char *rcline, char *regex, int size)
{
	char *ptr = 0;
	int rs = 0;

	if (method == HEADER) { /* "IF HEADER =..." */
		rs = regex_match("[ \t]*if[ \t]+header.*=", rcline);
		if (rs == 0)
			rs = regex_match("[ \t]*rule.*=", rcline);
	}
	else if (method == COMMAND) { /* "IF COMMAND =..." */
		rs = regex_match("[ \t]*if[ \t]+command.*=", rcline);
	}
	if (rs == 0)
		return 0;
	ptr = parse_line_regex(rcline);
	if (strlen(ptr) == 0)
		return 0;
	strncpy(regex, ptr, size);
	return 1;
}

static char *
parse_line_regex(char *rcline)
{
	char *ptr = 0;
	char *optptr = 0;
	int len;
	char optbuf[LINEBUFFER+1];
	memset(optbuf, 0, LINEBUFFER + 1);

	ptr = strchr(rcline, '=');
	if (ptr == 0)
		return rcline;

	len = strlen(rcline);
	len -= strlen(ptr);
	strncpy(optbuf, rcline, len);

	optptr = strchr(optbuf, ':'); /* additional options */
	if (optptr) {
		optptr++;
		change_to_lower(optptr);
		if (strstr(optptr, "basic"))
			ropt |= R_BASIC;
		if (strstr(optptr, "scase"))
			ropt |= R_SCASE;
#ifdef HAVE_PCRE
		if (strstr(optptr, "perlre"))
			ropt |= R_PERLRE;
#endif /* HAVE_PCRE */
	}
	else
		ropt = 0;
	ptr++;
	remcrlf(ptr);
	return ptr;
}

/*********************
 Read an ACTION-BLOCK
**********************/

int
read_action_block(const char *source_line)
{
	char rcline[LINEBUFFER+1];

	if (fp_rcfile == 0)
		return 0;

	while (fgets(rcline, LINEBUFFER, fp_rcfile) != 0)
	{
		if (strncmp(rcline, "#", 1) == 0 || strncmp(rcline, LF, 1) == 0)
			continue; /* skip: an empty line, comment (#) */
		else if (regex_match("[ \t]*(done|fi)[^0-9A-Za-z][ \t]*", rcline))
			break; /* 'fi' - END OF REGEX BLOCK ACTION */
		else {
			get_action_line(rcline);
			match_action(rcline, source_line);
			return 1;
		}
	}
	return 0;
}

static void
get_action_line(char *rcline)
{
	char *ptr = 0;
	char buf[LINEBUFFER+1];

	safe_strcpy(buf, rcline);
	ptr = buf;
	while (*ptr == ' ' || *ptr == '\t')
		ptr++;

	remcrlf(ptr);
	strncpy(rcline, ptr, LINEBUFFER);
	return;
}

static void
match_action(char *rcline, const char *source_line)
{
	char *ptr = 0;
	char *outbuf = 0;
	char buf[LINEBUFFER+1];
	int optlen;

	outbuf = substitute(rcline, submatch);
	if (outbuf) {
		strncpy(rcline, outbuf, LINEBUFFER);
		free(outbuf);
	}
	safe_strcpy(buf, rcline);
	change_to_lower(buf);
	optlen = optlength(buf);
	if (optlen == 0)
		return;

	if (strncmp("add", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		message.addlist_tail = new_element(message.addlist_tail,
			&message.addlist, ptr);
		return;
	}
	if (strncmp("remove", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		message.remlist_tail = new_element(message.remlist_tail,
			&message.remlist, ptr);
		return;
	}
	if (strncmp("modify", buf, optlen) == 0) {
		char *p = 0;
		char modify[LINEBUFFER+1];
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		p = strstr(ptr, " >> "); /* "SPC>>SPC" is a separator */
		if (p) {
			p += 4;
			strncpy(modify, p, LINEBUFFER-2);
			strcat(modify, CRLF);
			p -= 4;
			*p = '\0';
			message.modlist_tail = new_element(message.modlist_tail,
				&message.modlist, ptr);
			message.modlist_tail->modify = strdup(modify);
		}
		return;
	}
	if (strncmp("rot13-subject", buf, optlen) == 0) {
		set(parse_line_option(buf), mopt, M_ROT13S);
	}
	if (strncmp("rot13-body", buf, optlen) == 0) {
		set(parse_line_option(buf), mopt, M_ROT13B);
	}
	if (strncmp("signature-file-append", buf, optlen) == 0) {
		set(parse_line_option(buf), mopt, M_SIGNATURE);
	}
	if (strncmp("body-clear-append", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(message.body_append);
		message.body_append = allocbuf(ptr, MAXPATHLEN);
		mopt |= M_BODYAPPEND;
		mopt |= M_BODYCLEARAPPEND;
		return;
	}
	if (strncmp("body-append", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(message.body_append);
		message.body_append = allocbuf(ptr, MAXPATHLEN);
		mopt |= M_BODYAPPEND;
		mopt &= ~M_BODYCLEARAPPEND;
		return;
	}
	if (strncmp("external-body-processor", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(message.exteditor);
		message.exteditor = allocbuf(ptr, MAXPATHLEN);
		mopt |= M_EXTBODYPROC;
		return;
	}

	/*
	   GnuPG support.
	*/

#ifdef HAVE_GPG
	if (strncmp("gpg-passphrase", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		if (gpg.passphrase) {
			memset(gpg.passphrase, 0, strlen(gpg.passphrase));
			xfree(gpg.passphrase);
		}
		gpg.passphrase = allocbuf(ptr, 0);
		mopt |= M_GPG_PASSPHRASE;
		return;
	}
	if (strncmp("gpg-encrypt", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(gpg.keys);
		gpg.keys = allocbuf(ptr, 0);
		gpg.keys = (char *)xrealloc((char *)gpg.keys, strlen(gpg.keys) + 2);
		strcat(gpg.keys, ",");
		mopt |= M_GPG_ENCRYPT;
		return;
	}
	if (strncmp("gpg-sign", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		if (regex_match("yes", ptr) == 0
		|| (mopt & M_GPG_PASSPHRASE) == 0) {
			if (gpg.passphrase) {
				memset(gpg.passphrase, 0, strlen(gpg.passphrase));
				xfree(gpg.passphrase);
			}
			gpg.passphrase = allocbuf(ptr, 0);
		}
		mopt |= M_GPG_SIGN;
		return;
	}
#endif /* HAVE_GPG */

	/*
	   Guile support
	*/
#ifdef WITH_GUILE
	if (strncmp("guile-rewrite-line", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		guile_rewrite_line(ptr, source_line);
		return;
	}
#endif /* WITH_GUILE */
	
	/*
	   Remailer Type-I support.
	*/

	if (strncmp("rm-rrt", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(rm.rrt);
		rm.rrt = allocbuf(ptr, 0);
		mopt |= M_RM;
		mopt |= M_RMRRT;
		return;
	}
	if (strncmp("rm-post", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(rm.post);
		rm.post = allocbuf(ptr, 0);
		mopt |= M_RM;
		mopt |= M_RMPOST;
		return;
	}
#ifdef HAVE_GPG
	if (strncmp("rm-gpg", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(gpg.rm_key);
		gpg.rm_key = allocbuf(ptr, 0);
		mopt |= M_RMGPG;
		return;
	}
#endif /* HAVE_GPG */
	if (strncmp("rm-header", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(rm.header);
		rm.header = allocbuf(ptr, LINEBUFFER + 1);
		mopt |= M_RMHEADER;
		return;
	}
	if (strncmp("rm-lt", buf, optlen) == 0) {
		ptr = parse_line_option(rcline);
		if_empty_quit(ptr);
		xfree(rm.latent_time);
		rm.latent_time = allocbuf(ptr, 16);
		mopt |= M_RMLT;
		return;
	}
	if (strncmp("rm-rlt", buf, optlen) == 0) {
		set(parse_line_option(buf), mopt, M_RMRLT);
	}
	return;
}

/**************************
 Find the 'LINE' position.
***************************/

unsigned long
get_position(char *line)
{
	char buf[LINEBUFFER+1];

	if (fp_rcfile == 0 || line == 0)
		return 0;

	rewind(fp_rcfile);
	while (fgets(buf, LINEBUFFER, fp_rcfile) != 0)
	{
		if (strncmp(buf, line, strlen(line)) == 0)
			return (unsigned long)ftell(fp_rcfile);
	}
	return 0;
}

/* EOF */

