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
#include "rcfile.h"

#define setbool(a, b, c) \
   do {\
        if (strcmp("yes", a) == 0) \
		(b) |= (c); \
	else if (strcmp("no", a) == 0) \
		(b) &= ~(c); \
        else \
                return RC_KW_ERROR; \
   } while (0)

#define if_empty_set(a, b, c) \
   do {\
	if (strlen(a) == 0) { \
		(b) &= ~(c); \
	} else { \
		(b) |= (c); \
	}\
   } while (0)		 

#define MAX_SECTIONS 10

static RC_SECTION *parse_tree;
static time_t global_mtime;
static struct rc_secdef anubis_rc_sections[MAX_SECTIONS];
static int anubis_rc_numsections;

struct rc_secdef *
anubis_add_section(char *name)
{
	int i;
	
	if (anubis_rc_numsections >= MAX_SECTIONS)
		abort(); /*FIXME*/
	
	for (i = 0; i < anubis_rc_numsections; i++)
		if (strcmp(anubis_rc_sections[i].name, name) == 0)
			return &anubis_rc_sections[i];
	
	anubis_rc_sections[anubis_rc_numsections].name = name;
	anubis_rc_sections[anubis_rc_numsections].child = NULL;
	return &anubis_rc_sections[anubis_rc_numsections++];
}

void
open_rcfile(int method)
{
	char homedir[MAXPATHLEN+1];
	char *rcfile = 0;
	RC_SECTION *sec;

	switch (method) {
	case CF_SUPERVISOR:
	case CF_INIT:
		if (topt & T_ALTRC) {
			rcfile = strdup(options.altrc);
		} else if (check_superuser())
			rcfile = strdup(DEFAULT_GLOBAL_RCFILE);
		else {
			get_homedir(session.supervisor,
				    homedir, sizeof(homedir));
			rcfile = xmalloc(strlen(homedir) +
					 strlen(DEFAULT_LOCAL_RCFILE) + 2);
			sprintf(rcfile,	"%s/%s", homedir,
				DEFAULT_LOCAL_RCFILE);
		}
		
		if (check_filename(rcfile, &global_mtime) == 0) {
			free(rcfile);
			return;
		}
		info(DEBUG,
		     _("Reading system configuration file %s..."), rcfile);
		rc_section_list_destroy(parse_tree);
		parse_tree = NULL;
		break;

	case CF_CLIENT:
		if ((topt & (T_ALTRC|T_NORC)) == (T_ALTRC|T_NORC)) {
			rcfile = strdup(options.altrc);
		} else {
			get_homedir(session.client,
				    homedir, sizeof(homedir));
			rcfile = xmalloc(strlen(homedir) +
					 strlen(DEFAULT_LOCAL_RCFILE) + 2);
			sprintf(rcfile,	"%s/%s", homedir,
				DEFAULT_LOCAL_RCFILE);
		}
		info(DEBUG,
		     _("Reading user configuration file %s..."), rcfile);
	}

	if ((topt & T_RELAX_PERM_CHECK) == 0
	    && check_filemode(rcfile) == 0) { /* Wrong permissions... */
		free(rcfile);
		return;
	}

	sec = rc_parse(rcfile);
	/* FIXME: check 'sec' against anubis_rc_sections and remove the
	   erroneous statements  */
	free(rcfile);

	if (sec)
		rc_section_link(&parse_tree, sec);
}

void
process_rcfile(int method)
{
	rc_run_section_list(method, parse_tree, anubis_rc_sections);
}

/* ************************** The CONTROL Section ************************* */ 
#define KW_BIND                0
#define KW_TERMLEVEL           1
#define KW_ALLOW_LOCAL_MTA     2
#define KW_ALLOW_NOTPRIVILEGED 3 
#define KW_LOGLEVEL            4
#define KW_LOGFILE             5
#define KW_REMOTE_MTA          6 
#define KW_LOCAL_MTA           7
#define KW_ESMTP_AUTH          8
#define KW_SOCKS_PROXY         9
#define KW_SOCKS_V4           10
#define KW_SOCKS_AUTH         11
#define KW_READ_ENTIRE_BODY   12

int
control_parser(int method, int key, char *arg,
	       void *inv_data, void *func_data, char *line)
{
	switch (key) {
	case KW_BIND:                
		parse_mtahost(arg, session.tunnel, &session.tunnel_port);
		if (strlen(session.tunnel) != 0)
			topt |= T_NAMES;
		break;
		
	case KW_TERMLEVEL:           
		if (strcmp("silent", arg) == 0)
			options.termlevel = SILENT;
		else if (strcmp("normal", arg) == 0)
			options.termlevel = NORMAL;
		else if (strcmp("verbose", arg) == 0)
			options.termlevel = VERBOSE;
		else if (strcmp("debug", arg) == 0)
			options.termlevel = DEBUG;
		else
			return RC_KW_ERROR;
		break;
		
	case KW_ALLOW_LOCAL_MTA:
		setbool(arg, topt, T_ALLOW_LOCAL_MTA);
		break;
		
	case KW_ALLOW_NOTPRIVILEGED:
		safe_strcpy(session.notprivileged, arg);
		break;

	case KW_LOGFILE:
		if (method & (CF_SUPERVISOR|CF_INIT)) {
			xfree(options.slogfile);
			options.slogfile = allocbuf(arg, MAXPATHLEN);
		} else if (method == CF_CLIENT) {
			xfree(options.ulogfile);
			options.ulogfile = allocbuf(arg, MAXPATHLEN);
		}
		break;
		
	case KW_LOGLEVEL:
		if (strcmp("none", arg) == 0)
			options.uloglevel = NONE;
		else if (strcmp("all", arg) == 0)
			options.uloglevel = ALL;
		else if (strcmp("fails", arg) == 0)
			options.uloglevel = FAILS;
		else
			return RC_KW_ERROR;
		break;
		
	case KW_REMOTE_MTA:
		parse_mtaport(arg, session.mta, &session.mta_port);
		break;
		
	case KW_LOCAL_MTA: {
		char *a = 0;
		char *p = 0;
		char tmp[LINEBUFFER+1];

		a = strchr(arg, ' '); /* an extra arguments */
		if (a) {
			*a++ = '\0';
			p = strrchr(arg, '/');
			if (p)
				p++;
			else
				p = arg;
			snprintf(tmp, sizeof(tmp), "%s %s", p, a);
			p = arg;
			a = tmp;
		} else { /* no arguments */
			p = arg;
			a = strrchr(arg, '/');
			if (a)
				a++;
			else
				a = arg;
		}
		xfree(session.execpath);
		session.execpath = allocbuf(p, MAXPATHLEN);
		topt |= T_LOCAL_MTA;
		xfree_pptr(session.execargs);
		session.execargs = gen_execargs(a);
	}
	break;
		
	case KW_ESMTP_AUTH: {
		char *p = strchr(arg, ':');
		if (p) {
			safe_strcpy(session.mta_password, ++p);
			*--p = '\0';
			safe_strcpy(session.mta_username, arg);
			topt |= T_ESMTP_AUTH;
		}
	}		
	break;
		
	case KW_SOCKS_PROXY:
		parse_mtaport(arg, session.socks, &session.socks_port);
		if_empty_set(session.socks, topt, T_SOCKS);
		break;
		
	case KW_SOCKS_V4:
		setbool(arg, topt, T_SOCKS_V4);
		break;
		
	case KW_SOCKS_AUTH: { 
		char *p = 0;
		p = strchr(arg, ':');
		if (p) {
			safe_strcpy(session.socks_password, ++p);
			*--p = '\0';
			safe_strcpy(session.socks_username, arg);
			topt |= T_SOCKS_AUTH;
		}
		break;
	}

	case KW_READ_ENTIRE_BODY:
		setbool(arg, topt, T_ENTIRE_BODY);
		break;
		
	default:
		return RC_KW_UNKNOWN;
	}
	return RC_KW_HANDLED;
}

static struct rc_kwdef init_kw[] = {
	{ "bind", KW_BIND },
	{ NULL },
};

static struct rc_secdef_child init_sect_child = {
	NULL,
	CF_INIT,
	init_kw,
	control_parser,
	NULL
};

static struct rc_kwdef init_supervisor_kw[] = {
	{ "termlevel", KW_TERMLEVEL },
	{ "allow-local-mta", KW_ALLOW_LOCAL_MTA },
	{ "user-notprivileged", KW_ALLOW_NOTPRIVILEGED },
	{ NULL }
};

static struct rc_secdef_child init_supervisor_sect_child = {
	NULL,
	CF_INIT|CF_SUPERVISOR,
	init_supervisor_kw,
	control_parser,
	NULL
};

struct rc_kwdef client_kw[] = {
	{ "loglevel", KW_LOGLEVEL },
	{ NULL },
};

static struct rc_secdef_child client_sect_child = {
	NULL,
	CF_CLIENT,
	client_kw,
	control_parser,
	NULL
};

struct rc_kwdef control_kw[] = {
	{ "logfile", KW_LOGFILE },
	{ "remote-mta", KW_REMOTE_MTA },
	{ "local-mta", KW_LOCAL_MTA },
	{ "esmtp-auth", KW_ESMTP_AUTH },
	{ "socks-proxy", KW_SOCKS_PROXY },
	{ "socks-v4", KW_SOCKS_V4 },
	{ "socks-auth", KW_SOCKS_AUTH },
	{ "read-entire-body", KW_READ_ENTIRE_BODY },
	{ NULL },
};

static struct rc_secdef_child control_sect_child = {
	NULL,
	CF_ALL,
	control_kw,
	control_parser,
	NULL
};

/* FIXME: This belongs to another file */
#if defined(HAVE_TLS) || defined(HAVE_SSL)
#define KW_SSL                 1
#define KW_ONEWAY_SSL          2 
#define KW_CERT                3
#define KW_KEY                 4
#define KW_CAFILE              5

int
tls_parser(int method, int key, char *arg, 
	   void *inv_data, void *func_data, char *line)
{
	switch (key) {
	case KW_SSL:
		setbool(arg, topt, T_SSL);
		break;
		
	case KW_ONEWAY_SSL:
		setbool(arg, topt, T_SSL_ONEWAY);
		break;
		
	case KW_CERT:
		xfree(secure.cert);
		secure.cert = allocbuf(arg, MAXPATHLEN);
		if (method == CF_CLIENT)
			topt |= T_SSL_CKCLIENT;		
		break;
		
	case KW_KEY:
		xfree(secure.key);
		secure.key = allocbuf(arg, MAXPATHLEN);
		if (method == CF_CLIENT)
			topt |= T_SSL_CKCLIENT;
		break;
		
	case KW_CAFILE:
		xfree(secure.cafile);
		secure.cafile = allocbuf(arg, MAXPATHLEN);
		break;
		
	default:
		return RC_KW_UNKNOWN;
	}
	return RC_KW_HANDLED;
}

static struct rc_kwdef tls_kw[] = {
	{ "ssl", KW_SSL },
	{ "oneway-ssl", KW_ONEWAY_SSL },
	{ "cert", KW_CERT },
	{ "key", KW_KEY },
	{ "cafile", KW_CAFILE },
	{ NULL }
};

static struct rc_secdef_child tls_sect_child = {
	NULL,
	CF_ALL,
	tls_kw,
	tls_parser,
	NULL
};
#endif /* HAVE_TLS or HAVE_SSL */

void
control_section_init()
{
	struct rc_secdef *sp = anubis_add_section("CONTROL");
	rc_secdef_add_child(sp, &init_sect_child);
	rc_secdef_add_child(sp, &init_supervisor_sect_child);
	rc_secdef_add_child(sp, &client_sect_child);
	rc_secdef_add_child(sp, &control_sect_child);
#if defined(HAVE_TLS) || defined(HAVE_SSL)
	rc_secdef_add_child(sp, &tls_sect_child);
#endif /* HAVE_TLS or HAVE_SSL */
}

/* ********************** The ALL and RULE Sections *********************** */ 
#define KW_ADD                      1
#define KW_REMOVE                   2                
#define KW_MODIFY                   3
#define KW_SIGNATURE_FILE_APPEND    4
#define KW_BODY_APPEND              5
#define KW_BODY_CLEAR_APPEND        6
#define KW_ROT13_SUBJECT            7
#define KW_ROT13_BODY               8 
#define KW_RM_RRT                   9 
#define KW_RM_POST                 10  
#define KW_RM_HEADER               11
#define KW_RM_LT                   12
#define KW_RM_RLT                  13
#define KW_EXTERNAL_BODY_PROCESSOR 14 

int
all_parser(int method, int key, char *arg,
	   void *inv_data, void *func_data, char *line)
{
	switch (key) {
	case KW_ADD:
		message.addlist_tail = new_element(message.addlist_tail,
						   &message.addlist, arg);
		break;
		
	case KW_REMOVE:                                
		message.remlist_tail = new_element(message.remlist_tail,
						   &message.remlist, arg);
		break;
		
	case KW_MODIFY: {
		char *p = 0;
		char modify[LINEBUFFER+1];

		p = strstr(arg, " >> "); /* "SPC>>SPC" is a separator */
		if (p) {
			p += 4;
			strncpy(modify, p, LINEBUFFER-2);
			p -= 4;
			*p = '\0';
			message.modlist_tail =
				new_element(message.modlist_tail,
					    &message.modlist, arg);
			message.modlist_tail->modify = strdup(modify);
		}
	}
	break;
		
	case KW_SIGNATURE_FILE_APPEND:
		setbool(arg, mopt, M_SIGNATURE);
		break;
		
	case KW_BODY_APPEND:
		xfree(message.body_append);
		message.body_append = allocbuf(arg, MAXPATHLEN);
		mopt |= M_BODYAPPEND;
		mopt &= ~M_BODYCLEARAPPEND;
		break;
		
	case KW_BODY_CLEAR_APPEND:     
		xfree(message.body_append);
		message.body_append = allocbuf(arg, MAXPATHLEN);
		mopt |= M_BODYAPPEND;
		mopt |= M_BODYCLEARAPPEND;
		break;
		
	case KW_ROT13_SUBJECT:         
		setbool(arg, mopt, M_ROT13S);
		break;
		
	case KW_ROT13_BODY:
		setbool(arg, mopt, M_ROT13B);
		break;
		
	case KW_RM_RRT:                 
		xfree(rm.rrt);
		rm.rrt = allocbuf(arg, 0);
		mopt |= M_RM;
		mopt |= M_RMRRT;
		break;
		
	case KW_RM_POST:                
		xfree(rm.post);
		rm.post = allocbuf(arg, 0);
		mopt |= M_RM;
		mopt |= M_RMPOST;
		break;
		
	case KW_RM_HEADER:             
		xfree(rm.header);
		rm.header = allocbuf(arg, LINEBUFFER + 1);
		mopt |= M_RMHEADER;
		break;
		
	case KW_RM_LT:                  
		xfree(rm.latent_time);
		rm.latent_time = allocbuf(arg, 16);
		mopt |= M_RMLT;
		break;
		
	case KW_RM_RLT:                
		xfree(rm.latent_time);
		rm.latent_time = allocbuf(arg, 16);
		mopt |= M_RMLT;
		break;
		
	case KW_EXTERNAL_BODY_PROCESSOR:
		xfree(message.exteditor);
		message.exteditor = allocbuf(arg, MAXPATHLEN);
		mopt |= M_EXTBODYPROC;
		break;
		
	default:
		return RC_KW_UNKNOWN;
	}
	return RC_KW_HANDLED;
}

struct rc_kwdef all_kw[] = {
	{ "add",                     KW_ADD },                     
	{ "remove", 		     KW_REMOVE },                  
	{ "modify",		     KW_MODIFY },                  
	{ "signature-file-append",   KW_SIGNATURE_FILE_APPEND },   
	{ "body-append",	     KW_BODY_APPEND },             
	{ "body-clear-append",	     KW_BODY_CLEAR_APPEND },       
	{ "rot13-subject", 	     KW_ROT13_SUBJECT },           
	{ "rot13-body", 	     KW_ROT13_BODY },              
	{ "rm-rrt", 		     KW_RM_RRT },                  
	{ "rm-post", 		     KW_RM_POST },                 
	{ "rm-header", 		     KW_RM_HEADER },               
	{ "rm-lt", 		     KW_RM_LT },                   
	{ "rm-rlt", 		     KW_RM_RLT },                  
	{ "external-body-processor", KW_EXTERNAL_BODY_PROCESSOR },
        { NULL }
};

static struct rc_secdef_child all_sect_child = {
	NULL,
	CF_CLIENT,
	all_kw,
	all_parser,
	NULL
};

void
all_section_init()
{
	struct rc_secdef *sp = anubis_add_section("ALL");
	rc_secdef_add_child(sp, &all_sect_child);
}

void
rule_section_init()
{
	struct rc_secdef *sp = anubis_add_section("RULE");
	
	rc_secdef_add_child(sp, &all_sect_child);
}

void
rc_system_init()
{
	control_section_init();
	all_section_init();
	translate_section_init();
	rule_section_init();
#ifdef WITH_GUILE
	guile_section_init();
#endif /* WITH_GUILE */
#ifdef HAVE_GPG
	gpg_section_init();
#endif /* HAVE_GPG */
}

/* Placeholders */
void
rcfile_process_cond(char *name, int method, char *line)
{
	RC_SECTION *sec = rc_section_lookup(parse_tree, name);
	rc_run_section(CF_CLIENT, sec, anubis_rc_sections, method, line, NULL);
}

void
rcfile_process_section(int method, char *name, void *data)
{
	RC_SECTION *sec = rc_section_lookup(parse_tree, name);
	rc_run_section(method, sec, anubis_rc_sections, 0, NULL, data);
}
