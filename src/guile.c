/*
   guile.c

   This file is part of GNU Anubis.
   Copyright (C) 2003 The Anubis Team.

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

#ifdef WITH_GUILE

static struct list *process_head, *process_tail;
static struct list *postprocess_head, *postprocess_tail;

static void guile_ports_open();
static void guile_ports_close();

static SCM
catch_body (void *data)
{
	scm_init_load_path();
	anubis(data);
	return SCM_BOOL_F;
}

static SCM
catch_handler(void *data, SCM tag, SCM throw_args)
{
	return scm_handle_by_message_noexit("anubis", tag, throw_args);
}

void
anubis_boot(void *closure, int argc, char **argv)
{
	scm_internal_catch(SCM_BOOL_T,
			   catch_body, closure,
			   catch_handler, NULL);
}

void
guile_debug(int val)
{
	SCM_DEVAL_P = val;
	SCM_BACKTRACE_P = val;
	SCM_RECORD_POSITIONS_P = val;
	SCM_RESET_DEBUG_MODE;
}

void
guile_ports_open()
{
	SCM port;
	int fd = -1;
	char *name = options.guile_logfile;

	if (topt & (T_FOREGROUND_INIT|T_STDINOUT))
		return;
	
	if (name) {
		fd = open(options.guile_logfile, O_CREAT|O_WRONLY|O_APPEND, 0644);
		if (fd == -1) {
			anubis_error(SOFT,
				     _("cannot open guile output file %s: %s"),
				     options.guile_logfile, strerror(errno));
		}
	} else
		name = "/dev/null";

	if (fd == -1) 
		fd = open("/dev/null", O_WRONLY);

	port = scm_fdes_to_port(fd, "a", scm_makfrom0str(name));
	guile_ports_close();
	scm_set_current_error_port(port);
	scm_set_current_output_port(port);
	scm_close_input_port(scm_current_input_port());
}

void
guile_ports_close()
{
	if (topt & (T_FOREGROUND_INIT|T_STDINOUT))
		return;
	scm_close_output_port(scm_current_error_port());
	scm_close_output_port(scm_current_output_port());
}

void
guile_load_path_append(char *path)
{
        SCM scm, path_scm, *pscm;
	path_scm = SCM_VARIABLE_REF(scm_c_lookup("%load-path"));
	for (scm = path_scm; scm != SCM_EOL; scm = SCM_CDR(scm)) {
		SCM val = SCM_CAR(scm);
		if (SCM_NIMP(val) && SCM_STRINGP(val))
			if (strcmp(SCM_STRING_CHARS(val), path) == 0)
				return;
	}

	pscm = SCM_VARIABLE_LOC(scm_c_lookup("%load-path"));
	*pscm = scm_append(scm_list_3(path_scm,
				      scm_list_1(scm_makfrom0str(path)),
				      SCM_EOL));
}

void
guile_load_program(char *filename)
{
	guile_ports_open();
	scm_primitive_load_path(scm_makfrom0str(filename));
	guile_ports_close();
}

static SCM
eval_catch_body(void *list)
{
	return scm_primitive_eval_x((SCM)list);
}

static SCM
eval_catch_handler(void *data, SCM tag, SCM throw_args)
{
	scm_handle_by_message_noexit("anubis", tag, throw_args);
	longjmp(*(jmp_buf*)data, 1);
}

void
guile_rewrite_line(char *procname, const char *source_line)
{
	SCM arg;
	SCM procsym;
	jmp_buf jmp_env;
	SCM res;
	char str[LINEBUFFER+1];

	/* Prepare the argument */
	if (source_line) {
		strncpy(str, source_line, LINEBUFFER);
		remcrlf(str);
		arg = scm_makfrom0str(str);
	} else
		arg = SCM_BOOL_F;

	/* Evaluate the procedure */
	procsym = SCM_VARIABLE_REF(scm_c_lookup(procname));
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		anubis_error(SOFT,
			     _("%s not a procedure object"), procname);
		return;
	}

	guile_ports_open();
	if (setjmp(jmp_env)) {
		guile_ports_close();
		return;
	}

	res = scm_internal_lazy_catch(
		SCM_BOOL_T,
		eval_catch_body,
		(void*) SCM_LIST2(procsym,
				  scm_listify(scm_copy_tree(SCM_IM_QUOTE),
					      arg,
					      SCM_UNDEFINED)),
		eval_catch_handler, &jmp_env);
	
	if (SCM_IMP(res) && SCM_BOOLP(res)) {
		if (res == SCM_BOOL_F) {
			message.remlist_tail = new_element(
				message.remlist_tail,
				&message.remlist, str);
		}
	} else if (SCM_NIMP(res) && SCM_STRINGP(res)) {
		char *new_str = strdup (SCM_STRING_CHARS(res));
		message.modlist_tail = new_element(message.modlist_tail,
						   &message.modlist,
						   str);
		message.modlist_tail->modify = new_str;
	} else if (SCM_NIMP(res) && SCM_CONSP(res)) {
		SCM car = SCM_CAR(res);
		SCM cdr = SCM_CDR(res);
		int n;
		
		if (car == SCM_BOOL_F) {
			message.remlist_tail =
				new_element(message.remlist_tail,
					    &message.remlist, str);
		} else {
			char *new_str = strdup (SCM_STRING_CHARS(car));
			message.modlist_tail =
				new_element(message.modlist_tail,
					    &message.modlist,
					    str);
			message.modlist_tail->modify = new_str;
		}


		for (n = 2; cdr != SCM_EOL; cdr = SCM_CDR(cdr), n++) {
			SCM cell = SCM_CAR(cdr);
			if (!(SCM_NIMP(cell) && SCM_STRINGP(cell))) {
				anubis_error(SOFT,
					     _("Bad return type in element %d from %s."),
					     n, procname);
			} else {
				char *new_str = strdup(SCM_STRING_CHARS(cell));
				message.addlist_tail =
					new_element(message.addlist_tail,
						    &message.addlist,
						    new_str);
			}
		}
	} else 
		anubis_error(SOFT,
			     _("Bad return type from %s"),
			     procname);
	guile_ports_close();
}

static struct list *
guile_to_anubis(SCM cell)
{
	static struct list *head = NULL, *tail = NULL;

	for (; cell != SCM_EOL; cell = SCM_CDR(cell)) {
		SCM car = SCM_CAR(cell);
		if (SCM_NIMP(car) && SCM_CONSP(car)) {
			char *name;
			char *value;
			char *line;
			
			name = SCM_STRING_CHARS(SCM_CAR(car));
			value = SCM_STRING_CHARS(SCM_CDR(car));
			line = xmalloc(strlen(name) + 2 + strlen(value) + 3);
			sprintf(line, "%s: %s\r\n", name, value);
			tail = new_element(tail, &head, line);
			xfree(line);
		}
	}
	return head;
}

static SCM
anubis_to_guile(struct list *p)
{
	SCM head = SCM_EOL, 
	    tail; /* Don't let gcc fool you: tail cannot be used 
	             uninitialized */

	for (; p; p = p->next) {
		SCM cell, car, cdr;
		char *cp;

		cp = strchr(p->line, ':');
		if (!cp)
			continue;
		*cp = 0;
		car = scm_makfrom0str(p->line);
		*cp = ':';

		for (cp++; *cp && isspace(*cp); cp++)
			;
		remcrlf(cp);
		cdr = scm_makfrom0str(cp);
		strcat(cp, CRLF);
		
		SCM_NEWCELL(cell);
		
		SCM_SETCAR(cell, scm_cons(car, cdr));
		if (head == SCM_EOL) 
			head = cell;
		else 
			SCM_SETCDR(tail, cell);
		tail = cell;
	}
	if (head != SCM_EOL)
		SCM_SETCDR(tail, SCM_EOL);
	return head;
}

/* (define (postproc header-list body)*/
void
guile_process_proc(char *procname, struct list **hdr, char **body)
{
	SCM arg_hdr, arg_body;
	SCM procsym;
	jmp_buf jmp_env;
	SCM res;

	/* Prepare the arguments */
	arg_hdr = anubis_to_guile(*hdr);
	arg_body = scm_makfrom0str(*body);

	/* Evaluate the procedure */
	procsym = SCM_VARIABLE_REF(scm_c_lookup(procname));
	if (scm_procedure_p(procsym) != SCM_BOOL_T) {
		anubis_error(SOFT,
			     _("%s not a procedure object"), procname);
		return;
	}

	guile_ports_open();
	if (setjmp(jmp_env)) {
		guile_ports_close();
		return;
	}

	res = scm_internal_lazy_catch(
		SCM_BOOL_T,
		eval_catch_body,
		(void*) SCM_LIST3(procsym,
				  scm_listify(scm_copy_tree(SCM_IM_QUOTE),
					      arg_hdr,
					      SCM_UNDEFINED),
				  scm_listify(scm_copy_tree(SCM_IM_QUOTE),
					      arg_body,
					      SCM_UNDEFINED)),
		eval_catch_handler, &jmp_env);
	
	if (SCM_IMP(res) && SCM_BOOLP(res)) {
		/* FIXME 1*/;
	} else if (SCM_NIMP(res) && SCM_CONSP(res)) {
		SCM ret_hdr = SCM_CAR(res);
		SCM ret_body = SCM_CDR(res);

		if (ret_hdr == SCM_EOL || ret_hdr == SCM_BOOL_T) {
			/* Preserve the headers */;
		} else if (SCM_NIMP(ret_hdr) && SCM_CONSP(ret_hdr)) {
			/* Replace them */
			destroy_list(hdr);
			*hdr = guile_to_anubis(ret_hdr);
		} else
			anubis_error(SOFT,
				     _("Bad car type in return from %s"),
				     procname);
		
		if (ret_body == SCM_BOOL_T) {
			/* Preserve the body as is */;
		} else if (ret_body == SCM_BOOL_F) {
			/* Delete it */
			free(*body);
			*body = strdup("");
		} else if (SCM_NIMP(ret_body) && SCM_STRINGP(ret_body)) {
			/* Replace with the given string */
			xfree(*body);
			*body = strdup(SCM_STRING_CHARS(ret_body));
		} else
			anubis_error(SOFT,
				     _("Bad cdr type in return from %s"),
				     procname);
	} else 
		anubis_error(SOFT,
			     _("Bad return type from %s"),
			     procname);
	guile_ports_close();
}

void
guile_process_list(struct list **hdr, char **body)
{
	struct list *p;

	for (p = process_head; p; p = p->next)
		guile_process_proc(p->line, hdr, body);
}

void
guile_postprocess_list(struct list **hdr, char **body)
{
	struct list *p;

	for (p = postprocess_head; p; p = p->next)
		guile_process_proc(p->line, hdr, body);
}

int
guile_proclist_empty()
{
	return process_head == NULL;
}

/* RC file stuff */

#define KW_GUILE_OUTPUT           0
#define KW_GUILE_DEBUG            1
#define KW_GUILE_LOAD_PATH_APPEND 2
#define KW_GUILE_LOAD_PROGRAM     3
#define KW_GUILE_PROCESS          4
#define KW_GUILE_POSTPROCESS      5 
#define KW_GUILE_REWRITE_LINE     6

/* GUILE section */
static struct rc_kwdef guile_kw[] = {
	{ "guile-output",           KW_GUILE_OUTPUT },
	{ "guile-debug",            KW_GUILE_DEBUG },
	{ "guile-load-path-append", KW_GUILE_LOAD_PATH_APPEND }, 
	{ "guile-load-program",     KW_GUILE_LOAD_PROGRAM },
	{ "guile-process",          KW_GUILE_PROCESS },
	{ "guile-postprocess",      KW_GUILE_POSTPROCESS },
	{ NULL }
};

static struct rc_kwdef guile_rule_kw[] = {
	{ "guile-debug",            KW_GUILE_DEBUG },
	{ "guile-load-path-append", KW_GUILE_LOAD_PATH_APPEND }, 
	{ "guile-load-program",     KW_GUILE_LOAD_PROGRAM },
	{ "guile-rewrite-line",     KW_GUILE_REWRITE_LINE },
	{ "guile-process",          KW_GUILE_PROCESS },
	{ "guile-postprocess",      KW_GUILE_POSTPROCESS },
	{ NULL }
};

int
guile_parser(int method, int key, char *arg,
	     void *inv_data, void *func_data, char *line)
{
	switch (key) {
	case KW_GUILE_OUTPUT:
		xfree(options.guile_logfile);
		options.guile_logfile = strdup(arg);
		break;
		
	case KW_GUILE_DEBUG:
		guile_debug(strncmp("yes", arg, 3) == 0);
		break;
		
	case KW_GUILE_LOAD_PATH_APPEND:
		guile_load_path_append(arg);
		break;
		
	case KW_GUILE_LOAD_PROGRAM:
		guile_load_program(arg);
		break;

	case KW_GUILE_PROCESS:
		process_tail = new_element(process_tail,
					   &process_head,
					   strdup(arg));
		break;

	case KW_GUILE_POSTPROCESS:       
		postprocess_tail = new_element(postprocess_tail,
					       &postprocess_head,
					       strdup(arg));
		break;

	case KW_GUILE_REWRITE_LINE:
		guile_rewrite_line(arg, line);
		break;
		
	default:
		return RC_KW_UNKNOWN;
	}
	return RC_KW_HANDLED;
}

static struct rc_secdef_child guile_secdef_child = {
	NULL,
	CF_CLIENT,
	guile_kw,
	guile_parser,
	NULL
};

static struct rc_secdef_child guile_rule_secdef_child = {
	NULL,
	CF_CLIENT,
	guile_rule_kw,
	guile_parser,
	NULL
};

void
guile_section_init()
{
	struct rc_secdef *sp = anubis_add_section("GUILE");
	rc_secdef_add_child(sp, &guile_secdef_child);
	sp = anubis_add_section("RULE");
	rc_secdef_add_child(sp, &guile_rule_secdef_child);
}
	

#endif /* WITH_GUILE */

