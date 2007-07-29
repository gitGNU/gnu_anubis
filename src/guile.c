/*
   guile.c

   This file is part of GNU Anubis.
   Copyright (C) 2003, 2004, 2005, 2007 The Anubis Team.

   GNU Anubis is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   GNU Anubis is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Anubis; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "headers.h"
#include "extern.h"
#include "rcfile.h"

#ifdef WITH_GUILE

static void guile_ports_open (void);
static void guile_ports_close (void);

static SCM
catch_body (void *data)
{
  scm_init_load_path ();
  anubis (data);
  return SCM_BOOL_F;
}

static SCM
catch_handler (void *data, SCM tag, SCM throw_args)
{
  return scm_handle_by_message_noexit ("anubis", tag, throw_args);
}

void
anubis_boot (void *closure, int argc, char **argv)
{
  scm_internal_catch (SCM_BOOL_T, catch_body, closure, catch_handler, NULL);
}

void
guile_debug (int val)
{
  SCM_DEVAL_P = val;
  SCM_BACKTRACE_P = val;
  SCM_RECORD_POSITIONS_P = val;
  SCM_RESET_DEBUG_MODE;
}

void
guile_ports_open (void)
{
  SCM port;
  int fd = -1;
  char *name = options.glogfile;

  if (topt & (T_FOREGROUND_INIT | T_STDINOUT))
    return;

  if (name)
    {
      fd = open (options.glogfile, O_CREAT | O_WRONLY | O_APPEND, 0644);
      if (fd == -1)
	{
	  anubis_error (0, errno,
			_("cannot open guile output file %s"),
			options.glogfile);
	}
    }
  else
    name = "/dev/null";

  if (fd == -1)
    {
      name = "/dev/null";
      fd = open (name, O_WRONLY|O_APPEND);
    }
  
  port = scm_fdes_to_port (fd, "a", scm_makfrom0str (name));
  guile_ports_close ();
  scm_set_current_error_port (port);
  scm_set_current_output_port (port);
  scm_close_input_port (scm_current_input_port ());
}

void
guile_ports_close (void)
{
  if (topt & (T_FOREGROUND_INIT | T_STDINOUT))
    return;
  scm_close_output_port (scm_current_error_port ());
  scm_close_output_port (scm_current_output_port ());
}

void
guile_load_path_append (ANUBIS_LIST *arglist, MESSAGE *msg)
{
  char *path = list_item (arglist, 0);
  SCM scm, path_scm, *pscm;
  path_scm = SCM_VARIABLE_REF (scm_c_lookup ("%load-path"));
  for (scm = path_scm; scm != SCM_EOL; scm = SCM_CDR (scm))
    {
      SCM val = SCM_CAR (scm);
      if (SCM_NIMP (val) && SCM_STRINGP (val))
	if (strcmp (SCM_STRING_CHARS (val), path) == 0)
	  return;
    }

  pscm = SCM_VARIABLE_LOC (scm_c_lookup ("%load-path"));
  *pscm = scm_append (scm_list_3 (path_scm,
				  scm_list_1 (scm_makfrom0str (path)),
				  SCM_EOL));
}

void
guile_load_program (ANUBIS_LIST *arglist, MESSAGE *msg)
{
  scm_primitive_load_path (scm_makfrom0str (list_item (arglist, 0)));
}

static SCM
eval_catch_handler (void *data, SCM tag, SCM throw_args)
{
  scm_handle_by_message_noexit ("anubis", tag, throw_args);
  longjmp (*(jmp_buf *) data, 1);
}


static ANUBIS_LIST *
guile_to_anubis (SCM cell)
{
  static ANUBIS_LIST *list;

  list = list_create ();
  for (; cell != SCM_EOL; cell = SCM_CDR (cell))
    {
      SCM car = SCM_CAR (cell);
      if (SCM_NIMP (car) && SCM_CONSP (car))
	{
	  ASSOC *asc = xmalloc (sizeof (*asc));

	  asc->key = SCM_STRING_CHARS (SCM_CAR (car));
	  asc->value = SCM_STRING_CHARS (SCM_CDR (car));
	  list_append (list, asc);
	}
    }
  return list;
}

static SCM
anubis_to_guile (ANUBIS_LIST * list)
{
  ASSOC *asc;
  ITERATOR *itr;
  SCM head = SCM_EOL, tail;	/* Don't let gcc fool you: tail cannot be used 
				   uninitialized */

  itr = iterator_create (list);
  for (asc = iterator_first (itr); asc; asc = iterator_next (itr))
    {
      SCM cell, car, cdr;

      if (asc->key)
	car = scm_makfrom0str (asc->key);
      else
	car = SCM_BOOL_F;

      cdr = scm_makfrom0str (asc->value);

      SCM_NEWCELL (cell);

      SCM_SETCAR (cell, scm_cons (car, cdr));
      if (head == SCM_EOL)
	head = cell;
      else
	SCM_SETCDR (tail, cell);
      tail = cell;
    }
  iterator_destroy (&itr);
  if (head != SCM_EOL)
    SCM_SETCDR (tail, SCM_EOL);
  return head;
}

static SCM
list_to_args (ANUBIS_LIST * arglist)
{
  char *p;
  ITERATOR *itr;
  SCM head = SCM_EOL, tail;	/* Don't let gcc fool you: tail cannot be used 
				   uninitialized */
  SCM val;

  itr = iterator_create (arglist);
  iterator_first (itr);
  while ((p = iterator_next (itr)))
    {
      SCM cell;
      SCM_NEWCELL (cell);

      if (p[0] == '#')
	{
	  switch (p[1])
	    {
	    case ':':
	      val = scm_c_make_keyword (p + 2);
	      break;

	    case 'f':
	      val = SCM_BOOL_F;
	      break;

	    case 't':
	      val = SCM_BOOL_T;
	    }
	}
      else
	val = scm_makfrom0str (p);

      SCM_SETCAR (cell, scm_list_2 (SCM_IM_QUOTE, val));

      if (head == SCM_EOL)
	head = cell;
      else
	SCM_SETCDR (tail, cell);
      tail = cell;
    }
  iterator_destroy (&itr);
  if (head != SCM_EOL)
    SCM_SETCDR (tail, SCM_EOL);
  return head;
}

/* (define (postproc header-list body) */

void
guile_process_proc (ANUBIS_LIST *arglist, MESSAGE *msg)
{
  char *procname;
  SCM arg_hdr, arg_body;
  SCM invlist, rest_arg;
  SCM procsym;
  SCM res;

  procname = list_item (arglist, 0);
  if (!procname)
    {
      anubis_error (0, 0, _("missing procedure name"));
      return;
    }

  /* Prepare the required arguments */
  arg_hdr = anubis_to_guile (msg->header);
  arg_body = scm_makfrom0str (msg->body);

  /* Prepare the optional arguments */
  rest_arg = list_to_args (arglist);

  /* Evaluate the procedure */
  procsym = SCM_VARIABLE_REF (scm_c_lookup (procname));
  if (scm_procedure_p (procsym) != SCM_BOOL_T)
    {
      anubis_error (0, 0, _("%s not a procedure object"), procname);
      return;
    }

  invlist = scm_append (SCM_LIST2 (SCM_LIST3 (procsym,
					      SCM_LIST2 (SCM_IM_QUOTE,
							 arg_hdr),
					      SCM_LIST2 (SCM_IM_QUOTE,
							 arg_body)),
				   rest_arg));

  res = scm_primitive_eval (invlist);

  if (SCM_IMP (res) && SCM_BOOLP (res))
    {
      /* FIXME 1 */ ;
    }
  else if (SCM_NIMP (res) && SCM_CONSP (res))
    {
      SCM ret_hdr = SCM_CAR (res);
      SCM ret_body = SCM_CDR (res);

      if (ret_hdr == SCM_EOL || ret_hdr == SCM_BOOL_T)
	{
	  /* Preserve the headers */ ;
	}
      else if (SCM_NIMP (ret_hdr) && SCM_CONSP (ret_hdr))
	{
	  /* Replace them */
	  destroy_assoc_list (&msg->header);
	  msg->header = guile_to_anubis (ret_hdr);
	}
      else
	anubis_error (0, 0, _("Bad car type in return from %s"), procname);

      if (ret_body == SCM_BOOL_T)
	{
	  /* Preserve the body as is */ ;
	}
      else if (ret_body == SCM_BOOL_F)
	{
	  /* Delete it */
	  free (msg->body);
	  msg->body = strdup ("");
	}
      else if (SCM_NIMP (ret_body) && SCM_STRINGP (ret_body))
	{
	  /* Replace with the given string */
	  xfree (msg->body);
	  msg->body = strdup (SCM_STRING_CHARS (ret_body));
	}
      else
	anubis_error (0, 0, _("Bad cdr type in return from %s"), procname);
    }
  else
    anubis_error (0, 0, _("Bad return type from %s"), procname);
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
  {"guile-output", KW_GUILE_OUTPUT},
  {"guile-debug", KW_GUILE_DEBUG},
  {"guile-load-path-append", KW_GUILE_LOAD_PATH_APPEND},
  {"guile-load-program", KW_GUILE_LOAD_PROGRAM},
  {NULL}
};

static struct rc_kwdef guile_rule_kw[] = {
  {"guile-debug", KW_GUILE_DEBUG},
  {"guile-load-path-append", KW_GUILE_LOAD_PATH_APPEND},
  {"guile-load-program", KW_GUILE_LOAD_PROGRAM},
  {"guile-rewrite-line", KW_GUILE_REWRITE_LINE},
  {"guile-process", KW_GUILE_PROCESS},
  {NULL}
};

struct inner_closure
{
  ANUBIS_LIST *arglist;
  MESSAGE *msg;
  void (*fun) (ANUBIS_LIST *arglist, MESSAGE *msg);
};

static SCM
inner_catch_body (void *data)
{
  struct inner_closure *closure = data;
  closure->fun (closure->arglist, closure->msg);
  return SCM_BOOL_F;
}

int
guile_parser (int method, int key, ANUBIS_LIST * arglist,
	      void *inv_data, void *func_data, MESSAGE * msg)
{
  int rc;
  char *arg = list_item (arglist, 0);
  struct inner_closure closure;
  jmp_buf jmp_env;
  
  closure.arglist = arglist;
  closure.msg = msg;

  switch (key)
    {
    case KW_GUILE_OUTPUT:
      xfree (options.glogfile);
      options.glogfile = strdup (arg);
      return RC_KW_HANDLED;

    case KW_GUILE_DEBUG:
      guile_debug (strncmp ("yes", arg, 3) == 0);
      return RC_KW_HANDLED;

    case KW_GUILE_LOAD_PATH_APPEND:
      closure.fun = guile_load_path_append;
      break;

    case KW_GUILE_LOAD_PROGRAM:
      closure.fun = guile_load_program;
      break;

    case KW_GUILE_PROCESS:
      closure.fun = guile_process_proc;
      break;

    case KW_GUILE_REWRITE_LINE:
      /*FIXME*/
      /*guile_rewrite_line(arg, line); */
      return RC_KW_HANDLED;

    default:
      return RC_KW_UNKNOWN;
    }

  guile_ports_open ();
  if (setjmp (jmp_env) == 0)
    scm_internal_lazy_catch (SCM_BOOL_T,
			     inner_catch_body,
			     &closure,
			     eval_catch_handler, &jmp_env);
  else
    rc = RC_KW_ERROR;

  guile_ports_close ();

  return rc;
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
guile_section_init (void)
{
  struct rc_secdef *sp = anubis_add_section ("GUILE");
  rc_secdef_add_child (sp, &guile_secdef_child);
  sp = anubis_add_section ("RULE");
  rc_secdef_add_child (sp, &guile_rule_secdef_child);
}

#endif /* WITH_GUILE */

/* EOF */
