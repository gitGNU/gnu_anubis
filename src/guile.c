/*
   guile.c

   This file is part of GNU Anubis.
   Copyright (C) 2003-2014 The Anubis Team.

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

#ifdef WITH_GUILE

static void guile_ports_open (void);
static void guile_ports_close (void);

static SCM
eval_catch_handler (void *data, SCM tag, SCM throw_args)
{
  scm_handle_by_message_noexit ("anubis", tag, throw_args);
  longjmp(*(jmp_buf*)data, 1);
}

struct scheme_exec_data
{
  SCM (*handler) (void *data);
  void *data;
};

static SCM
scheme_safe_exec_body (void *data)
{
  struct scheme_exec_data *ed = data;
  return ed->handler (ed->data);
}

static int
guile_safe_exec (SCM (*handler) (void *data), void *data, SCM *result)
{
  jmp_buf jmp_env;
  struct scheme_exec_data ed;
  SCM res;
  
  if (setjmp(jmp_env))
    return 1;
  ed.handler = handler;
  ed.data = data;
  res= scm_c_catch (SCM_BOOL_T,
		    scheme_safe_exec_body, (void*)&ed,
		    eval_catch_handler, &jmp_env,
		    NULL, NULL);
  if (result)
    *result = res;
  return 0;
}

void
guile_debug (int val)
{
#ifdef GUILE_DEBUG_MACROS
  SCM_DEVAL_P = val;
  SCM_BACKTRACE_P = val;
  SCM_RECORD_POSITIONS_P = val;
  SCM_RESET_DEBUG_MODE;
#endif
}

void
init_guile ()
{
  scm_init_guile ();
  scm_load_goops ();
  guile_init_anubis_info_port ();
  guile_init_anubis_error_port ();
}


void
guile_ports_open ()
{
  SCM port = SCM_UNSPECIFIED;
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

      if (fd >= 0)
	{
	  port = scm_fdes_to_port (fd, "a", scm_makfrom0str (name));
	  guile_ports_close ();
	  scm_set_current_error_port (port);
	  scm_set_current_output_port (port);
	  scm_close_input_port (scm_current_input_port ());
	  return;
	}
    }

  scm_set_current_error_port (guile_make_anubis_error_port (1));
  scm_set_current_output_port (guile_make_anubis_info_port ());
  scm_close_input_port (scm_current_input_port ());
}

void
guile_ports_close ()
{
  if (!(topt & (T_FOREGROUND_INIT | T_STDINOUT)))
    {
      scm_close_output_port (scm_current_error_port ());
      scm_close_output_port (scm_current_output_port ());
    }
}


SCM
guile_load_path_append_handler (void *data)
{
  ANUBIS_LIST arglist = data;
  char *path = list_item (arglist, 0);
  SCM scm, path_scm, *pscm;
  path_scm = SCM_VARIABLE_REF (scm_c_lookup ("%load-path"));
  for (scm = path_scm; !scm_is_null (scm); scm = SCM_CDR (scm))
    {
      SCM val = SCM_CAR (scm);
      if (scm_is_string (val))
	{
	  char *p = scm_to_locale_string (val);
	  int rc = strcmp (p, path);
	  free (p);
	  if (rc == 0)
	    return SCM_UNSPECIFIED;
	}
    }

  pscm = SCM_VARIABLE_LOC (scm_c_lookup ("%load-path"));
  *pscm = scm_append (scm_list_3 (path_scm,
				  scm_list_1 (scm_makfrom0str (path)),
				  SCM_EOL));
  return SCM_UNSPECIFIED;
}

void
guile_load_path_append (ANUBIS_LIST arglist, MESSAGE msg /* unused */)
{
  guile_safe_exec (guile_load_path_append_handler, arglist, NULL);
}

  
struct load_closure
{
  char *filename;
  int argc;
  char **argv;
};

static SCM
load_path_handler (void *data)
{
  struct load_closure *lp = data;
    
  scm_set_program_arguments (lp->argc, lp->argv, lp->filename);
  scm_primitive_load_path (scm_from_locale_string (lp->filename));
  return SCM_UNDEFINED;
}

void
guile_load_program (ANUBIS_LIST arglist, MESSAGE msg /* unused */)
{
  struct load_closure clos;
  clos.filename = list_item (arglist, 0);
  clos.argc = 0;
  clos.argv = NULL;
  guile_safe_exec (load_path_handler, &clos, NULL);
}

static ANUBIS_LIST 
guile_to_anubis (SCM cell)
{
  static ANUBIS_LIST list;

  list = list_create ();
  for (; !scm_is_null (cell); cell = SCM_CDR (cell))
    {
      SCM car = SCM_CAR (cell);
      if (scm_is_pair (car))
	{
	  ASSOC *asc = xmalloc (sizeof (*asc));

	  asc->key = scm_to_locale_string (SCM_CAR (car));
	  asc->value = scm_to_locale_string (SCM_CDR (car));
	  list_append (list, asc);
	}
    }
  return list;
}

static SCM
anubis_to_guile (ANUBIS_LIST  list)
{
  ASSOC *asc;
  ITERATOR itr;
  SCM head = SCM_EOL, tail = SCM_EOL;

  itr = iterator_create (list);
  for (asc = iterator_first (itr); asc; asc = iterator_next (itr))
    {
      SCM cell, car, cdr;

      if (asc->key)
	car = scm_from_locale_string (asc->key);
      else
	car = SCM_BOOL_F;

      cdr = scm_from_locale_string (asc->value);

      cell = scm_cons (scm_cons (car, cdr), SCM_EOL);
      if (head == SCM_EOL)
	head = cell;
      else
	SCM_SETCDR (tail, cell);

      tail = cell;
    }
  iterator_destroy (&itr);
  return head;
}

static SCM
list_to_args (ANUBIS_LIST arglist)
{
  char *p;
  ITERATOR itr;
  SCM head = SCM_EOL, tail = SCM_EOL;
  SCM val;

  itr = iterator_create (arglist);
  iterator_first (itr);
  while ((p = iterator_next (itr)))
    {
      SCM cell;

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
	      break;

	    default:
	      /* FIXME: Spit out a message? */
	      val = SCM_BOOL_F;
	    }
	}
      else
	val = scm_from_locale_string (p);

      cell = scm_cons (val, SCM_EOL);

      if (tail == SCM_EOL)
	head = cell;
      else
	SCM_SETCDR (tail, cell);
      tail = cell;
    }
  iterator_destroy (&itr);
  return head;
}

/* (define (postproc header-list body) */

struct proc_handler_closure
{
  SCM procsym;
  ANUBIS_LIST arglist;
  MESSAGE msg;
};
  
SCM
guile_process_proc_handler (void *data)
{
  struct proc_handler_closure *clp = data;
  ANUBIS_LIST arglist = clp->arglist;
  MESSAGE msg = clp->msg;
  SCM arg_hdr, arg_body;
  SCM rest_arg;

  /* Prepare the required arguments */
  arg_hdr = anubis_to_guile (message_get_header (msg));
  arg_body = scm_from_locale_string (message_get_body (msg));

  /* Prepare the optional arguments */
  rest_arg = list_to_args (arglist);

  return scm_apply_2 (clp->procsym, arg_hdr, arg_body, rest_arg);
}

void
guile_process_proc (ANUBIS_LIST arglist, MESSAGE msg)
{
  struct proc_handler_closure clos;
  SCM procsym;
  SCM res;
  char *procname;
  
  procname = list_item (arglist, 0);
  if (!procname)
    {
      anubis_error (0, 0, _("missing procedure name"));
      return;
    }

  /* Evaluate the procedure */
  procsym = SCM_VARIABLE_REF (scm_c_lookup (procname));
  if (scm_procedure_p (procsym) != SCM_BOOL_T)
    {
      anubis_error (0, 0, _("%s not a procedure object"), procname);
      return;
    }

  clos.procsym = procsym;
  clos.arglist = arglist;
  clos.msg = msg;
  if (guile_safe_exec (guile_process_proc_handler, &clos, &res))
    return;

  if (scm_is_bool (res))
    {
      /* FIXME 1 */ ;
    }
  else if (scm_is_pair (res))
    {
      SCM ret_hdr = SCM_CAR (res);
      SCM ret_body = SCM_CDR (res);

      if (ret_hdr == SCM_EOL || ret_hdr == SCM_BOOL_T)
	{
	  /* Preserve the headers */ ;
	}
      else if (scm_is_pair (ret_hdr))
	{
	  /* Replace them */
	  message_replace_header (msg, guile_to_anubis (ret_hdr));
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
	  message_replace_body (msg, strdup (""));
	}
      else if (scm_is_string (ret_body))
	{
	  /* Replace with the given string */
	  message_replace_body (msg, scm_to_locale_string (ret_body));
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
  ANUBIS_LIST arglist;
  MESSAGE msg;
  void (*fun) (ANUBIS_LIST arglist, MESSAGE msg);
};

static SCM
inner_catch_body (void *data)
{
  struct inner_closure *closure = data;
  guile_ports_open ();
  closure->fun (closure->arglist, closure->msg);
  guile_ports_close ();
  return SCM_BOOL_F;
}

void
guile_parser (EVAL_ENV env, int key, ANUBIS_LIST arglist, void *inv_data)
{
  char *arg = list_item (arglist, 0);
  struct inner_closure closure;
  jmp_buf jmp_env;
  
  closure.arglist = arglist;
  closure.msg = eval_env_message (env);

  switch (key)
    {
    case KW_GUILE_OUTPUT:
      xfree (options.glogfile);
      options.glogfile = strdup (arg);
      return;

    case KW_GUILE_DEBUG:
      guile_debug (strncmp ("yes", arg, 3) == 0);
      return;

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
      eval_error (0, env, _("%s is not supported yet"), "guile-rewrite-line");
      /*guile_rewrite_line(arg, line); */
      return;

    default:
      eval_error (2, env,
		  _("INTERNAL ERROR at %s:%d: unhandled key %d; "
		    "please report"),
		  __FILE__, __LINE__,
		  key);
    }

  if (setjmp (jmp_env) == 0)
    scm_internal_lazy_catch (SCM_BOOL_T,
			     inner_catch_body,
			     &closure,
			     eval_catch_handler, &jmp_env);
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
