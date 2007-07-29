%{
/*
   rcfile.y

   This file is part of GNU Anubis.
   Copyright (C) 2003, 2004, 2007 The Anubis Team.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <setjmp.h>	
#include "headers.h"
#include "extern.h"
#include "rcfile.h"

extern int yylex (void);
int yyerror (char *s);

static RC_SECTION *rc_section_create (char *, size_t, RC_STMT *);
static void rc_section_destroy (RC_SECTION **);
static void rc_section_print (RC_SECTION *);
static void rc_asgn_destroy (RC_ASGN *);
static void rc_bool_destroy (RC_BOOL *);
static void rc_level_print (int, char *);
static RC_NODE *rc_node_create (enum rc_node_type);
static void rc_node_destroy (RC_NODE *);
static void rc_node_print (RC_NODE *);
static void rc_rule_destroy (RC_RULE *);
static void rc_cond_destroy (RC_COND *);
static RC_STMT *rc_stmt_create (enum rc_stmt_type);
static void rc_stmt_destroy (RC_STMT *);
static void rc_stmt_list_destroy (RC_STMT *);
static void rc_stmt_print (RC_STMT *, int);
static int reg_modifier_add (int *, char *);
static int check_kw (char *ident, int *flags);
static int is_prog_allowed (void);
 
static RC_SECTION *rc_section;
static int debug_level;
static int error_count;
static int def_regex_modifier = R_POSIX;
static struct rc_secdef *rc_secdef;
%}

%union {
  char *string;
  RC_SECTION *section;
  RC_STMT *stmt;
  struct {
    RC_STMT *head;
    RC_STMT *tail;
  } stmtlist;
  RC_COND cond;
  RC_RULE rule;
  RC_NODE *node;
  RC_REGEX *regex;
  int num;
  struct {
    int part;
    RC_REGEX *key;
    char *string;
  } msgpart;
  RC_LOC loc;
  struct {
    size_t line;
    char *name;
  } begin_sec;
  ANUBIS_LIST *list;
};

%token EOL T_BEGIN T_END AND OR
%token IF FI ELSE RULE DONE
%token CALL STOP ADD REMOVE MODIFY
%token <string> IDENT STRING REGEX D_BEGIN
%token <num> T_MSGPART

%left OR
%left AND
%left NOT

%type <string> keyword string modifier arg string_key
%type <section> section seclist
%type <stmtlist> stmtlist
%type <stmt> stmt asgn_stmt cond_stmt rule_stmt inst_stmt modf_stmt
%type <num> modlist opt_modlist
%type <node> rule_start cond expr
%type <msgpart> msgpart s_msgpart r_msgpart key opt_key
%type <list> arglist
%type <regex> regex
%type <begin_sec> begin

%%

input    : seclist
           {
           }
         ;

seclist  : section
           {
	     $$ = rc_section = $1;
	   }
         | seclist section
           {
	     if ($2)
	       {
		 if (rc_section == NULL)
		   {
		     $$ = rc_section = $2;
		   }
		 else
		   {
		     $1->next = $2;
		     $$ = $2;
		   }
	       }
	   }
         | seclist error
           {
	     lex_clear_state ();
	     yychar = error_sync_begin ();
	     if (yychar > 0)
	       {
		 yyerrok;
		 yyclearin;
	       }
	   }
         ;

section  : /* empty */ EOL
           {
	     $$ = NULL;
	   }
         | begin stmtlist end
           {
	     $$ = rc_section_create ($1.name, $1.line, $2.head);
	   }
         | begin end
           {
	     $$ = NULL;
	   }
         ;

begin    : T_BEGIN { verbatim (); } string EOL
           {
	     $$.line = cfg_line_num - 1;
	     $$.name = $3;
	     if (rc_section_lookup (rc_section, $3)) 
	       parse_error (_("Section %s already defined"), $3);
	     rc_secdef = anubis_find_section ($3);
	   }
         | D_BEGIN EOL
           {
	     $$.line = cfg_line_num - 1;
	     $$.name = $1;
	     if (rc_section_lookup (rc_section, $1)) 
	       parse_error (_("Section %s already defined"), $1);
	     rc_secdef = anubis_find_section ($1);
	   }		   
         ;

end      : T_END EOL
         ;

stmtlist : stmt
           {
	     $$.head = $$.tail = $1;
	   }
         | stmtlist stmt
           {
	     if ($2)
	       {
		 if ($$.head == NULL)
		   {
		     $$.head = $$.tail = $2;
		   }
		 else
		   {
		     $$.tail->next = $2;
		     $$.tail = $2;
		   } 
	       }
	   }
         ;

stmt     : /* empty */ EOL
           {
	     $$ = NULL;
	   }
         | asgn_stmt EOL
         | cond_stmt EOL
         | rule_stmt EOL
	 | inst_stmt EOL
	 | modf_stmt EOL
	 | error EOL
           {
	     lex_clear_state ();
	     yyerrok;
	     yyclearin;
	     $$ = NULL;
	   }
         ;

asgn_stmt: keyword arglist
           {
	     int flags;
	     if (!check_kw ($1, &flags))
	       {
		 parse_error (_("unknown keyword: %s"), $1);
		 YYERROR;
	       }

	     $$ = rc_stmt_create (rc_stmt_asgn);
	     $$->v.asgn.lhs = $1;
	     if (list_count ($2))
	       {
		 char *s = list_item ($2, 0);
		 if (s && !strcmp (s, "="))
		   list_remove ($2, s, NULL);
	       }
	     $$->v.asgn.rhs = $2;
	     $$->v.asgn.flags = flags;
	   }
         ;

keyword  : IDENT
           {
	     verbatim ();
	   }
         ;

arglist  : arg
           {
	     $$ = list_create ();
	     list_append ($$, $1);
	   }
         | arglist arg
           {
	     list_append ($1, $2);
	     $$ = $1;
	   }
         ;

arg      : string
         ;

cond_stmt: if cond stmtlist fi
           {
	     $$ = rc_stmt_create (rc_stmt_cond);
	     $$->v.cond.node = $2;
	     $$->v.cond.iftrue = $3.head;
	     $$->v.cond.iffalse = NULL;
	   }
         | if cond stmtlist else stmtlist fi
           {
	     $$ = rc_stmt_create (rc_stmt_cond);
	     $$->v.cond.node = $2;
	     $$->v.cond.iftrue = $3.head;
	     $$->v.cond.iffalse = $5.head;
	   }
	 ;

cond     : expr
         | '(' cond ')'
           {
	     $$ = $2;
	   }
         | cond AND cond
           {
	     $$ = rc_node_create (rc_node_bool);
	     $$->v.bool.op = bool_and;
	     $$->v.bool.left = $1;
	     $$->v.bool.right = $3;
	   }
         | cond OR cond
           {
	     $$ = rc_node_create (rc_node_bool);
	     $$->v.bool.op = bool_or;
	     $$->v.bool.left = $1;
	     $$->v.bool.right = $3;
	   }
         | NOT cond
           {
	     $$ = rc_node_create (rc_node_bool);
	     $$->v.bool.op = bool_not;
	     $$->v.bool.left = $2;
	     $$->v.bool.right = NULL;
	   }
         ;

meq      : /* empty */
         | '='
         ;

key      : regex
           {
	     $$.part = HEADER;
	     $$.key = $1;
	     $$.string = NULL;
	   }
         | '[' string ']'
           {
	     $$.part = HEADER;
	     $$.key = NULL;
	     $$.string = $2;
	   }
         ;

opt_key  : /* empty */
           {
	     $$.string = NULL;
	     $$.key = NULL;
           }
         | key
	 ;

msgpart  : T_MSGPART opt_key
           {
	     $$ = $2;
	     $$.part = $1;
	   }
         | key
         ;

s_msgpart: msgpart
           {
	     $$ = $1;
	     if ($$.key)
	       parse_error ("regexp is not allowed in this context");
	   }
         ;

r_msgpart: msgpart
           {
	     $$ = $1;
	     if (!$$.key)
	       {
		 $$.key = anubis_regex_compile ($$.string, R_EXACT);
		 xfree ($$.string);
	       }
	   }
         ;

regex    : modlist '[' string ']'
           {
	     $$ = anubis_regex_compile ($3, $1);
	     free ($3);
	     if (!$$)
	       {
		 parse_error (_("Invalid regular expression (see the above message)"));
		 YYERROR;
	       }
	   }
         ;

string_key: /* empty */
           {
	     $$ = NULL;
	   }
         | '[' string ']'
           {
	     $$ = $2;
	   }
	 ;

expr     : s_msgpart opt_modlist meq opt_modlist string
           {
	     $$ = rc_node_create (rc_node_expr);
	     $$->v.expr.part = $1.part;
	     $$->v.expr.key = $1.string;
	     $$->v.expr.re = anubis_regex_compile ($5, $4|$2);
	     free ($5);
	   }
         ;

modlist  : modifier
           {
	     $$ = def_regex_modifier;
	     reg_modifier_add (&$$, $1);
	     xfree ($1);
	   }
         | modlist modifier
           {
	     reg_modifier_add (&$1, $2);
	     xfree ($2);
	     $$ = $1;
	   }
         ;

opt_modlist: /* empty */
           {
	     $$ = def_regex_modifier;
	   }
         | modlist
	 ;

modifier   : ':' IDENT
           {
	     $$ = $2;
	   }
         ;

if       : IF
           {
	     if (!is_prog_allowed ())
	       YYERROR;
	   }
         ;

fi       : FI
         ;
 
else     : ELSE 
         ;

rule_stmt: rule_start EOL stmtlist DONE
           {
	     $$ = rc_stmt_create (rc_stmt_rule);
	     $$->v.rule.node = $1;
	     $$->v.rule.stmt = $3.head;
	   }
         ;

rule_start: rule opt_modlist string
           {
	     $$ = rc_node_create (rc_node_expr);
	     $$->v.expr.part = HEADER;
	     $$->v.expr.key = strdup (X_ANUBIS_RULE_HEADER);
	     $$->v.expr.re = anubis_regex_compile ($3, $2);
	     free ($3);
	   }
         ;

rule     : RULE
           {
	     if (!is_prog_allowed ())
	       YYERROR;
	   }
         ;

string   : STRING
         | IDENT
         ;

inst_stmt: STOP
           {
	     if (!is_prog_allowed ())
	       YYERROR;

	     $$ = rc_stmt_create (rc_stmt_inst);
	     $$->v.inst.opcode = inst_stop;
	     $$->v.inst.part = NIL;
	     $$->v.inst.key  = NULL;
	     $$->v.inst.key2 = NULL;
	     $$->v.inst.arg  = NULL;
	   }
         | CALL string
           {
	     if (!is_prog_allowed ())
	       YYERROR;

	     $$ = rc_stmt_create (rc_stmt_inst);
	     $$->v.inst.opcode = inst_call;
	     $$->v.inst.key = NULL;
	     $$->v.inst.part = NIL;
	     $$->v.inst.key2 = NULL;
	     $$->v.inst.arg  = $2;
	   }
         | ADD s_msgpart string
           {
	     if (!is_prog_allowed ())
	       YYERROR;

	     $$ = rc_stmt_create (rc_stmt_inst);
	     $$->v.inst.opcode = inst_add;
	     $$->v.inst.part = $2.part;
	     $$->v.inst.key  = NULL;
	     $$->v.inst.key2 = $2.string;
	     $$->v.inst.arg  = $3;
	   }
         | REMOVE r_msgpart
           {
	     if (!is_prog_allowed ())
	       YYERROR;

	     $$ = rc_stmt_create (rc_stmt_inst);
	     $$->v.inst.opcode = inst_remove;
	     $$->v.inst.part = $2.part;
	     $$->v.inst.key = $2.key;
	     $$->v.inst.key2 = NULL;
	     $$->v.inst.arg  = NULL;
	   }
         | MODIFY r_msgpart string_key string
           {
	     if (!is_prog_allowed ())
	       YYERROR;

	     $$ = rc_stmt_create (rc_stmt_inst);
	     $$->v.inst.opcode = inst_modify;
	     $$->v.inst.part = $2.part;
	     $$->v.inst.key  = $2.key;
	     $$->v.inst.key2 = $3;
	     $$->v.inst.arg  = $4;
	   }
         | MODIFY r_msgpart string_key 
           {
	     if (!is_prog_allowed ())
	       YYERROR;

	     $$ = rc_stmt_create (rc_stmt_inst);
	     $$->v.inst.opcode = inst_modify;
	     $$->v.inst.part = $2.part;
	     $$->v.inst.key  = $2.key;
	     if ($3 == NULL && anubis_regex_refcnt ($2.key))
	       {
		 parse_error (_("missing replacement value"));
	       }
	     $$->v.inst.key2 = $3;
	     $$->v.inst.arg  = NULL;
	   }
         ;

modf_stmt: REGEX modlist
           {
	     if (!is_prog_allowed ())
	       YYERROR;

	     def_regex_modifier = $2;
	     $$ = NULL;
	   }
         ;

%%

static int
err_line_num (void)
{
  return yychar == EOL ? cfg_line_num - 1 : cfg_line_num;
}

static void
default_error_printer (void *data, 
		       const char *filename, int line,
		       const char *fmt, va_list ap)
{
  char buf[LINEBUFFER];
  vsnprintf (buf, sizeof buf, fmt, ap);
  anubis_error (0, 0, "%s:%d: %s", filename, line, buf);
}	

static void *rc_error_printer_data;
static RC_ERROR_PRINTER rc_error_printer = default_error_printer;

void
parse_error (const char *fmt, ...)
{
  va_list ap;
  
  va_start (ap, fmt);
  rc_error_printer (rc_error_printer_data,
		    cfg_file, err_line_num (), fmt, ap);
  va_end (ap);
  error_count++;
}

int
yyerror (char *s)
{
  parse_error ("%s", s);
  return 0;
}

RC_SECTION *
rc_parse (char *name)
{
  int status;
  if (rc_open (name))
    return NULL;

  rc_section = NULL;
  error_count = 0;
  status = yyparse ();
  if (status || error_count) 
    rc_section_list_destroy (&rc_section);
  if (debug_level)
    rc_section_print (rc_section);
  return rc_section;
}

/* Same as rc_parse() but also allows user to specify his own
   error printer function */
RC_SECTION *
rc_parse_ep (char *name, RC_ERROR_PRINTER errprn, void *data)
{
  void *save_ep_data = rc_error_printer_data;
  void *save_ep_handler = rc_error_printer;
  RC_SECTION *sec;
  rc_error_printer = errprn;
  rc_error_printer_data = data;
  sec = rc_parse (name);
  rc_error_printer = save_ep_handler;
  rc_error_printer_data = save_ep_data;
  return sec;
}

void
rc_set_debug_level (char *arg)
{
  if (!arg)
    debug_level = 0;
  else if (arg[1] != 0 || !isdigit (arg[0]))
    {
      mprintf (_("Not a valid debugging level: %s"), arg);
      return;
    }
  else
    debug_level = arg[0] - '0';
  if (debug_level > 1)
    yydebug = debug_level;
}


/* Locations */

/* To save space, each filename is allocated only once. Each filename
   has a reference count associated with it. It is incremented
   with each new allocation of the same string. It is decremented
   with each attempt to free the string. Only when the reference count
   drops to zero is the storage actually reclaimed */

struct strobj {
  char *value;          /* String value */
  size_t refcnt;        /* Reference count */
};

/* A list of string objects */
static ANUBIS_LIST /* of struct strobj */ *string_list;

static int
string_comparator (void *item, void *data)
{
  struct strobj *s = item;
  return strcmp (s->value, (char*) data);
}

static int
value_comparator (void *item, void *data)
{
  struct strobj *s = item;
  return s->value != data;
}

/* Looks up a string object with the given value. If not found, a
   new object is created and added to the list. In any case the
   reference count of the objet is incremented.
   The return value is the string value associated with the object. */
char *
string_create (char *str)
{
  struct strobj *s = list_locate (string_list, str, string_comparator);
  if (!s)
    {
      s = xmalloc (sizeof (*s));
      s->value = strdup (str);
      s->refcnt = 0;
      list_prepend (string_list, s);
    }
  s->refcnt++;
  return s->value;
}

/* Destroys the object with the given string value */
void
string_destroy (char *str)
{
  struct strobj *s = list_locate (string_list, str, value_comparator);
  if (s)
    {
      if (--s->refcnt == 0)
	{
	  free (s->value);
	  list_remove (string_list, str, value_comparator);
	}
    }
}

/* Initializes LOC with the current location. If the second argument
   is not zero, it overrides the current line number. */
void
rc_mark_loc (RC_LOC *loc, size_t line)
{
  loc->file = string_create (cfg_file);
  loc->line = line ? line : cfg_line_num;
}

/* Reclaims the memory associated with the LOC */
void
rc_destroy_loc (RC_LOC *loc)
{
  string_destroy (loc->file);
}


/* Section manipulation */

RC_SECTION *
rc_section_create (char *name, size_t line, RC_STMT *stmt)
{
  RC_SECTION *p = xmalloc (sizeof (*p));
  rc_mark_loc (&p->loc, line);
  p->next = NULL;
  p->name = name;
  p->stmt = stmt;
  return p;
}

void
rc_section_destroy (RC_SECTION **s)
{
  rc_stmt_list_destroy ((*s)->stmt);
  rc_destroy_loc (&(*s)->loc);
  xfree ((*s)->name);
  xfree (*s);
}

void
rc_section_list_destroy (RC_SECTION **s)
{
  while (*s)
    {
      RC_SECTION *next = (*s)->next;
      rc_section_destroy (s);
      *s = next;
    }
}

void
rc_section_print (RC_SECTION *sect)
{
  for (; sect; sect = sect->next)
    {
      printf ("BEGIN SECTION %s\n", sect->name);
      rc_stmt_print (sect->stmt, 1);
      printf ("END SECTION %s\n", sect->name);
    }
}

RC_SECTION *
rc_section_lookup (RC_SECTION *sec, char *name)
{
  for (; sec; sec = sec->next)
    if (strcmp (sec->name, name) == 0)
      break;
  return sec;
}

void
rc_section_link (RC_SECTION **ap, RC_SECTION *b)
{
  RC_SECTION *a, *prev;

  /* Remove all sections with prio == override (the default) */
  a = *ap;
  prev = NULL;
  while (a)
    {
      RC_SECTION *next = a->next;
      struct rc_secdef *sd = anubis_find_section (a->name);
      if (sd && sd->prio == prio_user_only)
	{
	  if (prev)
	    prev->next = next;
	  else
	    *ap = next;
	  rc_section_destroy (&a);
	} else
	  prev = a;
      a = next;
    }
		
  if (!*ap)
    {
      *ap = b;
      return;
    }

  for (a = *ap; a->next; a = a->next)
    ;

  while (b)
    {
      struct rc_secdef *sd;
      RC_SECTION *nxtptr = b->next;

      sd = anubis_find_section (b->name);
      if (sd)
	{
	  switch (sd->prio) {
	  case prio_user:
	    b->next = *ap;
	    *ap = b;
	    break;
	    
	  case prio_system_only:
	    rc_section_destroy (&b);
	    break;
	    
	  default:
	    b->next = NULL;
	    a->next = b;
	    a = b;
	  }
	}
      else
	{
	  b->next = NULL;
	  a->next = b;
	  a = b;
	}
      b = nxtptr;
    }
}

/* Assignment manipulations */

void
rc_asgn_destroy (RC_ASGN *asgn)
{
  xfree (asgn->lhs);
  list_destroy (&asgn->rhs, anubis_free_list_item, NULL);
}

/* Bools */

void
rc_bool_destroy (RC_BOOL *bool)
{
  rc_node_destroy (bool->left);
  rc_node_destroy (bool->right);
}

/* Nodes */

RC_NODE *
rc_node_create (enum rc_node_type t)
{
  RC_NODE *p = xmalloc (sizeof (*p));
  memset (p, 0, sizeof (*p));
  rc_mark_loc (&p->loc, 0);
  p->type = t;
  return p;
}

void
rc_node_destroy (RC_NODE *node)
{
  if (!node)
    return;
  switch (node->type) {
  case rc_node_bool:
    rc_bool_destroy (&node->v.bool);
    break;
    
  case rc_node_expr:
    free (node->v.expr.key);
    anubis_regex_free (&node->v.expr.re);
  }
  rc_destroy_loc (&node->loc);
  xfree (node);
}

static char *
part_string (int part)
{
  switch (part) {
  case NIL:
    return "NIL";
  case COMMAND:
    return "COMMAND";
  case HEADER:
    return "HEADER";
  case BODY:
    return "BODY";
  default:
    return "UNKNOWN";
  }
}

void
rc_node_print (RC_NODE *node)
{
  switch (node->type) {
  case rc_node_expr:
    printf ("%s", part_string (node->v.expr.part));
    if (node->v.expr.key && node->v.expr.key[0] != '\n')
      printf ("[%s]",node->v.expr.key);
    printf (" ");
    anubis_regex_print (node->v.expr.re);
    break;
		
  case rc_node_bool:
    switch (node->v.bool.op) {
    case bool_not:
      printf ("NOT (");
      rc_node_print (node->v.bool.left);
      printf (")");
      break;
      
    case bool_and:
      printf ("AND (");
      rc_node_print (node->v.bool.left);
      printf (",");
      rc_node_print (node->v.bool.right);
      printf (")");
      break;
      
    case bool_or:
      printf ("OR (");
      rc_node_print (node->v.bool.left);
      printf (",");
      rc_node_print (node->v.bool.right);
      printf (")");
      break;
    }
  }
}

/* Rules */

void
rc_rule_destroy (RC_RULE *rule)
{
  rc_node_destroy (rule->node);
  rc_stmt_list_destroy (rule->stmt);
}

/* Conditionals */

void
rc_cond_destroy (RC_COND *cond)
{
  rc_node_destroy (cond->node);
  rc_stmt_list_destroy (cond->iftrue);
  rc_stmt_list_destroy (cond->iffalse);
}

/* Instructions */

void
rc_inst_destroy (RC_INST *inst)
{
  anubis_regex_free (&inst->key);
  free (inst->key2);
  free (inst->arg);
}

static char *
inst_name (enum rc_inst_opcode opcode)
{
  switch (opcode) {
  case inst_stop:
    return "STOP";
  case inst_call:
    return "CALL";
  case inst_add:
    return "ADD";
  case inst_remove:
    return "REMOVE";
  case inst_modify:
    return "MODIFY";
  }
  return "UNKNOWN";
}

void
rc_inst_print (RC_INST *inst, int level)
{
  rc_level_print (level, inst_name (inst->opcode));
  switch (inst->opcode) {
  case inst_stop:
    break;
    
  case inst_call:
    printf (" %s", inst->arg);
    break;
    
  case inst_add:
    printf (" %s[%s]", part_string (inst->part), inst->key2);
    if (inst->arg)
      printf (" \"%s\"", inst->arg);
    break;
    
  default:
    printf (" %s ", part_string (inst->part));
    if (inst->key)
      anubis_regex_print (inst->key);
    if (inst->key2)
      printf (" [%s]", inst->key2);
    if (inst->arg)
      printf (" \"%s\"", inst->arg);
  }
}

/* Statements */

RC_STMT *
rc_stmt_create (enum rc_stmt_type type)
{
  RC_STMT *p = xmalloc (sizeof (*p));
  memset (p, 0, sizeof (*p));
  rc_mark_loc (&p->loc, 0);
  p->type = type;
  return p;
}

void
rc_stmt_destroy (RC_STMT *stmt)
{
  switch (stmt->type) {
  case rc_stmt_asgn:
    rc_asgn_destroy (&stmt->v.asgn);
    break;
    
  case rc_stmt_rule:
    rc_rule_destroy (&stmt->v.rule);
    break;
    
  case rc_stmt_cond:
    rc_cond_destroy (&stmt->v.cond);
    break;
    
  case rc_stmt_inst:
    rc_inst_destroy (&stmt->v.inst);
  }
  rc_destroy_loc (&stmt->loc);
  xfree (stmt);
}

void
rc_stmt_list_destroy (RC_STMT *stmt)
{
  while (stmt)
    {
      RC_STMT *next = stmt->next;
      rc_stmt_destroy (stmt);
      stmt = next;
    }
}

void
rc_level_print (int level, char *str)
{
  int i;
  
  for (i = 0; i < level*2; i++)
    putchar (' ');
  printf ("%s", str);
}

static int
_print_str (void *item, void *data)
{
  printf (" %s", (char*)item);
  return 0;
}

static int
_print_stars (void *item, void *data)
{
  printf (" ***");
  return 0;
}

void
rc_stmt_print (RC_STMT *stmt, int level)
{
  for (; stmt; stmt = stmt->next)
    {
      switch (stmt->type) {
      case rc_stmt_asgn:
	rc_level_print (level, "ASGN: ");
	printf ("%s =", stmt->v.asgn.lhs);
	list_iterate (stmt->v.asgn.rhs,
		      (stmt->v.asgn.flags & KWF_HIDDEN) ?
		      _print_stars : _print_str, NULL);
	break;
	
      case rc_stmt_cond:
	rc_level_print (level, "COND: ");
	rc_node_print (stmt->v.cond.node);
	printf ("\n");
	rc_level_print (level, "IFTRUE:\n");
	rc_stmt_print (stmt->v.cond.iftrue, level+1);
	if (stmt->v.cond.iffalse)
	  {
	    rc_level_print (level, "IFFALSE:\n");
	    rc_stmt_print (stmt->v.cond.iffalse, level+1);
	  }
	rc_level_print (level, "END COND");
	break;
	
      case rc_stmt_rule:
	rc_level_print (level, "RULE: ");
	rc_node_print (stmt->v.rule.node);
	printf ("\n");
	rc_level_print (level, "BODY\n");
	rc_stmt_print (stmt->v.rule.stmt, level+1);
	rc_level_print (level, "END RULE");
	break;
	
      case rc_stmt_inst:
	rc_inst_print (&stmt->v.inst, level);
	break;
	
      default:
	abort ();
      }
      printf ("\n");
    }
}

int
reg_modifier_add (int *flag, char *opt)
{
  /* Regex types: */
  if (!strcasecmp (opt, "re") || !strcasecmp (opt, "regex"))
    {
      re_set_type (*flag, re_typeof (def_regex_modifier));
    }
  else if (!strcasecmp (opt, "posix"))
    {
      re_set_type (*flag, R_POSIX);
    }
#ifdef HAVE_PCRE
  else if (!strcasecmp (opt, "perlre")
	   || !strcasecmp (opt, "perl"))
    {
      re_set_type (*flag, R_PERLRE);
    }
#endif /* HAVE_PCRE */
  else if (!strcasecmp (opt, "ex") || !strcasecmp (opt, "exact"))
    {
      re_set_type (*flag, R_EXACT);
    }

  /* Modifiers: */
  else if (!strcasecmp (opt, "basic"))
    {
      re_set_type (*flag, R_POSIX);
      re_set_flag (*flag, R_BASIC);
    }
  else if (!strcasecmp (opt, "extended"))
    {
      re_set_type (*flag, R_POSIX);
      re_clear_flag (*flag, R_BASIC);
    }
  else if (!strcasecmp (opt, "scase"))
    re_set_flag (*flag, R_SCASE);
  else if (!strcasecmp (opt, "icase"))
    re_clear_flag (*flag, R_SCASE);
  else
    {
      parse_error (_("Unknown regexp modifier"));
      return 1;
    }
  return 0;
}


/* ******************************* Runtime ********************************* */

static struct rc_secdef_child *
child_copy (struct rc_secdef_child *p)
{
  struct rc_secdef_child *newp = xmalloc (sizeof (*newp));
  memcpy (newp, p, sizeof (*newp));
  newp->next = NULL;
  return newp;
}	

void
rc_secdef_add_child (struct rc_secdef *def,
		     struct rc_secdef_child *child)
{
  struct rc_secdef_child *p = child_copy (child);
  if (!def->child)
    def->child = p;
  else
    {
      struct rc_secdef_child *last;
      for (last = def->child; last->next; last = last->next)
	;
      last->next = p;
    }
}

struct rc_secdef_child *
rc_child_lookup (struct rc_secdef_child *child, char *str,
		 int method, int *key, int *flags)
{
  for (; child; child = child->next)
    {
      if (child->method & method)
	{
	  struct rc_kwdef *kw;
	  for (kw = child->kwdef; kw->name; kw++)
	    if (!strcmp (kw->name, str))
	      {
		*key = kw->tok;
		if (flags)
		  *flags = kw->flags;
		return child;
	      }
	}
    }
  return NULL;
}

struct eval_env
{
  int method;
  int cmp_method;
  struct rc_secdef_child *child;
  MESSAGE *msg;
  void *data;
  int refcnt;
  char **refstr;
  jmp_buf jmp;
  RC_LOC loc;
  int traceable;
};

static void asgn_eval (struct eval_env *env, RC_ASGN *asgn);
static int node_eval (struct eval_env *env, RC_NODE *node);
static int bool_eval (struct eval_env *env, RC_BOOL *bool);
static void cond_eval (struct eval_env *env, RC_COND *cond);
static void rule_eval (struct eval_env *env, RC_RULE *rule);
static void stmt_list_eval (struct eval_env *env, RC_STMT *stmt);
static void inst_eval (struct eval_env *env, RC_INST *inst);

#define VALID_STR(s) ((s)?(s):"NULL")

void
inst_eval (struct eval_env *env, RC_INST *inst)
{
  char *arg = NULL, *argp = NULL;
  
  if (!env->msg)
    return; /* FIXME: bail out? */
	
  if (inst->arg)
    {
      if (env->refstr)
	arg = argp = substitute (inst->arg, env->refstr);
      else
	arg = inst->arg;
    }
  
  switch (inst->opcode) {
  case inst_stop:
    tracefile (&env->loc, _("STOP"));
    longjmp (env->jmp, 1);
    break;
    
  case inst_call:
    tracefile (&env->loc, _("Calling %s"), inst->arg);
    rcfile_call_section (env->method, inst->arg,
			 env->data, env->msg);
    break;
    
  case inst_add:
    tracefile (&env->loc, _("ADD %s [%s] %s"),
	       (inst->part == BODY) ? "BODY" : "HEADER",
	       VALID_STR (inst->key2), arg);
    if (inst->part == BODY) 
      message_add_body (env->msg, inst->key2, arg);
    else
      message_add_header (env->msg, inst->key2, arg);
    break;
    
  case inst_modify:
    tracefile (&env->loc, _("MODIFY %s [%s] [%s] %s"),
	       (inst->part == BODY) ? "BODY" : "HEADER",
	       anubis_regex_source (inst->key), 
	       VALID_STR (inst->key2), arg);
    
    if (inst->part == BODY)
      message_modify_body (env->msg, inst->key, arg);
    else
      message_modify_headers (env->msg, inst->key,
			      inst->key2, arg);
    break;
    
  case inst_remove:
    tracefile (&env->loc, _("REMOVE HEADER [%s]"),
	       anubis_regex_source (inst->key));
    message_remove_headers (env->msg, inst->key);
    break;
    
  default:
    abort ();
  }
  
  if (argp)
    free (argp);
}
	
void
asgn_eval (struct eval_env *env, RC_ASGN *asgn)
{
  int key;
  struct rc_secdef_child *p = rc_child_lookup (env->child, asgn->lhs,
					       env->method, &key, NULL);
  if (!p)
    return;
  
  if (env->traceable)
    tracefile (&env->loc, _("Executing %s"), asgn->lhs);

  if (env->refstr)
    {
      char *s;
      ANUBIS_LIST *arg = list_create ();
      ITERATOR *itr = iterator_create (asgn->rhs);
      for (s = iterator_first (itr); s; s = iterator_next (itr))
	{
	  char *str = substitute (s, env->refstr);
	  list_append (arg, str);
	}
      iterator_destroy (&itr);
      p->parser (env->method, key, arg, p->data, env->data, env->msg);
      list_destroy (&arg, anubis_free_list_item, NULL);
    }
  else
    p->parser (env->method, key, asgn->rhs, p->data, env->data,
	       env->msg);
}


int
re_eval_list (struct eval_env *env, char *key,
	      RC_REGEX *re, ANUBIS_LIST *list)
{
  ASSOC *p;
  ITERATOR *itr;
  int rc = 0;

  itr = iterator_create (list);
  for (p = iterator_first (itr); rc == 0 && p; p = iterator_next (itr))
    {
      if (!p->key || !strcasecmp (p->key, key))
	rc = anubis_regex_match (re, p->value,
				 &env->refcnt, &env->refstr);
    }
  iterator_destroy (&itr);
  return rc;
}

int
re_eval_text (struct eval_env *env, RC_REGEX *re, char *text)
{
  /* FIXME */
  return anubis_regex_match (re, text, &env->refcnt, &env->refstr);
}

int
expr_eval (struct eval_env *env, RC_EXPR *expr)
{
  int rc;

  if (env->refstr && anubis_regex_refcnt (expr->re))
    {
      argcv_free (-1, env->refstr);
      env->refcnt = 0;
      env->refstr = NULL;
    }
  
  switch (expr->part) {
  case COMMAND:
    rc = re_eval_list (env, expr->key, expr->re,
		       env->msg->commands);
    break;
    
  case HEADER:
    rc = re_eval_list (env, expr->key, expr->re, env->msg->header);
    break;
    
  case BODY:
    rc = re_eval_text (env, expr->re, env->msg->body);
    break;
    
  default:
    abort ();
  }

  if (rc)
    {
      if (!strcmp (VALID_STR (expr->key), X_ANUBIS_RULE_HEADER))
	tracefile (&env->loc, _("Matched trigger \"%s\""),
		   anubis_regex_source (expr->re));
      else
	tracefile (&env->loc, 
		   _("Matched condition %s[%s] \"%s\""),
		   part_string (expr->part),
		   VALID_STR (expr->key),
		   anubis_regex_source (expr->re));
    }
  return rc;
}

int
node_eval (struct eval_env *env, RC_NODE *node)
{
  int rc; /* It won't be used uninitialized despite what cc says.
	     Note default: branch below */
  
  env->loc = node->loc;
  switch (node->type) {
  case rc_node_bool:
    rc = bool_eval (env, &node->v.bool);
    break;
    
  case rc_node_expr:
    rc = expr_eval (env, &node->v.expr);
    break;
    
  default:
    abort ();
  }
  
  return rc;
}

int
bool_eval (struct eval_env *env, RC_BOOL *bool)
{
  int rc = node_eval (env, bool->left);

  switch (bool->op) {
  case bool_not:
    return !rc;
    
  case bool_and:
    if (!rc)
      return 0;
    break;
    
  case bool_or:
    if (rc)
      return 1;
    break;
  }
  return node_eval (env, bool->right);
}

void
cond_eval (struct eval_env *env, RC_COND *cond)
{
  if (node_eval (env, cond->node))
    stmt_list_eval (env, cond->iftrue);
  else
    stmt_list_eval (env, cond->iffalse);
}

void
rule_eval (struct eval_env *env, RC_RULE *rule)
{
  if (node_eval (env, rule->node))
    stmt_list_eval (env, rule->stmt);
}

void
stmt_list_eval (struct eval_env *env, RC_STMT *stmt)
{
  for (; stmt; stmt = stmt->next)
    {
      env->loc = stmt->loc;
      
      switch (stmt->type) {
      case rc_stmt_asgn:
	asgn_eval (env, &stmt->v.asgn);
	break;
	
      case rc_stmt_cond:
	cond_eval (env, &stmt->v.cond);
	break;
	
      case rc_stmt_rule:
	rule_eval (env, &stmt->v.rule);
	break;
	
      case rc_stmt_inst:
	inst_eval (env, &stmt->v.inst);
      }
    }
}

void
eval_section (int method, RC_SECTION *sec, struct rc_secdef *secdef,
	      void *data, MESSAGE *msg)
{
  struct eval_env env;
  env.method = method;
  env.child = secdef->child;
  env.refcnt = 0;
  env.refstr = NULL;
  env.msg = msg;
  env.data = data;
  env.loc = sec->loc;
  env.traceable = secdef->allow_prog;

  if (env.traceable)
    tracefile (&sec->loc, _("Section %s"), sec->name);
  
  if (setjmp (env.jmp) == 0)
    stmt_list_eval (&env, sec->stmt);
  
  if (env.refstr)
    argcv_free (-1, env.refstr);
}	

void
rc_run_section (int method, RC_SECTION *sec, struct rc_secdef *secdef,
		void *data, MESSAGE *msg)
{
  if (!sec)
    return;

  for (; secdef->name; secdef++)
    {
      if (!strcmp (sec->name, secdef->name))
	{
	  eval_section (method, sec, secdef, data, msg);
	  return;
	}
    }
  anubis_error (0, 0, _("Unknown section: %s"), sec->name);
}

void
rc_call_section (int method, RC_SECTION *sec, struct rc_secdef *secdef,
		 void *data, MESSAGE *msg)
{
  if (!sec)
	  return;

  for (; secdef->name; secdef++)
    {
      if (!strcmp (secdef->name, "RULE"))
	{
	  eval_section (method, sec, secdef, data, msg);
	  return;
	}
    }
}

void
rc_run_section_list (int method, RC_SECTION *sec,
		     struct rc_secdef *secdef)
{
  for (; sec; sec = sec->next)
    rc_run_section (method, sec, secdef, NULL, NULL);
}

static int
check_kw (char *ident, int *flags)
{
  struct rc_secdef *p = rc_secdef;
  int key;
  
  if (!p)
    p = anubis_find_section ("RULE");
  return rc_child_lookup (p->child, ident, CF_ALL, &key, flags) != NULL;
}

static int
is_prog_allowed (void)
{
  struct rc_secdef *p = rc_secdef;
  if (!p)
    p = anubis_find_section ("RULE");
  
  if (!p->allow_prog)
    parse_error (_("program is not allowed in this section"));
  return p->allow_prog;
}
