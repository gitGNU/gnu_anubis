%{
/*
   GNU Anubis -- an outgoing mail processor and the SMTP tunnel.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include "headers.h"
#include "extern.h"
#include "rcfile.h"

static RC_SECTION *rc_section_create(char *name, RC_STMT *stmt);
static void rc_section_destroy(RC_SECTION *s);
static void rc_section_print(RC_SECTION *sect);
 
static void rc_asgn_destroy(RC_ASGN *asgn);
 
static void rc_bool_destroy(RC_BOOL *bool);
 
static RC_NODE *rc_node_create(enum rc_node_type t);
static void rc_node_destroy(RC_NODE *node);
static void rc_node_print(RC_NODE *node);
 
static void rc_rule_destroy(RC_RULE *rule);
 
static void rc_cond_destroy(RC_COND *cond);
 
static RC_STMT *rc_stmt_create(enum rc_stmt_type type);
static void rc_stmt_destroy(RC_STMT *stmt);
static void rc_stmt_list_destroy(RC_STMT *stmt);
static void rc_stmt_print(RC_STMT *stmt);
static void reg_option_init();
static int reg_option_add(char *opt);

static RC_SECTION *rc_section;
static int reg_opt;
static int perlre;

static int debug_level;
 
%}

%union {
	char *string;
	RC_SECTION *section;
	RC_STMT *stmt;
	struct { RC_STMT *head; RC_STMT *tail; } stmtlist;
	RC_COND cond;
	RC_RULE rule;
	RC_NODE *node;
	RC_REGEX *regex;
	int num;
};

%token EOL T_BEGIN T_END AND OR EQ NE
%token T_HEADER T_COMMAND IF FI ELSE RULE DONE
%token <string> IDENT STRING REGEX D_BEGIN

%left OR
%left AND

%type <string> begin keyword
%type <section> section seclist
%type <stmtlist> stmtlist
%type <stmt> stmt asgn_stmt cond_stmt rule_stmt 
%type <cond> cond
%type <num> cond_lhs
%type <node> cond_rhs compat_rx_list rx_list regex rule_start
%type <regex> compat_rx

%%

input    : seclist
         ;

seclist  : section
           {
		   $$ = rc_section = $1;
	   }
         | seclist section
           {
		   if ($2) {
			   if (rc_section == NULL) {
				   $$ = rc_section = $2;
			   } else {
				   $1->next = $2;
				   $$ = $2;
			   } 
		   }
	   }
         ;

section  : /* empty */ EOL
           {
		   $$ = NULL;
	   }
         | begin stmtlist end
           {
		   $$ = rc_section_create($1, $2.head);
	   }
         | begin end
           {
		   $$ = NULL;
	   }
         ;

begin    : T_BEGIN { verbatim(); } STRING EOL
           {
		   $$ = $3;
	   }
         | D_BEGIN EOL
         ;

end      : T_END EOL
         ;

stmtlist : stmt
           {
		   $$.head = $$.tail = $1;
	   }
         | stmtlist stmt
           {
		   if ($2) {
			   if ($$.head == NULL) {
				   $$.head = $$.tail = $2;
			   } else {
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
         ;

asgn_stmt: keyword EQ { verbatim(); } STRING
           {
		   $$ = rc_stmt_create(rc_stmt_asgn);
		   $$->v.asgn.lhs = $1;
		   $$->v.asgn.rhs = $4;
	   }
         | keyword REGEX /* Compatibility syntax */
           {
		   $$ = rc_stmt_create(rc_stmt_asgn);
		   $$->v.asgn.lhs = $1;
		   $$->v.asgn.rhs = $2;
	   }
          ;

keyword  : IDENT
         ;

cond_stmt: if cond stmtlist fi
           {
		   $$ = rc_stmt_create(rc_stmt_cond);
		   $$->v.cond = $2;
		   $$->v.cond.iftrue = $3.head;
		   $$->v.cond.iffalse = NULL;
	   }
         | if cond stmtlist else stmtlist fi
           {
		   $$ = rc_stmt_create(rc_stmt_cond);
		   $$->v.cond = $2;
		   $$->v.cond.iftrue = $3.head;
		   $$->v.cond.iffalse = $5.head;
	   }
	 ;

cond     : cond_lhs { reg_option_init(); } optlist cond_rhs
           {
		   $$.method = $1;
		   $$.node = $4;
	   }
         ;

cond_lhs : T_HEADER
           {
		   $$ = HEADER;
	   }
         | T_COMMAND
           {
		   $$ = COMMAND;
	   }
         ;

optlist  : /* empty */
         | option
         | optlist option
         ;

option   : ':' IDENT
           {
		   int rc = reg_option_add($2);
		   xfree($2);
		   if (rc)
			   YYERROR;
	   }
         ;

cond_rhs : compat_rx_list
         | rx_list
         ;

compat_rx_list: compat_rx
           {
		   $$ = rc_node_create(rc_node_re);
		   $$->v.re = $1;
	   }
         | compat_rx_list compat_rx
           {
		   RC_NODE *node;

		   node = rc_node_create(rc_node_bool);
		   node->v.bool.op = bool_not;
		   node->v.bool.left = rc_node_create(rc_node_re);
		   node->v.bool.left->v.re = $2;
			   
		   $$ = rc_node_create(rc_node_bool);
		   $$->v.bool.op = bool_and;
		   $$->v.bool.left = $1;
		   $$->v.bool.right = node;
	   }
         ;

compat_rx: REGEX
           {
		   $$ = anubis_regex_compile($1, reg_opt);
		   if (!$$)
			   YYERROR;
	   }
         ;

rx_list  : regex
         | rx_list and regex
           {
		   $$ = rc_node_create(rc_node_bool);
		   $$->v.bool.op = bool_and;
		   $$->v.bool.left = $1;
		   $$->v.bool.right = $3;
	   }
         | rx_list or regex
           {
		   $$ = rc_node_create(rc_node_bool);
		   $$->v.bool.op = bool_or;
		   $$->v.bool.left = $1;
		   $$->v.bool.right = $3;
	   }
         ;

regex    : '(' rx_list ')'
           {
		   $$ = $2;
	   }
         | EQ STRING
           {
		   RC_REGEX *re = anubis_regex_compile($2, reg_opt);
		   
		   if (!re)
			   YYERROR;
		   $$ = rc_node_create(rc_node_re);
		   $$->v.re = re;
	   }
         | NE STRING
           {
		   RC_REGEX *re = anubis_regex_compile($2, reg_opt);
		   
		   if (!re)
			   YYERROR;

		   $$ = rc_node_create(rc_node_bool);
		   $$->v.bool.op = bool_not;
		   $$->v.bool.left = rc_node_create(rc_node_re);
		   $$->v.bool.left->v.re = re;
		   $$->v.bool.right = NULL;
	   }
         ;

and      : /* empty */
         | AND
         ;

or       : OR
         ;

if       : IF
         ;

fi       : FI
         ;
 
else     : ELSE 
         ;

rule_stmt: rule_start EOL stmtlist DONE
           {
		   $$ = rc_stmt_create(rc_stmt_rule);
		   $$->v.rule.node = $1;
		   $$->v.rule.stmt = $3.head;
	   }
         ;

rule_start: RULE optlist cond_rhs
           {
		   $$ = $3;
	   }
         ;

%%

int
yyerror(char *s)
{
	anubis_error(SOFT, "%s:%d: %s",
		     cfg_file, cfg_line_num, s);
}

RC_SECTION *
rc_parse(char *name)
{
	int status;
	if (rc_open(name))
		return NULL;
	rc_section = NULL;
	status = yyparse();
	if (status) {
		rc_section_list_destroy(rc_section);
		rc_section = NULL;
	}
	if (debug_level)
		rc_section_print(rc_section);
	return rc_section;
}

void
rc_set_debug_level(char *arg)
{
	if (!arg)
		debug_level = 1;
	else
		debug_level = arg[0] - '0';
	if (debug_level > 1)
		yydebug = debug_level;
}

/* Section manipulation */
RC_SECTION *
rc_section_create(char *name, RC_STMT *stmt)
{
	RC_SECTION *p = xmalloc(sizeof(*p));
	p->next = NULL;
	p->name = name;
	p->stmt = stmt;
	return p;
}

void
rc_section_destroy(RC_SECTION *s)
{
	rc_stmt_list_destroy(s->stmt);
	xfree(s->name);
	xfree(s);
}

void
rc_section_list_destroy(RC_SECTION *s)
{
	while (s) {
		RC_SECTION *next = s->next;
		rc_section_destroy(s);
		s = next;
	}
}

void
rc_section_print(RC_SECTION *sect)
{
	for (; sect; sect = sect->next) {
		printf("BEGIN %s\n", sect->name);
		rc_stmt_print(sect->stmt);
		printf("END %s\n", sect->name);
	}
}

RC_SECTION *
rc_section_lookup(RC_SECTION *sec, char *name)
{
	for (; sec; sec = sec->next)
		if (strcmp(sec->name, name) == 0)
			break;
	return sec;
}

void
rc_section_link(RC_SECTION **ap, RC_SECTION *b)
{
	RC_SECTION *a;
	
	if (!*ap) {
		*ap = b;
		return;
	}
	for (a = *ap; a->next; a = a->next)
		;
	a->next = b;
}

/* Assignment manipulations */
void
rc_asgn_destroy(RC_ASGN *asgn)
{
	xfree(asgn->lhs);
	xfree(asgn->rhs);
}

/* Bools */

void
rc_bool_destroy(RC_BOOL *bool)
{
	rc_node_destroy(bool->left);
	rc_node_destroy(bool->right);
}

/* Nodes */

RC_NODE *
rc_node_create(enum rc_node_type t)
{
	RC_NODE *p = xmalloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	p->type = t;
	return p;
}

void
rc_node_destroy(RC_NODE *node)
{
	if (!node)
		return;
	switch (node->type) {
	case rc_node_bool:
		rc_bool_destroy(&node->v.bool);
		break;
		
	case rc_node_re:
		anubis_regex_free(node->v.re);
	}
	xfree(node);
}

void
rc_node_print(RC_NODE *node)
{
	switch (node->type) {
	case rc_node_re:
		printf("%s", anubis_regex_source(node->v.re));
		break;
		
	case rc_node_bool:
		switch (node->v.bool.op) {
		case bool_not:
			printf("NOT (");
			rc_node_print(node->v.bool.left);
			printf(")");
			break;
			
		case bool_and:
			printf("AND (");
			rc_node_print(node->v.bool.left);
			printf(",");
			rc_node_print(node->v.bool.right);
			printf(")");
			break;
			
		case bool_or:
			printf("OR (");
			rc_node_print(node->v.bool.left);
			printf(",");
			rc_node_print(node->v.bool.right);
			printf(")");
			break;
		}
	}
}

/* Rules */

void
rc_rule_destroy(RC_RULE *rule)
{
	rc_node_destroy(rule->node);
	rc_stmt_list_destroy(rule->stmt);
}

/* Conditionals */

void
rc_cond_destroy(RC_COND *cond)
{
	rc_node_destroy(cond->node);
	rc_stmt_list_destroy(cond->iftrue);
	rc_stmt_list_destroy(cond->iffalse);
}

/* Statements */
RC_STMT *
rc_stmt_create(enum rc_stmt_type type)
{
	RC_STMT *p = xmalloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	p->type = type;
	return p;
}

void
rc_stmt_destroy(RC_STMT *stmt)
{
	switch (stmt->type) {
	case rc_stmt_asgn:
		rc_asgn_destroy(&stmt->v.asgn);
		break;
		
	case rc_stmt_rule:
		rc_rule_destroy(&stmt->v.rule);
		break;
		
	case rc_stmt_cond:
		rc_cond_destroy(&stmt->v.cond);
	}
	xfree(stmt);
}

void
rc_stmt_list_destroy(RC_STMT *stmt)
{
	while (stmt) {
		RC_STMT *next = stmt->next;
		rc_stmt_destroy(stmt);
		stmt = next;
	}
}

void
rc_stmt_print(RC_STMT *stmt)
{
	for (; stmt; stmt = stmt->next) {
		switch (stmt->type) {
		case rc_stmt_asgn:
			printf("ASGN: %s = %s",
			       stmt->v.asgn.lhs, stmt->v.asgn.rhs);
			break;
			
		case rc_stmt_cond:
			printf("COND: ");
			rc_node_print(stmt->v.cond.node);
			printf("\nIFTRUE:\n");
			rc_stmt_print(stmt->v.cond.iftrue);
			printf("IFFALSE:\n");
			rc_stmt_print(stmt->v.cond.iffalse);
			printf("END COND");
			break;
			
		case rc_stmt_rule:
			printf("RULE: ");
			rc_node_print(stmt->v.rule.node);
			printf("\nBODY\n");
			rc_stmt_print(stmt->v.rule.stmt);
			printf("END RULE");
			break;
			
		default:
			abort();
		}
		printf("\n");
	}
}


void
reg_option_init()
{
	reg_opt = 0;
}

int
reg_option_add(char *opt)
{
	if (strcasecmp(opt, "basic") == 0) 
		reg_opt |= R_BASIC;
	else if (strcasecmp(opt, "scase") == 0)
		reg_opt |= R_SCASE;
#ifdef HAVE_PCRE
	else if (strcasecmp(opt, "perlre") == 0) 
		reg_opt |= R_PERLRE;
#endif
	else {
		yyerror(_("Unknown regexp option"));
		return 1;
	}
	return 0;
}
	
/* ******************************* Runtime ********************************* */
static struct rc_secdef_child *
child_copy(struct rc_secdef_child *p)
{
	struct rc_secdef_child *newp = xmalloc(sizeof(*newp));
	memcpy(newp, p, sizeof(*newp));
	newp->next = NULL;
	return newp;
}	

void
rc_secdef_add_child(struct rc_secdef *def, struct rc_secdef_child *child)
{
	struct rc_secdef_child *p = child_copy(child);
	if (!def->child)
		def->child = p;
	else {
		struct rc_secdef_child *last;

		for (last = def->child; last->next; last = last->next)
			;
		last->next = p;
	}
}

struct rc_secdef_child *
rc_child_lookup(struct rc_secdef_child *child, char *str, int method, int *key)
{
	for (; child; child = child->next) {
		if (child->method & method) {
			struct rc_kwdef *kw;
			for (kw = child->kwdef; kw->name; kw++)
				if (strcmp(kw->name, str) == 0) {
					*key = kw->tok;
					return child;
				}
		}
	}
	return NULL;
}

struct eval_env {
	int method;
	int cmp_method;
	struct rc_secdef_child *child;
	void *data;
	char *line;
	int refcnt;
	char **refstr;
};

static void asgn_eval(struct eval_env *env, RC_ASGN *asgn);
static int node_eval(struct eval_env *env, RC_NODE *node);
static int bool_eval(struct eval_env *env, RC_BOOL *bool);
static void cond_eval(struct eval_env *env, RC_COND *cond);
static void rule_eval(struct eval_env *env, RC_RULE *rule);
static void stmt_list_eval(struct eval_env *env, RC_STMT *stmt);

void
asgn_eval(struct eval_env *env, RC_ASGN *asgn)
{
	int key;
	char *str;
	struct rc_secdef_child *p = rc_child_lookup(env->child, asgn->lhs,
						    env->method, &key);
	if (!p)
		return;
	if (env->refstr)
		str = substitute(asgn->rhs, env->refstr);
	else
		str = asgn->rhs;
	p->parser(env->method, key, str, env->data, p->data, env->line);
}

int
node_eval(struct eval_env *env, RC_NODE *node)
{
	int rc; /* It won't be used uninitialized despite what cc says.
		   Note default: branch below */
	
	switch (node->type) {
	case rc_node_bool:
		rc = bool_eval(env, &node->v.bool);
		break;
	case rc_node_re:
		if (env->refstr && anubis_regex_refcnt(node->v.re)) {
			xfree_pptr(env->refstr);
			env->refstr = NULL;
			env->refcnt = 0;
		}
		rc = anubis_regex_match(node->v.re, env->line,
					&env->refcnt, &env->refstr);
		break;
		
	default:
		abort();
	}
	return rc;
}

int
bool_eval(struct eval_env *env, RC_BOOL *bool)
{
	int rc = node_eval(env, bool->left);

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
	return node_eval(env, bool->right);
}

void
cond_eval(struct eval_env *env, RC_COND *cond)
{
	if (cond->method != env->cmp_method)
		stmt_list_eval(env, cond->iffalse);
	else if (node_eval(env, cond->node))
		stmt_list_eval(env, cond->iftrue);
	else
		stmt_list_eval(env, cond->iffalse);
}

void
rule_eval(struct eval_env *env, RC_RULE *rule)
{
	if (env->cmp_method == HEADER && node_eval(env, rule->node))
		stmt_list_eval(env, rule->stmt);
}

void
stmt_list_eval(struct eval_env *env, RC_STMT *stmt)
{
	for (; stmt; stmt = stmt->next)
		switch (stmt->type) {
		case rc_stmt_asgn:
			asgn_eval(env, &stmt->v.asgn);
			break;

		case rc_stmt_cond:
			cond_eval(env, &stmt->v.cond);
			break;

		case rc_stmt_rule:
			rule_eval(env, &stmt->v.rule);
		}
}

void
rc_run_section(int method, RC_SECTION *sec, struct rc_secdef *secdef,
	       int cmp_method, char *line, void *data)
{
	for (; secdef->name; secdef++)
		if (strcmp(sec->name, secdef->name) == 0) {
			struct eval_env env;
			env.method = method;
			env.cmp_method = cmp_method;
			env.child = secdef->child;
			env.line = line;
			env.refcnt = 0;
			env.refstr = NULL;
			env.data = data;
			
			stmt_list_eval(&env, sec->stmt);
			if (env.refstr)
				xfree_pptr(env.refstr);

			return;
		}
	anubis_error(SOFT,
		     _("Unknown section: %s"), sec->name);
}

void
rc_run_section_list(int method, RC_SECTION *sec, struct rc_secdef *secdef)
{
	for (; sec; sec = sec->next)
		rc_run_section(method, sec, secdef, NIL, NULL, NULL);
}


