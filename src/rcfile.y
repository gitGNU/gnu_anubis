%{
/*
   rcfile.y

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <setjmp.h>	
#include "headers.h"
#include "extern.h"
#include "rcfile.h"

static RC_SECTION *rc_section_create(char *name, RC_STMT *stmt);
static void rc_section_destroy(RC_SECTION *s);
static void rc_section_print(RC_SECTION *sect);
 
static void rc_asgn_destroy(RC_ASGN *asgn);
 
static void rc_bool_destroy(RC_BOOL *bool);

static void rc_level_print(int level, char *str);
 
static RC_NODE *rc_node_create(enum rc_node_type t);
static void rc_node_destroy(RC_NODE *node);
static void rc_node_print(RC_NODE *node);
 
static void rc_rule_destroy(RC_RULE *rule);
 
static void rc_cond_destroy(RC_COND *cond);
 
static RC_STMT *rc_stmt_create(enum rc_stmt_type type);
static void rc_stmt_destroy(RC_STMT *stmt);
static void rc_stmt_list_destroy(RC_STMT *stmt);
static void rc_stmt_print(RC_STMT *stmt, int level);
static int reg_option_add(int *flag, char *opt);

static RC_SECTION *rc_section;

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
	struct {
		int part;
		char *key;
	} msgpart;
};

%token EOL T_BEGIN T_END AND OR 
%token T_HEADER T_COMMAND T_BODY IF FI ELSE RULE DONE
%token CALL STOP ADD REMOVE MODIFY
%token <string> IDENT STRING REGEX D_BEGIN
%token <num> T_MSGPART

%left OR
%left AND
%left NOT

%type <string> begin keyword string option opt_key
%type <section> section seclist
%type <stmtlist> stmtlist
%type <stmt> stmt asgn_stmt cond_stmt rule_stmt inst_stmt
%type <num> optlist
%type <node> rule_start cond expr
%type <msgpart> msgpart 

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
	 | inst_stmt EOL
         ;

asgn_stmt: keyword '=' { verbatim(); } STRING
           {
		   $$ = rc_stmt_create(rc_stmt_asgn);
		   $$->v.asgn.lhs = $1;
		   $$->v.asgn.rhs = $4;
	   }
         ;

keyword  : IDENT
         ;

cond_stmt: if cond stmtlist fi
           {
		   $$ = rc_stmt_create(rc_stmt_cond);
		   $$->v.cond.node = $2;
		   $$->v.cond.iftrue = $3.head;
		   $$->v.cond.iffalse = NULL;
	   }
         | if cond stmtlist else stmtlist fi
           {
		   $$ = rc_stmt_create(rc_stmt_cond);
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
		   $$ = rc_node_create(rc_node_bool);
		   $$->v.bool.op = bool_and;
		   $$->v.bool.left = $1;
		   $$->v.bool.right = $3;
	   }
         | cond OR cond
           {
		   $$ = rc_node_create(rc_node_bool);
		   $$->v.bool.op = bool_or;
		   $$->v.bool.left = $1;
		   $$->v.bool.right = $3;
	   }
         | NOT cond
           {
		   $$ = rc_node_create(rc_node_bool);
		   $$->v.bool.op = bool_not;
		   $$->v.bool.left = $2;
		   $$->v.bool.right = NULL;
	   }
         ;

meq      : /* empty */
         | '='
         ;

opt_key  : /* empty */
           {
		   $$ = NULL;
	   }
         | '[' string ']'
           {
		   $$ = $2;
	   }
         ;

msgpart  : T_MSGPART opt_key
           {
		   $$.part = $1;
		   $$.key = $2;
	   }
         | '[' string ']'
           {
		   $$.part = HEADER;
		   $$.key = $2;
	   }
         ;

expr     : msgpart optlist meq optlist string
           {
		   $$ = rc_node_create(rc_node_expr);
		   $$->v.expr.part = $1.part;
		   $$->v.expr.key = $1.key;
		   $$->v.expr.re = anubis_regex_compile($5, $4|$2);
	   }
         ;

optlist  : /* empty */
           {
		   $$ = 0;
	   }
         | option
           {
		   int rc;
		   $$ = 0;
		   rc = reg_option_add(&$$, $1);
		   xfree($1);
		   if (rc)
			   YYERROR;
	   }
         | optlist option
           {
		   int rc = reg_option_add(&$1, $2);
		   xfree($2);
		   if (rc)
			   YYERROR;
		   $$ = $1;
	   }
         ;

option   : ':' IDENT
           {
		   $$ = $2;
	   }
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

rule_start: RULE optlist string
           {
		   $$ = rc_node_create(rc_node_expr);
		   $$->v.expr.part = HEADER;
		   $$->v.expr.key = strdup(X_ANUBIS_RULE_HEADER);
		   $$->v.expr.re = anubis_regex_compile($3, $2);
	   }
         ;

string   : STRING
         | IDENT
         ;

inst_stmt: STOP
           {
		   $$ = rc_stmt_create(rc_stmt_inst);
		   $$->v.inst.opcode = inst_stop;
		   $$->v.inst.part = NIL;
		   $$->v.inst.key  = NULL;
		   $$->v.inst.key2 = NULL;
		   $$->v.inst.arg  = NULL;
	   }
         | CALL string
           {
		   $$ = rc_stmt_create(rc_stmt_inst);
		   $$->v.inst.opcode = inst_call;
		   $$->v.inst.key = $2;
		   $$->v.inst.part = NIL;
		   $$->v.inst.key2 = NULL;
		   $$->v.inst.arg  = NULL;
	   }
         | ADD msgpart string
           {
		   $$ = rc_stmt_create(rc_stmt_inst);
		   $$->v.inst.opcode = inst_add;
		   $$->v.inst.part = $2.part;
		   $$->v.inst.key  = $2.key;
		   $$->v.inst.key2 = NULL;
		   $$->v.inst.arg  = $3;
	   }
         | REMOVE msgpart
           {
		   $$ = rc_stmt_create(rc_stmt_inst);
		   $$->v.inst.opcode = inst_remove;
		   $$->v.inst.part = $2.part;
		   $$->v.inst.key  = $2.key;
		   $$->v.inst.key2 = NULL;
		   $$->v.inst.arg  = NULL;
	   }
         | MODIFY msgpart opt_key string
           {
		   $$ = rc_stmt_create(rc_stmt_inst);
		   $$->v.inst.opcode = inst_modify;
		   $$->v.inst.part = $2.part;
		   $$->v.inst.key  = $2.key;
		   $$->v.inst.key2 = $3;
		   $$->v.inst.arg  = $4;
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
		printf("BEGIN SECTION %s\n", sect->name);
		rc_stmt_print(sect->stmt, 1);
		printf("END SECTION %s\n", sect->name);
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
		
	case rc_node_expr:
		free(node->v.expr.key);
		anubis_regex_free(node->v.expr.re);
	}
	xfree(node);
}

static char *
part_string(int part)
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
rc_node_print(RC_NODE *node)
{
	switch (node->type) {
	case rc_node_expr:
		printf("%s", part_string(node->v.expr.part));
		if (node->v.expr.key && node->v.expr.key[0] != '\n')
			printf("[%s]",node->v.expr.key);
		printf(" %s", anubis_regex_source(node->v.expr.re));
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

/* Instructions */

void
rc_inst_destroy(RC_INST *inst)
{
	free(inst->key);
	free(inst->key2);
	free(inst->arg);
}

static char *
inst_name(enum rc_inst_opcode opcode)
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
rc_inst_print(RC_INST *inst, int level)
{
	rc_level_print(level, inst_name(inst->opcode));
	switch (inst->opcode) {
	case inst_stop:
		break;
		
	case inst_call:
		printf(" %s", inst->key);
		break;

	default:
		printf(" %s[%s]", part_string(inst->part),
		       inst->key ? inst->key : "");
		if (inst->key2)
			printf(" [%s]", inst->key2);
		if (inst->arg)
			printf(" \"%s\"", inst->arg);
	}
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
		break;

	case rc_stmt_inst:
		rc_inst_destroy(&stmt->v.inst);
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
rc_level_print(int level, char *str)
{
	int i;

	for (i = 0; i < level*2; i++)
		putchar(' ');
	printf("%s", str);
}

void
rc_stmt_print(RC_STMT *stmt, int level)
{
	for (; stmt; stmt = stmt->next) {
		switch (stmt->type) {
		case rc_stmt_asgn:
			rc_level_print(level, "ASGN: ");
			printf("%s = %s",
			       stmt->v.asgn.lhs, stmt->v.asgn.rhs);
			break;
			
		case rc_stmt_cond:
			rc_level_print(level, "COND: ");
			rc_node_print(stmt->v.cond.node);
			printf("\n");
			rc_level_print(level, "IFTRUE:\n");
			rc_stmt_print(stmt->v.cond.iftrue, level+1);
			if (stmt->v.cond.iffalse) {
				rc_level_print(level, "IFFALSE:\n");
				rc_stmt_print(stmt->v.cond.iffalse, level+1);
			}
			rc_level_print(level, "END COND");
			break;
			
		case rc_stmt_rule:
			rc_level_print(level, "RULE: ");
			rc_node_print(stmt->v.rule.node);
			printf("\n");
			rc_level_print(level, "BODY\n");
			rc_stmt_print(stmt->v.rule.stmt, level+1);
			rc_level_print(level, "END RULE");
			break;

		case rc_stmt_inst:
			rc_inst_print(&stmt->v.inst, level);
			break;
			
		default:
			abort();
		}
		printf("\n");
	}
}

int
reg_option_add(int *flag, char *opt)
{
	if (strcasecmp(opt, "basic") == 0) 
		*flag |= R_BASIC;
	else if (strcasecmp(opt, "scase") == 0)
		*flag |= R_SCASE;
#ifdef HAVE_PCRE
	else if (strcasecmp(opt, "perlre") == 0) 
		*flag |= R_PERLRE;
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
	MESSAGE *msg;
	void *data;
	int refcnt;
	char **refstr;
	jmp_buf jmp;
};

static void asgn_eval(struct eval_env *env, RC_ASGN *asgn);
static int node_eval(struct eval_env *env, RC_NODE *node);
static int bool_eval(struct eval_env *env, RC_BOOL *bool);
static void cond_eval(struct eval_env *env, RC_COND *cond);
static void rule_eval(struct eval_env *env, RC_RULE *rule);
static void stmt_list_eval(struct eval_env *env, RC_STMT *stmt);
static void inst_eval(struct eval_env *env, RC_INST *inst);

void
inst_eval(struct eval_env *env, RC_INST *inst)
{
	char *arg, *argp = NULL;

	if (!env->msg)
		return; /* FIXME: bail out? */
	
	if (inst->arg) {
		if (env->refstr)
			arg = argp = substitute(inst->arg, env->refstr);
		else
			arg = inst->arg;
	}
	
	switch (inst->opcode) {
	case inst_stop:
		longjmp(env->jmp, 1);
		break;

	case inst_call:
		rcfile_call_section(env->method, inst->key,
				    env->data, env->msg);
		break;
		
	case inst_add:
		if (inst->part == BODY)
			message_add_body(env->msg, inst->key, arg);
		else
			message_add_header(env->msg, inst->key, arg);
		break;
		
	case inst_modify:
		message_modify_headers(env->msg, inst->key, inst->key2, arg);
		break;
		
	case inst_remove:
		message_remove_headers(env->msg, inst->key);
		break;
		
	default:
		abort();
	}

	if (argp)
		free(argp);
}
	
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
	p->parser(env->method, key, str, p->data, env->data, env->msg);
}


int
re_eval_list(struct eval_env *env, char *key, RC_REGEX *re, struct list *list)
{
	ASSOC *p;
	int rc = 0;
	
	for (p = list_first(list); rc == 0 && p; p = list_next(list)) {
		if (!p->key || strcasecmp(p->key, key) == 0) 
			rc = anubis_regex_match(re, p->value,
						&env->refcnt, &env->refstr);
	}
	return rc;
}

int
re_eval_text(struct eval_env *env, RC_REGEX *re, char *text)
{
	/*FIXME*/
	return anubis_regex_match(re, text, &env->refcnt, &env->refstr);
}

int
expr_eval(struct eval_env *env, RC_EXPR *expr)
{
	int rc;
	
	if (env->refstr && anubis_regex_refcnt(expr->re)) {
		xfree_pptr(env->refstr);
		env->refstr = NULL;
		env->refcnt = 0;
	}

	switch (expr->part) {
	case COMMAND:
		rc = re_eval_list(env, expr->key, expr->re,
				  env->msg->commands);
		break;
		
	case HEADER:
		rc = re_eval_list(env, expr->key, expr->re, env->msg->header);
		break;
		
	case BODY:
		rc = re_eval_text(env, expr->re, env->msg->body);
		break;

	default:
		abort();
	}
	return rc;
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
	case rc_node_expr:
		rc = expr_eval(env, &node->v.expr);
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
	if (node_eval(env, cond->node))
		stmt_list_eval(env, cond->iftrue);
	else
		stmt_list_eval(env, cond->iffalse);
}

void
rule_eval(struct eval_env *env, RC_RULE *rule)
{
	if (node_eval(env, rule->node))
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
			break;

		case rc_stmt_inst:
			inst_eval(env, &stmt->v.inst);
		}
}

void
eval_section(int method, RC_SECTION *sec, struct rc_secdef *secdef,
	     void *data, MESSAGE *msg)
{
	struct eval_env env;
	env.method = method;
	env.child = secdef->child;
	env.refcnt = 0;
	env.refstr = NULL;
	env.msg = msg;
	env.data = data;
	
	if (setjmp(env.jmp) == 0)
		stmt_list_eval(&env, sec->stmt);
			
	if (env.refstr)
		xfree_pptr(env.refstr);
}	

void
rc_run_section(int method, RC_SECTION *sec, struct rc_secdef *secdef,
	       void *data, MESSAGE *msg)
{
	if (!sec)
		return;
	for (; secdef->name; secdef++)
		if (strcmp(sec->name, secdef->name) == 0) {
			eval_section(method, sec, secdef, data, msg);
			return;
		}
	anubis_error(SOFT,
		     _("Unknown section: %s"), sec->name);
}

void
rc_call_section(int method, RC_SECTION *sec, struct rc_secdef *secdef,
		void *data, MESSAGE *msg)
{
	if (!sec)
		return;
	for (; secdef->name; secdef++)
		if (strcmp(secdef->name, "RULE") == 0) {
			eval_section(method, sec, secdef, data, msg);
			return;
		}
}

void
rc_run_section_list(int method, RC_SECTION *sec, struct rc_secdef *secdef)
{
	for (; sec; sec = sec->next)
		rc_run_section(method, sec, secdef, NULL, NULL);
}


