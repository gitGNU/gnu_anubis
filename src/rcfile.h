/*
   rcfile.h

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

/* Types describing the basic syntax of an anubis rc file */
typedef struct rc_section RC_SECTION;
typedef struct rc_stmt RC_STMT;
typedef struct rc_rule RC_RULE;
typedef struct rc_cond RC_COND;
typedef struct rc_asgn RC_ASGN;
typedef struct rc_node RC_NODE;
typedef struct rc_bool RC_BOOL;
typedef struct rc_expr RC_EXPR;
typedef struct rc_inst RC_INST;
typedef struct rc_loc RC_LOC;

struct rc_loc {
	char *file;
	size_t line;
};

struct rc_section {          /* RC Section */
	RC_LOC loc;          /* Location in the config file */
	RC_SECTION *next;    /* Link to the next section */
	char *name;          /* Section name */
	RC_STMT *stmt;       /* List of parsed statements */
};

enum rc_stmt_type {          /* Statement type: */
	rc_stmt_asgn,        /* Assignment */
	rc_stmt_rule,        /* Rule definition */
	rc_stmt_cond,        /* Conditional expression */
	rc_stmt_inst         /* Instruction */
};

struct rc_asgn {             /* Assignment */
	char *lhs;           /* Left-hand side: A keyword */
	LIST *rhs;    /* Right-hand side: A list of character strings */
	int flags;           /* Flags control various aspects of assignment
				functionality */
};

enum bool_op {               /* Boolean operator */
	bool_not,
	bool_and,
	bool_or
};

struct rc_bool {             /* Boolean expression */ 
	enum bool_op op;     /* Opcode */ 
	RC_NODE *left;       /* Left operand */
	RC_NODE *right;      /* Right operand (NULL for bool_not) */
};

enum rc_node_type {          /* Executable node type */
	rc_node_bool,        /* Boolean instruction */
	rc_node_expr         /* Regular expression */
};

struct rc_expr {
	int part;  /* HEADER, COMMAND or BODY */
	char *key;
	RC_REGEX *re;
};

struct rc_node {             /* Executable node */
	RC_LOC loc;          /* Location in the config file */
	enum rc_node_type type;  /* Node type */
	union {
		RC_EXPR expr;
		RC_BOOL bool;
	} v;
};

struct rc_cond {             /* Conditional expression */
	RC_NODE *node;       /* Condition node */
	RC_STMT *iftrue;     /* Branch to follow when the condition is true */
	RC_STMT *iffalse;    /* Branch to follow when the condition is false */
};

struct rc_rule {             /* Rule definition */
	RC_NODE *node;       /* Compiled regular expression */
	RC_STMT *stmt;       /* Body of the rule */
};

enum rc_inst_opcode {        /* Operation code */
	inst_add,
	inst_remove,
	inst_modify,
	inst_stop,
	inst_call
};

struct rc_inst {             /* Instruction definition */
	enum rc_inst_opcode opcode;
	int part;            /* Message part to operate upon */ 
	RC_REGEX *key;       /* Key */
	char *key2;          /* New key value (for modify) */
	char *arg;           /* Argument */
};

struct rc_stmt {             /* General statement representation */
	RC_LOC loc;          /* Location in the config file */
	RC_STMT *next;       /* Link to the next statement */
	enum rc_stmt_type type;   /* Statement type */
	union {                   /* Actual data */
		RC_ASGN asgn;     /* type == rc_stmt_asgn */
		RC_RULE rule;     /* type == rc_stmt_rule */
		RC_COND cond;     /* type == rc_stmt_cond */
		RC_INST inst;     /* type == rc_stmt_inst */
	} v;
};

/* Semantic handler tables */
#define RC_KW_HANDLED 0
#define RC_KW_UNKNOWN 1
#define RC_KW_ERROR   2

typedef int (*rc_kw_parser_t)(int method, int key, LIST *arg,
			      void *inv_data, void *func_data, MESSAGE *msg);

/* Keyword flags */
#define KWF_HIDDEN 0x0001   /* Replace RHS with stars in debugging output */

struct rc_kwdef {
	char *name;         /* Keyword name */
	int tok;            /* Assigned token number */
	int flags;          /* Flags controlling debugging output, etc. */
};

struct rc_secdef_child {
	struct rc_secdef_child *next;
	int method;
	struct rc_kwdef *kwdef;
	rc_kw_parser_t parser;
	void *data;
};

/* Section priorities affect linking the user-defined sections to
   the parse tree left from parsing the system configuration file. */
enum section_prio {
	prio_user_only, /* Only user-defined section is taken into account */
	prio_system_only,/* Only system-defined section */
	prio_system,    /* System-defined section first, user-defined next */
	prio_user       /* User-defined section first, system-defined next */
};

struct rc_secdef {
	char *name;                   /* Section name */
	enum section_prio prio;       /* Execution priority */ 
	int allow_prog;               /* Are rules allowed in this section? */
	struct rc_secdef_child *child;
};
	
typedef void (*RC_ERROR_PRINTER) (void *data, 
				  const char *filename, int line,
				  const char *fmt, va_list ap);

/* Global data */
extern int cfg_line_num;
extern char *cfg_file; 

/* Function declarations */
void verbatim(void);
void lex_clear_state(void);

int error_sync_begin();

RC_SECTION *rc_section_lookup(RC_SECTION *, char *);
void rc_section_link(RC_SECTION **, RC_SECTION *);
void rc_secdef_add_child(struct rc_secdef *, struct rc_secdef_child *);
RC_SECTION *rc_parse(char *);
RC_SECTION *rc_parse_ep(char *name, RC_ERROR_PRINTER errprn, void *data);
void rc_section_list_destroy(RC_SECTION **);
int rc_run_cond(char *, int, char *);
void rc_run_section_list(int, RC_SECTION *, struct rc_secdef *);
void rc_run_section(int, RC_SECTION *, struct rc_secdef *, void *, MESSAGE *);
void rc_call_section(int, RC_SECTION *, struct rc_secdef *, void *, MESSAGE *);
void rc_set_debug_level(char *);
int rc_open(char *);
struct rc_secdef *anubis_add_section(char *);
struct rc_secdef *anubis_find_section(char *);

void parse_error(const char *fmt, ...);
void tracefile(RC_LOC *, const char *fmt, ...);

/* EOF */

