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
#include "rcfile-gram.h"	

struct string_list {
	struct string_list *next;
	char *str;
	int length;
};

static int simple_string();
static void string_begin();
static void string_add(char *s, int len);
static void string_add_char(int n);
static void string_finish();
static int escape(int c);
char * trimws(char *s);

static struct string_list *str_head, *str_tail;
int cfg_line_num;
char *cfg_file;

extern int yydebug;
#define DBG(t,s) do {\
 if (yydebug > 1) \
   printf("LEX %s:%d: %s %s\n", cfg_file, cfg_line_num, t, s);\
 } while (0)
 
%}

%x STR LIT RX RXM

WS [ \t][ \t]*
IDENT [a-zA-Z_][a-zA-Z_0-9-]+
LDASHES ---[ \t]*
RDASHES [ \t]*---
%%
         /* End-of-line comments */
#.*\n          { cfg_line_num++; }
#.*            /* end-of-file comment */;
         /* Keywords */
[aA][nN][dD]   return AND;
[oO][rR]       return OR;
BEGIN          return T_BEGIN;
{LDASHES}BEGIN{WS}{IDENT}{RDASHES} {
	char *p = strstr(yytext, "BEGIN") + 5;
	char *q;
	int len;
	
	for (; *p && isspace(*p); p++)
		;
	for (q = yytext + yyleng - 4; q > p && isspace(*q); q--)
		;
	len = q - p + 1;
	yylval.string = xmalloc(len + 1);
	memcpy(yylval.string, p, len);
	yylval.string[len] = 0;
	DBG("D_BEGIN", yylval.string);
	return D_BEGIN; }
END |
{LDASHES}END{RDASHES}        return T_END;
[hH][eE][aA][dD][eE][rR]     return T_HEADER;
[cC][oO][mM][mM][aA][nN][dD] return T_COMMAND;
         /* Backward compatible (unquoted) regular expressions */
=[^ \t][^!\n]*/\n  { yylval.string = trimws(strdup(yytext + 1));
		     DBG("RX0", yylval.string);
		     return REGEX; }
=[^ \t][^!\n]*!=   { BEGIN(RXM);
		     yylval.string = malloc(yyleng-2);
		     memcpy(yylval.string, yytext + 1, yyleng-3);
		     yylval.string[yyleng-3] = 0;
		     trimws(yylval.string);
		     DBG("RX1", yylval.string);
		     return REGEX; }
=[^ \t][^!\n]*!    { BEGIN(RX);
                     string_begin();
	             string_add(yytext+1, yyleng-1); }
<RX>[^!\n]*!=      { BEGIN(RXM);
		     string_add(yytext, yyleng - 2);
		     string_finish();
		     trimws(yylval.string);
                     DBG("RX2", yylval.string);
		     return REGEX; }
<RX>[^!\n]*/\n     { BEGIN(INITIAL);
		     string_add(yytext, yyleng);
		     string_finish();
		     trimws(yylval.string);
                     DBG("RX2", yylval.string);
		     return REGEX; }
<RX>[^!\n]*!       { string_add(yytext, yyleng); }
<RXM>[^!\n]*/\n    { BEGIN(INITIAL); 
		     yylval.string = strdup(yytext);
		     trimws(yylval.string);
		     DBG("RX3", yylval.string);
		     return REGEX; }
<RXM>[^!\n]*!      { BEGIN(RX);
                     string_begin();
	             string_add(yytext, yyleng); }
=                 return EQ;
!=                return NE;
[iI][fF]          return IF;
[fF][iI]          return FI;
[eE][lL][sS][eE]  return ELSE;
[rR][uU][lL][eE]  return RULE;
[dD][oO][nN][eE]  return DONE;
         /* Literal */
<LIT>[^\n]*/\n   { int i, j, len;

                   BEGIN(INITIAL);
		   for (i = 0; i < yyleng && isspace(yytext[i]); i++)
			   ;
		   for (j = yyleng - 1; j > i && isspace(yytext[i]); j--)
			   ;
		   len = j - i + 1;
	           yylval.string = xmalloc(len + 1);
                   memcpy(yylval.string, yytext + i, len);
                   yylval.string[len] = 0;
		   DBG("<LIT>STRING", yylval.string);
		   return STRING; }
         /* Identifiers */
{IDENT}          { yylval.string = strdup(yytext);
                   DBG("IDENT", yytext);
		   return IDENT; }
         /* Quoted strings */
\"[^\\"\n]*\"     { return simple_string(); }
\"[^\\"\n]*\\.    { BEGIN(STR);
                   string_begin();
		   string_add(yytext+1, yyleng-3);
		   string_add_char(escape(yytext[yyleng-1])); }
<STR>[^\\"\n]*\\. { string_add(yytext, yyleng-2);
                    string_add_char(escape(yytext[yyleng-1])); }
<STR>[^\\"\n]*\" { BEGIN(INITIAL);
                   string_add(yytext, yyleng-1); 
                   string_finish();
		   return STRING; }
         /* Other tokens */
{WS}           ;
\n             { cfg_line_num++; return EOL; }
.              return yytext[0];

%%

int
yywrap ()
{
	if (yyin) {
		fclose(yyin);
		yyin = NULL;
	}
	return 1;
}

void
verbatim()
{
	BEGIN(LIT);
}

int
simple_string()
{
  yylval.string = xmalloc(yyleng - 1);
  memcpy(yylval.string, yytext + 1, yyleng - 2);
  yylval.string[yyleng - 2] = 0;
  return STRING; 
}

void
string_begin()
{
	str_head = str_tail = NULL;
}

void
string_add(char *str, int len)
{
	struct string_list *s = xmalloc(sizeof(*s) + len);
	s->str = (char*)(s+1);
	memcpy(s->str, str, len);
	s->length = len;
	if (str_tail)
		str_tail->next = s;
	else
		str_head = s;
	str_tail = s;
}

void
string_add_char(int n)
{
	char c = n;
	string_add(&c, 1);
}

void
string_finish()
{
	struct string_list *s;
	int len = 0;
	char *p;
	
	for (s = str_head; s; s = s->next) 
		len += s->length;
	len++;
	yylval.string = xmalloc(len);
	for (p = yylval.string, s = str_head; s; ) {
		struct string_list *next = s->next;
		memcpy(p, s->str, s->length);
		p += s->length;
		xfree(s);
		s = next;
	}
	*p = 0;
}

int
escape(int c)
{
	switch (c) {
	case 'a':
		return '\a';
	case 'f':
		return '\f';
	case 'e':
		return '\e';
	case 'n':
		return '\n';
	case 'r':
		return '\t';
	case 't':
		return '\t';
	case 'v':
		return '\v';
	default:
		break;
	}
	return c;
}

char *
trimws(char *s)
{
	int len;

	for (len = strlen(s) - 1; len > 0 && isspace(s[len]); len--)
		;
	if (len > 0)
		s[len+1] = 0;
	return s;
}

int
rc_open(char *name)
{
	yyin = fopen(name, "r");
	if (!yyin) {
		if (options.termlevel == DEBUG)
			anubis_error(SOFT,
				     _("Anubis RC file error: %s."),
				     strerror(errno));
		return -1;
	}
	
	cfg_file = name;
	cfg_line_num = 1;
	return 0;
}


