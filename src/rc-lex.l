%{
/*
   rcfile.l

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include "headers.h"
#include "extern.h"
#include "rcfile.h"
#include "rc-gram.h"	

struct string_list
{
  struct string_list *next;
  char *str;
  int length;
};

static int simple_string (void);
static void string_begin (void);
static void string_add (char *, int);
static void string_add_char (int);
static void string_finish (void);
static int escape (int);
char *trimws (char *);
char *trimcpy (void);

static void multiline_begin (void);
static void multiline_add (char *);
static void multiline_finish (void);
static char *multiline_strip_tabs (char *);
static int isemptystr (char *);
 
static char *multiline_delimiter;
static int strip_tabs;
 
static struct string_list *str_head, *str_tail;
struct rc_loc rc_locus;

#define DBG(t,s)							\
  do									\
    {									\
      if (yy_flex_debug)						\
	fprintf (stderr,						\
		 "LEX %s:%lu.%lu-%lu.%lu: %s %s\n",			\
		 yylloc.beg.file,					\
		 (unsigned long) yylloc.beg.line,			\
		 (unsigned long) yylloc.beg.column,			\
		 (unsigned long) yylloc.end.line,			\
		 (unsigned long) yylloc.end.column,			\
		 t, s);							\
    }									\
  while (0)

/* Advance locus to the next line */
void
advance_line ()
{
        ++rc_locus.line;
        rc_locus.column = 1;
}

#define YY_USER_ACTION					  \
  yylloc.beg = yylloc.end = rc_locus;			  \
  yylloc.end.column += yyleng;

%}

%x STR LIT ML

WS [ \t][ \t]*
IDENT [a-zA-Z0-9_./-]+
LDASHES ---[ \t]*
RDASHES [ \t]*---
PUNCT [=:()\[\]]
%%
         /* End-of-line comments */
#.*\n          { advance_line(); return EOL; }
#.*            /* end-of-file comment */;
         /* Keywords */
BEGIN          return T_BEGIN;
{LDASHES}BEGIN{WS}{IDENT}{RDASHES} {
	char *p = strstr (yytext, "BEGIN") + 5;
	char *q;
	int len;

	for (; *p && isspace (*(u_char*)p); p++)
		;
	for (q = yytext + yyleng - 4; q > p && isspace (*(u_char*)q); q--)
		;
	len = q - p + 1;
	yylval.string = xmalloc (len + 1);
	memcpy (yylval.string, p, len);
	yylval.string[len] = 0;
	DBG ("D_BEGIN", yylval.string);
	return D_BEGIN; }
END |
{LDASHES}END{RDASHES}        return T_END;
[aA][nN][dD]                 return AND;
[oO][rR]                     return OR;
[nN][oO][tT]                 return NOT;
[hH][eE][aA][dD][eE][rR]     { yylval.num = HEADER; return T_MSGPART; }
[cC][oO][mM][mM][aA][nN][dD] { yylval.num = COMMAND; return T_MSGPART; }
[bB][oO][dD][yY]             { yylval.num = BODY; return T_MSGPART; }
[sS][tT][oO][pP]             return STOP;
[cC][aA][lL][lL]             return CALL;
[iI][fF]                     return IF;
[fF][iI]                     return FI;
[eE][lL][sS][eE]             return ELSE;
[eE][lL][iI][fF]             return ELIF;
[rR][uU][lL][eE]             return RULE;
[tT][rR][iI][gG][gG][eE][rR] return RULE;
[dD][oO][nN][eE]             return DONE;
[aA][dD][dD]                 return ADD;
[rR][eE][mM][oO][vV][eE]     return REMOVE;
[mM][oO][dD][iI][fF][yY]     return MODIFY;
[rR][eE][gG][eE][xX]         return REGEX;

         /* Identifiers */
{IDENT}          { yylval.string = strdup (yytext);
                   DBG ("IDENT", yytext);
		   return IDENT; }
         /* Quoted strings */
<INITIAL,LIT>\"[^\\"\n]*\"     { return simple_string (); }
<INITIAL,LIT>\"[^\\"\n]*\\[0-9] {BEGIN (STR);
                   string_begin ();
		   string_add (yytext+1, yyleng-1);
                  }
<INITIAL,LIT>\"[^\\"\n]*\\.    { BEGIN (STR);
                   string_begin ();
		   string_add (yytext+1, yyleng-3);
		   string_add_char (escape (yytext[yyleng-1])); }
<STR>[^\\"\n]*\\[0-9] { string_add (yytext, yyleng); }
<STR>[^\\"\n]*\\. { string_add (yytext, yyleng-2);
                    string_add_char (escape (yytext[yyleng-1])); }
<STR>[^\\"\n]*\" { BEGIN (INITIAL);
                   string_add (yytext, yyleng-1); 
                   string_finish ();
		   return STRING; }
         /* "Here document" (multiline strings) */
<INITIAL,LIT>"<<"-?{IDENT}[ \t]*\n |
<INITIAL,LIT>"<<"-?{IDENT}[ \t]*#.*\n { BEGIN (ML);
                                        multiline_begin ();
	                         	advance_line (); }
<ML>.*\n { char *p = multiline_strip_tabs (yytext);
           advance_line ();
	   
           if (strncmp (p, multiline_delimiter, strlen (multiline_delimiter))
	        == 0
	       && isemptystr (p + strlen (multiline_delimiter))) {
		   BEGIN (INITIAL);
		   multiline_finish ();
		   unput ('\n');
		   DBG ("<ML>STRING", yylval.string);
		   return STRING;
	     }
	    multiline_add (p);
         } 
         /* Literal */
<LIT>\\\n     { advance_line (); }
<LIT>[^ \t\n]+\\\n   { yylval.string = malloc (yyleng-1);
                       memcpy (yylval.string, yytext, yyleng-2);
		       yylval.string[yyleng-2] = 0;
		       DBG ("<LIT>STRING", yylval.string);
		       advance_line ();
		       return STRING; }
<LIT>[^ \t\n]+   { yylval.string = trimcpy ();
		   DBG ("<LIT>STRING", yylval.string);
		   return STRING; }
<LIT>{WS}        ;
<LIT>\n          { BEGIN (INITIAL); advance_line (); return EOL; }
         /* Other tokens */
{WS}           ;
\\\n           { advance_line (); }
\n             { advance_line (); return EOL; }
{PUNCT}        return yytext[0];
!=             return NE;
.              { parse_error (&rc_locus,
			      _("Stray character in config: \\%03o. Possibly missing quotes around the string"), yytext[0]); }

%%

int
yywrap ()
{
  if (yyin)
    {
      fclose (yyin);
      yyin = NULL;
    }
  return 1;
}

void
verbatim (void)
{
  BEGIN (LIT);
}

void
lex_clear_state (void)
{
  BEGIN (INITIAL);
}

int
simple_string (void)
{
  yylval.string = xmalloc (yyleng - 1);
  memcpy (yylval.string, yytext + 1, yyleng - 2);
  yylval.string[yyleng - 2] = 0;
  DBG ("STRING", yylval.string); 
  return STRING;
}

void
string_begin (void)
{
  str_head = str_tail = NULL;
}

void
string_add (char *str, int len)
{
  struct string_list *s = xmalloc (sizeof (*s) + len);
  s->next = NULL;
  s->str = (char*)(s+1);
  memcpy (s->str, str, len);
  s->length = len;
  if (str_tail)
    str_tail->next = s;
  else
    str_head = s;
  str_tail = s;
}

void
string_add_char (int n)
{
  char c = n;
  string_add (&c, 1);
}

void
string_finish (void)
{
  struct string_list *s;
  int len = 0;
  char *p;
	
  for (s = str_head; s; s = s->next) 
    len += s->length;
  len++;
  yylval.string = xmalloc (len);
  for (p = yylval.string, s = str_head; s; )
    {
      struct string_list *next = s->next;
      memcpy (p, s->str, s->length);
      p += s->length;
      xfree (s);
      s = next;
    }
  *p = 0;
}

void
multiline_begin (void)
{
  char *endp;
  int len;
  char *p = yytext + 2; /* past the << marker */

  if (*p == '-')
    {
      strip_tabs = 1;
      p++;
    }
  else
    strip_tabs = 0;

  /* Find the delimiter */
  for (endp = p; *endp; endp++)
    if (isspace (*(u_char*)endp))
      break;

  len = endp - p;
  multiline_delimiter = xmalloc (len + 1);
  memcpy (multiline_delimiter, p, len);
  multiline_delimiter[len] = 0;
  string_begin ();
}

void
multiline_finish (void)
{
  free (multiline_delimiter);
  multiline_delimiter = NULL;
  string_finish ();
}

int
isemptystr (char *text)
{
  for (; *text && isspace (*(u_char*)text); text++)
    ;
  return *text == 0;
}

char *
multiline_strip_tabs (char *text)
{
  if (strip_tabs)
    for (; *text == '\t'; text++)
      ;
  return text;
}

void
multiline_add (char *p)
{
  string_add (p, strlen (p));
}

int
escape (int c)
{
  switch (c) {
  case 'a':
    return '\a';
  case 'b':
    return '\b';
  case 'f':
    return '\f';
  case 'e':
    return '\033';
  case 'n':
    return '\n';
  case 'r':
    return '\r';
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
trimws (char *s)
{
  int len;

  for (len = strlen (s) - 1; len > 0 && isspace ((u_char)s[len]); len--)
    ;
  if (len > 0)
    s[len+1] = 0;
  return s;
}

char *
trimcpy (void)
{
  char *string;
  int i, j, len;

  for (i = 0; i < yyleng && isspace ((u_char)yytext[i]); i++)
    ;
  for (j = yyleng - 1; j > i && isspace ((u_char)yytext[i]); j--)
    ;
  len = j - i + 1;
  string = xmalloc (len + 1);
  memcpy (string, yytext + i, len);
  string[len] = 0;
  return string;
}

int
rc_open (char *name)
{
  yyin = fopen (name, "r");
  if (!yyin)
    {
      if (options.termlevel == DEBUG)
	anubis_error (0, errno, _("Anubis RC file error"));
      return -1;
    }
  
  rc_locus.file = name;
  rc_locus.line = 1;
  rc_locus.column = 1;
  return 0;
}

int
error_sync_begin ()
{
  int c;
  
  while (yyin && (c = yylex ()) > 0)
    {
      if (c == T_BEGIN)
	{
	  rc_locus.column -= yyleng;
	  yyless (0);
	  yylloc.beg = yylloc.end = rc_locus;
	  break;
	}
      else if (c == D_BEGIN)
	{
	  xfree (yylval.string);
	  rc_locus.column -= yyleng;
	  yyless (0);
	  yylloc.beg = yylloc.end = rc_locus;
	  break;
	}
    }
  return c;
}

