dnl This file is part of GNU Anubis.
dnl Copyright (C) 2007-2014 The Anubis Team.
dnl 
dnl GNU Anubis is free software; you can redistribute it and/or modify it
dnl under the terms of the GNU General Public License as published by the
dnl Free Software Foundation; either version 3 of the License, or (at your
dnl option) any later version.
dnl 
dnl GNU Anubis is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License along
dnl with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.
dnl
divert(-1)
changequote([<,>])
changecom(/*,*/)

dnl upcase(ARGS...)
dnl Concatenate and convert ARGS to upper case.
dnl
define([<upcase>], [<translit([<$*>], [<a-z>], [<A-Z>])>])

dnl concat(ARGS...)
dnl Concatenate arguments, inserting ", " between each of pair of them.
dnl
define([<concat>],[<ifelse([<$#>],1,[<$1>],[<$1, concat(shift($@))>])>])

dnl flushleft(ARGS...)
dnl Concatenate ARGS and remove any leading whitespace
dnl
define([<flushleft>],
 [<patsubst([<concat($*)>], [<^[ 	]+>])>])

dnl chop(ARGS...)
dnl Concatenate ARGS and remove any trailing whitespace
dnl
define([<chop>],
 [<patsubst([<$*>], [<[ 	]+$>])>])

dnl escape(ARGS...)
dnl Concatenate ARGS and escape any occurrences of double-quotes with
dnl backslashes.
dnl
define([<escape>],
[<patsubst([<concat($*)>],[<[\"]>],[<\\\&>])>])

dnl prep(ARG)
dnl Prepare ARG for including in C strings: replace newlines with any amount
dnl of preceding and following whitespace by a single space character, remove
dnl leading whitespace, and escape double-quotes.
dnl
define([<prep>],
[<escape(flushleft(patsubst([<$1>],[<[ 	]*
+[ 	]*>],[< >])))>])

define([<newline>],
[<patsubst([<concat($*)>],[<\\n>],[<\n>])>])

define([<mprep>],[<newline(prep($1))>])

dnl SHORT_OPTS
dnl Accumulator for the 3rd argument of getopt_long
dnl
define([<SHORT_OPTS>],[<>])

dnl GROUP(STRING)
dnl Begin a named group of options
dnl
define([<GROUP>],[<dnl
divert(3)
	{ NULL, NULL, 0, N_("prep([<$1>])") },
divert(-1)>]) 

define([<__GATHER_OPTIONS>],[<
define([<KEY>],ifelse([<$2>],,[<OPTION_>]upcase(patsubst($1,-,_)),'$2'))
ifelse([<$2>],,[<
divert(1)
	KEY,
divert(-1)
>])
define([<SELECTOR>],ifdef([<SELECTOR>],SELECTOR) case KEY:)
ifelse([<$1>],,,[<
divert(2)
	{ "$1", ARGTYPE, 0, KEY },
divert(-1)>])
dnl
define([<SHORT_OPTS>],SHORT_OPTS[<>]dnl
ifelse([<$2>],,,$2[<>]ifelse(ARGTYPE,[<no_argument>],,ARGTYPE,[<required_argument>],:,ARGTYPE,[<optional_argument>],::)))
dnl
ifelse([<$1>],,,dnl
[<define([<LONG_TAG>],ifelse(LONG_TAG,,[<--$1>],[<LONG_TAG; --$1>]))>])
ifelse([<$2>],,,dnl
[<define([<SHORT_TAG>],ifelse(SHORT_TAG,,[<-$2>],[<SHORT_TAG; -$2>]))>])
>])

dnl OPTION(long-opt, short-opt, [arg], [descr])
dnl Introduce a command line option. Arguments:
dnl   long-opt     Long option.  
dnl   short-opt    Short option (a single char)
dnl   (At least one of long-opt or short-opt must be present)
dnl
dnl   Optional arguments:
dnl   arg          Option argument. 
dnl   descr        Option description
dnl
dnl If arg is absent, the option does not take any arguments. If arg is
dnl enclosed in square brackets, the option takes an optional argument.
dnl Otherwise, the argument is required.
dnl
dnl If descr is not given the option will not appear in the --help and
dnl --usage outputs.
dnl
define([<OPTION>],[<
pushdef([<LONG_TAG>])
pushdef([<SHORT_TAG>])
pushdef([<ARGNAME>],[<$3>])
pushdef([<DOCSTRING>],[<prep([<$4>])>])
pushdef([<ARGTYPE>],[<ifelse([<$3>],,[<no_argument>],dnl
patsubst([<$3>],[<\[.*\]>]),,[<optional_argument>],dnl
[<required_argument>])>])
__GATHER_OPTIONS($@)
>])

dnl ALIAS(long-opt, short-opt)
dnl Declare aliases for the previous OPTION statement.
dnl   long-opt     Long option.
dnl   short-opt    Short option (a single char)
dnl   (At least one of long-opt or short-opt must be present)
dnl An OPTION statement may be followed by any number of ALIAS statements.
dnl 
define([<ALIAS>],[<
__GATHER_OPTIONS($1,$2)
>])

dnl BEGIN
dnl Start an action associated with the declared option. Must follow OPTION
dnl statement, with optional ALIAS statements in between.
dnl
define([<BEGIN>],[<
ifelse([<DOCSTRING>],,,[<
divert(3)
	{ "translit(dnl
ifelse(SHORT_TAG,,LONG_TAG,[<SHORT_TAG[<>]ifelse(LONG_TAG,,,; LONG_TAG)>]),
                    [<;>],[<,>])", ifelse(ARGNAME,,[<NULL, 0>],
[<ifelse(ARGTYPE,[<optional_argument>],
[<patsubst([<ARGNAME>],[<\[\(.*\)\]>],[<N_("\1"), 1>])>],[<N_("ARGNAME"), 0>])>]), N_("DOCSTRING") },
divert(-1)>])
popdef([<ARGTYPE>])
popdef([<ARGNAME>])
popdef([<DOCSTRING>])
divert(4)dnl
popdef([<LONG_TAG>])dnl
popdef([<SHORT_TAG>])dnl
	SELECTOR
          {
>])

dnl END
dnl Finish the associated action
dnl
define([<END>],[<
             break;
          }
divert(-1)
undefine([<SELECTOR>])>])

dnl GETOPT(argc, argv, [optindex])
dnl Emit option parsing code. Arguments:
dnl
dnl  argc        Name of the 1st argument to getopt_long.
dnl  argv        Name of the 2nd argument to getopt_long.
dnl  optindex    Variable to assign optind to.
dnl
define([<GETOPT>],[<
 {
  int c;

  while ((c = getopt_long($1, $2, "SHORT_OPTS",
                          long_options, NULL)) != EOF)
    {
      switch (c)
        {
        default:
	   exit(1);
	undivert(4)
        }
    }
  ifelse([<$#>],3,[<$3 = optind;>])
 }   
>])

define([<STDFUNC>],[<
divert(0)
void print_help(void);
void print_usage(void);
divert(5)
const char *program_version = [<$1>];
static char doc[] = N_("[<$3>]");
static char args_doc[] = N_("[<$4>]");
static char *after_desc ifelse([<$5>],,[<= NULL>],[<= N_("mprep($5)")>]);
const char *program_bug_address = "<" PACKAGE_BUGREPORT ">";
		    
#define DESCRCOLUMN 30
#define RMARGIN 79
#define GROUPCOLUMN 2
#define USAGECOLUMN 13
		    
static void
indent (size_t start, size_t col)
{
  for (; start < col; start++)
    putchar (' ');
}
		    
static void
print_option_descr (const char *descr, size_t lmargin, size_t rmargin)
{
  while (*descr)
    {
      size_t s = 0;
      size_t i;
      size_t width = rmargin - lmargin;
      
      while (*descr && (*descr == ' ' || *descr == '\t'))
	descr++;
      for (i = 0; ; i++)
	{
	  if (descr[i] == '\n')
	    {
	      s = i;
	      break;
	    }
	  if (descr[i] == 0 || (descr[i] == ' ' || descr[i] == '\t'))
	    {
	      if (i > width)
		break;
	      s = i;
	      if (descr[i] == 0)
		break;
	    }
	}
      if (s > width)
	while (!(descr[s] == ' ' || descr[s] == '\t'))
	  s--;
      printf ("%*.*s\n", s, s, descr);
      descr += s;
      if (*descr)
	{
	  indent (0, lmargin);
	  descr++;
	}
    }
}

void
print_help(void)
{
  unsigned i;
  
  printf ("%s %s [%s]... %s\n", _("Usage:"), [<$2>], _("[<OPTION>]"),
	  gettext (args_doc)); 
  if (doc[0])
    print_option_descr(gettext (doc), 0, RMARGIN);
  putchar ('\n');

  for (i = 0; i < sizeof (opthelp) / sizeof (opthelp[0]); i++)
    {
      unsigned n;
      if (opthelp[i].opt)
	{
	  n = printf ("  %s", opthelp[i].opt);
	  if (opthelp[i].arg)
	    {
	      char *cb, *ce;
	      if (strlen (opthelp[i].opt) == 2)
		{
		  if (!opthelp[i].is_optional)
		    {
		      putchar (' ');
		      n++;
		    }
		}
	      else
		{
		  putchar ('=');
		  n++;
		}
	      if (opthelp[i].is_optional)
		{
		  cb = "[";
		  ce = "]";
		}
	      else
		cb = ce = "";
	      n += printf ("%s%s%s", cb, gettext (opthelp[i].arg), ce);
	    }
	  if (n >= DESCRCOLUMN)
	    {
	      putchar ('\n');
	      n = 0;
	    }
	  indent (n, DESCRCOLUMN);
	  print_option_descr (gettext (opthelp[i].descr), DESCRCOLUMN, RMARGIN);
	}
      else
	{
	  if (i)
	    putchar ('\n');
	  indent (0, GROUPCOLUMN);
	  print_option_descr (gettext (opthelp[i].descr),
			      GROUPCOLUMN, RMARGIN);
	  putchar ('\n');
	}
    }
  
  putchar ('\n');
dnl **************************************************************************
dnl This string cannot be split over serveal lines, because this would trigger
dnl a bug in GNU M4 (version 1.4.9 and 1.4.10), which would insert #line
dnl directives between the lines.
dnl **************************************************************************
  print_option_descr (_("Mandatory or optional arguments to long options are also mandatory or optional for any corresponding short options."), 0, RMARGIN);
  putchar ('\n');

  if (after_desc)
    {
      print_option_descr (gettext (after_desc), 0, RMARGIN);
    }	
  printf (_("Report bugs to %s.\n"), program_bug_address);
}

void
print_usage(void)
{
  unsigned i;
  int f = 0;
  unsigned n;
  char buf[RMARGIN+1];

#define FLUSH                      dnl
  do                               dnl         
    {                              dnl         
	  buf[n] = 0;              dnl        
	  printf ("%s\n", buf);    dnl        
	  n = USAGECOLUMN;         dnl        
	  memset (buf, ' ', n);    dnl        
    }                              dnl                                
  while (0)
#define ADDC(c) dnl
  do { if (n == RMARGIN) FLUSH; buf[n++] = c; } while (0)

  n = snprintf (buf, sizeof buf, "%s %s ", _("Usage:"), [<$2>]);

  /* Print a list of short options without arguments. */
  for (i = 0; i < sizeof (opthelp) / sizeof (opthelp[0]); i++)
    {
      if (opthelp[i].opt && opthelp[i].descr && opthelp[i].opt[1] != '-'
	  && opthelp[i].arg == NULL)
	{
	  if (f == 0)
	    {
	      ADDC('[');
	      ADDC('-');
	      f = 1;
	    }
	  ADDC(opthelp[i].opt[1]);
	}
    }
  if (f)
    ADDC(']');

  /* Print a list of short options with arguments. */
  for (i = 0; i < sizeof (opthelp) / sizeof (opthelp[0]); i++)
    {
      if (opthelp[i].opt && opthelp[i].descr && opthelp[i].opt[1] != '-'
	  && opthelp[i].arg)
	{
	  size_t len = 5 
	                + strlen (opthelp[i].arg)
			   + (opthelp[i].is_optional ? 2 : 1);
	  if (n + len > RMARGIN) FLUSH;
	  buf[n++] = ' '; 
	  buf[n++] = '['; 
	  buf[n++] = '-';
	  buf[n++] = opthelp[i].opt[1];
	  if (opthelp[i].is_optional)
	    {
	      buf[n++] = '[';
	      strcpy (&buf[n], opthelp[i].arg);
	      n += strlen (opthelp[i].arg);
	      buf[n++] = ']';
	    }
	  else
	    {
	      buf[n++] = ' ';
	      strcpy (&buf[n], opthelp[i].arg);
	      n += strlen (opthelp[i].arg);
	    }
	  buf[n++] = ']';
	}
    }

  /* Print a list of long options */
  for (i = 0; i < sizeof (opthelp) / sizeof (opthelp[0]); i++)
    {
      if (opthelp[i].opt && opthelp[i].descr)
	{
	  size_t len;
	  const char *longopt;

	  if (opthelp[i].opt[1] == '-')
	    longopt = opthelp[i].opt;
	  else if (opthelp[i].opt[2] == ',')
	    longopt = opthelp[i].opt + 4;
	  else
	    continue;

	  len = 3 + strlen (longopt)
	          + (opthelp[i].arg ? 1 + strlen (opthelp[i].arg)
		      + (opthelp[i].is_optional ? 2 : 0) : 0);
	  if (n + len > RMARGIN) FLUSH;
	  buf[n++] = ' '; 
	  buf[n++] = '['; 
	  strcpy (&buf[n], longopt);
	  n += strlen (longopt);
	  if (opthelp[i].arg)
	    {
	      buf[n++] = '=';
	      if (opthelp[i].is_optional)
		{
		  buf[n++] = '[';
		  strcpy (&buf[n], opthelp[i].arg);
		  n += strlen (opthelp[i].arg);
		  buf[n++] = ']';
		}
	      else
		{
		  strcpy (&buf[n], opthelp[i].arg);
		  n += strlen (opthelp[i].arg);
		}
	    }
	  buf[n++] = ']';
	}
    }
  FLUSH;
  
}

const char version_etc_copyright[] =
  /* Do *not* mark this string for translation.  %s is a copyright
     symbol suitable for this locale. */
  "Copyright %s 2001-2014 The Anubis Team.";

void
print_version_only(const char *program_version, FILE *stream)
{
  fprintf (stream, "%s\n", program_version);
  /* TRANSLATORS: Translate "(C)" to the copyright symbol
     (C-in-a-circle), if this symbol is available in the user's
     locale.  Otherwise, do not translate "(C)"; leave it as-is.  */
  fprintf (stream, version_etc_copyright, _("(C)"));
  fputc ('\n', stream);
}

void
print_version(const char *program_version, FILE *stream)
{
  print_version_only(program_version, stream);
	
dnl **************************************************************************
dnl This string cannot be split over serveal lines, because this would trigger
dnl a bug in GNU M4 (version 1.4.9 and 1.4.10), which would insert #line
dnl directives between the lines.
dnl **************************************************************************
  fputs (_("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\nThis is free software: you are free to change and redistribute it.\nThere is NO WARRANTY, to the extent permitted by law.\n\n"),
	 stream);
}

divert(-1)
popdef([<ADDC>])
popdef([<FLUSH>])
>])

define([<OPTIONS_BEGIN>],
   [<divert(-1)
     define([<GETOPT_STYLE>],[<$1>]) 
     ifelse([<$1>],[<gnu>],
	    [<STDFUNC([<$2 " (" PACKAGE_STRING ")">], [<$2>], [<$3>], [<$4>], [<$5>])>])
>])
  
define([<OPTIONS_END>],[<
ifelse(GETOPT_STYLE,[<gnu>],[<
         GROUP([<Other options>])
         OPTION([<help>],h,,[<Give this help list>])
         BEGIN
		print_help ();
                exit (0);
	 END
         OPTION([<usage>],,,[<Give a short usage message>])
	 BEGIN
		print_usage ();
		exit (0);
	 END
	 OPTION([<version>],,,[<Print program version>])
	 BEGIN
		/* Give version */
		print_version(program_version, stdout);
		exit (0);
         END>])
divert
/* Option codes */
enum {
	_OPTION_INIT=255,
	undivert(1)
	MAX_OPTION
};
static struct option long_options[] = {
	undivert(2)
	{0, 0, 0, 0}
};
static struct opthelp {
        const char *opt;
        const char *arg;
        int is_optional;
        const char *descr;
} opthelp[] = {
	undivert(3)
};
undivert(5)
>])

divert(0)dnl
/* -*- buffer-read-only: t -*- vi: set ro:
   THIS FILE IS GENERATED AUTOMATICALLY.  PLEASE DO NOT EDIT.
*/

