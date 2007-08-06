/*
   This file is part of GNU Anubis 
   Copyright (C) 2004, 2007 The Anubis Team.

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

#include "headers.h"
#include "extern.h"
#include <getopt.h>
#include <getline.h>

#define OPT_VERSION          257
#define OPT_HELP             258

static struct option option[] = {
  {"create", no_argument, 0, 'c'},
  {"list", no_argument, 0, 'l'},
  {"add", no_argument, 0, 'a'},
  {"remove", no_argument, 0, 'r'},
  {"modify", no_argument, 0, 'm'},
  {"authid", required_argument, 0, 'i'},
  {"user", required_argument, 0, 'u'},
  {"rcfile", required_argument, 0, 'f'},
  {"password", optional_argument, 0, 'p'},

  {"version", no_argument, 0, OPT_VERSION},
  {"help", no_argument, 0, OPT_HELP},
  {NULL, 0, 0, 0}
};

typedef int (*operation_fp) (int, char **);

char *progname;
char *authid;
char *username;
char *rcfile;
char *password;

void
error (const char *fmt, ...)
{
  va_list ap;
  fprintf (stderr, "%s: ", progname);
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fprintf (stderr, "\n");
}

static void
adm_memory_error (const char *msg)
{
  error ("%s", msg);
  exit (1);
}

int
op_usage (int argc, char **argv)
{
  error (_("operation not specified"));
  return 1;
}

int
opendb (void **dptr, int argc, char **argv, enum anubis_db_mode mode)
{
  int rc;
  char *err;

  if (argc == 0)
    {
      error (_("database URL is not specified"));
      return 1;
    }
  if (argc > 1)
    {
      error (_("too many arguments"));
      return 1;
    }

  rc = anubis_db_open (argv[0], mode, dptr, &err);

  if (rc != ANUBIS_DB_SUCCESS)
    error ("%s", err);
  return rc;
}

static const char delim[] = " \t\r\n";

int
op_create (int argc, char **argv)
{
  ANUBIS_USER rec;
  char *buf = NULL;
  size_t n = 0;
  size_t line = 0;
  void *db;
  int rc;

  if (opendb (&db, argc, argv, anubis_db_rdwr))
    return 1;

  memset (&rec, 0, sizeof (rec));
  while (getline (&buf, &n, stdin) > 0 && n > 0)
    {
      char *p;
      int len = strlen (buf);
      if (len > 0 && buf[len - 1] == '\n')
	buf[len - 1] = 0;
      line++;

      for (p = buf; *p && isspace (*p); p++)
	;

      if (*p == '#')
	continue;		/* Skip comments */
      p = strtok (p, delim);
      if (!p)
	continue;		/* Skip empty lines */
      rec.smtp_authid = strdup (p);

      p = strtok (NULL, delim);
      if (!p)
	{
	  error (_("%lu: incomplete line"), (unsigned long) line);
	  free (rec.smtp_authid);
	  continue;
	}
      rec.smtp_passwd = strdup (p);

      p = strtok (NULL, delim);
      if (p)
	{
	  rec.username = strcmp(p, "NONE") ? strdup (p) : NULL;
	  p = strtok (NULL, delim);
	  if (p)
	    rec.rcfile_name = strcmp(p, "NONE") ? strdup (p) : NULL;
	}

      rc = anubis_db_put_record (db, rec.smtp_authid, &rec);
      anubis_db_free_record (&rec);
      if (rc)
	{
	  error (_("%lu: cannot write to the database: %s"),
		 (unsigned long) line, anubis_db_strerror (db));
	  break;
	}
    }
  free (buf);
  anubis_db_close (&db);
  return rc;
}

void
print_record (ANUBIS_USER * rec)
{
  printf ("%s\t%s\t%s\t%s\n", rec->smtp_authid, rec->smtp_passwd,
	  rec->username ? rec->username : "NONE",
	  rec->rcfile_name ? rec->rcfile_name : "NONE");
}

void
print_list_header (void)
{
  printf ("# %s\n", _("AuthID\tPassword\tUserName\tRCfile"));
}

int
record_printer (void *item, void *data)
{
  print_record (item);
  return 0;
}

int
record_free (void *item, void *data)
{
  anubis_db_free_record (item);
  free (item);
  return 0;
}

int
op_list (int argc, char **argv)
{
  ANUBIS_USER rec;
  void *db;
  int rc;

  if (opendb (&db, argc, argv, anubis_db_rdonly))
    return 1;

  if (authid)
    {
      rc = anubis_db_get_record (db, authid, &rec);
      switch (rc)
	{
	case ANUBIS_DB_SUCCESS:
	  print_list_header ();
	  print_record (&rec);
	  anubis_db_free_record (&rec);
	  rc = 0;
	  break;

	case ANUBIS_DB_NOT_FOUND:
	  error (_("%s: authid not found"), authid);
	  rc = 0;
	  break;

	case ANUBIS_DB_FAIL:
	  error (_("database error: %s"), anubis_db_strerror (db));
	  rc = 1;
	  break;
	}
    }
  else
    {
      ANUBIS_LIST *reclist;
      rc = anubis_db_get_list (db, &reclist);
      switch (rc)
	{
	case ANUBIS_DB_SUCCESS:
	  rc = 0;
	  print_list_header ();
	  list_iterate (reclist, record_printer, NULL);
	  list_destroy (&reclist, record_free, NULL);
	  break;

	case ANUBIS_DB_NOT_FOUND:
	  rc = 0;
	  printf ("# %s\n", _("Database is empty"));
	  break;

	default:
	  error (_("database error: %s"), anubis_db_strerror (db));
	  rc = 1;
	}
    }
  anubis_db_close (&db);
  return rc;
}

int
op_add_or_modify (char *database, int code, char *errmsg)
{
  ANUBIS_USER rec;
  void *db;
  char *err;
  int rc;

  if (!authid)
    {
      error (_("authid not specified"));
      return 1;
    }
  if (!password)
    password = getpass (_("Password:"));
  if (!password)
    {
      error (_("password not specified"));
      return 1;
    }

  rc = anubis_db_open (database, anubis_db_rdwr, &db, &err);

  if (rc != ANUBIS_DB_SUCCESS)
    {
      error ("%s", err);
      return 1;
    }

  rc = anubis_db_get_record (db, authid, &rec);
  if (rc == ANUBIS_DB_FAIL)
    {
      error (_("database error: %s"), anubis_db_strerror (db));
      anubis_db_close (&db);
      return 1;
    }

  if (rc != code)
    {
      error ("%s", errmsg);
      anubis_db_close (&db);
      return 1;
    }

  rec.smtp_authid = authid;
  rec.smtp_passwd = password;
  rec.username = username;
  rec.rcfile_name = rcfile;

  rc = anubis_db_put_record (db, authid, &rec);
  if (rc != ANUBIS_DB_SUCCESS)
    {
      error (_("database error: %s"), anubis_db_strerror (db));
      return 1;
    }
  anubis_db_close (&db);
  return 0;
}

int
op_add (int argc, char **argv)
{
  return op_add_or_modify (argv[0], ANUBIS_DB_NOT_FOUND,
			   _
			   ("Record already exists. Use --modify to change it."));
}

int
op_remove (int argc, char **argv)
{
  void *db;
  int rc;

  if (!authid)
    {
      error (_("authid not specified"));
      return 1;
    }

  if (opendb (&db, argc, argv, anubis_db_rdwr))
    return 1;

  switch (anubis_db_delete_record (db, authid))
    {
    case ANUBIS_DB_NOT_FOUND:
      error (_("record not found"));
      rc = 1;
      break;

    case ANUBIS_DB_FAIL:
      error (_("database error: %s"), anubis_db_strerror (db));
      rc = 1;

    case ANUBIS_DB_SUCCESS:
      rc = 0;
    }
  anubis_db_close (&db);
  return rc;
}

int
op_modify (int argc, char **argv)
{
  return op_add_or_modify (argv[0], ANUBIS_DB_SUCCESS,
			   _("Record not found. Use --add to create it."));
}

void
print_help (void)
{
  puts (_("anubisadm -- Interface for GNU Anubis database administration."));
  puts (_("Usage: anubisadm [COMMAND] [OPTIONS] URL"));

  puts (_("\nCOMMAND is one of\n"));
  puts (_("  -c, --create            Creates the database."));
  puts (_
	("  -l, --list              List the contents of an existing database."));
  puts (_("  -a, --add               Add a new record."));
  puts (_("  -m, --modify            Modify existing record."));
  puts (_("  -r, --remove            Remove existing record."));
  puts (_
	("  --version               Display program version number and exit."));
  puts (_("  --help                  Display this help screen and exit."));

  puts (_("\nOPTION is one or more of\n"));
  puts (_
	("  -i, --authid=STRING     Specify the authid to operate upon. This option\n"
	 "                          is mandatory with --add, --modify and --remove.\n"
	 "                          It is optional when used with --list."));
  puts (_
	("  -p, --password=STRING   Specify the password for the authid. Mandatory\n"
	 "                          with --add, --modify and --remove."));
  puts (_
	("  -u, --user=STRING       Specify the system user name corresponding to\n"
	 "                          the given authid. Optional for --add, --modify\n"
	 "                          and --remove."));
  puts (_
	("  -f, --rcfile=STRING     Specify the rc file to be used for this authid.\n"
	 "                          Optional for --add, --modify and --remove."));

  puts (_("\nEXAMPLES\n"));
  puts (_("1. Create the GDBM database from a plaintext file:\n\n"
	  "example$ anubisadm --create gdbm:/etc/anubis.db < plaintext\n"));

  puts (_("2. Add SMTP authid \"test\" with password \"guessme\" and map it\n"
	  "to the system account \"gray\":\n\n"
	  "example$ anubisadm --add --authid test --password guessme \\\n"
	  "                   --user gray gdbm:/etc/anubis.db\n"));

  puts (_("3. List the entire database contents:\n\n"
	  "example$ anubisadm --list gdbm:/etc/anubis.db\n"));

  puts (_("4. List only the record with authid \"test\":\n\n"
	  "example$ anubisadm --list --authid test gdbm:/etc/anubis.db\n"));

  printf (_("\nReport bugs to <%s>.\n"), PACKAGE_BUGREPORT);
}

int
main (int argc, char **argv)
{
  int c;
  operation_fp operation = op_usage;

  /* save the program name */
  progname = strrchr (argv[0], '/');
  if (progname)
    progname++;
  else
    progname = argv[0];

  /* Register memory error printer */
  memory_error = adm_memory_error;

  /* Initialize various database formats */

  dbtext_init ();
# ifdef HAVE_LIBGDBM
  gdbm_db_init ();
# endif
# ifdef WITH_MYSQL
  mysql_db_init ();
# endif
# ifdef WITH_PGSQL
  pgsql_db_init ();
# endif

  while ((c = getopt_long (argc, argv, "clarmi:u:f:p:?",
			   option, NULL)) != EOF)
    {
      switch (c)
	{
	case OPT_VERSION:
	  printf ("%s\n", PACKAGE_STRING);
	  exit (0);
	  break;

	case OPT_HELP:
	  print_help ();
	  exit (0);
	  break;

	case 'c':
	  operation = op_create;
	  break;

	case 'l':
	  operation = op_list;
	  break;

	case 'a':
	  operation = op_add;
	  break;

	case 'r':
	  operation = op_remove;
	  break;

	case 'm':
	  operation = op_modify;
	  break;

	case 'i':
	  authid = optarg;
	  break;

	case 'u':
	  username = optarg;
	  break;

	case 'f':
	  rcfile = optarg;
	  break;

	case 'p':
	  password = optarg;
	  break;

	default:
	  return 1;
	}
    }

  return operation (argc - optind, argv + optind);
}

/* EOF */
