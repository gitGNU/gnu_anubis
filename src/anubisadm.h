/*
   This file is part of GNU Anubis 
   Copyright (C) 2004-2014 The Anubis Team.

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
#include "getopt.h"

typedef int (*operation_fp) (int, char **);

char *authid;
char *username;
char *rcfile;
char *password;

int op_create (int argc, char **argv);
int op_list (int argc, char **argv);
int op_add (int argc, char **argv);
int op_modify (int argc, char **argv);
int op_remove (int argc, char **argv);

void adm_get_options (int argc, char *argv[],
		      operation_fp *operation, int *index);
