/*
   sql.h

   This file is part of GNU Anubis.
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

struct anubis_sql_db
{
  /* Access methods */
  int (*query) (struct anubis_sql_db * amp);
  size_t (*num_tuples) (struct anubis_sql_db * amp);
  size_t (*num_columns) (struct anubis_sql_db * amp);
  int (*release_result) (struct anubis_sql_db * amp);
  int (*get_tuple) (struct anubis_sql_db * amp, size_t i);
  const char *(*get_column) (struct anubis_sql_db * amp, size_t i);

  /* Interface-specific data */
  void *data;

  /* Query buffer */
  char *buf;
  size_t bufsize;

  /* Names of tables and columns */
  char *table;
  char *authid;
  char *passwd;
  char *user;
  char *rcfile;
};

#define ERR_MISS         0
#define ERR_BADBUFSIZE   1
#define ERR_BADPORT      2
#define ERR_CANTCONNECT  3

void sql_db_init (const char *proto, anubis_db_open_t open,
		  anubis_db_close_t close, anubis_db_strerror_t str_error);
char *sql_open_error_text (int s);
