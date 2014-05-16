/*
   Simple keyword translation.
   
   This file is part of GNU Anubis.
   Copyright (C) 2009-2014 The Anubis Team.

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
#include "keyword.h"

struct anubis_keyword *
anubis_keyword_lookup (struct anubis_keyword *tab, const char *name)
{
  for (; tab->name; tab++)
    if (strcmp (tab->name, name) == 0)
      return tab;
  return NULL;
}

struct anubis_keyword *
anubis_keyword_lookup_ci (struct anubis_keyword *tab, const char *name)
{
  for (; tab->name; tab++)
    if (strcasecmp (tab->name, name) == 0)
      return tab;
  return NULL;
}
  
