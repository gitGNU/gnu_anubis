/*
   proclist.c

   This file is part of GNU Anubis.
   Copyright (C) 2005-2014 The Anubis Team.

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

#include "headers.h"

/* This module runs a list (or a database) of running subprocesses for
   Anubis. It is necessary in order to provide normal reporting about
   processes being launched/finished without calling unsafe functions
   from the SIGCHLD handler.

   The module provides three interface calls:

   proclist_init(void) initializes internal structure. This is called
   at the beginning of master and child processes.
   
   proclist_register(pid) registers the given pid in the database. It is
   called after fork().

   proclist_cleanup(function) cleans up exited processes from the
   database, calling `function' for each of them. This is called somewhere
   in the main process loop. */

struct process_status
{
  pid_t pid;              /* Process ID */
  int running;            /* 1 if the process is running */
  int status;             /* When running == 0, status returned by waitpid */
};

static ANUBIS_LIST process_list; /* A list of processes. Separate for each
				     Anubis instance. */

/* list_iterator_t update_process_status. Used to update status of the
   process description in the database */
static int
update_process_status (void *item, void *data)
{
  struct process_status *ps = item;
  struct process_status *sample = data;

  if (sample->pid == ps->pid)
    {
      ps->running = 0;
      ps->status = sample->status;
      return 1;
    }
  return 0;
}

/* list_comp_t finished_process. Returns 0 (equal) for the first entry
   describing an exited process. */
static int
finished_process (void *item, void *data)
{
  struct process_status *ps = item;
  return ps->running;
}

/* Cleans up exited processes from the database, calling `fun' for each of
   them. `fun' takes three arguments:

   size_t count  - number of entries in the database *before* removing the
                   current one;
   pid_t  pid    - pid of the process
   int    status - exit status of the process.

   proclist_cleanup returns number of the entries left in the database after
   processing. */
size_t
proclist_cleanup (void (*fun) (size_t, pid_t, int))
{
  sigset_t blockset;
  struct process_status *ps;
  size_t count = list_count (process_list);
  
  sigemptyset (&blockset);
  sigaddset (&blockset, SIGCHLD);
  sigprocmask (SIG_BLOCK, &blockset, NULL);		
  while ((ps = list_remove (process_list, NULL, finished_process)))
    {
      if (fun)
	fun (count, ps->pid, ps->status);
      xfree (ps);
      count--;
    }
  sigprocmask (SIG_UNBLOCK, &blockset, NULL);		
  return count;
}

/* SIGCHLD handler. */
static RETSIGTYPE
sig_child (int code)
{
  struct process_status ps;
  while ((ps.pid = waitpid (-1, &ps.status, WNOHANG)) > 0)
    list_iterate (process_list, update_process_status, &ps);
  signal (code, sig_child);
}

/* Register `pid' in the database. */
void
proclist_register (pid_t pid)
{
  struct process_status *ps;
  if (!process_list)
    process_list = list_create ();
  ps = xmalloc (sizeof *ps);
  ps->pid = pid;
  ps->running = 1;
  list_append (process_list, ps);
}

/* Initialize the process database */
void
proclist_init ()
{
  process_list = list_create ();
  signal (SIGCHLD, sig_child);
}

/* Return the number of entries resident in the database. */
size_t
proclist_count ()
{
  return list_count (process_list);
}

