/*
   exec.c

   This file is part of GNU Anubis.
   Copyright (C) 2001-2014 The Anubis Team.

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
#include "extern.h"

static int make_sockets (int fd[]);

/*************************
 Connect to stdin/stdout.
**************************/

static int
make_sockets (int fd[2])
{
#ifndef HAVE_SOCKETPAIR
  struct sockaddr_in addr;
  int addrlen;
  int sd;

  if ((sd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      anubis_error (0, errno, _("#1 socket() failed."));
      return -1;
    }
  if ((fd[1] = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      anubis_error (0, errno, _("#2 socket() failed."));
      return -1;
    }
  addrlen = sizeof (addr);
  memset (&addr, 0, addrlen);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind (sd, (struct sockaddr *) &addr, addrlen))
    {
      anubis_error (0, errno, _("#1 bind() failed"));
      return -1;
    }
  if (bind (fd[1], (struct sockaddr *) &addr, addrlen))
    {
      anubis_error (0, errno, _("#2 bind() failed"));
      return -1;
    }
  if (listen (sd, 5))
    {
      anubis_error (0, errno, _("listen() failed"));
      return -1;
    }
  if (getsockname (sd, (struct sockaddr *) &addr, &addrlen))
    {
      anubis_error (0, errno, _("getsockname() failed: %s."));
      return -1;
    }
  if (connect (fd[1], (struct sockaddr *) &addr, addrlen))
    {
      anubis_error (0, errno, _("connect() failed"));
      return -1;
    }
  if ((fd[0] = accept (sd, (struct sockaddr *) &addr, &addrlen)) < 0)
    {
      anubis_error (0, errno, _("accept() failed"));
      return -1;
    }
  close_socket (sd);
#else
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, fd))
    {
      anubis_error (0, errno, _("socketpair() failed"));
      return -1;
    }
#endif /* not HAVE_SOCKETPAIR */
  return 0;
}

static int
make_local_connection_fd (char *exec_path, char **exec_args)
{
  int fd[2];
  pid_t pid;
  
  if (check_filename (exec_path, 0) == 0)
    return -1;

  if (VERBOSE > options.termlevel) /* Extra check to avoid unnecessary
				      memory allocation */
    {
        char *args;
	argcv_string (-1, exec_args, &args);
	info (VERBOSE, _("Executing %s..."), args);
	free (args);
    }
  
  if (make_sockets (fd))
    return -1;

  switch (pid = fork ())
    {
    case -1:			/* an error */
      anubis_error (0, errno, _("fork() failed"));
      close (fd[0]);
      close (fd[1]);
      return -1;

    case 0:			/* a child process */
      close (fd[0]);
      if (fd[1] != 0)
	dup2 (fd[1], 0);
      if (fd[1] != 1)
	dup2 (fd[1], 1);
      if (fd[1] > 1)
	close (fd[1]);
      execvp (exec_path, exec_args);
      anubis_error (EXIT_FAILURE, errno, _("execvp() failed"));

    default:
      /* Master: register created process */
      proclist_register (pid);
    }
  close (fd[1]);
#ifdef FD_CLOEXEC
  fcntl (fd[0], F_SETFD, FD_CLOEXEC);
#endif /* FD_CLOEXEC */
  return fd[0];
}

NET_STREAM
make_local_connection (char *exec_path, char **exec_args)
{
  int fd;
  NET_STREAM str;

  fd = make_local_connection_fd (exec_path, exec_args);
  if (fd == -1)
    return NULL;
  net_create_stream (&str, fd);
  return str;
}
  
/*************************************
 Use an external program, which works
 on standard input and output.
**************************************/

char *
external_program (int *rs, char *path, char *src, char *dst, int dstsize)
{
  int rc;
  char *ret;
  int argc;
  char **argv = 0;

  if ((rc = argcv_get (path, "", "#", &argc, &argv)))
    anubis_error (EX_SOFTWARE, rc, _("argcv_get failed"));
  
  ret = exec_argv (rs, argv[0], argv, src, dst, dstsize);
  argcv_free (argc, argv);
  return ret;
}

char *
exec_argv (int *rs, char *path, char **argv, char *src, char *dst,
	   int dstsize)
{
  int status;
  int fd;
  int n;
  char *buf;
  size_t dstpos;
  
  fd = make_local_connection_fd (path ? path : argv[0], argv);
  if (fd == -1)
    {
      *rs = -1;
      return 0;
    }

  if (write (fd, src, strlen (src)) == -1)
    {
      *rs = -1;
      return 0;
    }
  if (shutdown (fd, 1) == -1)
    {
      *rs = -1;
      return 0;
    }

  buf = (char *) xmalloc (DATABUFFER + 1);
  memset (dst, 0, dstsize);
  dstpos = 0;

  if (dst && dstsize)
    {				/* static array */
      dstsize--; /* leave place for the terminating nul */
      while (dstpos < dstsize && (n = read (fd, buf, DATABUFFER)) > 0)
	{
	  size_t len = dstsize - dstpos;
	  if (len > n)
	    len = n;
	  memcpy (dst + dstpos, buf, len);
	  dstpos += len;
	}
      dst[dstpos] = 0;   
    }
  else
    {				/* dynamic array */
      dstsize = DATABUFFER;
      dst = xmalloc (dstsize);
      while ((n = read (fd, buf, DATABUFFER)) > 0)
	{
	  if (dstsize - dstpos < n)
	    {
	       dstsize += DATABUFFER;
	       dst = xrealloc (dst, dstsize);
	    } 
	  memcpy (dst + dstpos, buf, n);  
	}
      if (dstsize - dstpos < n)
        {
          dstsize++;
          dst = xrealloc (dst, dstsize);
        }
      dst[dstpos] = 0;
    }
  free (buf);
  close (fd);
  waitpid (-1, &status, WNOHANG);
  *rs = 0;
  return dst;
}

/* EOF */
