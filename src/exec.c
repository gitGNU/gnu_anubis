/*
   exec.c

   This file is part of GNU Anubis.
   Copyright (C) 2001, 2002, 2003 The Anubis Team.

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

#include "headers.h"
#include "extern.h"

static int make_sockets(int fd[]);
static void sig_local(int);

/********************************
 execargs generator for execvp()
*********************************/

char **
gen_execargs(const char *commandline)
{
	int argc;
	char *dupstr;
	char *str;
	char **args;

	/* strtok modifies the string. Prevent it by making a private copy. */
	dupstr = strdup(commandline);

	/* Count the arguments first. */
	for (argc = 0, str = strtok(dupstr, " "); str; argc++)
		str = strtok(0, " ");
	free(dupstr);

	args = xmalloc((argc + 1) * sizeof(*args));

	/* strtok above has modified the string, so we duplicate it again. */
	dupstr = strdup(commandline);

	/* Now copy the arguments. */
	for (argc = 0, str = strtok(dupstr, " "); str; argc++)
	{
		args[argc] = strdup(str);
		str = strtok(0, " ");
	}
	args[argc] = NULL;
	free(dupstr);

	return args;
}

/*************************
 Connect to stdin/stdout.
**************************/

static int
make_sockets(int fd[2])
{
#ifndef HAVE_SOCKETPAIR
	struct sockaddr_in addr;
	int addrlen;
	int sd;

	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		anubis_error(HARD, _("#1 socket() failed."));
		return -1;
	}
	if ((fd[1] = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		anubis_error(HARD, _("#2 socket() failed."));
		return -1;
	}
	addrlen = sizeof(addr);
	memset(&addr, 0, addrlen);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(sd, (struct sockaddr *)&addr, addrlen)) {
		anubis_error(HARD, _("#1 bind() failed: %s."), strerror(errno));
		return -1;
	}
	if (bind(fd[1], (struct sockaddr *)&addr, addrlen)) {
		anubis_error(HARD, _("#2 bind() failed: %s."), strerror(errno));
		return -1;
	}
	if (listen(sd, 5)) {
		anubis_error(HARD, _("listen() failed: %s."), strerror(errno));
		return -1;
	}
	if (getsockname(sd, (struct sockaddr *)&addr, &addrlen)) {
		anubis_error(HARD, _("getsockname() failed: %s."), strerror(errno));
		return -1;
	}
	if (connect(fd[1], (struct sockaddr *)&addr, addrlen)) {
		anubis_error(HARD, _("connect() failed: %s."), strerror(errno));
		return -1;
	}
	if ((fd[0] = accept(sd, (struct sockaddr *)&addr, &addrlen)) < 0) {
		anubis_error(HARD, _("accept() failed: %s."), strerror(errno));
		return -1;
	}
	close_socket(sd);
#else
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		anubis_error(HARD, _("socketpair() failed: %s."), strerror(errno));
		return -1;
	}
#endif /* not HAVE_SOCKETPAIR */
	return 0;
}

static void
sig_local(int code)
{
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		info(VERBOSE, _("Local program [%d] finished."), pid);
	return;
}

int
make_local_connection(char *exec_path, char **exec_args)
{
	int fd[2];
	char **pargs;
	char args[LINEBUFFER+1];

	if (check_filename(exec_path, 0) == 0)
		return -1;

	memset(args, 0, LINEBUFFER + 1);
	pargs = exec_args;
	pargs++;
	while (*pargs)
	{
		strncat(args, *pargs, LINEBUFFER - strlen(args));
		strncat(args, " ", LINEBUFFER - strlen(args));
		pargs++;
	}
	info(VERBOSE, _("Executing %s %s..."), exec_path, args);
	if (make_sockets(fd))
		return -1;

	signal(SIGCHLD, sig_local);
	switch(fork())
	{
		case -1: /* an error */
			anubis_error(HARD, _("fork() failed."));
			close(fd[0]);
			close(fd[1]);
			return -1;
		case 0: /* a child process */
			close(fd[0]);
			dup2(fd[1], 0);
			dup2(fd[1], 1);
			close(fd[1]);
			execvp(exec_path, exec_args);
			anubis_error(HARD, _("execvp() failed: %s"), strerror(errno));
			return -1;
	}
	close(fd[1]);
#ifdef FD_CLOEXEC
	fcntl(fd[0], F_SETFD, FD_CLOEXEC);
#endif /* FD_CLOEXEC */
	return fd[0];
}

/*************************************
 Use an external program, which works
 on standard input and output.
**************************************/

char *
external_program(int *rs, char *path, char *src, char *dst, int dstsize)
{
	char *ret;
	char tmp[LINEBUFFER+1];
	char **args = 0;
	char *a = 0; /* args */
	char *p = 0; /* path */

	a = strchr(path, ' '); /* an extra arguments */
	if (a) {
		*a++ = '\0';
		p = strrchr(path, '/');
		if (p)
			p++;
		else
			p = path;
		snprintf(tmp, LINEBUFFER, "%s %s", p, a);
		p = path;
		a = tmp;
	}
	else { /* no arguments */
		p = path;
		a = strrchr(path, '/');
		if (a)
			a++;
		else
			a = path;
	}
	
	args = gen_execargs(a);
	ret = exec_argv(rs, args, src, dst, dstsize);
	xfree_pptr(args);
	return ret;
}

char *
exec_argv(int *rs, char **argv, char *src, char *dst, int dstsize)
{
	int status;
	int fd;
	int n;
	char *buf;
	
	fd = make_local_connection(argv[0], argv);
	if (fd == -1) {
		*rs = -1;
		return 0;
	}

	if (write(fd, src, strlen(src)) == -1) {
		*rs = -1;
		return 0;
	}
	if (shutdown(fd, 1) == -1) {
		*rs = -1;
		return 0;
	}

	buf = (char *)xmalloc(DATABUFFER + 1);
	memset(dst, 0, dstsize);

	if (dst && dstsize) { /* static array */
		while ((n = read(fd, buf, DATABUFFER)) > 0) {
			strncat(dst, buf, dstsize);
			memset(buf, 0, DATABUFFER + 1);
			dstsize -= n;
			if (dstsize < 1)
				break;
		}
	} else { /* dynamic array */
		dst = (char *)xmalloc(1);
		while ((n = read(fd, buf, DATABUFFER)) > 0) {
			dst = xrealloc(dst, strlen(dst) + n + 1);
			strncat(dst, buf, n);
			memset(buf, 0, DATABUFFER + 1);
		}
		free(buf);
		close(fd);
		waitpid(-1, &status, WNOHANG);
		*rs = 0;
		return dst;
	}
	free(buf);
	close(fd);
	waitpid(-1, &status, WNOHANG);
	*rs = 0;
	return 0;
}

/* EOF */

