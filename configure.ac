dnl
dnl configure.ac
dnl
dnl This file is part of GNU Anubis.
dnl Copyright (C) 2001, 2002, 2003 The Anubis Team.
dnl
dnl GNU Anubis is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl GNU Anubis is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with GNU Anubis; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
dnl
dnl GNU Anubis is released under the GPL with the additional exemption that
dnl compiling, linking, and/or using OpenSSL is allowed.
dnl

dnl Process this file with autoconf to produce a configure script.
AC_INIT([GNU Anubis], [3.9.90], [bug-anubis@gnu.org], [anubis])
AC_PREREQ([2.57])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

if test "$CFLAGS"; then
 CFLAGS_CUSTOM=yes
fi

dnl Internationalization macros.
AM_GNU_GETTEXT
AM_GNU_GETTEXT_VERSION(0.12.1)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_YACC
AM_PROG_LEX
AC_PATH_PROG(idecrypt_path,idecrypt,/usr/sbin/idecrypt,
$PATH:/sbin:/usr/sbin:/usr/local/sbin)
AC_DEFINE_UNQUOTED(IDECRYPT_PATH,"${idecrypt_path}",
[Define if IDECRYPT_PATH is requested.])

dnl Checks for header files.
AC_HEADER_STDC
AC_TYPE_SIZE_T
AC_TYPE_PID_T

AC_CHECK_HEADERS(arpa/inet.h syslog.h regex.h \
 sys/types.h sys/socket.h socket.h)

AC_CHECK_TYPE(socklen_t, , AC_DEFINE(socklen_t, int, [Define to int if <sys/types.h> does not define]),
[
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SOCKET_H
# include <socket.h>
#endif
])

dnl Check for getopt_long in standard library
AC_CHECK_FUNCS(getopt_long,, [AC_LIBOBJ(getopt)
                              AC_LIBOBJ(getopt1)])

dnl Checks for library functions.
AC_CHECK_FUNCS(syslog getrlimit setrlimit socketpair strdup)
AC_CHECK_FUNCS(regcomp daemon isatty putenv)

AC_REPLACE_FUNCS(snprintf setenv)
AC_CHECK_FUNCS(_obstack_begin,
               [AC_DEFINE(HAVE_OBSTACK,1,[Define if GNU obstack is present])],
               [AC_LIBOBJ(obstack)])

AC_FUNC_SETVBUF_REVERSED
AH_BOTTOM([
#if defined (SETVBUF_REVERSED)
# define SETVBUF(str,buf,mode,size) setvbuf(str,mode,buf,size)
#else
# define SETVBUF(str,buf,mode,size) setvbuf(str,buf,mode,size)
#endif
])

AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, gethostbyaddr)

AC_SUBST(INCLUDES)
case $build in
  *-apple-darwin*)
    INCLUDES="$INCLUDES -I/usr/include" ;;
esac

dnl Use option --without-guile to NOT compile Guile support.
AC_ARG_WITH([guile],
            AC_HELP_STRING([--without-guile],
	    [without Guile support]),
            [
case "${withval}" in
  yes) useguile=yes ;;
  no)  useguile=no ;;
  *)   AC_MSG_ERROR(bad value ${withval} for --without-guile) ;;
esac],[useguile=yes])

AC_SUBST(M4_DEFS)

AC_SUBST(GUILE_INCLUDES)
AC_SUBST(GUILE_LIBS)
AC_SUBST(GUILE_BINDIR)
AC_SUBST(GUILE_SNARF_VERSION)
AC_SUBST(GUILE_SCRIPTS)
if test x"$useguile" = x"yes"; then
  MU_CHECK_GUILE(,[
    AC_DEFINE(WITH_GUILE,1,[Enable Guile support])
    GUILE_INCLUDES=`guile-config compile`
    GUILE_LIBS=`guile-config link`
    GUILE_BINDIR=`guile-config info bindir`
    GUILE_SCRIPTS='$(GUILE_SCM)'
    M4_DEFS="$M4_DEFS -DWITH_GUILE"
    case "$GUILE_VERSION" in
    16|17) GUILE_SNARF_VERSION="1.6";;
    *) GUILE_SNARF_VERSION="1.6";;
    esac
   ],[useguile=no])
fi
if test x"$useguile" = x"no"; then
 AC_MSG_RESULT([Disabling GUILE support...])
fi

dnl Use option --without-gpgme to NOT compile GnuPG (GPGME library) support.
AC_SUBST(ANUBIS_GPGFILES)
AC_ARG_WITH(gpgme,
	AC_HELP_STRING([--without-gpgme],
	[without GnuPG (GPGME library) support]),
	[with_gpgme=${withval}],
	[with_gpgme=yes])
if test "$with_gpgme" = "no"; then
 AC_DEFINE(NOGPG, 1, [Define to 1 if NOGPG is requested.])
else
 AC_CHECK_LIB(gpgme, main,, with_gpgme=no)
fi
if test "$with_gpgme" = "no"; then
 AC_MSG_RESULT([Disabling GPGME support...])
else
 AC_PATH_PROG(GPG, gpg)
 findgpgmedir() { :
  if test -f "$1/include/gpgme.h"; then
   gpgmedir=1
   INCLUDES="$INCLUDES -I$1/include"
   AC_MSG_CHECKING(for $1/include/gpgme.h)
   AC_MSG_RESULT([yes])
   return 0
  fi
  return 1
 }
 for maindir in /usr/pkg /opt /sw; do
  findgpgmedir $maindir && break 2
 done
 if test $gpgmedir; then
  AC_DEFINE(HAVE_GPGME_H, 1, [Define to 1 if HAVE_GPGME_H is requested.])
 else
  AC_CHECK_HEADERS(gpgme.h)
 fi
 ANUBIS_GPGFILES='$(GPGFILES)'
 AC_LIBOBJ(gpg)
 M4_DEFS="$M4_DEFS -DWITH_GPG"
fi

dnl Use option --without-gnutls to NOT compile GnuTLS library support.
AC_ARG_WITH(gnutls,
	AC_HELP_STRING([--without-gnutls],
	[without GnuTLS library support]),
	[with_gnutls=${withval}],
	[with_gnutls=yes])

dnl Use option --with-openssl to compile OpenSSL support.
AC_ARG_WITH(openssl,
	AC_HELP_STRING([--with-openssl],
	[with OpenSSL library support (disable GnuTLS)]),
	[with_openssl=${withval}],
	[with_openssl=no])

if test "$with_openssl" = "yes"; then
 with_gnutls=no
fi

if test "$with_openssl" = "yes"; then
 AC_CHECK_LIB(crypto, main,, with_openssl=no)
 AC_CHECK_LIB(ssl, main,, with_openssl=no)
 if test "$with_openssl" = "yes"; then
  findopenssldir() { :
   if test -f "$1/include/openssl/ssl.h"; then
    openssldir=1
    INCLUDES="$INCLUDES -I$1/include"
    AC_MSG_CHECKING(for $1/include/openssl/ssl.h)
    AC_MSG_RESULT([yes])
    return 0
   fi
   return 1
  }
  for maindir in /usr/pkg /opt /sw; do
   findopenssldir $maindir && break 2
  done
  if test $openssldir; then
   AC_DEFINE(HAVE_OPENSSL_SSL_H, 1, [Define to 1 if HAVE_OPENSSL_SSL_H is requested.])
  else
   AC_CHECK_HEADERS(openssl/ssl.h)
  fi
  M4_DEFS="$M4_DEFS -DWITH_SSL"
  AC_LIBOBJ(ssl)
  AC_DEFINE(USE_OPENSSL, 1, [Define to 1 if USE_OPENSSL is requested.])
  AC_MSG_RESULT([Enabling OpenSSL support...])
 fi
fi

if test $with_gnutls = yes; then
  AC_CHECK_HEADERS(gnutls/gnutls.h)
  if test $ac_cv_header_gnutls_gnutls_h != no; then
    AM_PATH_LIBGNUTLS("0.9.6",
                      [M4_DEFS="$M4_DEFS -DWITH_SSL"
                      AC_LIBOBJ(tls)
                      AC_DEFINE(USE_GNUTLS, 1,
                                [Define to 1 if USE_GNUTLS is requested.])],
                                [AC_MSG_RESULT([Disabling GnuTLS support...])])
  fi
fi

dnl Use option --with-pcre to compile PCRE library support.
AC_ARG_WITH(pcre,
	AC_HELP_STRING([--with-pcre],
	[with PCRE library support]),
	[with_pcre=${withval}],
	[with_pcre=no])
if test "$with_pcre" = "yes"; then
 AC_CHECK_LIB(pcre, main)
 AC_CHECK_HEADERS(pcre.h pcre/pcre.h)
 AC_MSG_RESULT([Enabling PCRE support...])
fi

dnl Use option --with-pam to compile PAM support.
AC_ARG_WITH(pam,
	AC_HELP_STRING([--with-pam],
	[with Pluggable Authentication Modules support]),
	[with_pam=${withval}],
	[with_pam=no])
if test "$with_pam" = "yes"; then
 AC_CHECK_LIB(pam, main,, with_pam=no)
 AC_CHECK_LIB(pam_misc, main,, with_pam=no)
 AC_CHECK_HEADERS(security/pam_appl.h security/pam_misc.h)
 AC_MSG_RESULT([Enabling PAM support...])
fi

dnl Use option --with-tcp-wrappers to compile libwrap library support.
AC_ARG_WITH(tcp-wrappers,
	AC_HELP_STRING([--with-tcp-wrappers],
	[with libwrap (TCP wrappers) support]),
	[with_tcp_wrappers=${withval}],
	[with_tcp_wrappers=no])
if test "$with_tcp_wrappers" = "yes"; then
 AC_CHECK_LIB(wrap, main)
 AC_CHECK_LIB(nsl, main)
 AC_CHECK_HEADERS(tcpd.h)
 AC_MSG_RESULT([Enabling libwrap (TCP wrappers) support...])
fi

dnl Use option --with-unprivileged-user
AC_ARG_WITH(unprivileged-user,
	AC_HELP_STRING([--with-unprivileged-user=USER],
	[set an unprivileged user (default is "nobody")]))
if test -z "$with_unprivileged_user"; then
 with_unprivileged_user="nobody"
fi
AC_DEFINE_UNQUOTED(DEFAULT_UNPRIVILEGED_USER, "$with_unprivileged_user",
[Define the default unprivileged user.])

dnl Use option --enable-gcc-debug to enable GCC debug code.
AC_ARG_ENABLE(gcc-debug,
	AC_HELP_STRING([--enable-gcc-debug],
	[enable GCC DEBUG code]),
	[enable_gcc_debug=yes],
	[enable_gcc_debug=no])
if test "$enable_gcc_debug" = "yes" && (test "$GCC" = "yes"); then
 if test -z "$CFLAGS_CUSTOM"; then
  CFLAGS="-Wall -ggdb"
 else
  CFLAGS="$CFLAGS -ggdb"
 fi
 AC_MSG_RESULT([Enabling GCC DEBUG support...])
else
 if test -z "$CFLAGS_CUSTOM" && (test "$GCC" = "yes"); then
  CFLAGS="-Wall -O2"
 fi
fi

AC_CONFIG_FILES([Makefile
 build/Makefile
 build/guile-1.6/Makefile
 contrib/Makefile
 doc/Makefile
 examples/Makefile
 examples/pam/Makefile
 guile/Makefile
 intl/Makefile
 m4/Makefile
 po/Makefile.in
 scripts/Makefile
 src/Makefile
 testsuite/Makefile
 testsuite/data/Makefile
 testsuite/etc/Makefile
 ])
AC_OUTPUT

dnl EOF

