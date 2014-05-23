dnl configure.ac -*- autoconf-*-
dnl
dnl This file is part of GNU Anubis.
dnl Copyright (C) 2001-2014 The Anubis Team.
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

dnl Process this file with autoconf to produce a configure script.
AC_INIT([GNU Anubis], [4.2], [bug-anubis@gnu.org])
AC_PREREQ([2.63])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([1.11 gnits tar-ustar dist-bzip2 std-options silent-rules])
AC_GNU_SOURCE

dnl Enable silent rules by default:
AM_SILENT_RULES([yes])

dnl Checks for programs.
AC_PROG_CC
gl_EARLY
AC_PROG_YACC
AM_PROG_LEX
AC_PATH_PROG(idecrypt_path,idecrypt,/usr/sbin/idecrypt,
$PATH:/sbin:/usr/sbin:/usr/local/sbin)
AC_DEFINE_UNQUOTED(IDECRYPT_PATH,"${idecrypt_path}",
[Define if IDECRYPT_PATH is present.])

dnl Checks for header files.
AC_HEADER_STDC
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_CHECK_TYPE(u_char, unsigned char)
AC_CHECK_HEADERS(arpa/inet.h sys/types.h sys/socket.h socket.h locale.h)

AC_CHECK_TYPE([socklen_t], , 
[AC_DEFINE_UNQUOTED([socklen_t], [int], [Type to use instead of socklen_t, if <sys/types.h> does not define])],
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

dnl Checks for library functions.
gl_INIT

AC_CHECK_FUNCS(getrlimit setrlimit socketpair)
AC_CHECK_FUNCS(setegid setregid setresgid seteuid setreuid)
AC_CHECK_FUNCS(daemon putenv)

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

AC_SUBST(ADD_INCLUDES)
case $build in
  *-apple-darwin*)
    ADD_INCLUDES="$ADD_INCLUDES -I/usr/include" ;;
esac

dnl Internationalization macros.
AM_GNU_GETTEXT([external], [need-formatstring-macros])
AM_GNU_GETTEXT_VERSION([0.16])

AC_SUBST([M4_DEFS])
AC_SUBST([GUILE_SCRIPTS])
GINT_INIT([gint],[1.8 with-guile nodoc std-site-dir],
          [useguile=yes
	   AC_DEFINE(WITH_GUILE,1,[Enable Guile support])
           GUILE_SCRIPTS='$(GUILE_SCM)'
           M4_DEFS="$M4_DEFS -DWITH_GUILE"],
          [useguile=no])

if test "$useguile" = "no"; then
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
 AM_PATH_GPGME([1.0.0], with_gpgme=yes, with_gpgme=no)
 AC_CHECK_LIB(gpgme, main,, with_gpgme=no)
 LIBS="$LIBS -lgpg-error"
fi
if test "$with_gpgme" = "no"; then
 AC_MSG_RESULT([Disabling GPGME support...])
else
 AC_PATH_PROG(GPG, gpg)
 findgpgmedir() { :
  if test -f "$1/include/gpgme.h"; then
   gpgmedir=1
   ADD_INCLUDES="$ADD_INCLUDES -I$1/include"
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
 M4_DEFS="$M4_DEFS -DWITH_GPG"
fi

AC_SUBST(GSASL_LIBS)
AC_CHECK_LIB(resolv, res_query)

# Needed for GpgME
AC_SYS_LARGEFILE

AC_SUBST(ANUBIS_DEFINES)
AC_SUBST(ANUBIS_SBIN_ADM)
AC_SUBST(ANUBIS_BIN_ADM)

dnl Use option --enable-gcc-debug to enable GCC debug code.
AC_ARG_ENABLE(gcc-debug,
	AC_HELP_STRING([--enable-gcc-debug],
	[enable GCC DEBUG code]),
	[enable_gcc_debug=yes],
	[enable_gcc_debug=no])
if test "$enable_gcc_debug" = "yes" && (test "$GCC" = "yes"); then
 CFLAGS="$CFLAGS -ggdb"
 AC_MSG_RESULT([Enabling GCC DEBUG support...])
fi

WITH_SQL=no
WITH_MYSQL=no
WITH_POSTGRES=no
WITH_GDBM=no
WITH_GSASL=no

dnl Use option --with-gsasl to compile GSASL library support.
MU_CHECK_GSASL(0.2.3, [
    WITH_GSASL=yes
    AC_DEFINE(WITH_GSASL,1,[Define if Anubis is using GNU SASL])
    AC_MSG_RESULT([Enabling GSASL support...])
    ANUBIS_SBIN_ADM='$(adm_sbin_programs)'
    ANUBIS_BIN_ADM='$(adm_bin_programs)'
    M4_DEFS="$M4_DEFS -DWITH_GSASL"

    AC_CHECK_LIB(gdbm, gdbm_open,
                 [WITH_GDBM=yes
                  LIBS="$LIBS -lgdbm"
                  AC_DEFINE(HAVE_LIBGDBM,1,[Define if you have libgdbm])],
                 [AC_MSG_RESULT([Disabling GDBM support...])])

    AC_ARG_WITH(mysql,
	AC_HELP_STRING([--with-mysql],
	[Configure to work with MySQL]),
	[case $withval in
	 yes)  USE_SQL=0
               ANUBIS_CHECK_LIB(mysqlclient, 
	                        mysql_real_connect, 
	                        [-lm],
                                [ USE_SQL=1
                                  AC_DEFINE(WITH_MYSQL,1,
                                       [Define to 1 to enable MySQL interface])
                                  AC_DEFINE(HAVE_LIBMYSQL,1,
                                       [Define if you have libmysqlclient])
                                ],
			        [AC_MSG_FAILURE([The requested library libmysqlclient is not found or is unusable])],
                                [/usr/local/lib/mysql /usr/lib/mysql])
                if test "$USE_SQL" = "1" ;then
		       WITH_SQL=yes
                       LIBS="$LIBS $anubis_cv_lib_mysqlclient"
                       AC_MSG_RESULT([Enabling MySQL support...])
                       WITH_MYSQL=yes
	        else
		       AC_MSG_FAILURE([Required MySQL libraries not found])
		fi
		;;
	 no)    ;;
         *)     AC_MSG_FAILURE([Unexpected option argument $withval. Please use either --with-mysql or --without-mysql]);;
        esac])

    AC_ARG_WITH(postgres,
	AC_HELP_STRING([--with-postgres],
	[Configure to work with Postgres]),
	[case $withval in
	yes)	USE_SQL=0
                ANUBIS_CHECK_LIB(pq,
				 PQconnectStart,
			         [],
				 [ USE_SQL=1
 				   AC_DEFINE(WITH_PGSQL,1,
                                             [Define to 1 to enable PostgreSQL interface])
                                 ],
		                 [AC_MSG_FAILURE([The requested library libpq is not found or is unusable])],
                                 [/usr/local/pgsql/lib /usr/pgsql/lib])
                if test "$USE_SQL" = "1" ;then
		       WITH_SQL=yes
                       LIBS="$LIBS $anubis_cv_lib_pq"
                       AC_MSG_RESULT([Enabling PostgreSQL support...])
                       WITH_POSTGRES=yes
	        else
		       AC_MSG_FAILURE([Required PostgreSQL libraries not found])
		fi
		;;
	 no)    ;;
	 *)     AC_MSG_FAILURE([Unexpected option argument $withval. Please use either --with-postgres or --without-postgres]);;
        esac])

    if test "$WITH_SQL" = "yes"; then
       AC_DEFINE(WITH_SQL, 1, [Define this if you use an SQL interface])
    fi

    AC_LIBOBJ(lbuf)])

ANUBIS_CHECK_TLS([
 M4_DEFS="$M4_DEFS -DWITH_SSL -DWITH_GNUTLS"
 AC_DEFINE(USE_GNUTLS, 1, [Define to 1 if USE_GNUTLS is requested.])])
AM_CONDITIONAL([TLS_COND], [test $anubis_cv_gnutls = yes])

dnl Use option --with-socks-proxy to compile SOCKS v4/5 proxy support.
AC_ARG_WITH(socks-proxy,
	AC_HELP_STRING([--with-socks-proxy],
	[with SOCKS v4/5 proxy support]),
	[with_socks_proxy=${withval}],
	[with_socks_proxy=no])
if test "$with_socks_proxy" = "yes"; then
 AC_DEFINE(USE_SOCKS_PROXY, 1, [Define to 1 if USE_SOCKS_PROXY is requested.])
 AC_MSG_RESULT([Enabling SOCKS v4/5 proxy support...])
fi

dnl Use option --with-pcre to compile PCRE library support.
AC_ARG_WITH(pcre,
	AC_HELP_STRING([--with-pcre],
	[with PCRE library support]),
	[with_pcre=${withval}],
	[with_pcre=no])
if test "$with_pcre" = "yes"; then
 AC_CHECK_LIB(pcre, main,, with_pcre=no)
 AC_CHECK_HEADERS(pcre.h pcre/pcre.h)
fi
if test "$with_pcre" = "yes"; then
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
 AC_CHECK_HEADERS(security/pam_appl.h security/pam_misc.h,, with_pam=no)
fi
if test "$with_pam" = "yes"; then
 AC_MSG_RESULT([Enabling PAM support...])
fi

dnl Use option --with-tcp-wrappers to compile libwrap library support.
AC_ARG_WITH(tcp-wrappers,
	AC_HELP_STRING([--with-tcp-wrappers],
	[with libwrap (TCP wrappers) support]),
	[with_tcp_wrappers=${withval}],
	[with_tcp_wrappers=no])
if test "$with_tcp_wrappers" = "yes"; then
 AC_CHECK_LIB(wrap, main,, with_tcp_wrappers=no)
 AC_CHECK_LIB(nsl, main,, with_tcp_wrappers=no)
 AC_CHECK_HEADERS(tcpd.h,, with_tcp_wrappers=no)
fi
if test "$with_tcp_wrappers" = "yes"; then
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

dnl Check for Emacs site-lisp directory
AM_PATH_LISPDIR
if test "$EMACS" != "no"; then
	lisp_LISP='$(LISPSRC)'
fi
AC_SUBST(lisp_LISP)

AC_CONFIG_COMMANDS([status],[
cat <<EOF

*******************************************************************
GNU Anubis configured with the following settings:

Use Guile...................... $useguile
Use GPGme...................... $with_gpgme
Use GNU SASL................... $WITH_GSASL
Use GDBM....................... $WITH_GDBM
Use SQL........................ $WITH_SQL
Use MySQL...................... $WITH_MYSQL
Use PostgreSQL................. $WITH_POSTGRES
Use GNU TLS.................... $with_gnutls
Support for SOCKS v4/5......... $with_socks_proxy
Perl-style regular expressions. $with_pcre
Enable PAM Support............. $with_pam
Use TCP wrapper library........ $with_tcp_wrappers
Unprivileged user name......... $with_unprivileged_user

*******************************************************************

Before proceeding, make sure these satisfy your requirements. 
EOF
],
[useguile=$useguile
with_gpgme=$with_gpgme
mu_cv_lib_gsasl=$mu_cv_lib_gsasl
WITH_GDBM=$WITH_GDBM
WITH_SQL=$WITH_SQL
WITH_MYSQL=$WITH_MYSQL
WITH_POSTGRES=$WITH_POSTGRES
WITH_GSASL=$WITH_GSASL
with_gnutls=$anubis_cv_gnutls
with_socks_proxy=$with_socks_proxy
with_pcre=$with_pcre
with_pam=$with_pam
with_tcp_wrappers=$with_tcp_wrappers
with_unprivileged_user=$with_unprivileged_user])

AC_CONFIG_FILES([Makefile
 build/Makefile
 build/guile-1.6/Makefile
 contrib/Makefile
 gint/Makefile
 doc/Makefile
 elisp/Makefile
 examples/Makefile
 examples/pam/Makefile
 guile/Makefile
 lib/Makefile
 po/Makefile.in
 scripts/Makefile
 src/Makefile
 testsuite/Makefile
 testsuite/data/Makefile
 testsuite/etc/Makefile
 ])

AC_OUTPUT
