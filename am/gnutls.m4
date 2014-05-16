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
AC_SUBST(LIBGNUTLS_LIBS)
AC_SUBST(LIBGNUTLS_INCLUDES)
AC_DEFUN([ANUBIS_CHECK_TLS],[
 AC_ARG_WITH([gnutls],
             AC_HELP_STRING([--with-gnutls],
                            [use GNU TLS library]),
             [anubis_cv_gnutls=$withval],
             [anubis_cv_gnutls=yes],
	     [anubis_cv_gnutls=yes])

 if test "$anubis_cv_gnutls" != "no"; then
   AC_CHECK_HEADER(gnutls/gnutls.h,
                   [:],
                   [anubis_cv_gnutls=no])
   if test "$anubis_cv_gnutls" != "no"; then
     saved_LIBS=$LIBS
     AC_CHECK_LIB(gcrypt, main,
                  [LIBGNUTLS_LIBS="-lgcrypt"],
                  [anubis_cv_gnutls=no])
     LIBS="$LIBS $LIBGNUTLS_LIBS"
     AC_CHECK_LIB(gnutls, gnutls_global_init,
                  [LIBGNUTLS_LIBS="-lgnutls $LIBGNUTLS_LIBS"],
                  [anubis_cv_gnutls=no])
     LIBS=$saved_LIBS
   fi
 fi

 if test "$anubis_cv_gnutls" = "yes"; then
   m4_if([$1],[],[:],[$1])
 else
   m4_if([$2],[],[:],[$2])
 fi])

