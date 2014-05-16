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

AC_SUBST(ANUBIS_LIBOBJS)
AC_DEFUN([ANUBIS_LIBOBJ],[
 ANUBIS_LIBOBJS="$ANUBIS_LIBOBJS $1.$ac_objext"])

dnl ANUBIS_RESULT_ACTIONS -- generate shell code for the result of a test
dnl   $1 -- CVAR  -- cache variable to check
dnl   $2 -- NAME  -- if not empty, used to generate a default value TRUE:
dnl                  `AC_DEFINE(HAVE_NAME)'
dnl   $2 -- TRUE  -- what to do if the CVAR is not `no'
dnl   $3 -- FALSE -- what to do otherwise; defaults to `:'
dnl
AC_DEFUN([ANUBIS_RESULT_ACTIONS], [
[if test "$$1" != "" -a "$$1" != no; then
  ]ifelse([$3], ,
          [AC_DEFINE(HAVE_]translit($2, [a-z ./<>], [A-Z___])[,1,[FIXME])],
          [$3])[
else
  ]ifelse([$4], , [:], [$4])[
fi]])dnl

dnl Arguments:
dnl   $1     --    Library to look for
dnl   $2     --    Function to check in the library
dnl   $3     --    Any additional libraries that might be needed
dnl   $4     --    Action to be taken when test succeeds
dnl   $5     --    Action to be taken when test fails
dnl   $6     --    Directories where the library may reside
AC_DEFUN([ANUBIS_CHECK_LIB],
[
  save_LIBS=$LIBS
  AC_CACHE_CHECK([for -l$1], anubis_cv_lib_$1,
  [
   for path in $6
   do
      LIBS="$save_LIBS $3 -L$path -l$1"
      AC_TRY_LINK_FUNC($2,
                       [anubis_cv_lib_$1="$3 -L$path -l$1"
                        break],
                       [anubis_cv_lib_$1=no],$3)
   done
  ])
  ANUBIS_RESULT_ACTIONS([anubis_cv_lib_$1],[LIB$1],[$4],[$5])
  LIBS=$save_LIBS
])


