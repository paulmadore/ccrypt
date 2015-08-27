dnl  Copyright (C) 2000-2009 Peter Selinger.
dnl  This file is part of ccrypt. It is free software and it is covered
dnl  by the GNU general public license. See the file COPYING for details.

dnl  Process this file with autoconf to produce a configure script.

dnl ----------------------------------------------------------------------
AC_INIT(src/ccrypt.c)
AM_INIT_AUTOMAKE(ccrypt, 1.9)
DATE="August 2009"
AM_CONFIG_HEADER(config.h)

AC_GNU_SOURCE

dnl ----------------------------------------------------------------------
dnl  Find lisp installation directory
AM_PATH_LISPDIR

dnl ----------------------------------------------------------------------
dnl  The names of the installed executables and the default suffix are in
dnl  principle configurable. However, they should not normally be changed,
dnl  because other scripts might depend on them.

NAMECCRYPT=ccrypt
NAMEENCRYPT=ccencrypt
NAMEDECRYPT=ccdecrypt
NAMECAT=ccat
SUF=.cpt

dnl Upper case name
NAMEUC=`echo $NAMECCRYPT | tr a-z A-Z`

dnl ----------------------------------------------------------------------
dnl Export some parameters to config file
AC_DEFINE_UNQUOTED(NAMECCRYPT,"$NAMECCRYPT",Name of the ccrypt binary)
AC_DEFINE_UNQUOTED(NAMEENCRYPT,"$NAMEENCRYPT",Name of the ccencrypt binary)
AC_DEFINE_UNQUOTED(NAMEDECRYPT,"$NAMEDECRYPT",Name of the ccdecrypt binary)
AC_DEFINE_UNQUOTED(NAMECAT,"$NAMECAT",Name of the ccat binary)
AC_DEFINE_UNQUOTED(SUF,"$SUF",Default suffix for encrypted files)

dnl ----------------------------------------------------------------------
dnl remember user's CFLAGS
iCFLAGS="$CFLAGS"

dnl ----------------------------------------------------------------------
dnl Check for programs.
AC_PROG_CC

dnl If compiler is gcc, use our own CFLAGS unless user overrides them
if test "$GCC" = "yes" && test "$iCFLAGS" = ""; then
  CFLAGS="-g -O2 -Wall"
fi

AC_CHECK_PROGS(TAR, gtar, tar)

dnl ----------------------------------------------------------------------
dnl enable large file support

AC_SYS_LARGEFILE

dnl ----------------------------------------------------------------------
dnl check for features

AC_ARG_ENABLE(libcrypt,
[  --disable-libcrypt      do not link against libcrypt, use own replacement])

dnl ----------------------------------------------------------------------
dnl Checks for libraries.

dnl Unless explicitly disabled, link against libcrypt if possible
if test "$enable_libcrypt" != no; then
  AC_CHECK_LIB(crypt, crypt)
fi

dnl If not linking against libcrypt, must link against replacement
if test "$ac_cv_lib_crypt_crypt" != yes; then
   EXTRA_OBJS="$EXTRA_OBJS unixcrypt3.o"
fi

dnl SCO Open Server requires -lsocket for gethostname()
AC_CHECK_LIB(socket, gethostname)

dnl ----------------------------------------------------------------------
dnl Checks for header files.
AC_CHECK_HEADERS(stdint.h crypt.h)

dnl ----------------------------------------------------------------------
dnl Checks for library functions.
AC_CHECK_FUNC(getopt_long, , EXTRA_OBJS="$EXTRA_OBJS getopt.o getopt1.o")

dnl ----------------------------------------------------------------------
dnl Find sizes of some types
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned long, 4)

dnl Determine 32-bit unsigned integer type
AC_MSG_CHECKING([for 32 bit unsigned integer type])
if test "$ac_cv_sizeof_unsigned_int" -eq 4; then
   UINT32_TYPE="unsigned int";
elif test "$ac_cv_sizeof_unsigned_long" -eq 4; then
   UINT32_TYPE="unsigned long";
else
AC_MSG_ERROR(cannot find 32 bit integer type)
fi
AC_MSG_RESULT($UINT32_TYPE)
AC_DEFINE_UNQUOTED(UINT32_TYPE,$UINT32_TYPE,unsigned 32 bit integer type)

dnl ----------------------------------------------------------------------
dnl Internationalization

GETTEXT_PACKAGE=ccrypt
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Package name for gettext])

AM_GNU_GETTEXT
AM_GNU_GETTEXT_VERSION([0.14.3])
IT_PROG_INTLTOOL([0.34.2], [no-xml])

dnl ----------------------------------------------------------------------
dnl Libtool (needed by intl/)

AC_PROG_LIBTOOL

dnl ----------------------------------------------------------------------
dnl Set up substitutions of non-standard configuration parameters
AC_SUBST(NAMECCRYPT)
AC_SUBST(NAMEENCRYPT)
AC_SUBST(NAMEDECRYPT)
AC_SUBST(NAMECAT)
AC_SUBST(SUF)
AC_SUBST(DATE)
AC_SUBST(NAMEUC)
AC_SUBST(EXTRA_OBJS)
AC_SUBST(TAR)

dnl ----------------------------------------------------------------------
AC_OUTPUT([doc/ccrypt.1 
	   po/Makefile.in 
	   m4/Makefile 
	   intl/Makefile 
	   Makefile 
	   src/Makefile 
	   emacs/Makefile
	   check/Makefile
	   doc/Makefile
          ])
