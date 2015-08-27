## Copyright (C) 2000-2009 Peter Selinger.
## This file is part of ccrypt. It is free software and it is covered
## by the GNU general public license. See the file COPYING for details.

## Process this file with automake to produce Makefile.in

bin_PROGRAMS = ccrypt
EXTRA_DIST = getopt.c getopt1.c getopt.h unixcrypt3.c unixcrypt3.h maketables.c

ccrypt_SOURCES = main.c main.h traverse.c traverse.h xalloc.c xalloc.h	 \
  readkey.c readkey.h ccrypt.c ccrypt.h ccryptlib.c ccryptlib.h		 \
  unixcryptlib.c unixcryptlib.h rijndael.h rijndael.c tables.h tables.c  \
  gettext.h platform.h platform.c

ccrypt_LDADD = @EXTRA_OBJS@
ccrypt_DEPENDENCIES = @EXTRA_OBJS@

localedir = $(datadir)/locale
INCLUDES = -I../intl -I$(top_srcdir)/intl -DLOCALEDIR=\"$(localedir)\"
LIBS = @LIBINTL@ @LIBS@

maketables: maketables.c

tables.c: maketables.c
	make maketables
	maketables > tables.c

install-exec-hook:
	test "@NAMECCRYPT@" = ccrypt || \
	mv -f $(DESTDIR)$(bindir)/ccrypt $(DESTDIR)$(bindir)/@NAMECCRYPT@
	ln -f -s @NAMECCRYPT@ $(DESTDIR)$(bindir)/@NAMEENCRYPT@
	ln -f -s @NAMECCRYPT@ $(DESTDIR)$(bindir)/@NAMEDECRYPT@
	ln -f -s @NAMECCRYPT@ $(DESTDIR)$(bindir)/@NAMECAT@

uninstall-local:
	rm -f $(DESTDIR)$(bindir)/@NAMECCRYPT@
	rm -f $(DESTDIR)$(bindir)/@NAMEENCRYPT@
	rm -f $(DESTDIR)$(bindir)/@NAMEDECRYPT@
	rm -f $(DESTDIR)$(bindir)/@NAMECAT@


