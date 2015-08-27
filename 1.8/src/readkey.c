/* Copyright (C) 2000-2008 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* readkey.c: read secret key phrase from terminal */
/* $Id: readkey.c 248 2009-06-05 14:58:58Z selinger $ */

#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "xalloc.h"

#include "gettext.h"
#define _(String) gettext (String)

/* read key from /dev/tty */
char *readkey(const char *prompt, const char *promptcont, const char *myname) {
  char *line;
  FILE *fin;
  struct termios tio, saved_tio;

  fin = fopen("/dev/tty", "r");
  if (fin==NULL) {
    fprintf(stderr, _("%s: cannot open /dev/tty: %s\n"), myname, strerror(errno));
    exit(2);
  }

  fprintf(stderr, "%s%s", prompt, promptcont);
  fflush(stderr);

  /* disable echo */
  tcgetattr(fileno(fin), &tio);
  saved_tio = tio;
  tio.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  tcsetattr(fileno(fin), TCSANOW, &tio);

  /* read key */
  line = xreadline(fin, myname);

  /* restore echo, print newline, close file */
  tcsetattr(fileno(fin), TCSANOW, &saved_tio);
  fprintf(stderr, "\n");
  fflush(stderr);
  fclose(fin);

  return line;
}
