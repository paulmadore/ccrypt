/* Copyright (C) 2000-2002 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* readkey.c: read secret key phrase from terminal */
/* $Id: readkey.c,v 1.2 2002/04/09 01:10:38 selinger Exp $ */

#include <termios.h>
#include <stdio.h>
#include <stdlib.h>

#include "xalloc.h"

/* read key from /dev/tty */
char *readkey(char *prompt, char *myname) {
  char *line;
  FILE *fin;
  struct termios tio, saved_tio;

  fin = fopen("/dev/tty", "r");
  if (fin==NULL) {
    fprintf(stderr, "%s: cannot open /dev/tty\n", myname);
    exit(2);
  }

  fprintf(stderr, "%s", prompt);
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
