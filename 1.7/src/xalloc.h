/* Copyright (C) 2000-2004 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* xalloc.h: safe dynamic allocation */
/* $Id: xalloc.h,v 1.3 2003/03/30 00:38:29 selinger Exp $ */

#ifndef __XALLOC_H
#define __XALLOC_H

#include <stdio.h>

/* safe malloc */
void *xalloc(size_t size, char *myname);

/* safe realloc */
void *xrealloc(void *p, size_t size, char *myname);

/* read an allocated line from input stream */
char *xreadline(FILE *fin, char *myname);

#endif /* __XALLOC_H */
