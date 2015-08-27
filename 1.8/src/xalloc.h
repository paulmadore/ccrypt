/* Copyright (C) 2000-2008 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* xalloc.h: safe dynamic allocation */
/* $Id: xalloc.h 248 2009-06-05 14:58:58Z selinger $ */

#ifndef __XALLOC_H
#define __XALLOC_H

#include <stdio.h>

/* safe malloc */
void *xalloc(size_t size, const char *myname);

/* safe realloc */
void *xrealloc(void *p, size_t size, const char *myname);

/* read an allocated line from input stream */
char *xreadline(FILE *fin, const char *myname);

#endif /* __XALLOC_H */
