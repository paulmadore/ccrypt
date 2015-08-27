/* xalloc.h: safe dynamic allocation */
/* $Id: xalloc.h,v 1.1 2001/11/27 10:45:15 selinger Exp $ */

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
