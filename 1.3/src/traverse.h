/* Copyright (C) 2000-2002 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* traverse.h: functions for traversing through a list of files, optionally
   recursing through directory structure */
/* $Id: traverse.h,v 1.2 2002/04/09 01:10:38 selinger Exp $ */ 

#ifndef __TRAVERSE_H
#define __TRAVERSE_H

#include <sys/stat.h>
#include <dirent.h>

void reset_inodes(void);
void traverse_file(char *filename);
void traverse_files(char **filelist, int count);

#endif /* __TRAVERSE_H */
