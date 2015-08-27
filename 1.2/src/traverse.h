/* traverse.h: functions for traversing through a list of files, optionally
   recursing through directory structure */
/* $Id: traverse.h,v 1.1 2001/11/27 10:45:15 selinger Exp $ */ 

#ifndef __TRAVERSE_H
#define __TRAVERSE_H

#include <sys/stat.h>
#include <dirent.h>

void reset_inodes(void);
void traverse_file(char *filename);
void traverse_files(char **filelist, int count);

#endif /* __TRAVERSE_H */
