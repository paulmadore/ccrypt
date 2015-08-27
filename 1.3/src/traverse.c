/* Copyright (C) 2000-2002 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* traverse.c: functions for traversing through a list of files,
   optionally recursing through directory structure, and doing
   whatever action is required for encrypting/decrypting files in the
   various modes */
/* $Id: traverse.c,v 1.5 2002/09/25 08:11:21 selinger Exp $ */ 

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <utime.h>
#include <unistd.h>

#include "xalloc.h"
#include "main.h"
#include "traverse.h"
#include "ccrypt.h"
#include "unixcryptlib.h"

/* ---------------------------------------------------------------------- */
/* an "object" for keeping track of a list of inodes that we have seen */

struct inode_dev_s {
  ino_t inode;  /* an inode */
  dev_t dev;    /* a device */
  int success;  /* was encryption/decryption successful for this inode? */
};
typedef struct inode_dev_s inode_dev_t;

/* inode_list: a list of inode/device pairs. inode_num is number of
   nodes in the list, and inode_size is its allocated size */

inode_dev_t *inode_list = NULL;
int inode_num = 0;
int inode_size = 0;

/* reset the list */
void reset_inodes(void) {
  free(inode_list);
  inode_list = NULL;
  inode_num = 0;
  inode_size = 0;
}

/* add an inode/device pair to the list and record success or failure */
void add_inode(ino_t ino, dev_t dev, int success) {
  if (inode_list==NULL) {
    inode_size = 100;
    inode_list = xalloc(inode_size*sizeof(inode_dev_t), cmd.name);
  }
  if (inode_num >= inode_size) {
    inode_size += 100;
    inode_list = xrealloc(inode_list, inode_size*sizeof(inode_dev_t), cmd.name);
  }
  inode_list[inode_num].inode = ino;
  inode_list[inode_num].dev = dev;
  inode_list[inode_num].success = success;
  inode_num++;
}

/* look up ino/dev pair in list. Return -1 if not found, else 0 if
   success=0, else 1 */
int known_inode(ino_t ino, dev_t dev) {
  int i;

  /* have we already seen this inode/device pair? */
  for (i=0; i<inode_num; i++) {
    if (inode_list[i].inode == ino && inode_list[i].dev == dev) {
      return inode_list[i].success ? 1 : 0;
    }
  }
  return -1;
}

/* ---------------------------------------------------------------------- */

/* return 1 if filename ends in, but is not equal to, suffix. */
int has_suffix(char *filename, char *suffix) {
  int flen = strlen(filename);
  int slen = strlen(suffix);
  return flen>slen && strcmp(filename+flen-slen, suffix)==0;
}

/* add suffix to filename */

char *add_suffix(char *filename, char *suffix) {
  static char *outfile = NULL;
  int flen = strlen(filename);
  int slen = strlen(suffix);

  outfile = xrealloc(outfile, flen+slen+1, cmd.name);
  strncpy (outfile, filename, flen);
  strncpy (outfile+flen, suffix, slen+1);
  return outfile;
}

/* remove suffix from filename */

char *remove_suffix(char *filename, char *suffix) {
  static char *outfile = NULL;
  int flen = strlen(filename);
  int slen = strlen(suffix);

  if (suffix[0]==0 || !has_suffix(filename, suffix))
    return filename;
  outfile = xrealloc(outfile, flen-slen+1, cmd.name);
  strncpy (outfile, filename, flen-slen);
  outfile[flen-slen] = 0;
  return outfile;
}

/* ---------------------------------------------------------------------- */

/* read a yes/no response from the user */
int prompt(void) {
  char *line;
  FILE *fin;

  fin = fopen("/dev/tty", "r");
  if (fin==NULL) {
    fin = stdin;
  }
  
  line = xreadline(fin, cmd.name);
  return (line && (!strcmp(line, "y") || !strcmp(line, "yes")));
  free(line);
}

/* check whether named file exists */
int file_exists(char *filename) {
  struct stat buf;
  int st;

  st = lstat(filename, &buf);

  if (st) 
    return 0;
  else 
    return 1;
}

/* (re)set attributes of filename to those in bufp, where
   possible. Fail quietly if this is not possible */

void set_attributes(char *filename, struct stat *bufp) {
  struct utimbuf ut = {bufp->st_atime, bufp->st_mtime};

  utime(filename, &ut);
  chown(filename, bufp->st_uid, bufp->st_gid);
  chmod(filename, bufp->st_mode);
}

/* ---------------------------------------------------------------------- */

/* this function is called to act on a file if cmd.mode is ENCRYPT,
   DECRYPT, or KEYCHANGE */
int crypt_filename(char *filename) {
  int fd;
  int res;
  
  /* open file */
#ifdef __CYGWIN__
  fd = open(filename, O_RDWR | O_BINARY);
#else
  fd = open(filename, O_RDWR);
#endif
  if (fd == -1) {
    /* could not open file. */
    return -3;
  }
  
  /* crypt */
  switch (cmd.mode) {   /* note: can't be CAT or UNIXCRYPT */

  case ENCRYPT: default:
    if (cmd.verbose>0)
      fprintf(stderr, "Encrypting %s\n", filename);
    res = ccencrypt_file(fd, cmd.keyword);
    break;
    
  case DECRYPT:
    if (cmd.verbose>0)
      fprintf(stderr, "Decrypting %s\n", filename);
    res = ccdecrypt_file(fd, cmd.keyword);
    break;
    
  case KEYCHANGE:
    if (cmd.verbose>0)
      fprintf(stderr, "Changing key for %s\n", filename);
    res = cckeychange_file(fd, cmd.keyword, cmd.keyword2);
    break;
    
  }    
  
  /* close file */
  close(fd);

  return res;
}

/* this function is called to act on a file if cmd.mode is CAT or
   UNIXCRYPT */
int crypt_cat(char *infile) {
  FILE *fin;
  int res;
  
  /* open file */
  fin = fopen(infile, "rb");
  if (fin == NULL) {
    return -3;
  }

  /* crypt */

  switch (cmd.mode) {

  case CAT: default:
    if (cmd.verbose>0) {
      fprintf(stderr, "Decrypting %s\n", infile);
      fflush(stderr);
    }
    res = ccdecrypt_streams(fin, stdout, cmd.keyword);
    break;

  case UNIXCRYPT:
    if (cmd.verbose>0) {
      fprintf(stderr, "Decrypting %s\n", infile);
      fflush(stderr);
    }
    res = unixcrypt_streams(fin, stdout, cmd.keyword);
    break;

  }
  fflush(stdout);

  /* close file */
  fclose(fin);

  return res;
}

/* ---------------------------------------------------------------------- */

void file_action(char *filename) {
  struct stat buf;
  int st;
  int link = 0;
  char buffer[strlen(filename)+strlen(cmd.suffix)+1];
  char *outfile;
  int r;
  int do_chmod = 0;

  st = lstat(filename, &buf);

  if (st) {
    int orig_errno = errno;
    char *orig_filename = filename;

    /* if file didn't exist and decrypting, try if suffixed file exists */
    if (errno==ENOENT 
	&& (cmd.mode==DECRYPT || cmd.mode==CAT || cmd.mode==KEYCHANGE 
	    || cmd.mode==UNIXCRYPT) 
	&& cmd.suffix[0]!=0) {
      strcpy(buffer, filename);
      strcat(buffer, cmd.suffix);
      filename=buffer;
      st = lstat(buffer, &buf);
    }
    if (st) {
      errno = orig_errno;
      perror(orig_filename);
      return;
    }
  }
  
  /* if link following is enabled, follow links */
  if (cmd.symlinks && S_ISLNK(buf.st_mode)) {
    link = 1;
    st = stat(filename, &buf);
    if (st) {
      fprintf(stderr, "%s: %s: %s\n", cmd.name, filename, strerror(errno));
      return;
    }
  }

  /* if file is not a regular file, skip */
  if (!st && S_ISLNK(buf.st_mode)) {
    if (cmd.verbose>=0)
      fprintf(stderr, "%s: %s: is a symbolic link -- ignored\n", cmd.name, filename);
    return;
  }
  if (!st && !S_ISREG(buf.st_mode)) {
    if (cmd.verbose>=0) 
      fprintf(stderr, "%s: %s: is not a regular file -- ignored\n", cmd.name, 
	      filename);
    return;
  }
  
  /* now we have a regular file, and we have followed a link if
     appropriate. Or the link exists but the file does not. */
  
  if (!st && (buf.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0) {
    /* file is write-protected. In this case, we prompt the user to
       see if they want to operate on it anyway. Or if they give the
       "-f" option, we just do it without asking. */
    if (!cmd.force) {
      fprintf(stderr, "%s: %s write-protected file %s (y or n)? ", cmd.name, cmd.mode == ENCRYPT ? "encrypt" : cmd.mode == KEYCHANGE ? "perform keychange on" : "decrypt", filename);
      fflush(stderr);
      if (prompt()==0) {
	fprintf(stderr, "Not changed.\n");
	add_inode(buf.st_ino, buf.st_dev, 0);
	return;
      }
    }
    /* we will attempt to change the mode just before encrypting it. */
    do_chmod = 1;
  }
  
  /* do the mode-dependent encryption/decryption */

  switch (cmd.mode) {

  case ENCRYPT: case DECRYPT: case KEYCHANGE: /* overwrite mode */

    /* determine outfile name */
    switch (cmd.mode) {
    case ENCRYPT: default:
      if (cmd.strictsuffix && cmd.suffix[0] != 0 && has_suffix(filename, cmd.suffix)) {
	if (cmd.verbose>=0) {
	  fprintf(stderr, "%s already has %s suffix -- ignoring\n", filename, cmd.suffix); 
	}
	return;
      }
      outfile = add_suffix(filename, cmd.suffix);
      break;
    case DECRYPT:
      outfile = remove_suffix(filename, cmd.suffix);
      break;
    case KEYCHANGE:
      outfile = filename;
      break;
    }
    
    /* if outfile exists and cmd.force is not set, prompt whether to
       overwrite */
    if (!cmd.force && strcmp(filename, outfile) && 
	file_exists(outfile)) {
      fprintf(stderr, "%s: %s already exists; overwrite (y or n)? ", cmd.name, 
	      outfile);
      fflush(stderr);
      if (prompt()==0) {
	fprintf(stderr, "Not overwritten.\n");
	return;
      }
    }
  
    /* crypt file unless already done so */
    if (!st) {
      r = known_inode(buf.st_ino, buf.st_dev);
      if (r != -1 && cmd.verbose>0) {
	fprintf(stderr, "Already visited inode %s.\n", filename);
      }
      if (r == 0) {
	/* inode was not acted upon successfully - do not rename */
	return;
      } else if (r == 1) {
	/* inode was acted upon successfully - do nothing, but rename */
      } else {
	/* act on this inode now */
	if (buf.st_nlink>1 && cmd.verbose>=0)
	  fprintf(stderr, "%s: warning: %s has %d links\n", cmd.name, 
		  filename, buf.st_nlink);
	if (do_chmod) {
	  chmod(filename, buf.st_mode | S_IWUSR);
	}
	st = crypt_filename(filename);
	set_attributes(filename, &buf);
	if (st==-2) {
	  fprintf(stderr, "%s: %s: %s -- unchanged\n", cmd.name, filename,
		  ccrypt_error(st));
	  add_inode(buf.st_ino, buf.st_dev, 0);
	  break;
	} else if (st==-1) {
	  fprintf(stderr, "%s: %s: %s\n", cmd.name, filename,
		  strerror(errno));
	  exit(3);
	} else if (st==-3) {
	  fprintf(stderr, "%s: %s: %s\n", cmd.name, filename,
		  strerror(errno));
	  add_inode(buf.st_ino, buf.st_dev, 0);
	  return;
	} else {
	  add_inode(buf.st_ino, buf.st_dev, 1);
	}
      }
    }
    
    /* rename file if necessary */
    if (strcmp(filename, outfile)) {
      st = rename(filename, outfile);
      if (st) {
	fprintf(stderr, "%s: could not rename %s as %s: ", cmd.name, 
		filename, outfile);
	perror("");
      }
    }

    if (sigint_flag) {  /* SIGINT received while crypting - delayed exit */
      exit(6);
    }
    break;
    
  case CAT: case UNIXCRYPT: default: 
    if (!st) {
      st = crypt_cat(filename);
      if (st==-2) {
	fprintf(stderr, "%s: %s: %s -- ignored\n", cmd.name, filename,
		ccrypt_error(st));
      } else if (st==-1) {
	fprintf(stderr, "%s: %s: %s\n", cmd.name, filename,
		strerror(errno));
	exit(3);
      } else if (st==-3) {
	fprintf(stderr, "%s: %s: %s\n", cmd.name, filename,
		strerror(errno));
	return;
      }
    }
    break;
    
  }
}

/* ---------------------------------------------------------------------- */

/* read a whole directory. This is because we change directory entries
   while traversing the directory; this could otherwise lead to
   strange behavior on Solaris. After done with the file list, it
   should be freed with free_filelist. */

int get_filelist(char *dirname, char*** filelistp, int *countp) {
  DIR *dir;
  struct dirent *dirent;
  char **filelist = NULL;
  int count = 0;

  dir = opendir(dirname);
  if (dir==NULL) {
    perror(dirname);
    *filelistp = NULL;
    *countp = 0;
    return 0;
  }
  
  while ((dirent = readdir(dir)) != NULL) {
    if (strcmp(dirent->d_name, "..")!=0 && strcmp(dirent->d_name, ".")!=0) {
      char *strbuf = xalloc(strlen(dirname)+strlen(dirent->d_name)+2, cmd.name);
      strcpy (strbuf, dirname);
      strcat (strbuf, "/");
      strcat (strbuf, dirent->d_name);
      filelist = xrealloc(filelist, (count+1)*sizeof(char *), cmd.name);
      filelist[count] = strbuf;
      count++;
    }
  }
  
  closedir(dir);

  *filelistp = filelist;
  *countp = count;
  return count;
}

void free_filelist(char** filelist, int count) {
  int i;

  for (i=0; i<count; i++)
    free(filelist[i]);
  free(filelist);
}

/* ---------------------------------------------------------------------- */
/* if filename is a directory or a symlink to a directory, traverse
   recursively if appropriate or issue warning and do nothing. In all
   other cases, call action with the filename. Do this even if the
   file does not exist. Descend into directories if recursive>=1, and
   follow symlinks if recursive==2. */

void traverse_file(char *filename) {
  struct stat buf;
  int st;
  int link = 0;
  int r;
  
  st = lstat(filename, &buf);
  if (!st && S_ISLNK(buf.st_mode)) {  /* is a symbolic link */
    link = 1;
    st = stat(filename, &buf);
  }
  if (st || !S_ISDIR(buf.st_mode)) {
    file_action(filename);
    return;
  }
  
  /* is a directory */
  if (cmd.recursive<=1 && link==1) { /* ignore link */
    if (cmd.verbose>=0)
      fprintf(stderr, "%s: %s: directory is a symbolic link -- ignored\n", cmd.name, filename);
    return;
  }

  if (cmd.recursive==0) {  /* ignore */
    if (cmd.verbose>=0) {
      fprintf(stderr, "%s: %s: is a directory -- ignored\n", cmd.name, filename);
    }
    return;
  } 

  r = known_inode(buf.st_ino, buf.st_dev);

  if (r != -1) { /* already traversed */
    if (cmd.verbose>0) {
      fprintf(stderr, "Already visited directory %s -- skipped.\n", filename);
    }
    return;
  }
  
  add_inode(buf.st_ino, buf.st_dev, 1);

  /* recursively traverse directory */
  {
    char **filelist;
    int count;

    get_filelist(filename, &filelist, &count);
    traverse_files(filelist, count);
    free_filelist(filelist, count);
  }
}

/* same as traverse_file, except go through a list of files. */
void traverse_files(char **filelist, int count) {
  while (count > 0) {
    traverse_file(*filelist);
    ++filelist, --count;
  }
}
