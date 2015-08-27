/* Copyright (C) 2000-2003 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* traverse.c: functions for traversing through a list of files,
   optionally recursing through directory structure, and doing
   whatever action is required for encrypting/decrypting files in the
   various modes */
/* $Id: traverse.c,v 1.9 2003/03/30 00:38:29 selinger Exp $ */ 

#define _FILE_OFFSET_BITS 64  /* turn off 2GB limit on file size */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <utime.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

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
/* suffix handling */

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

  if (suffix[0]==0 || !has_suffix(filename, suffix)) {
    return filename;
  }
  outfile = xrealloc(outfile, flen-slen+1, cmd.name);
  strncpy (outfile, filename, flen-slen);
  outfile[flen-slen] = 0;
  return outfile;
}

/* ---------------------------------------------------------------------- */
/* some helper functions */

/* read a yes/no response from the user */
int prompt(void) {
  char *line;
  FILE *fin;
  int r;

  fin = fopen("/dev/tty", "r");
  if (fin==NULL) {
    fin = stdin;
  }
  
  line = xreadline(fin, cmd.name);
  r = line && (!strcmp(line, "y") || !strcmp(line, "yes"));
  free(line);
  return r;
}

/* check whether named file exists */
int file_exists(char *filename) {
  struct stat buf;
  int st;

  st = lstat(filename, &buf);

  if (st) {
    return 0;
  } else {
    return 1;
  }
}

/* ---------------------------------------------------------------------- */
/* read a whole directory into a data structure. This is because we
   change directory entries while traversing the directory; this could
   otherwise lead to strange behavior on Solaris. After done with the
   file list, it should be freed with free_filelist. */

int get_filelist(char *dirname, char*** filelistp, int *countp) {
  DIR *dir;
  struct dirent *dirent;
  char **filelist = NULL;
  int count = 0;

  dir = opendir(dirname);
  if (dir==NULL) {
    fprintf(stderr, "%s: %s: %s\n", cmd.name, dirname, strerror(errno));
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

/* file actions for the individual modes. */

/* local signal handler for overwrite mode - catch interrupt signal */
int sigint_flag = 0;

void sigint_overwrite(int dummy) {
  static time_t sigint_time = 0;
  int save_errno = errno;
  
  /* exit if two SIGINTS are received in one second */
  if ((time(NULL)-sigint_time) <= 1) {
    fprintf(stderr, "%s: interrupted.\n", cmd.name);
    exit(6);
  }

  /* otherwise, schedule to exit at the end of the current file. Note:
     this signal handler is only in use if we're not in cat,
     unixcrypt, or filter mode */
  sigint_time = time(NULL);
  sigint_flag = 1;
  fprintf(stderr, "Interrupt - will exit after current file. Press CTRL-C twice to exit now.\n");
  errno = save_errno;
}

/* this function is called to act on a file in overwrite mode */
void action_overwrite(char *infile, char *outfile) {
  int st;
  struct stat buf;
  int do_chmod = 0;
  int r;
  int fd;
  int save_errno;
  
  /* read file attributes */
  st = stat(infile, &buf);
  if (st) {
    fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
    return;
  }

  /* check whether this file is write protected */
  if ((buf.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0) {
    /* file is write-protected. In this case, we prompt the user to
       see if they want to operate on it anyway. Or if they give the
       "-f" option, we just do it without asking. */
    if (!cmd.force) {
      fprintf(stderr, "%s: %s write-protected file %s (y or n)? ", cmd.name, cmd.mode == ENCRYPT ? "encrypt" : cmd.mode == KEYCHANGE ? "perform keychange on" : "decrypt", infile);
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
  
  /* check whether this inode was already handled under another filename */
  r = known_inode(buf.st_ino, buf.st_dev);
  if (r != -1 && cmd.verbose>0) {
    fprintf(stderr, "Already visited inode %s.\n", infile);
  }
  if (r == 0) {
    /* previous action on this inode failed - do nothing */
    return;
  } else if (r == 1) {
    /* previous action on this inode succeeded - rename only */
    goto rename;
  }
  
  /* act on this inode now */
  if (buf.st_nlink>1 && cmd.verbose>=0) {
    fprintf(stderr, "%s: warning: %s has %d links\n", cmd.name, 
	    infile, buf.st_nlink);
  }
  if (do_chmod) {
    chmod(infile, buf.st_mode | S_IWUSR);
  }
  
  /* open file */
#ifdef __CYGWIN__
  fd = open(infile, O_RDWR | O_BINARY);
#else
  fd = open(infile, O_RDWR);
#endif
  if (fd == -1) {
    /* could not open file. */
    fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
    add_inode(buf.st_ino, buf.st_dev, 0);
    return;
  }
  
  /* set local signal handler for SIGINT */
  signal(SIGINT, sigint_overwrite);

  /* crypt */
  switch (cmd.mode) {   /* note: can't be CAT or UNIXCRYPT */

  case ENCRYPT: default:
    if (cmd.verbose>0) {
      fprintf(stderr, "Encrypting %s\n", infile);
    }
    r = ccencrypt_file(fd, cmd.keyword);
    break;
    
  case DECRYPT:
    if (cmd.verbose>0) {
      fprintf(stderr, "Decrypting %s\n", infile);
    }
    r = ccdecrypt_file(fd, cmd.keyword);
    break;
    
  case KEYCHANGE:
    if (cmd.verbose>0) {
      fprintf(stderr, "Changing key for %s\n", infile);
    }
    r = cckeychange_file(fd, cmd.keyword, cmd.keyword2);
    break;
    
  }    
  save_errno = errno;
  
  /* restore the original file attributes for this file descriptor. 
     Ignore failures silently */
  fchown(fd, buf.st_uid, buf.st_gid);
  fchmod(fd, buf.st_mode);

  /* close file */
  close(fd);

  /* now restore original modtime */
  {
    struct utimbuf ut = {buf.st_atime, buf.st_mtime};

    utime(infile, &ut);
  }
  
  /* restore default signal handler */
  signal(SIGINT, SIG_DFL);

  errno = save_errno;
  if (r==-2) {
    fprintf(stderr, "%s: %s: %s -- unchanged\n", cmd.name, infile, ccrypt_error(r));
    add_inode(buf.st_ino, buf.st_dev, 0);
    return;
  } else if (r==-1) {
    fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
    exit(3);
  } else {
    add_inode(buf.st_ino, buf.st_dev, 1);
  }

 rename:
  /* rename file if necessary */
  if (strcmp(infile, outfile)) {
    r = rename(infile, outfile);
    if (r) {
      fprintf(stderr, "%s: could not rename %s as %s: %s\n", cmd.name, 
	      infile, outfile, strerror(errno));
    }
  }
  
  if (sigint_flag) {  /* SIGINT received while crypting - delayed exit */
    exit(6);
  }
}

/* local signal handler for SIGINT for tmpfiles mode */
char *sigint_tmpfilename;

void sigint_tmpfiles(int dummy) {
  unlink(sigint_tmpfilename);
  exit(6);
}

/* this function is called to act on a file in tmpfiles mode */
void action_tmpfiles(char *infile, char *outfile) {
  int st;
  struct stat buf;
  char *tmpfile;
  int fdout;
  int r;
  int save_errno;
  FILE *fin, *fout;

  /* tmpfiles mode is supposed to provide safety from data corruption.
     We have the following goal: at any given time, either infile
     should contain the original file contents, or outfile should
     contain the new file contents. Thus, if execution gets
     interrupted at any given time, at least one of the two files
     should exist and be un-corrupted.

     There are several cases to consider. (1) The most common case is
     that infile != outfile, and outfile does not yet exist. In this
     case, we just crypt from infile to outfile, then change outfile's
     attributes, then remove infile.

     (2) It can also happen that infile == outfile, or that outfile
     already exists. In this case, we will create a temporary filename
     in the same directory as outfile, crypt from infile to tmpfile,
     then change tmpfile's attributes, then rename tmpfile as outfile,
     then remove infile (unless infile == outfile). In this way, we
     avoid destroying the previous contents of outfile until crypting
     is complete.

     Cases (1) and (2) can be handled uniformly; we simply chose
     tmpfile == outfile if we are in case (1), and omit the extra
     renaming step. 

     If an error occurs during crypting (e.g., a non-matching
     password, i/o error, etc), we remove the file being currently
     written, and therefore we return everything to its original
     state. If an error occurs during one of the final renaming steps,
     we print a warning, but we do not remove the tmpfile/outfile in
     this case (since its contents are presumably valid). I guess it
     is okay to still remove infile in this case if infile!=outfile. */

  /* read infile attributes */
  st = stat(infile, &buf);
  if (st) {
    fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
    return;
  }
  
  /* if infile==outfile or outfile exists, need to make a new
     temporary file name. Else, just use outfile. */
  if (strcmp(infile, outfile)==0 || file_exists(outfile)) {
    tmpfile = xalloc(strlen(outfile)+8, cmd.name);
    strcpy(tmpfile, outfile);
    strcat(tmpfile, ".XXXXXX");
    fdout = mkstemp(tmpfile);
    if (fdout == -1) {
      fprintf(stderr, "%s: could not create temporary file for %s: %s\n", cmd.name, outfile, strerror(errno));
      free(tmpfile);
      return;
    }
  } else {
    tmpfile = strdup(outfile);
#ifdef __CYGWIN__
    fdout = open(tmpfile, O_CREAT | O_EXCL | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
#else
    fdout = open(tmpfile, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
#endif
    if (fdout == -1) {
      fprintf(stderr, "%s: %s: %s\n", cmd.name, tmpfile, strerror(errno));
      free(tmpfile);
      return;
    }
  }

  /* set local signal handler to remove tmpfile on SIGINT */
  sigint_tmpfilename = tmpfile;
  signal(SIGINT, sigint_tmpfiles);
  
  /* tmpfile: allocated string, fdout: open (and newly created) file */

  /* open file */
  fin = fopen(infile, "rb");
  if (fin == NULL) {
    /* could not open file. */
    fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
    goto fail_with_fdout;
  }
  fout = fdopen(fdout, "wb");
  if (fout == NULL) {
    /* oops? */
    fprintf(stderr, "%s: %s: %s\n", cmd.name, tmpfile, strerror(errno));
    fclose(fin);
    goto fail_with_fdout;
  }

  /* crypt */
  switch (cmd.mode) {   /* note: can't be CAT or UNIXCRYPT */
  case ENCRYPT: default:
    if (cmd.verbose>0) {
      fprintf(stderr, "Encrypting %s\n", infile);
    }
    r = ccencrypt_streams(fin, fout, cmd.keyword);
    break;
  case DECRYPT:
    if (cmd.verbose>0) {
      fprintf(stderr, "Decrypting %s\n", infile);
    }
    r = ccdecrypt_streams(fin, fout, cmd.keyword);
    break;
  case KEYCHANGE:
    if (cmd.verbose>0) {
      fprintf(stderr, "Changing key for %s\n", infile);
    }
    r = cckeychange_streams(fin, fout, cmd.keyword, cmd.keyword2);
    break;
  }    
  save_errno = errno;

  /* restore the original file attributes for this file descriptor. 
     Ignore failures silently */
  fchown(fdout, buf.st_uid, buf.st_gid);
  fchmod(fdout, buf.st_mode);

  /* close files */
  fclose(fout);  /* this also closed the underlying fdout */
  fclose(fin);

  /* now restore original modtime */
  {
    struct utimbuf ut = {buf.st_atime, buf.st_mtime};

    utime(tmpfile, &ut);
  }
  
  errno = save_errno;

  /* handle errors */
  if (r==-2) {  /* e.g., key mismatch */
    fprintf(stderr, "%s: %s: %s -- unchanged\n", cmd.name, infile, ccrypt_error(r));
    goto fail_with_tmpfile;
  } else if (r==-1) { /* e.g. i/o error */
    fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
    unlink(tmpfile);
    exit(3);
  }

  /* restore default signal handler */
  signal(SIGINT, SIG_DFL);

  /* crypting was successful. Now rename new file if necessary */
  if (strcmp(tmpfile, outfile) != 0) {
    r = rename(tmpfile, outfile);
    if (r == -1) {
      fprintf(stderr, "%s: could not rename %s to %s: %s\n", cmd.name, tmpfile, outfile, strerror(errno));
    }
  }
  free(tmpfile);

  /* unlink original file, if necessary */
  if (strcmp(infile, outfile) != 0) {
    r = unlink(infile);
    if (r == -1) {
      fprintf(stderr, "%s: could not remove %s: %s\n", cmd.name, infile, strerror(errno));
    }
  }

  return;
  
 fail_with_fdout:
  close(fdout);
 fail_with_tmpfile:
  unlink(tmpfile);
  free(tmpfile);

  /* restore default signal handler */
  signal(SIGINT, SIG_DFL);
  return;
}

/* this function is called to act on a file if cmd.mode is CAT or
   UNIXCRYPT */
void action_cat(char *infile) {
  int r;
  FILE *fin;
  int save_errno;

  /* open file */
  fin = fopen(infile, "rb");
  if (fin == NULL) {
    fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
    return;
  }

  /* crypt */

  if (cmd.verbose>0) {
    fprintf(stderr, "Decrypting %s\n", infile);
    fflush(stderr);
  }
  
  if (cmd.mode==UNIXCRYPT) {
    r = unixcrypt_streams(fin, stdout, cmd.keyword);
  } else {
    r = ccdecrypt_streams(fin, stdout, cmd.keyword);
  }
  save_errno = errno;
  fflush(stdout);

  /* close file */
  fclose(fin);

  errno = save_errno;

  /* handle errors */
  if (r==-2) {
    fprintf(stderr, "%s: %s: %s -- ignored\n", cmd.name, infile, ccrypt_error(r));
  } else if (r==-1) {
    fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
    exit(3);
  }
}
	  
/* ---------------------------------------------------------------------- */
/* file_action(): this procedure is called once for each file
   encountered (on the command line, or while recursively traversing
   directories, etc). It is only called on files (and symlinks to
   files), not directories. The decision whether to follow a symbolic
   link is made here. Also, the name of the input and (except in cat
   and unixcrypt mode) output filename is determined here - this
   involves manipulating suffixes as needed. Furthermore, the decision
   of whether to overwrite an existing outfile is also made here. Note
   that the file_action procedure does not itself write or modify
   anything in the filesystem; these tasks are delegated to the
   mode-specific action_* functions. */

void file_action(char *filename) {
  struct stat buf;
  int st;
  int link = 0;
  char buffer[strlen(filename)+strlen(cmd.suffix)+1];
  char *outfile;
  char *infile;

  infile = filename;  /* but it may be changed below */

  st = lstat(infile, &buf);

  if (st) {
    int save_errno = errno;

    /* if file didn't exist and decrypting, try if suffixed file exists */
    if (errno==ENOENT 
	&& (cmd.mode==DECRYPT || cmd.mode==CAT || cmd.mode==KEYCHANGE 
	    || cmd.mode==UNIXCRYPT) 
	&& cmd.suffix[0]!=0) {
      strcpy(buffer, infile);
      strcat(buffer, cmd.suffix);
      infile=buffer;
      st = lstat(buffer, &buf);
    }
    if (st) {
      fprintf(stderr, "%s: %s: %s\n", cmd.name, filename, strerror(save_errno));
      return;
    }
  }
  
  /* if link following is enabled, follow links */
  if (cmd.symlinks && S_ISLNK(buf.st_mode)) {
    link = 1;
    st = stat(infile, &buf);
    if (st) {
      fprintf(stderr, "%s: %s: %s\n", cmd.name, infile, strerror(errno));
      return;
    }
  }

  /* assert st==0 */

  /* if file is not a regular file, skip */
  if (S_ISLNK(buf.st_mode)) {
    if (cmd.verbose>=0) {
      fprintf(stderr, "%s: %s: is a symbolic link -- ignored\n", cmd.name, infile);
    }
    return;
  }
  if (!S_ISREG(buf.st_mode)) {
    if (cmd.verbose>=0) {
      fprintf(stderr, "%s: %s: is not a regular file -- ignored\n", cmd.name, 
	      infile);
    }
    return;
  }
  
  /* now we have a regular file, and we have followed a link if
     appropriate. */

  if (cmd.mode==ENCRYPT || cmd.mode==DECRYPT || cmd.mode==KEYCHANGE) {
    /* determine outfile name */
    switch (cmd.mode) {
    case ENCRYPT: default:
      if (cmd.strictsuffix && cmd.suffix[0] != 0 && has_suffix(infile, cmd.suffix)) {
	if (cmd.verbose>=0) {
	  fprintf(stderr, "%s: %s already has %s suffix -- ignoring\n", cmd.name, infile, cmd.suffix); 
	}
	return;
      }
      outfile = add_suffix(infile, cmd.suffix);
      break;
    case DECRYPT:
      outfile = remove_suffix(infile, cmd.suffix);
      break;
    case KEYCHANGE:
      outfile = infile;
      break;
    }
    
    /* if outfile exists and cmd.force is not set, prompt whether to
       overwrite */
    if (!cmd.force && strcmp(infile, outfile) && 
	file_exists(outfile)) {
      fprintf(stderr, "%s: %s already exists; overwrite (y or n)? ", cmd.name, 
	      outfile);
      fflush(stderr);
      if (prompt()==0) {
	fprintf(stderr, "Not overwritten.\n");
	return;
      }
    }
    if (cmd.tmpfiles) {
      action_tmpfiles(infile, outfile);
    } else {
      action_overwrite(infile, outfile);
    }
  } else {
    action_cat(infile);
  }
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
    if (cmd.verbose>=0) {
      fprintf(stderr, "%s: %s: directory is a symbolic link -- ignored\n", cmd.name, filename);
    }
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
