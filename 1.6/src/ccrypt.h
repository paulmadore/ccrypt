/* Copyright (C) 2000-2003 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* ccrypt.c: high-level functions for accessing ccryptlib */
/* $Id: ccrypt.h,v 1.4 2003/03/30 00:38:29 selinger Exp $ */

/* ccrypt implements a stream cipher based on the block cipher
   Rijndael, the candidate for the AES standard. */

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "ccryptlib.h"

const char *ccrypt_error(int st);

int ccencrypt_streams(FILE *fin, FILE *fout, char *key);
int ccdecrypt_streams(FILE *fin, FILE *fout, char *key);
int cckeychange_streams(FILE *fin, FILE *fout, char *key1, char *key2);
int unixcrypt_streams(FILE *fin, FILE *fout, char *key);

int ccencrypt_file(int fd, char *key);
int ccdecrypt_file(int fd, char *key);
int cckeychange_file(int fd, char *key1, char *key2);
int unixcrypt_file(int fd, char *key);
