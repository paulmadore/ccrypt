/* Copyright (C) 2000-2003 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* rijndael.h */
/* $Id: rijndael.h,v 1.5 2003/03/30 00:38:29 selinger Exp $ */

/* derived from original source: rijndael-alg-ref.h   v2.0   August '99
 * Reference ANSI C code for NIST competition
 * authors: Paulo Barreto
 *          Vincent Rijmen
 */

#ifndef __RIJNDAEL_H
#define __RIJNDAEL_H

# ifndef __RIJNDAEL_WORD
# define __RIJNDAEL_WORD

#include <config.h>    /* generated by configure */

typedef unsigned char		word8;

typedef UINT32_TYPE word32;

# endif /* __RIJNDAEL_WORD */

#include "tables.h"

#define MAXBC		(256/32)
#define MAXKC		(256/32)
#define MAXROUNDS	14
#define MAXRK           ((MAXROUNDS+1)*MAXBC)

typedef struct {
  int BC;
  int KC;
  int ROUNDS;
  int shift[2][4];
  word32 rk[MAXRK];
} roundkey;

/* keys and blocks are externally treated as word32 arrays, to
   make sure they are aligned on 4-byte boundaries on architectures
   that require it. */

/* make a roundkey rkk from key. key must have appropriate size given
   by keyBits. keyBits and blockBits may only be 128, 196, or
   256. Returns non-zero if arguments are invalid. */

int xrijndaelKeySched (word32 key[], int keyBits, int blockBits, 
		       roundkey *rkk);

/* encrypt, resp. decrypt, block using rijndael roundkey rkk. rkk must
   have been created with xrijndaelKeySched. Size of block, in bits,
   must be equal to blockBits parameter that was used to make rkk. In
   all other cases, behavior is undefined - for reasons of speed, no
   check for error conditions is done. */

void xrijndaelEncrypt (word32 block[], roundkey *rkk);
void xrijndaelDecrypt (word32 block[], roundkey *rkk);

#endif /* __RIJNDAEL_H */
