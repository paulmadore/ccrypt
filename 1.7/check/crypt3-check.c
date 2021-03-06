/* Copyright (C) 2000-2004 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* test the crypt(3) replacement against the library crypt(3). Note
   that on many systems, crypt(3) does not exist, and even on those
   systems where it does, it is often buggy. 

   crypt(3) only looks at the lower 7 bits of the characters in a key,
   and only at the first 8 characters. Some implementations differ in
   whether they consider 128 as an end-of-string character or not
   (FreeBSD does, SunOS and GNU do not). The character 128 is unlikely
   to appear in a password, and we only check compliance for
   characters 1-127 here. */

#ifdef HAVE_CONFIG_H
#include <config.h>  /* generated by configure */
#endif

#ifndef HAVE_LIBCRYPT      /* this check doesn't make sense if the
			      reference crypt(3) is not available */
int main() {
  return 77;
}

#else

#define _XOPEN_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "../src/unixcrypt3.h"

#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

int main() {
  int seed = time(0);
  int total = 0;
  int i,j,l,n,k;
  char salt[2];
  char key[8];
  char res1[13];
  char res2[13];
  char *p;

  printf("Random seed: %d\n", seed);
  srand(seed);

  /* give it a good spin */
  for (i=0; i<64; i++) {
    salt[0] = bin_to_ascii(i);

    for (k=0; k<20; k++) {
      j = rand() % 64;
      salt[1] = bin_to_ascii(j);

      l = rand() % 9;
      for (n=0; n<l; n++) {
	key[n] = rand() % 127 + 1;
      }
      if (n<8) {
	key[n] = 0;
      }
      p = crypt_replacement(key, salt);
      strncpy(res1, p, 13);
      p = crypt(key, salt);
      strncpy(res2, p, 13);
      if (strncmp(res1, res2, 13)!=0) {
        printf("Discrepancy for salt %c%c, password length %d\n",
               salt[0], salt[1], l);
        total++;
      }
    }
  }
  
  if (total) {
    printf("Failed: %d discrepancies.\n", total);
    return 1;
  } else {
    printf("Passed.\n");
    return 0;
  }
}

#endif /* HAVE_LIBCRYPT */
