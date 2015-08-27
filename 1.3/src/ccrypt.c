/* Copyright (C) 2000-2002 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* ccrypt.c: high-level functions for accessing ccryptlib */
/* $Id: ccrypt.c,v 1.7 2002/09/26 17:12:37 selinger Exp $ */

/* ccrypt implements a stream cipher based on the block cipher
   Rijndael, the candidate for the AES standard. */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "ccryptlib.h"
#include "unixcryptlib.h"

/* heuristically, the fastest inbufsize is 992 - this is slightly, but
   significantly, faster than 1024 or very large buffer sizes. I'm not
   sure why this is - maybe some strange interaction between the
   filesystem blocksize and the page size? */

#define INBUFSIZE 992  
#define MIDBUFSIZE 1024  /* for key change */
#define OUTBUFSIZE 1056

/* ---------------------------------------------------------------------- */
/* ccrypt error messages. These correspond to the error codes returned
   by the ccrypt functions. Note: the error code -1 corresponds to a
   system error, with errno set, and the error code -2 corresponds to
   a ccrypt error, with ccrypt_errno set. */

const char *ccrypt_error(int st) {
  if (st == -1) {
    return strerror(errno);
  } else if (st == -2) {
    return ccrypt_errstr[ccrypt_errno];
  } else {
    return "unknown error";
  }
}

/* ---------------------------------------------------------------------- */
/* keychange = compose decryption and encryption */

struct keychange_state_s {
  ccrypt_stream_t b1;
  ccrypt_stream_t b2;
  int iv;                /* count-down for IV bytes */
  char buf[MIDBUFSIZE];
};
typedef struct keychange_state_s keychange_state_t;

int keychange_init(ccrypt_stream_t *b, char *key1, char *key2) {
  keychange_state_t *st;
  int r;

  st = malloc(sizeof(keychange_state_t));
  if (st == NULL) {
    return -1;
  }
  b->state = (void *)st;

  r = ccdecrypt_init(&st->b1, key1);
  if (r) {
    return r;
  }
  r = ccencrypt_init(&st->b2, key2);
  if (r) {
    return r;
  }
  st->b2.next_in = &st->buf;
  st->b2.avail_in = 0;
  st->iv = 32;  /* count down IV bytes */

  return 0;
}

int keychange(ccrypt_stream_t *b) {
  keychange_state_t *st = (keychange_state_t *)b->state;
  int r;

  /* note: we do not write anything until we have seen 32 bytes of
     input. This way, we don't write the output IV until the input IV
     has been verified. */

  while (1) { 
    /* clear mid-buffer */
    if (b->avail_out && !st->iv) {
      st->b2.next_out = b->next_out;
      st->b2.avail_out = b->avail_out;
      r = ccencrypt(&st->b2);
      if (r) {
	return r;
      }
      b->next_out = st->b2.next_out;
      b->avail_out = st->b2.avail_out;
    }
    
    /* if mid-buffer not empty, or no input available, stop */
    if (st->b2.avail_in != 0 || b->avail_in == 0) {
      break;
    }

    /* fill mid-buffer */
    st->b1.next_out = &st->buf;
    st->b1.avail_out = MIDBUFSIZE;
    st->b1.next_in = b->next_in;
    st->b1.avail_in = b->avail_in;
    r = ccdecrypt(&st->b1);
    if (r) {
      return r;
    }
    if (st->iv) {
      st->iv -= b->avail_in - st->b1.avail_in;
      if (st->iv <= 0) {
	st->iv = 0;
      }
    }
    b->next_in = st->b1.next_in;
    b->avail_in = st->b1.avail_in;
    st->b2.next_in = &st->buf;
    st->b2.avail_in = st->b1.next_out - st->b2.next_in;
  }
  return 0;
}

int keychange_end(ccrypt_stream_t *b) {
  keychange_state_t *st = (keychange_state_t *)b->state;
  int r, cerr, err;

  r = ccdecrypt_end(&st->b1);
  if (r) {
    cerr = ccrypt_errno;
    err = errno;
    ccencrypt_end(&st->b2);
    free(b->state);
    b->state = NULL;
    ccrypt_errno = cerr;
    errno = err;
    return r;
  }
  r = ccencrypt_end(&st->b2);
  if (r) {
    cerr = ccrypt_errno;
    err = errno;
    free(b->state);
    b->state = NULL;
    ccrypt_errno = cerr;
    errno = err;
    return r;
  }
  free(b->state);
  b->state = NULL;
  return 0;
}

/* ---------------------------------------------------------------------- */
/* encryption/decryption of streams */

typedef int initfun(ccrypt_stream_t *b, char *key);
typedef int workfun(ccrypt_stream_t *b);
typedef int endfun(ccrypt_stream_t *b);

/* apply ccrypt_stream to pipe stuff from fin to fout. Assume the
   ccrypt_stream has already been initialized. */
static int streamhandler(ccrypt_stream_t *b, workfun *work, endfun *end, 
			 FILE *fin, FILE *fout) {
  /* maybe should align buffers on page boundary */
  char inbuf[INBUFSIZE], outbuf[OUTBUFSIZE]; 
  int eof = 0;
  int r;
  int cerr, err;

  b->avail_in = 0;

  while (1) {
    /* fill input buffer */
    if (b->avail_in == 0 && !eof) {
      r = fread(inbuf, 1, INBUFSIZE, fin);
      b->next_in = &inbuf;
      b->avail_in = r;
      if (r<INBUFSIZE) {
	eof = 1;
      }
    }
    /* prepare output buffer */
    b->next_out = &outbuf;
    b->avail_out = OUTBUFSIZE;

    /* do some work */
    r = work(b);
    if (r) {
      cerr = ccrypt_errno;
      err = errno;
      end(b);
      ccrypt_errno = cerr;
      errno = err;
      return r;
    }
    /* process output buffer */
    if (b->avail_out < OUTBUFSIZE) {
      fwrite(outbuf, 1, OUTBUFSIZE-b->avail_out, fout);
    }
    if (eof && b->avail_out != 0) {
      break;
    }
  }
  r = end(b);
  if (r) {
    return r;
  }
  return 0;
}  

int ccencrypt_streams(FILE *fin, FILE *fout, char *key) {
  ccrypt_stream_t ccs;
  ccrypt_stream_t *b = &ccs;
  int r;

  r = ccencrypt_init(b, key);
  if (r) {
    return r;
  }

  return streamhandler(b, ccencrypt, ccencrypt_end, fin, fout);
}

int ccdecrypt_streams(FILE *fin, FILE *fout, char *key) {
  ccrypt_stream_t ccs;
  ccrypt_stream_t *b = &ccs;
  int r;

  r = ccdecrypt_init(b, key);
  if (r) {
    return r;
  }

  return streamhandler(b, ccdecrypt, ccdecrypt_end, fin, fout);
}

int cckeychange_streams(FILE *fin, FILE *fout, char *key1, char *key2) {
  ccrypt_stream_t ccs;
  ccrypt_stream_t *b = &ccs;
  int r;

  r = keychange_init(b, key1, key2);
  if (r) {
    return r;
  }

  return streamhandler(b, keychange, keychange_end, fin, fout);
}

int unixcrypt_streams(FILE *fin, FILE *fout, char *key) {
  ccrypt_stream_t ccs;
  ccrypt_stream_t *b = &ccs;
  int r;

  r = unixcrypt_init(b, key);
  if (r) {
    return r;
  }

  return streamhandler(b, unixcrypt, unixcrypt_end, fin, fout);
}

/* ---------------------------------------------------------------------- */
/* destructive encryption/decryption of files */

/* A large value of FILEINBUFSIZE keeps the cost of "lseek" down. It
   is okay for FILEINBUFSIZE to be much larger than MIDBUFSIZE.
   FILEOUTBUFSIZE must be large enough to hold the encryption of
   FILEINBUFSIZE in one piece, or otherwise there will be a buffer
   overflow error. */

#define FILEINBUFSIZE 10240
#define FILEOUTBUFSIZE (FILEINBUFSIZE+32)

/* apply ccrypt_stream to destructively update (and resize) the given
   fd, which must be opened in read/write mode and seekable.
   Encryption will begin at the current file position (normally 0),
   and extend until the end of the file. Note: this only works if the
   stream encoder b/work/end expands its input by at most
   FILEINBUFSIZE bytes; otherwise there will be a buffer overflow
   error. */

static int filehandler(ccrypt_stream_t *b, workfun *work, endfun *end,
		       int fd) {
  /* rp = reader's position, wp = writer's position, fp = file position */
  int p;      /* rp-wp */
  char inbuf[FILEINBUFSIZE];
  char outbuf[FILEINBUFSIZE+32];
  int inbufsize, outbufsize;
  off_t offs;
  int r;
  int i;
  int eof=0;
  int err, errc;

  p = 0;
  outbufsize = 0;

  while (1) {
    /* file is at position wp */
    if (p != 0) {
      r = lseek(fd, p, SEEK_CUR);
      if (r == -1) {
	goto error;
      }
    }
    /* file is at position rp */

    /* read block */
    i = 0;
    while (i<FILEINBUFSIZE && !eof) {
      r = read(fd, inbuf+i, FILEINBUFSIZE-i);
      if (r == -1) {
	goto error;
      } else if (r==0) {
	eof = 1;
      }
      i += r;
    }
    p += i;
    inbufsize = i;

    /* file is at position rp */
    if (p != 0) {
      r = lseek(fd, -p, SEEK_CUR);
      if (r == -1) {
	goto error;
      }
    }
    /* file is at position wp */

    /* write previous block */
    if (outbufsize > p && !eof) {
      ccrypt_errno = CCRYPT_EBUFFER; /* buffer overflow; should never happen */
      r = -2;
      goto error;
    }
    if (outbufsize != 0) {
      i = 0;
      while (i<outbufsize) {
	r = write(fd, outbuf+i, outbufsize-i);
	if (r == -1) {
	  goto error;
	}
	i += r;
      }
      p -= outbufsize;
      outbufsize = 0;
    }
    
    /* encrypt block */
    b->next_in = inbuf;
    b->avail_in = inbufsize;
    b->next_out = outbuf;
    b->avail_out = FILEINBUFSIZE+32;

    r = work(b);
    if (r) {
      goto error;
    }      
    
    if (b->avail_in != 0) {
      ccrypt_errno = CCRYPT_EBUFFER; /* buffer overflow; should never happen */
      r = -2;
      goto error;
    }
    inbufsize = 0;
    outbufsize = FILEINBUFSIZE+32-b->avail_out;

    if (eof && outbufsize == 0) { /* done */
      break;
    }
  }
  /* file is at position wp */

  /* close the stream (we need to do this before truncating, because
     there might be an error!) */
  r = end(b);
  if (r) {
    return r;
  }

  /* truncate the file to where it's been written */
  r = offs = lseek(fd, 0, SEEK_CUR);
  if (r == -1) {
    return -1;
  }
  r = ftruncate(fd, offs);
  if (r == -1) {
    return -1;
  }
  
  return 0;

 error:
  err = errno;
  errc = ccrypt_errno;
  end(b);
  errno = err;
  ccrypt_errno = errc;
  return r;
}

int ccencrypt_file(int fd, char *key) {
  ccrypt_stream_t ccs;
  ccrypt_stream_t *b = &ccs;
  int r;

  r = ccencrypt_init(b, key);
  if (r) {
    return r;
  }

  return filehandler(b, ccencrypt, ccencrypt_end, fd);
}

int ccdecrypt_file(int fd, char *key) {
  ccrypt_stream_t ccs;
  ccrypt_stream_t *b = &ccs;
  int r;

  r = ccdecrypt_init(b, key);
  if (r) {
    return r;
  }

  return filehandler(b, ccdecrypt, ccdecrypt_end, fd);
}

int cckeychange_file(int fd, char *key1, char *key2) {
  ccrypt_stream_t ccs;
  ccrypt_stream_t *b = &ccs;
  int r;

  r = keychange_init(b, key1, key2);
  if (r) {
    return r;
  }

  return filehandler(b, keychange, keychange_end, fd);
}

int unixcrypt_file(int fd, char *key) {
  ccrypt_stream_t ccs;
  ccrypt_stream_t *b = &ccs;
  int r;

  r = unixcrypt_init(b, key);
  if (r) {
    return r;
  }

  return filehandler(b, unixcrypt, unixcrypt_end, fd);
}
