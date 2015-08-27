/* Copyright (C) 2000-2009 Peter Selinger.
   This file is part of ccrypt. It is free software and it is covered
   by the GNU general public license. See the file COPYING for details. */

/* user interface for ccrypt: encrypt and decrypt files and streams */
/* $Id: main.c 258 2009-08-26 17:46:10Z selinger $ */ 

/* This is written to replace the UNIX crypt utility, which uses a
   weak algorithm and is often omitted from free UNIX distributions.
   ccrypt can operate as a filter like crypt, or it can operate
   directly on files in the manner of gzip; it can overwrite files
   in-place on media that support read/write access. Encryption is
   based on the Rijndael algorithm, one of the contenders for the
   U.S. government's Advances Encryption Standard (AES). */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <locale.h>

#ifdef HAVE_CONFIG_H
#include <config.h>  /* generated by configure */
#endif

#include "main.h"
#include "readkey.h"
#include "ccrypt.h"
#include "traverse.h"
#include "xalloc.h"
#include "unixcryptlib.h"
#include "platform.h"

#include "gettext.h"
#define _(String) gettext (String)

cmdline cmd;

/* print usage information */

static void usage(FILE *fout) {
  fprintf(fout, _("%s %s. Secure encryption and decryption of files and streams.\n"), NAMECCRYPT, VERSION);
  fprintf(fout, "\n");
  fprintf(fout,
_("Usage: %s [mode] [options] [file...]\n"
"       %s [options] [file...]\n"
"       %s [options] [file...]\n"
"       %s [options] file...\n\n"), NAMECCRYPT, NAMEENCRYPT, NAMEDECRYPT, NAMECAT);
  fprintf(fout,
_("Modes:\n"
"    -e, --encrypt         encrypt\n"
"    -d, --decrypt         decrypt\n"
"    -c, --cat             cat; decrypt files to stdout\n"
"    -x, --keychange       change key\n"
"    -u, --unixcrypt       decrypt old unix crypt files\n"
"\n"
"Options:\n"
"    -h, --help            print this help message and exit\n"
"    -V, --version         print version info and exit\n"
"    -L, --license         print license info and exit\n"
"    -v, --verbose         print progress information to stderr\n"
"    -q, --quiet           run quietly; suppress warnings\n"
"    -f, --force           overwrite existing files without asking\n"
"    -m, --mismatch        allow decryption with non-matching key\n"
"    -E, --envvar var      read keyword from environment variable (unsafe)\n"
"    -K, --key key         give keyword on command line (unsafe)\n"
"    -k, --keyfile file    read keyword(s) as first line(s) from file\n"
"    -P, --prompt prompt   use this prompt instead of default\n"
"    -S, --suffix .suf     use suffix .suf instead of default %s\n"
"    -s, --strictsuffix    refuse to encrypt files which already have suffix\n"
"    -F, --envvar2 var     as -E for second keyword (for keychange mode)\n"
"    -H, --key2 key        as -K for second keyword (for keychange mode)\n"
"    -Q, --prompt2 prompt  as -P for second keyword (for keychange mode)\n"
"    -t, --timid           prompt twice for encryption keys (default)\n"
"    -b, --brave           prompt only once for encryption keys\n"
"    -y, --keyref file     encryption key must match this encrypted file\n"
"    -r, --recursive       recurse through directories\n"
"    -R, --rec-symlinks    follow symbolic links as subdirectories\n"
"    -l, --symlinks        dereference symbolic links\n"
"    -T, --tmpfiles        use temporary files instead of overwriting (unsafe)\n"
"    --                    end of options, filenames follow\n"),
	  SUF);
}

/* print version and copyright information */
static void version(FILE *fout) {
  fprintf(fout, _("%s %s. Secure encryption and decryption of files and streams.\n"), NAMECCRYPT, VERSION);
  fprintf(fout, _("Copyright (C) 2000-2009 Peter Selinger.\n"));
}

static void license(FILE *fout) {
  fprintf(fout, _("%s %s. Secure encryption and decryption of files and streams.\n"), NAMECCRYPT, VERSION);
  fprintf(fout, _("Copyright (C) 2000-2009 Peter Selinger.\n"));
  fprintf(fout, "\n");
  fprintf(fout,
  _("For the full text of the GNU General Public License, see the file\n"
  "COPYING distributed with this software.\n"
  "\n"
  "This program is free software; you can redistribute it and/or modify\n"
  "it under the terms of the GNU General Public License as published by\n"
  "the Free Software Foundation; either version 2 of the License, or\n"
  "(at your option) any later version.\n"
  "\n"
  "This program is distributed in the hope that it will be useful,\n"
  "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
  "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
  "GNU General Public License for more details.\n"
  "\n"
  "You should have received a copy of the GNU General Public License\n"
  "along with this program; if not, write to the Free Software\n"
  "Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.\n")
  );
}

/* ---------------------------------------------------------------------- */
/* read the command line */

static void output_commandline(cmdline cmd, FILE *fout) {
  char *recursive[] = {"no", "dirs, not symlinks", "dirs and symlinks"};
  char *verbosity[] = {"quiet", "normal", "verbose"};
  char *mode[] = {"encrypt", "decrypt", "keychange", "cat", "unixcrypt"};

  fprintf(fout, _("\nCommand line:\n"));
  fprintf(fout, "name = %s\n", cmd.name);
  fprintf(fout, "verbosity = %s\n", verbosity[cmd.verbose+1]);
  fprintf(fout, "debug = %d\n", cmd.debug);
  fprintf(fout, "keyword = %s\n", cmd.keyword ? _("(known)") : _("(unknown)"));
  fprintf(fout, "keyword2 = %s\n", cmd.keyword2 ? _("(known)") : _("(unknown)"));
  fprintf(fout, "mode = %s\n", mode[cmd.mode]);
  fprintf(fout, "filter = %s\n", cmd.filter ? "yes" : "no");
  fprintf(fout, "tmpfiles = %s\n", cmd.tmpfiles ? "yes" : "no");
  fprintf(fout, "suffix = %s\n", cmd.suffix);
  fprintf(fout, "prompt = %s\n", cmd.prompt ? cmd.prompt : _("(none)"));
  fprintf(fout, "prompt2 = %s\n", cmd.prompt2 ? cmd.prompt2 : _("(none)"));
  fprintf(fout, "recursive = %s\n", recursive[cmd.recursive]);
  fprintf(fout, "symlinks = %s\n", cmd.symlinks ? "yes" : "no");
  fprintf(fout, "force = %s\n", cmd.force ? "yes" : "no");
  fprintf(fout, "mismatch = %s\n", cmd.mismatch ? "yes" : "no");
  fprintf(fout, "keyfile = %s\n", cmd.keyfile ? cmd.keyfile : _("(none)"));
  fprintf(fout, "timid = %s\n", cmd.timid ? "yes" : "no");
  fprintf(fout, "keyref = %s\n", cmd.keyref ? cmd.keyref : _("(none)"));
  fprintf(fout, "strictsuffix = %s\n", cmd.strictsuffix ? "yes" : "no");
  fprintf(fout, "infiles:");
  while (cmd.count-- > 0)
    fprintf(fout, " %s", *(cmd.infiles++));
  fprintf(fout, "\n\n");
}

static struct option longopts[] = {
  {"encrypt",      0, 0, 'e'},
  {"decrypt",      0, 0, 'd'},
  {"cat",          0, 0, 'c'},
  {"keychange",    0, 0, 'x'},
  {"unixcrypt",    0, 0, 'u'},
  {"help",         0, 0, 'h'},
  {"version",      0, 0, 'V'},
  {"license",      0, 0, 'L'},
  {"verbose",      0, 0, 'v'},
  {"quiet",        0, 0, 'q'},
  {"debug",        0, 0, 'D'},
  {"force",        0, 0, 'f'},
  {"mismatch",     0, 0, 'm'},
  {"envvar",       1, 0, 'E'},
  {"key",          1, 0, 'K'},
  {"keyfile",      1, 0, 'k'},
  {"prompt",       1, 0, 'P'},
  {"suffix",       1, 0, 'S'},
  {"strictsuffix", 0, 0, 's'},
  {"envvar2",      1, 0, 'F'},
  {"key2",         1, 0, 'H'},
  {"prompt2",      1, 0, 'Q'},
  {"timid",        0, 0, 't'},
  {"brave",        0, 0, 'b'},
  {"keyref",       1, 0, 'y'},
  {"recursive",    0, 0, 'r'},
  {"rec-symlinks", 0, 0, 'R'},
  {"symlinks",     0, 0, 'l'},
  {"tmpfiles",     0, 0, 'T'},
  {0, 0, 0, 0}
};

static char *shortopts = "edcxuhVLvqDfmE:K:k:F:H:S:sP:Q:tby:rRlT-";

static cmdline read_commandline(int ac, char *av[]) {
  cmdline cmd;
  int c;
  char *p;

  /* defaults: */
  cmd.verbose = 0;
  cmd.debug = 0;
  cmd.keyword = NULL;
  cmd.keyword2 = NULL;
  cmd.mode = ENCRYPT;
  cmd.suffix = SUF;
  cmd.prompt = NULL;
  cmd.prompt2 = NULL;
  cmd.recursive = 0;
  cmd.symlinks = 0;
  cmd.force = 0;
  cmd.mismatch = 0;
  cmd.filter = 1;
  cmd.infiles = NULL;
  cmd.count = 0;
  cmd.keyfile = NULL;
  cmd.timid = 1;
  cmd.keyref = NULL;
  cmd.strictsuffix = 0;
  cmd.tmpfiles = 0;

  /* find the basename with which we were invoked */
  cmd.name = strrchr(av[0], '/');
  cmd.name = cmd.name ? cmd.name+1 : av[0];

  if (!strcmp(cmd.name, NAMEENCRYPT)) {
    cmd.mode = ENCRYPT;
  } else if (!strcmp(cmd.name, NAMEDECRYPT)) {
    cmd.mode = DECRYPT;
  } else if (!strcmp(cmd.name, NAMECAT)) {
    cmd.mode = CAT;
  } else {
    cmd.name = av[0] = NAMECCRYPT;
  }

  while ((c = getopt_long(ac, av, shortopts, longopts, NULL)) != -1) {
    switch (c) {
    case 'h':
      usage(stdout);
      exit(0);
      break;
    case 'V':
      version(stdout);
      exit(0);
      break;
    case 'L':
      license(stdout);
      exit(0);
      break;
    case 'v':
      cmd.verbose=1;
      break;
    case 'q':
      cmd.verbose=-1;
      break;
    case 'D':
      cmd.debug++;
      break;
    case 'E':
    case 'F':
      p = getenv(optarg);
      if (p==NULL) {
	fprintf(stderr, _("%s: environment variable %s does not exist.\n"),
		cmd.name, optarg);
	exit(9);
      }
      if (c == 'E') {
	cmd.keyword = strdup(p);
      } else {
	cmd.keyword2 = strdup(p);
      }
      /* attempt to erase keyword from the environment, so that
         subsequent calls to 'ps' don't display it */
      for (; *p; p++) {
	*p = 0;
      }
      break;
    case 'K':
      cmd.keyword = strdup(optarg);
      /* attempt to erase keyword from command line so that subsequent
         calls to 'ps' don't display it */
      for (p=optarg; *p; p++) {  
	*p = 0;
      }
      break;
    case 'H':
      cmd.keyword2 = strdup(optarg);
      /* attempt to erase keyword from command line so that subsequent
         calls to 'ps' don't display it */
      for (p=optarg; *p; p++) {  
	*p = 0;
      }
      break;
    case 'k':
      cmd.keyfile = optarg;
      break;
    case 'S':
      cmd.suffix = optarg;
      break;
    case 's':
      cmd.strictsuffix = 1;
      break;
    case 'P':
      cmd.prompt = optarg;
      break;
    case 'Q':
      cmd.prompt2 = optarg;
      break;
    case 'e':
      cmd.mode = ENCRYPT;
      break;
    case 'd':
      cmd.mode = DECRYPT;
      break;
    case 'c':
      cmd.mode = CAT;
      break;
    case 'x':
      cmd.mode = KEYCHANGE;
      break;
    case 'u':
      cmd.mode = UNIXCRYPT;
      break;
    case 't':
      cmd.timid = 1;
      break;
    case 'b':
      cmd.timid = 0;
      break;
    case 'y':
      cmd.keyref = optarg;
      cmd.timid = 0;
      break;
    case 'r':
      cmd.recursive = 1;
      break;
    case 'R':
      cmd.recursive = 2;
      break;
    case 'l':
      cmd.symlinks = 1;
      break;
    case 'f':
      cmd.force = 1;
      break;
    case 'm':
      cmd.mismatch = 1;
      break;
    case 'T':
      cmd.tmpfiles = 1;
      break;
    case '?':
      fprintf(stderr, _("Try --help for more information.\n"));
      exit(1);
      break;
    default:
      fprintf(stderr, _("%s: unimplemented option -- %c\n"), cmd.name, c);
      exit(1);
    }
  }

  cmd.infiles = &av[optind];
  cmd.count = ac-optind;

  /* figure out if there are some filenames. Even an empty list of
     filenames is considered "some" filenames if "--" was used */

  if (cmd.count > 0 || strcmp(av[optind-1], "--")==0) {
    cmd.filter = 0;
  }

  /* in certain modes, allow symlinks by default */
  if (cmd.mode == CAT || cmd.mode == UNIXCRYPT) {
    cmd.symlinks = 1;
  }

  if (cmd.debug) {
    output_commandline(cmd, stderr);
  }

  /* and now check that options are consistent */

  /* don't allow killer combination of -m and destructive update */
  if (cmd.mismatch && !cmd.filter && cmd.mode!=CAT && cmd.mode!=UNIXCRYPT) {
    fprintf(stderr, _("%s: option -m can only be used with -c or when running as a filter.\n"), cmd.name);
    exit(1);
  }

  /* if not in filter mode, and 0 filenames follow, don't bother continuing */
  if (!cmd.filter && cmd.count==0) {
    if (cmd.verbose>=0) {
      fprintf(stderr, _("%s: warning: empty list of filenames given\n"), cmd.name);
    }
    exit(0);
  }

  /* check that we are not reading or writing encrypted data from/to a
     terminal, unless -f given */
  if (cmd.filter && !cmd.force) {
    if ((cmd.mode==ENCRYPT || cmd.mode==KEYCHANGE)
	&& isatty(fileno(stdout))) {
      fprintf(stderr, _("%s: encrypted data not written to a terminal. "
	      "Use -f to force encryption.\n"
	      "Try --help for more information.\n"), cmd.name);
      exit(1);
    }
    if ((cmd.mode==DECRYPT || cmd.mode==KEYCHANGE || cmd.mode==CAT
	 || cmd.mode==UNIXCRYPT)
	&& isatty(fileno(stdin))) {
      fprintf(stderr, _("%s: encrypted data not read from a terminal. "
	      "Use -f to force decryption.\n"
	      "Try --help for more information.\n"), cmd.name);
      exit(1);
    }
  }
  
  return cmd;
}

/* ---------------------------------------------------------------------- */
  
int main(int ac, char *av[]) {
  int r;
  FILE *f;

#if ENABLE_NLS
  setlocale (LC_ALL, "");
  bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
  textdomain(GETTEXT_PACKAGE);
#endif

  /* read command line */
  cmd = read_commandline(ac, av);

  /* if --keyfile requested, read one (normal mode) or two (change key
     mode) keywords from file, which may be "-" for stdin. Note that
     in this case, we ignore any keywords given on the command line
     etc. */

  if (cmd.keyfile) {
    if (strcmp(cmd.keyfile, "-")==0) {
      f = stdin;
    } else {
      f = fopen(cmd.keyfile, "r");
      if (!f) {
	fprintf(stderr, _("%s: could not read key from %s: %s\n"), cmd.name, cmd.keyfile, strerror(errno));
	exit(9);
      }
    }

    cmd.keyword = xreadline(f, cmd.name);
    if (cmd.keyword==NULL) {  /* end of file */
      fprintf(stderr, _("%s: error reading keyfile\n"), cmd.name);
      exit(9);
    }
    if (cmd.mode==KEYCHANGE) {
      cmd.keyword2 = xreadline(f, cmd.name);
      if (cmd.keyword2==NULL) { /* end of file */
	fprintf(stderr, _("%s: error reading keyfile\n"), cmd.name);
	exit(9);
      }
    }
    if (strcmp(cmd.keyfile, "-")!=0) {
      fclose(f);
    }
  }

  /* read keyword from terminal if necessary */
  if (cmd.keyword==NULL) {
    if (!cmd.prompt) {
      switch (cmd.mode) {

      case ENCRYPT: default:
	cmd.prompt = _("Enter encryption key: ");
	break;

      case DECRYPT: case CAT:
	cmd.prompt = _("Enter decryption key: ");
	break;

      case KEYCHANGE:
	cmd.prompt = _("Enter old key: ");
	break;

      case UNIXCRYPT:
	cmd.prompt = _("Enter key: ");
	break;
      }
    }
    cmd.keyword = readkey(cmd.prompt, "", cmd.name);
    if (cmd.keyword==NULL) {  /* end of file: exit gracefully */
      fprintf(stderr, _("%s: no key given\n"), cmd.name);
      exit(9);
    }
    /* in some circumstances, prompt for the key a second time */
    if (cmd.timid && cmd.mode==ENCRYPT) {
      char *repeat;

      repeat = readkey(cmd.prompt, _("(repeat) "), cmd.name);
      if (repeat==NULL || strcmp(repeat, cmd.keyword)!=0) {
	fprintf(stderr, _("Sorry, the keys you entered did not match.\n"));
	exit(7);
      }
    }
  }

  /* read keyword2 from terminal if necessary */
  if (cmd.mode==KEYCHANGE && cmd.keyword2==NULL) {
    if (cmd.prompt2 == NULL) {
      cmd.prompt2 = _("Enter new key: ");
    }
    cmd.keyword2 = readkey(cmd.prompt2, "", cmd.name);
    if (cmd.keyword2==NULL) {  /* end of file: exit gracefully */
      fprintf(stderr, _("%s: no key given\n"), cmd.name);
      exit(9);
    }
    /* in some circumstances, prompt for the key a second time */
    if (cmd.timid) {
      char *repeat;

      repeat = readkey(cmd.prompt2, _("(repeat) "), cmd.name);
      if (repeat==NULL || strcmp(repeat, cmd.keyword2)!=0) {
	fprintf(stderr, _("Sorry, the keys you entered did not match.\n"));
	exit(7);
      }
    }
  }

  /* reset stdin/stdout to binary mode under Windows */
  setmode(0,O_BINARY);
  setmode(1,O_BINARY);

  /* if --keyref given, check encryption keys against named file */
  if (cmd.keyref && (cmd.mode == ENCRYPT || cmd.mode == KEYCHANGE)) {
    f = fopen(cmd.keyref, "rb");
    if (!f) {
      fprintf(stderr, _("%s: could not open %s: %s\n"), cmd.name, cmd.keyref, strerror(errno));
      exit(10);
    }
    if (cmd.mode == ENCRYPT) {
      r = keycheck_stream(f, cmd.keyword);
    } else {
      r = keycheck_stream(f, cmd.keyword2);
    }
    if (r == -2 && (ccrypt_errno == CCRYPT_EFORMAT || ccrypt_errno == CCRYPT_EMISMATCH)) {
      fprintf(stderr, _("The encryption key does not match the reference file.\n"));
      exit(10);
    } else if (r==-2 || r==-1) { /* e.g. i/o error: fatal */
      fprintf(stderr, "%s: %s: %s\n", cmd.name, cmd.keyref, ccrypt_error(r));
      exit(10);
    }
  }

  /* filter mode */

  if (cmd.filter) {   
    switch (cmd.mode) {  

    case ENCRYPT: default:
      r = ccencrypt_streams(stdin, stdout, cmd.keyword);
      break;

    case DECRYPT: case CAT:
      r = ccdecrypt_streams(stdin, stdout, cmd.keyword);
      break;

    case KEYCHANGE:
      r = cckeychange_streams(stdin, stdout, cmd.keyword, cmd.keyword2);
      break;

    case UNIXCRYPT:
      r = unixcrypt_streams(stdin, stdout, cmd.keyword);
      break;
    }

    if (r) {
      fprintf(stderr, "%s: %s\n", cmd.name, ccrypt_error(r));
      if (r==-2 && (ccrypt_errno==CCRYPT_EFORMAT || ccrypt_errno==CCRYPT_EMISMATCH)) {
	return 4;
      } else {
	return 3;
      }
    }
    fflush(stdout);
    return 0;
  }

  /* non-filter mode: traverse files */
  r = traverse_toplevel(cmd.infiles, cmd.count);
  if (r==1) {
    return 4;
  } else if (r) {
    return 8;
  } else {
    return 0;
  }
}
