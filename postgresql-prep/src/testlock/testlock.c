/*
    Usage: testlock [-t timeout] [-s] filename command args ...

    Copyright (C) 2017 AT&T Intellectual Property. All rights reserved. 

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this code except in compliance
    with the License. You may obtain a copy of the License
    at http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software  
    distributed under the License is distributed on an "AS IS" BASIS,  
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or  
    implied. See the License for the specific language governing  
    permissions and limitations under the License. 

*/

#include <sys/file.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

void usage(const char *prog0, const char *msg) 
{
  if (msg) fprintf(stderr, "%s\n", msg);
  fprintf(stderr, "Usage: %s [-v] [-t timeout] [-s] [-r retcode] lock-filename command args ...\n", prog0);
  fprintf(stderr, "-t ##\thow long to wait for a lock to be freed. 0 means exit immediately\n");
  fprintf(stderr, "-s\tsilently ignore errors with locking\n");
  fprintf(stderr, "-r ##\texit with this code when the lock fails\n");
  fprintf(stderr, "-v\tbe verbose\n");
  fprintf(stderr, "Note:\tlock-filename is created (if it does not exist) and truncated before locking.\n");
  fprintf(stderr, "\tlock-filename is not removed after the command finishes\n");
  exit(1);
}

int main(int argc, char **argv) 
{
  const char *prog0 = argv[0];

  int c;
  int timeout = -1;
  bool silent = false;
  bool verbose = false;
  int nolockret = 99;

  while ((c = getopt(argc, argv, "t:r:sv?")) != -1) {
    switch (c) {
    case 's': silent = true; break;
    case 't': timeout = atoi(optarg); break;
    case 'r': nolockret = atoi(optarg); break;
    case 'v': verbose = true; break;
    default: usage(prog0, NULL);
    }
  }

  argc -= optind;
  argv += optind;

  if (argc < 1) {
    usage(prog0, "Missing lock filename");
  } else if (argc < 2) {
    usage(prog0, "Missing command to run");
  }

  const char *lockFilename = *argv++;
  if (verbose) printf("lockfilename=%s\n", lockFilename);

  int lockfd = creat(lockFilename, 0666);
  if (lockfd < 0) {
    fprintf(stderr, "Cannot open %s: %s\n", lockFilename, strerror(errno));
    exit(2);
  }

  if (timeout < 0) {
    /* wait forever */
    lockf(lockfd, F_LOCK, 0);
  } else {
    /* try each second (for up to timeout seconds) to get the lock */
    int lockret = lockf(lockfd, F_TLOCK, 0);
    int count = 0;
    while ((lockret < 0) && (count++ < timeout)) {
      sleep(1);
      lockret = lockf(lockfd, F_TLOCK, 0);
    }
    if (lockret < 0) {
      if (!silent) {
	fprintf(stderr, "Cannot lock %s: %s\n", lockFilename, strerror(errno));
      }
      exit(nolockret);
    }
  }

  /* now execute the given command */
  if (verbose) {
    char **a = argv;
    printf("calling program '%s'\n", *a);
    while (*++a) {
      printf("with argument '%s'\n", *a);
    }
  }
  execvp(argv[0], argv);
}
