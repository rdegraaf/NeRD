/*************************************************
* Copyright (c) 2003, Matt Messier, John Viega.  All rights reserved.
* Copyright (c) 2005, 2007, Rennie deGraaf.  All rights reserved.
* $Id: spc_sanitize.c 14 2005-07-26 02:00:59Z degraaf $
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met: 
* 
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 
* 3. Neither the name of the author nor the names of its
*    contributors may be used to endorse or promote products derived from
*    this software without specific prior written permission.
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**************************************************/

/* 
Taken from "Secure Programming Cookbook for C and C++ by Matt Messier and 
John Viega, on-line source at 
http://www.secureprogramming.com/?action=downloads&bookid=1
Modified by Rennie deGraaf, 2005/07/22, 2007/05/26

spc_sanitize_environment() - sanitizes system environemnt variables
spc_sanitize_files() - closes all file descriptors above a limit
*/

/**
* @file spc_sanitize.c
* @author Rennie deGraaf 
* @date 2007/05/27
*
* Functions to sanitize the system environment.
*/

#define _POSIX_SOURCE   /* for fileno() */
#define _BSD_SOURCE     /* for getdtablesize() */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "logmsg.h"

#ifndef SIZE_T_MAX
    #define SIZE_T_MAX (sizeof(size_t))
#endif

#ifndef OPEN_MAX
    #define OPEN_MAX 256
#endif


/**
* Pointer to the global environment table.
*/
extern char** environ;

/**
* Default environment configuration.
*/
static const char* spc_restricted_environ[] = 
{
    "IFS= \t\n",
    "PATH=" _PATH_STDPATH,
    NULL
};

/**
* Environment variables to preserve if present.
*/
static const char* spc_preserve_environ[] = 
{
    "TZ",
    NULL
};


/**
* Sanitizes the system environment.  Sets all variables in 
* \a spc_restricted_environ to default values and deletes all other variables 
* not listed either in \a preservev or \a spc_preserve_environ.
* @param preservec The number of variables in \a preservev.
* @param preservev A list of environemnt variable names to preserve.
* @note Logs an error message to the logmsg facility and calls \c abort() on 
*       integer overflow or memory allocation failure.
* @sideeffect Changes the value of the global variable environ.
* @warning This function will leak memory if called more than once.
*/
void spc_sanitize_environment(int preservec, const char** preservev) {
  int    i;
  char   **new_environ, *ptr, *value;
  const char* var;
  size_t arr_size = 1, arr_ptr = 0, len, new_size = 0;

  for (i = 0;  i >= 0 && (var = spc_restricted_environ[i]) != 0;  i++) {
    if (arr_size == SIZE_T_MAX || new_size > SIZE_T_MAX - strlen(var)) 
    {
      logmsg(logmsg_err, "Integer overflow (%s:%i)", __FILE__, __LINE__);
      LOGMSG_FATAL_EXIT();
      abort();
    }
    new_size += strlen(var) + 1;
    arr_size++;
  }
  if (i < 0)
  {
    logmsg(logmsg_err, "Integer overflow (%s:%i)", __FILE__, __LINE__);
    LOGMSG_FATAL_EXIT();
    abort();
  }
  for (i = 0;  i >= 0 && (var = spc_preserve_environ[i]) != 0;  i++) {
    if (!(value = getenv(var))) continue;
    if (arr_size == SIZE_T_MAX || new_size > SIZE_T_MAX - strlen(var) - strlen(value) - 1) 
    {
      logmsg(logmsg_err, "Integer overflow (%s:%i)", __FILE__, __LINE__);
      LOGMSG_FATAL_EXIT();
      abort();
    }
    new_size += strlen(var) + strlen(value) + 2; /* include the '=' */
    arr_size++;
  }
  if (i < 0)
  {
    logmsg(logmsg_err, "Integer overflow (%s:%i)", __FILE__, __LINE__);
    LOGMSG_FATAL_EXIT();
    abort();
  }
  if (preservec && preservev) {
    for (i = 0;  i < preservec && (var = preservev[i]) != 0;  i++) {
      if (!(value = getenv(var))) continue;
      if (arr_size == SIZE_T_MAX || new_size > SIZE_T_MAX - strlen(var) - strlen(value) - 1)
      {
        logmsg(logmsg_err, "Integer overflow (%s:%i)", __FILE__, __LINE__);
        LOGMSG_FATAL_EXIT();
        abort();
      }
      new_size += strlen(var) + strlen(value) + 2; /* include the '=' */
      arr_size++;
    }
  }

  if (new_size > SIZE_T_MAX - (arr_size * sizeof(char *)) + 1)
  {
    logmsg(logmsg_err, "Integer overflow (%s:%i)", __FILE__, __LINE__);
    LOGMSG_FATAL_EXIT();
    abort();
  }
  new_size += (arr_size * sizeof(char *));
  if (!(new_environ = (char **)malloc(new_size)))
  {
    LOGMSG_LIB(malloc);
    LOGMSG_FATAL_EXIT();
    abort();
  }
  new_environ[arr_size - 1] = 0;

  ptr = (char *)new_environ + (arr_size * sizeof(char *));
  for (i = 0;  (var = spc_restricted_environ[i]) != 0;  i++) {
    new_environ[arr_ptr++] = ptr;
    len = strlen(var);
    memcpy(ptr, var, len + 1);
    ptr += len + 1;
  }
  for (i = 0;  (var = spc_preserve_environ[i]) != 0;  i++) {
    if (!(value = getenv(var))) continue;
    new_environ[arr_ptr++] = ptr;
    len = strlen(var);
    memcpy(ptr, var, len);
    *(ptr + len + 1) = '=';
    memcpy(ptr + len + 2, value, strlen(value) + 1);
    ptr += len + strlen(value) + 2; /* include the '=' */
  }
  if (preservec && preservev) {
    for (i = 0;  i < preservec && (var = preservev[i]) != 0;  i++) {
      if (!(value = getenv(var))) continue;
      new_environ[arr_ptr++] = ptr;
      len = strlen(var);
      memcpy(ptr, var, len);
      *(ptr + len + 1) = '=';
      memcpy(ptr + len + 2, value, strlen(value) + 1);
      ptr += len + strlen(value) + 2; /* include the '=' */
    }
  }

  environ = new_environ;
}


/**
* Attempts to open /dev/null as stdin, stdout, or stderr.
* @param fd The stream to open.  Must be 0 for stdin, 1 for stdout, or 2 for 
*       stderr.
* @return Non-zero on success, or zero on failure.
*/
static int open_devnull(int fd) {
  FILE *f = 0;

  if (!fd) f = freopen(_PATH_DEVNULL, "rb", stdin);
  else if (fd == 1) f = freopen(_PATH_DEVNULL, "wb", stdout);
  else if (fd == 2) f = freopen(_PATH_DEVNULL, "wb", stderr);
  return (f && fileno(f) == fd);
}


/**
* Closes all file descriptors above a limit, and ensures that stdin, stdout, and
* stderr are open.
* @param maxfd The highest-numbered file descriptor to preserve.  Set to 2 or
*       less to close all files except for stdin, stdout, and stderr.
* @note If stdin, stdout, or stderr is closed and cannot be opened, attempts to 
*       log a message through the logmsg facility and calls \c abort().
*/
void spc_sanitize_files(int maxfd) {
  int         fd, fds;
  struct stat st;

  /* Make sure all open descriptors other than the standard ones are closed */
  if ((fds = getdtablesize()) == -1) fds = OPEN_MAX;
  for (fd = ((maxfd<2) ? 3 : maxfd+1);  fd < fds;  fd++) close(fd);

  /* Verify that the standard descriptors are open.  If they're not, attempt to
   * open them using /dev/null.  If any are unsuccessful, abort.
   */
  for (fd = 0;  fd < 3;  fd++)
    if (fstat(fd, &st) == -1 && (errno != EBADF || !open_devnull(fd))) 
    {
        logmsg(logmsg_err, "Error opening file descriptor %i: %s (%s:%i)", fd, strerror(errno), __FILE__, __LINE__);
        LOGMSG_FATAL_EXIT();
        abort();
    }
}
