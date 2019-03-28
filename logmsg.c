/*************************************************
* Copyright (c) Rennie deGraaf, 2005-2007.  All rights reserved.
* $Id: logmsg.c 14 2005-07-26 02:00:59Z degraaf $
*
* Generic system for logging error or status messages to various targets.
* Currently, valid targets are stdout, stderr, syslog, or any file.  The 
* default target is stderr.  Messages are formatted along syslog conventions.
*
* Note: this framework is not re-entrant.  Be careful using it in a multi-
* threaded environment.
*
* logmsg_open() - open the logmsg facility
* logmsg() - write a message to the current log
* logmsg_close() - close the logmsg facility
*
* This file is part of the libwheel project.
*
* libwheel is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* libwheel is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with libwheel; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
**************************************************/

/**
* @file logmsg.c
* @author Rennie deGraaf
* @date 2007/05/29
*
* Implementation of  logmsg - a generic framework for logging error or status
* messages to various targets.  Currently, valid targets are stdout, stderr, 
* syslog, or any file.  The default target is stderr.  Messages are formatted
* along syslog conventions.
*
* @todo Verify thread safety.
* @todo Extend logmsg to allow multiple separate loggers to be used 
*       simultaneously, along the lines of Java's "Logger" class.
*/

#define _POSIX_SOURCE   /* for localtime_r() */
#define _BSD_SOURCE     /* for vsyslog() */

#include <syslog.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include "logmsg.h"

/** Internal logmsg configuration object. */
typedef struct 
{
    logmsg_target_t target;
    unsigned options;
    const char* name;
    FILE* file;
} logmsg_t;

/** String table for logmsg priorities (\see logmsg_priority_t). */
static const char* _priority_tag[] = 
{
    "Emergency:",
    "Alert:",
    "Critical:",
    "Error:",
    "Warning:",
    "Notice:",
    "Info:",
    "Debug:"
};

/** syslog macros corresponding to values of logmsg_priority_t */
static const int _priority_id[] = 
{
    LOG_EMERG,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG
};

/** Global logmsg configuration object. */
static logmsg_t _log_config = {logmsg_stderr, 0, "", NULL};


/**
* Initializes the logmsg facility.  Opens and initializes a target, and sets
* logmsg options.
* @param target The type of target to use.
* @param options A bitfield of option flags.
* @param name A string whose purpose is determined by the value of \a target:
*       - \c logmsg_file: The name of the file to use.
*       - \c logmsg_syslog, \c logmsg_stdout, \c logmsg_stderr: A string to 
*           prepend to each log message.
* @return 0 on success or -1 on failure, with errno set appropriately.
*/
int logmsg_open(logmsg_target_t target, unsigned options, const char* name)
{
    int syslog_opt = 0;
    _log_config.target = target;
    _log_config.options = options;
    _log_config.name = name;
    _log_config.file = NULL;
    
    switch (_log_config.target)
    {
        case logmsg_stdout:
            _log_config.file = stdout;
            break;
        case logmsg_stderr:
            _log_config.file = stderr;
            break;
        case logmsg_syslog:
            if (_log_config.options & LOGMSG_PID)
                syslog_opt |= LOG_PID;
            openlog(name, syslog_opt, LOG_USER);
            break;
        case logmsg_file:
            _log_config.file = fopen(name, "a");
            if (_log_config.file == NULL)
                return -1;
            break;
    }
    
    return 0;
}


/**
* Prints a message to the current target.  The message is formatted according to
* syslog() conventions.
* @param priority The message priority.  How this is interpreted depends on the
*       target:
*       - \c logmsg_syslog: Use the equivalent syslog priority.
*       - \c logmsg_file, \c logmsg_stdout, \c logmsg_stderr: Prepend a string 
*           to the message indicating the priority
* @param format A printf()-style format string, followed by arguments.
* @return 0 on success, or -1 on failure
*/
int logmsg(logmsg_priority_t priority, const char* format, ...)
{
    va_list args;
    int ret;
    
    va_start(args, format);
    ret = vlogmsg(priority, format, args);
    va_end(args);
    
    return ret;
}


/**
* Prints a message to the current target.  The message is formatted according to
* syslog() conventions.
* @param priority The message priority.  How this is interpreted depends on the
*       target:
*       - \c logmsg_syslog: Use the equivalent syslog priority.
*       - \c logmsg_file, \c logmsg_stdout, \c logmsg_stderr: Prepend a string 
*           to the message indicating the priority
* @param format A printf()-style format string.
* @param args Arguments to \a format.
* @return 0 on success, or -1 on failure
*/
int vlogmsg(logmsg_priority_t priority, const char* format, va_list args)
{
    time_t t;
    struct tm tm;
    char timebuf[100];
    int ret;
    
    /* safety check, in case logmsg is called without first calling logmsg_open */
    if (_log_config.file == NULL)
        _log_config.file = stderr;
    
    switch (_log_config.target)
    {
        case logmsg_stdout:
        case logmsg_stderr:
        case logmsg_file:
            /* print the time */
            t = time(NULL);
            localtime_r(&t, &tm);
            strftime(timebuf, 100, "%b %d %T ", &tm);
            ret = fputs(timebuf, _log_config.file);
            if (ret == EOF) return -1;
        
            /* print name for stdout and stderr */
            if (_log_config.target == logmsg_stdout || _log_config.target == logmsg_stderr)
            {
                ret = fputs(_log_config.name, _log_config.file);
                if (ret == EOF) return -1;
                ret = fputc(' ', _log_config.file);
                if (ret == EOF) return -1;
            }

            /* print the PID, if LOGMSG_PID is set */
            if (_log_config.options & LOGMSG_PID)
            {
                char buf[30];
                snprintf(buf, 30, "[%i] ", getpid());
                ret = fputs(buf, _log_config.file);
                if (ret == EOF) return -1;
            }
            
            /* print the priority */
            ret = fputs(_priority_tag[priority], _log_config.file);
            if (ret == EOF) return -1;           
            ret = fputc(' ', _log_config.file);
            if (ret == EOF) return -1;
            
            /* print the actual message */
            ret = vfprintf(_log_config.file, format, args);
            if (ret < 0) return -1;
            ret = fputc('\n', _log_config.file);
            if (ret == EOF) return -1;
            break;
        case logmsg_syslog:
            vsyslog(_priority_id[priority], format, args);
            break;
    }
    
    return 0;
}    


/**
* Shuts down the logmsg facility.  Closes the target appropriately.
* @return 0 on success, or EOF on failure, with errno set appropriately.
*/
int logmsg_close()
{
    switch (_log_config.target)
    {
        case logmsg_stdout:
            return 0;
        case logmsg_stderr:
            return 0;
        case logmsg_syslog:
            closelog();
            return 0;
        case logmsg_file:
            return fclose(_log_config.file);
        default:
            return EOF;
    }
}
