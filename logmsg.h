/*************************************************
* Copyright (c) Rennie deGraaf, 2005-2007.  All rights reserved.
* $Id: logmsg.h 14 2005-07-26 02:00:59Z degraaf $
*
* Generic system for logging error or status messages to various targets.
* See logmsg.c for further details.
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
* @file logmsg.h
* @author Rennie deGraaf
* @date 2007/05/29
*
* Declarations for the C interface to logmsg - a generic framework for logging 
* error or status messages to various targets.
*/

#ifndef LOGMSG_H
#define LOGMSG_H

    #ifdef __cplusplus
        #include <cstring>
        #include <cstdarg>
        #include <cerrno>
        #define LOGMSG_STRERROR std::strerror
        #define LOGMSG_VA_LIST std::va_list
    #else
        #include <errno.h>
        #include <string.h>
        #include <stdarg.h>
        #define LOGMSG_STRERROR strerror
        #define LOGMSG_VA_LIST va_list
    #endif

    #ifdef __cplusplus
    namespace LibWheel
    {
    #endif

    /** Available logging targets. */
    typedef enum
    {
        logmsg_stderr,  /**< Write messages to stderr (default). */
        logmsg_stdout,  /**< Write messages to stdout. */
        logmsg_syslog,  /**< Send message to syslog. */
        logmsg_file     /**< Append messages to a file. */
    } logmsg_target_t;

    /** Valid logging priorities, from highest to lowest.  Based on syslog 
        priorities. */
    typedef enum
    {
        logmsg_emerg,   /**< The system is unusable. */
        logmsg_alert,   /**< Action must be taken immediately. */
        logmsg_crit,    /**< Critical error condition. */
        logmsg_err,     /**< Error condtion. */
        logmsg_warning, /**< Warning condition. */
        logmsg_notice,  /**< Normal, but significant, condition. */
        logmsg_info,    /**< Informational message. */
        logmsg_debug    /**< Debug message. */
    } logmsg_priority_t;

    /* flags for logmsg options */
    #define LOGMSG_PID 1    /**< logmsg option: include the PID in logged messages.*/

    #ifdef __cplusplus
    extern "C" {
    #endif

    #if (!defined LOGMSG_HPP || defined LOGMSG_CPP) /* don't pollute the C++ namespace */
    int logmsg_open(logmsg_target_t target, unsigned options, const char* name);
    int logmsg(logmsg_priority_t priority, const char* format, ...) __attribute__((format(printf, 2, 3)));
    int vlogmsg(logmsg_priority_t priority, const char* format, LOGMSG_VA_LIST args);
    int logmsg_close();
    #endif

    /** 
    Shortcut to log standard library function errors. 
    @param FUNC The name of the library function that experienced the error
    */
    #define LOGMSG_LIB(FUNC) logmsg(logmsg_err, "%s: %s (%s:%i)", #FUNC, LOGMSG_STRERROR(errno), __FILE__, __LINE__)

    /** Shortcut to log a fatal exit message. */
    #define LOGMSG_FATAL_EXIT() logmsg(logmsg_notice, "Exiting due to fatal error")

    #ifdef __cplusplus
    }}
    #endif

#endif /* LOGMSG_H */
