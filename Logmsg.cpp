/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
* 
* This file is part of LibWheel
**************************************************/

/**
* @file Logmsg.cpp
* @author Rennie deGraaf
* @date 2007/05/28
*
* C++ interface to logmsg - a generic framework for logging error or status 
* messages to various targets.
* @see logmsg.c
*
* @todo Verify thread safety.
* @todo Extend logmsg to allow multiple separate loggers to be used 
*       simultaneously, along the lines of Java's "Logger" class.
*/

/* import the C API declarations */
#define LOGMSG_CPP

#include <cstdarg>
#include "Logmsg.hpp"

namespace LibWheel
{
    /**
    * Retrieve the global Logmsg object.
    * @return a reference to the global Logmsg object.
    */
    Logmsg&
    Logmsg::getLogmsg()
    {
        static Logmsg l;
        return l;
    }


    /**
    * Initialize a Logmsg object in a closed state.
    */
    Logmsg::Logmsg()
    : isopen(false)
    {}


    /**
    * Destructor for Logmsg.  Closes the target if it's open.
    */
    Logmsg::~Logmsg()
    {
        if (isopen)
            close();
    }


    /**
    * Check if a Logmsg object is open.
    * @return \b true if it's open; \b false otherwise.
    */
    bool
    Logmsg::isOpen() const
    {
        return isopen;
    }


    /**
    * Open and initialize a target.  If a target is already open, close it 
    * first.
    * @param target The type of target to use.
    * @param options A bitfield of option flags.
    * @param name A string whose purpose is determined by the value of \a 
    *       target:
    *       - \c logmsg_file: The name of the file to use.
    *       - \c logmsg_syslog, \c logmsg_stdout, \c logmsg_stderr: A string to 
    *           prepend to each log message.
    * @return 0 on success or -1 on failure, with errno set appropriately.
    * @see logmsg_open()
    */
    int
    Logmsg::open(logmsg_target_t target, unsigned options, const char* name)
    {
        int ret;
        
        // if logmsg is already open, close it and re-open
        if (isopen)
        {
            ret = logmsg_close();
            if (ret)
                return ret;
        }
        
        ret = logmsg_open(target, options, name);
        if (ret == 0)
            isopen = true;
        return ret;
    }


    /**
    * Shuts down the logmsg facility.  Closes the target appropriately.
    * @return 0 on success, or EOF on failure, with errno set appropriately.
    * @see logmsg_close()
    */
    int Logmsg::close()
    {
        if (isopen)
        {
            isopen = false;
            return logmsg_close();
        }
        return 0;
    }


    /**
    * Prints a message to the current target.  The message is formatted \
    * according to syslog() conventions.
    * @param priority The message priority.  How this is interpreted depends on
    *       the target:
    *       - \c logmsg_syslog: Use the equivalent syslog priority.
    *       - \c logmsg_file, \c logmsg_stdout, \c logmsg_stderr: Prepend a 
    *           string to the message indicating the priority
    * @param format A printf()-style format string, followed by arguments.
    * @return 0 on success, or -1 on failure
    * @see logmsg()
    */
    int
    Logmsg::operator() (logmsg_priority_t priority, const char* format, ...)
    {
        if (isopen)
        {
            va_list args;
            int ret;
        
            va_start(args, format);
            ret = vlogmsg(priority, format, args);
            va_end(args);
            return ret;
        }
        return -1;
    }

} // namespace LibWheel
