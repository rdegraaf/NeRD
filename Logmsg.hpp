/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
* 
* This file is part of LibWheel
**************************************************/

/**
* @file Logmsg.hpp
* @author Rennie deGraaf
* @date 2007/05/28
*
* C++ interface to logmsg - a generic framework for logging error or status 
* messages to various targets.
* @see logmsg.c
*/

#ifndef LOGMSG_HPP
    #define LOGMSG_HPP
    
    #include <boost/utility.hpp>
    #include "logmsg.h"
        
    namespace LibWheel
    {
        /**
        * A C++ front-end to logmsg: a generic framework for logging error or
        * status messages to various targets.  
        * @see logmsg.c
        * @see logmsg.h
        */
        class Logmsg : public boost::noncopyable
        {
          public:
            bool isOpen() const;
            int open(logmsg_target_t target, unsigned options, const char* name);
            int operator() (logmsg_priority_t priority, const char* format, ...) __attribute__((format (printf, 3, 4)));
            int close();
            static Logmsg& getLogmsg();
          private:
            Logmsg();
            ~Logmsg();
            bool isopen; ///< \b true if this logger is currently open; \b false otherwise
        };
#ifndef LOGMSG_CPP
        /** Global logmsg object.  Used to emulate the C API in C++. */
        static Logmsg& logmsg = Logmsg::getLogmsg();
#endif
    
    } // namespace LibWheel
    
#endif /* LOGMSG_HPP */
