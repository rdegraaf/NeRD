/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
*
* This file is part of LibWheel.
**************************************************/

/**
* @file util.cpp
* @author Rennie deGraaf 
* @date 2007/06/13
*
* Miscellaneous LibWheel functions that don't fit anywhere else.
*/

#include <sstream>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <boost/cstdint.hpp>
#include <unistd.h>
#include <fcntl.h>
#include "Logmsg.hpp"
#include "util.hpp"

namespace LibWheel
{

    /**
    * Converts an IPv4 address to a string in dotted-decimal format.
    * @param a The address to convert, in host byte order
    * @return The address in dotted-decimal format.
    * @note This is essentially a thread-safe version of \c inet_ntoa(), except 
    *       that it takes the address to convert in host byte order.
    */
    std::string
    ipv4_to_string(in_addr_t a)
    {
        union ipv4_bytes
        {
            in_addr_t addr;
            boost::uint8_t bytes[4];
        };
        std::ostringstream os;
        ipv4_bytes addr;

        addr.addr = htonl(a); // convert to big-endian
        os << static_cast<unsigned>(addr.bytes[0]) << '.'
           << static_cast<unsigned>(addr.bytes[1]) << '.'
           << static_cast<unsigned>(addr.bytes[2]) << '.'
           << static_cast<unsigned>(addr.bytes[3]);
        return os.str();
    }


    /**
    * Counts the number of currently-open file descriptors.
    * @return The number of open file descriptors, or -1 on error (with \c errno
    *       set appropriately).
    * @note This function assumes that \c getdtablesize() always works.  This 
    *       may not be true on all systems.
    */
    int
    open_files()
    {
        int fd;
        int max_fd;
        int retval;
        int count;
        struct stat statbuf;

        count = 0;
        max_fd = getdtablesize();
        for (fd=0; fd<max_fd; fd++)
        {
            retval = fstat(fd, &statbuf);
            if ((retval == -1) && (errno != EBADF))
                return -1;
            else if (retval == 0)
                count++;
        }
        return count;
    }


    /**
    * Set the "close-on-exec" attribute on open file descriptors greater than
    * \a maxfd.
    * @param maxfd The highest-numbered file descriptor to preserve.
    * @sideeffect Logs a message to logmsg on error.
    */
    void
    close_files_on_exec(int maxfd)
    {
        int fd;
        int fds;
        int retval;
        
        fds = getdtablesize();
        for (fd = ((maxfd<2) ? 3 : maxfd+1); fd < fds; ++fd)
        {
            retval = fcntl(fd, F_SETFD, FD_CLOEXEC);
            if ((retval == -1) && (errno != EBADF))
                LibWheel::logmsg(LibWheel::logmsg_err, "Error setting the close-on-exec flag on fd %d: %s", fd, std::strerror(errno));
        }
    }
    
    
    /**
    * Write the current PID to a file
    * @param file The file to which the PID is to be written.
    * @note Logs messages to LibWheel::logmsg on failure.
    * @warning If \a file exists, its contents will be truncated.
    */
    void
    write_pid(const char* file)
    {
        FILE* f;
        
        f = fopen(file, "w");
        if (f == NULL)
        {
            logmsg(logmsg_err, "Couldn't create PID file %s: %s", file,
            std::strerror(errno));
        }
        else
        {
            (void)fprintf(f, "%ld\n", getpid());
            (void)fclose(f);
        }
    }


    /**
    * Constructor for IOException.
    * @param s A string describing the reason for throwing the exception.
    */
    IOException::IOException(const std::string& s)
    : runtime_error(s)
    {}


    /**
    * Constructor for SocketException.
    * @param s A string describing the reason for throwing the exception.
    */
    SocketException::SocketException(const std::string& s)
    : runtime_error(s)
    {}


    /**
    * Constructor for ParseError.
    * @param s A string describing the reason for throwing the exception.
    */
    ParseError::ParseError(const std::string& s)
    : runtime_error(s)
    {}

} // namespace LibWheel
