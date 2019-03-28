/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
*
* This file is part of LibWheel
**************************************************/

/**
* @file Signals.cpp
* @author Rennie deGraaf
* @date 2007/11/20
*
* Functions and classes for working with Unix signals in C++.
*/


#include <list>
#include <stdexcept>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <csignal>
#include <boost/function.hpp>
#include <boost/function_equal.hpp>
#include <boost/utility.hpp>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/select.h>
#include "Signals.hpp"


namespace LibWheel
{
    /**
    * Constructor for SignalException.
    * @param signum The signal number represented by this SignalException.
    * @param desc A description of the exception.
    * @param info Signal details.
    */
    SignalException::SignalException(int signum, const char* desc, const siginfo_t* info) throw()
    : std::exception(), description(desc), siginfo(info), number(signum)
    {}


    /**
    * Constructor for SignalException.
    * @param signum The signal number represented by this SignalException.
    * @param desc A description of the exception.
    */
    SignalException::SignalException(int signum, const char* desc) throw()
    : std::exception(), description(desc), siginfo(NULL), number(signum)
    {}


    /**
    * Constructor for SignalException.
    * @param signum The signal number represented by this SignalException.
    */
    SignalException::SignalException(int signum) throw()
    : std::exception(), description(), siginfo(NULL), number(signum)
    {}


    /**
    * Destructor for SignalException.
    */
    SignalException::~SignalException() throw() 
    {}


    /**
    * Retrieve the details of a the signal represented by this SignalException. 
    * See the man page for sigaction() for details on the contents of a \c 
    * siginfo_t.
    * @return A pointer to the details, or NULL if they're not available.  
    */
    const siginfo_t* 
    SignalException::getInfo() const throw()
    {
        return siginfo;
    }


    /**
    * Retrieve the description of the this exception.
    * @return A pointer to the description, which may be an empty string.
    */
    const char* 
    SignalException::what() const throw()
    {
        return description.c_str();
    }


    /**
    * Retrieve the signal number represented by this SignalException.
    * @return The signal number.
    */
    int
    SignalException::getSignalNumber() const throw()
    {
        return number;
    }


    /**
    * Constructor for SignalException.  Initializes the base class 
    * (SignalException) with values appropriate for a SIGINT.
    * @param info Signal details.
    */
    Interrupt::Interrupt(const siginfo_t* info) throw()
    : SignalException(SIGINT, "SIGINT received", info)
    {}


    /**
    * Constructor for SignalException.  Initializes the base class 
    * (SignalException) with values appropriate for a SIGINT.
    */
    Interrupt::Interrupt() throw()
    : SignalException(SIGINT, "SIGINT received")
    {}


    /**
    * Signal number for Interrupt 
    */
    const int Interrupt::signalNumber = SIGINT;


    /**
    * Create a pipe in non-blocking I/O mode.
    * @throw std::runtime_error If pipe creation or initialization fails.
    */
    SignalQueue::Pipe::Pipe() throw(std::runtime_error)
    {
        int ret = pipe(fds);
        if (ret == -1)
            throw std::runtime_error(std::strerror(errno));
        ret = fcntl(fds[0], F_SETFL, O_NONBLOCK);
        if (ret == -1)
            throw std::runtime_error(std::strerror(errno));
        ret = fcntl(fds[1], F_SETFL, O_NONBLOCK);
        if (ret == -1)
            throw std::runtime_error(std::strerror(errno));
    }


    /**
    * Destructor for Pipe.  Close both endpoints. 
    */
    SignalQueue::Pipe::~Pipe()
    {
        close(fds[0]);
        close(fds[1]);
    }


    /**
    * Retrieve the signal pipe used by SignalQueue.
    * @return A reference to SignalQueue's signal pipe.
    */
    const SignalQueue::Pipe& 
    SignalQueue::getSignalPipe()
    {
        static Pipe pipe;
        return pipe;
    }


    /**
    * Retrieve the table of signal handlers.
    * @return A pointer to the signal handler table (an array of _NSIG 
    *       elements).
    */
    SignalQueue::HandlerList* 
    SignalQueue::getSignalTable()
    {
        static HandlerList sigs[_NSIG];
        return sigs;
    }


    /** 
    * Set the action to perform when a signal is received.
    * @param sig The signal whose action to set.
    * @param act The action to perform when \a signal is received.
    * @throw std::domain_error If \a act is invalid.
    * @throw std::invalid_argument If \a sig is invalid.
    */
    void 
    SignalQueue::setHandler(int sig, Action act) THROW((std::domain_error, std::invalid_argument))
    {
        struct sigaction handler;
        int ret;

        switch (act)
        {
          case DEFAULT:
            handler.sa_handler = SIG_DFL;
            handler.sa_flags = 0;
            break;
          case IGNORE:
            handler.sa_handler = SIG_IGN;
            handler.sa_flags = 0;
            break;
          case HANDLE:
            handler.sa_sigaction = SignalQueue_signalHandler;
            handler.sa_flags = SA_SIGINFO | SA_NOCLDSTOP;
            break;
          default:
            throw std::domain_error("Invalid action");
        }

        // make sure that everything has been constructed
        (void)getSignalPipe();

        // register the signal handler
        sigemptyset(&handler.sa_mask);
        ret = sigaction(sig, &handler, NULL);
        if (ret == -1)
            throw std::invalid_argument("Invalid signal number");
    }


    /**
    * Add a handler function for a signal.
    * @param sig The signal for which the handler is to be added.
    * @param act The handler to add.
    * @throw std::invalid_argument If \a sig is invalid.
    */
    void 
    SignalQueue::addHandler(int sig, boost::function<void()> act) THROW((std::invalid_argument))
    {
        if ((sig < 1) || (sig >= _NSIG))
            throw std::invalid_argument("Invalid signal number");

        getSignalTable()[sig].push_back(act);
    }


    /**
    * Remove all handlers for a signal.
    * @param sig The signal whose handlers to remove.
    * @throw std::invalid_argument If \a sig is invalid.
    */
    void 
    SignalQueue::deleteHandlers(int sig) THROW((std::invalid_argument))
    {
        if ((sig < 1) || (sig >= _NSIG))
            throw std::invalid_argument("Invalid signal number");

        getSignalTable()[sig].clear();
    }


    /**
    * Call all handlers for the next signal in the signal pipe.
    * @throw Anything that a registered signal handler throws.
    */
    void
    SignalQueue::handleNext()
    {
        int ret;
        unsigned char signal;

        // get the signal 
        ret = read(getReadFD(), &signal, 1);
        if (ret != 1)
        {
            if (errno == EAGAIN)
                return;
            else
                throw std::runtime_error(std::strerror(errno));
        }
        if (signal >= _NSIG)
        {
            throw std::runtime_error("Invalid signal number");
        }

        const HandlerList& list = getSignalTable()[signal];
        for (HandlerList::const_iterator i = list.begin(); i != list.end(); ++i)
            (*i)();
    }


    /**
    * Call all handlers for all signals in the signal pipe.
    * @throw Anything that a registered signal handler throws.
    */
    void 
    SignalQueue::handleAll()
    {
        while (pending())
            handleNext();
    }


    /**
    * Check if any signals are pending in the signal queue.
    * @return \b true if a signal is pending; \b false otherwise.
    * @throw std::runtime_error If there is an error checking the signal queue.
    */
    bool
    SignalQueue::pending() THROW((std::runtime_error))
    {
        struct timeval timeout;
        fd_set readfds;
        int ret;

        // call select() with a zero timeout to check if data is ready
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        FD_ZERO(&readfds);
        FD_SET(getReadFD(), &readfds);
        ret = ::select(getReadFD()+1, &readfds, NULL, NULL, &timeout);
        if (ret == -1)
            throw std::runtime_error(std::strerror(errno));
        else if (ret == 1)
            return true;
        else
            return false;
    }


    /**
    * Retrieve the read file descriptor of the signal pipe.  It may be used to
    * poll for pending signals using \c poll() or \c %select(); reading from it
    * will cause signals to be lost.
    * @return The file descriptor of the signal pipe.
    */
    int 
    SignalQueue::getReadFD()
    {
        return getSignalPipe().fds[0];
    }


    /**
    * Wait for an event to occur on a file descriptor.  This works identically
    * to %select(), except that any signals that are delivered before an event
    * occurs are handled.  See the man page for %select() for details.
    * @param n The highest-numbered file descriptor in \a readfds, \a writefds 
    *       and \a exceptfds, plus 1.
    * @param readfds A set of file descriptors to watch for avaiable data to 
    *       read.
    * @param writefds A set of file descriptors to watch for the possibility of 
    *       writing data without blocking.
    * @param exceptfds A set of file descriptors to watch for exceptional 
    *       conditions.
    * @param timeout An upper bound on the time to wait for events to occur.  If
    *       it is zero, select() will return immediately.  If it is null, 
    *       select() will block indefinately.
    */
    int
    SignalQueue::select(int n, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout)
    {
        fd_set rfd;
        int ret;
        int max_fd = (getReadFD() >= n) ? getReadFD()+1 : n;

        while (1)
        {
            if (readfds != NULL)
                std::memcpy(&rfd, readfds, sizeof(rfd));
            else
                FD_ZERO(&rfd);
            FD_SET(getReadFD(), &rfd);

            do
            {
                ret = ::select(max_fd, &rfd, writefds, exceptfds, timeout);
            }
            while ((ret == -1) && (errno == EINTR));
            if (ret == -1)
                return ret;
            else if (FD_ISSET(getReadFD(), &rfd))
            {
                handleAll();
                if (ret > 1)
                    return ret-1;
            }
            else
                return ret;
        }
    }


    /**
    * Retrieve the global Timer object.
    * @return A reference to the global Timer object.
    */
    Timer&
    Timer::getTimer()
    {
        static Timer timer;
        return timer;
    }


    /**
    * Schedule a timer interrupt for \a seconds seconds from the current time.
    * @param seconds The interval until the requested timer interrupt, in 
    *       seconds.  If \a seconds is 0, no interrupt is scheduled.
    */
    void
    Timer::schedule(unsigned short seconds)
    {
        if (seconds == 0)
            return;
            
        time_t t = std::time(NULL) + seconds;
        if (!times.empty() && (t == times.top()))
            return;
        else if (times.empty() || (t < times.top()))
        {
            // schedule a timer interrupt
            struct itimerval itime;
            itime.it_interval.tv_sec = 0;
            itime.it_interval.tv_usec = 0;
            itime.it_value.tv_sec = seconds;
            itime.it_value.tv_usec = 0;
            (void)setitimer(ITIMER_REAL, &itime, NULL);
        }
        times.push(t);
    }


    /**
    * Initialize a Timer signal handler object.
    */
    Timer::Handler::Handler(QueueType& t)
    : times(t)
    {}


    /**
    * Handle a timer interrupt through SignalQueue.  This functor simply 
    * schedules the next requested timer interrupt; use a SignalQueue handler 
    * for SIGALRM to perform additional actions when the signal is received.
    */
    void
    Timer::Handler::operator()()
    {
        times.pop();
        if (!times.empty())
        {
            struct itimerval itime;
            time_t curtime = std::time(NULL);
        
            // schedule the next timer interrupt
            itime.it_interval.tv_sec = 0;
            itime.it_interval.tv_usec = 0;
            if (curtime >= times.top())
            {
                itime.it_value.tv_sec = 0;
                itime.it_value.tv_usec = 1;
            }
            else
            {
                itime.it_value.tv_sec = times.top()-curtime;
                itime.it_value.tv_usec = 0;
            }
            (void)setitimer(ITIMER_REAL, &itime, NULL);
        }
    }


    /**
    * Initialize a Timer object.
    * @sideeffect Registers a signal handler for SIGALRM through SignalQueue.
    */
    Timer::Timer()
    : times(), handler(times)
    {
        SignalQueue::setHandler(SIGALRM, SignalQueue::HANDLE);
        SignalQueue::addHandler(SIGALRM, boost::ref(handler));
    }
    

    /**
    * Destructor for Timer.
    * @sideeffect Unregisters the timer signal handler from SignalQueue; no 
    *       further timer interrupts will be scheduled.
    */
    Timer::~Timer()
    {
        SignalQueue::deleteHandler(SIGALRM, boost::ref(handler));
    }


    /**
    * Close a file descriptor.  This function is identical to close(), except 
    * that it will resume if interrupted by a signal and will never set EINTR
    * on error.
    * @param fd The file descriptor to close.
    * @return 0 on success, or -1 on error (with \c errno set appropriately).
    */
    int 
    uninterruptible_close(int fd)
    {
        int retval;
        do
        {
            retval = ::close(fd);
        } while ((retval == -1) && (errno == EINTR));
        return retval;
    }

    
    /**
    * Read data from a file descriptor.  This function is identical to \c 
    * read(), except that it will resume if interrupted by a signal and will 
    * never set EINTR on error.  Also, it assumes that \a fd is in non-blocking 
    * mode, and will return -1 and set \c errno to EAGAIN if no data is 
    * available.  See the man page for \c read() for further details.
    * @param fd The file descriptor from which to read.
    * @param buf The buffer to which to write.
    * @param count The maximum number of bytes to read.
    * @return The number of bytes read, or -1 on error (with \c errno set
    *       appropriately).
    */
    ssize_t
    uninterruptible_read(int fd, unsigned char* buf, size_t count)
    {
        ssize_t bytes = 0;
        ssize_t retval;
        while (1)
        {
            retval = ::read(fd, &buf[bytes], count-bytes);
            if ((retval == -1) && (errno != EINTR))
                return retval;
            else if (retval == 0)
            {
                /* read()s on file descriptors in non-blocking mode should never
                   return 0 (they should return -1 and set EAGAIN), but 
                   sometimes they do anyway */
                if (bytes > 0)
                    return bytes;
                else
                {
                    errno = EAGAIN;
                    return -1;
                }
            }
            else
            {
                bytes += retval;
                if (bytes == static_cast<ssize_t>(count))
                    return count;
            }
        }
    }

} // namespace LibWheel


/**
* Low-level signal handler.  Writes the signal number to the signal pipe as a 
* single byte and returns.  C++ signal handler conventions require that this be 
* a function with C linkage in the global namespace.  Don't call it directly.
*/
extern "C" void SignalQueue_signalHandler(int signum, siginfo_t*, void*)
{
    char buf[1];
    buf[0] = signum;
    write(LibWheel::SignalQueue::getSignalPipe().fds[1], buf, 1);
}

