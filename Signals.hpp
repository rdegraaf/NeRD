/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
*
* This file is part of LibWheel
**************************************************/

/**
* @file Signals.hpp
* @author Rennie deGraaf
* @date 2007/11/20
*
* Functions and classes for working with Unix signals in C++.
*/


#ifndef LIBWHEEL_SIGNALS_HPP
    #define LIBWHEEL_SIGNALS_HPP
    
    #include <list>
    #include <string>
    #include <queue>
    #include <stdexcept>
    #include <csignal>
    #include <ctime>
    #include <boost/function.hpp>
    #include <boost/utility.hpp>
    #include <sys/select.h>
    #include "libwheel.h"

    extern "C" void SignalQueue_signalHandler(int signum, siginfo_t*, void*);

    namespace LibWheel
    {
        /**
        * Base class for exceptions thrown by signal handlers.
        */
        class SignalException : public std::exception
        {
            const std::string description; ///< Description of the event triggering the exception.
            const siginfo_t* siginfo; ///< Signal details, if available.
            const int number; ///< Signal number.

          protected:
            SignalException(int signum) throw();
            SignalException(int signum, const char* desc) throw();
            SignalException(int signum, const char* desc, const siginfo_t* info) throw();

          public:
            virtual ~SignalException() throw();
            const siginfo_t* getInfo() const throw();
            virtual const char* what() const throw();
            int getSignalNumber() const throw();
        };

        /**
        * Exception to be thrown in response to a SIGINT.
        */
        class Interrupt : public SignalException
        {
          public:
            Interrupt() throw();
            explicit Interrupt(const siginfo_t* info) throw();
            static const int signalNumber;
        };
        
        /**
        * Template for functors to throw exceptions in response to signals.
        * @param except The type of exception to throw.
        */
        template <typename except>
        class Thrower
        {
          public:
            /** Throw an exception. */
            void operator()() THROW((except)) {throw except();}
        };
        

        /**
        * A system for synchronously handling asynchronous signals in a 
        * uni-threaded process.  Users can request that certain signals be 
        * handled, and can register any number of arbitrary functions to handle
        * them.  When a signal arrives, all that is done is that its number is
        * written to a pipe.  The user can then poll for pending signals from 
        * the pipe using SignalQueue::pending() or by calling \c poll() or \c 
        * %select() on SignalQueue::getReadFD(), and can execute all handlers for 
        * pending signals using SignalQueue::handleNext() and 
        * SignalQueue::handleAll(). Handlers are executed in the order that they
        * were registered.  SignalQueue::select() is provided as an version of
        * \c %select() that waits for file descriptors to change status, while
        * handling any signals that arrive in the meantime.
        *
        * Signal handlers can be either functions or functors that take no 
        * parameters and return \c void.  Since they are called synchronously 
        * from normal program flow, they can safely perform any action, including
        * throw exceptions. (SignalException is provided for this purpose.)
        *
        * Since SignalQueue only has static methods, it could simply be a 
        * namespace (rather than a class).  However, I couldn't get a 
        * non-template version of deleteHandler() to work properly, so its 
        * definition needs to be inline, and it needs to call getSignalTable(), 
        * which should be private.  If this was a namespace, getSignalTable() 
        * and all the other private stuff could be static to Signals.cpp.
        */
        class SignalQueue
        {
          private:
            /**
            * Convienience wrapper for a non-blocking Unix pipe
            */
            struct Pipe : public boost::noncopyable
            {
                int fds[2]; ///< The pipe's read and write file descriptors.
                Pipe() throw(std::runtime_error);
                ~Pipe();
            };

            /** The type of a set of handlers for a particular signal. */
            typedef std::list<boost::function<void()> > HandlerList; 
            
            static const Pipe& getSignalPipe();
            static HandlerList* getSignalTable();
            
            friend void ::SignalQueue_signalHandler(int, siginfo_t*, void*); ///< This needs to call getSignalPipe().

          public:
            /** Possible ways to handle a signal. */
            enum Action {DEFAULT,   ///< Take the operating systems's default action for the signal.
                         IGNORE,    ///< Ignore the signal.
                         HANDLE     ///< Call all registered signal handlers when a signal is received.
            };
            
            static void setHandler(int sig, Action act) THROW((std::domain_error, std::invalid_argument));
            static void addHandler(int sig, boost::function<void()> act) THROW((std::invalid_argument));
            template <typename T> static void deleteHandler(int sig, const T& act) THROW((std::invalid_argument));
            static void deleteHandlers(int sig) THROW((std::invalid_argument));
            static void handleNext();
            static void handleAll();
            static bool pending() THROW((std::runtime_error));
            static int getReadFD();
            static int select(int n, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);

        };


        /**
        * Unregister a handler for a signal
        * @param sig A signal number.
        * @param act A reference to the signal handler to unregister for \a 
        *       sig.
        * @throw std::invalid_argument If \a sig is not a valid signal number.
        */
        template <typename T>
        void 
        SignalQueue::deleteHandler(int sig, const T& act) THROW((std::invalid_argument))
        {
            if ((sig < 1) || (sig >= _NSIG))
                throw std::invalid_argument("Invalid signal number");

            std::list<boost::function<void()> >& list = getSignalTable()[sig];
            for (std::list<boost::function<void()> >::iterator i = list.begin(); i != list.end(); )
            {
                if (boost::function_equal(*i, act))
                    i = list.erase(i);
                else
                    ++i;
            }
        }


        /**
        * Singleton class to manage real time timer interrupts.  Causes SIGALRMs
        * to be sent to the calling processes at requested times.  These signals
        * must then be handled using SignalQueue.
        */
        class Timer : public boost::noncopyable
        {
          public:
            static Timer& getTimer();
            
            void schedule(unsigned short seconds);
          private:
            /** The type of the queue of signal delivery times. */
            typedef std::priority_queue<time_t, std::vector<time_t>, std::greater<time_t> > QueueType;
            
            /** SignalQueue interrupt handler for SIGALRM that schedules the next
                timer interrupt. */
            class Handler
            {
              public:
                Handler(QueueType& t);
                void operator()();
              private:
                QueueType& times; ///< A reference to the containing Timer's queue of interrupt times.
            };
            
            Timer();
            ~Timer();

            QueueType times; ///< Queue of signal delivery times.
            Handler handler; ///< SignalQueue SIGALRM interrupt handler functor.
        };
        
        int uninterruptible_close(int fd);
        ssize_t uninterruptible_read(int fd, unsigned char* buf, size_t count);

    } // namespace LibWheel
    
#endif /* LIBWHEEL_SIGNAL_HPP */
