/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
*
* This file is part of LibWheel.
**************************************************/

/**
* @file WaitList.hpp
* @author Rennie deGraaf 
* @date 2007/05/27
*
* Declarations for LibWheel::WaitList.
*/

#ifndef LIBWHEEL_WAITLIST_HPP
    #define LIBWHEEL_WAITLIST_HPP

    #include <list>
    #include <ctime>
    
    namespace LibWheel
    {

        /**
        * A list from which items will be removed after a timeout.  When an item 
        * is inserted, a timer interrupt is scheduled using Timer.  When the
        * interrupt is handled (by calling SignalQueue::handleNext() or
        * SignalQueue::handleAll()), the item will be removed.  Additional 
        * operations can be performed at this time by specializing 
        * WaitList::WaitGC::operator()() for value_type.
        *
        * The underlying container is std::list.
        *
        * @bug The timer interrupt handler (WaitList::WaitGC) assumes that the 
        * list is sorted in chronological order.  However, since list iterators 
        * are provided, this is not necessarily true.  Consequently, objects 
        * that are out of chronological order will not be removed until after 
        * all objects before them in list order have timed out and been removed.
        *
        * @warning The constructor to WaitList sets a signal handler for SIGALRM
        * through SignalQueue.  Don't use this class if you have a handler for 
        * SIGALRM outside of SignalQueue or if you're using a library function 
        * that uses SIGALRM.
        */
        template <typename V>
        class WaitList
        {
          protected:
            class WaitGC; // forward declaration
          public:
            /**
            * Wrapper that attaches a timestamp to objects stored in a WaitList.
            */
            class WaitWrapper
            {
              public:
                WaitWrapper(const V& v, unsigned short timeout);
                V value; ///< The object being stored.
              private:
                friend void WaitGC::operator()();
                std::time_t timeout; ///< The time to remove the object, in seconds since the epoch.
            };
            typedef V value_type; ///< The type of object stored in this WaitList.
            typedef typename std::list<WaitWrapper>::iterator iterator; ///< A type describing a bidirectional iterator for the list.
            typedef typename std::list<WaitWrapper>::const_iterator const_iterator; ///< A type describing a constant bidirectional iterator for the list.

            WaitList(unsigned short time);
            ~WaitList();
            iterator begin();
            iterator end();
            const_iterator begin() const;
            const_iterator end() const;
            void add(const value_type& rev);
            iterator erase(iterator& i);
            std::size_t size() const;
            bool empty() const;
          protected:
            /** 
            * %Timer interrupt handler for WaitList.  Functors of this type are
            * called from SignalQueue::handleNext() or SignalQueue::handleAll()
            * to remove expired objects from a WaitList.
            */
            class WaitGC
            {
              public:
                WaitGC(std::list<WaitWrapper>& l);
                void operator()();
              private:
                std::list<WaitWrapper>& objs; ///< A reference to the object list of the parent WaitList.
            };
            
            std::list<WaitWrapper> objs; ///< The list of objects contained by this WaitList.
            WaitGC gc; ///< The timer interrupt handler for this WaitList.
            unsigned short timeout; ///< The lifetime of objects stored in this WaitList, in seconds.
        };
    
    } // namespace LibWheel
    
#include "WaitList_impl.cpp"

#endif /* LIBWHEEL_WAITLIST_HPP */
