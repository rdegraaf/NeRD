/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
*
* This file is part of LibWheel.
**************************************************/

/**
* @file WaitList_impl.cpp
* @author Rennie deGraaf 
* @date 2007/05/27
*
* Method definitions for LibWheel::WaitList.
*/

#include <boost/utility.hpp>
#include "WaitList.hpp"
#include "Signals.hpp"

namespace LibWheel
{

/**
* Constructor for WaitList::WaitWrapper.  
* @param v The object to store.
* @param t The lifetime of v, in seconds.
*/
template <typename V>
WaitList<V>::WaitWrapper::WaitWrapper(const V& v, unsigned short t)
: value(v), timeout(::time(NULL)+t)
{}


/**
* Constructor for WaitList.
* @param time The lifetime of objects stored in this WaitList.
* @sideeffect Sets the signal handler for SIGALRM.
*/
template <typename V>
WaitList<V>::WaitList(unsigned short time)
: objs(), gc(objs), timeout(time)
{
    SignalQueue::setHandler(SIGALRM, SignalQueue::HANDLE);
    SignalQueue::addHandler(SIGALRM, boost::ref(gc));
}


/**
* Destructor for WaitList
*/
template <typename V>
WaitList<V>::~WaitList()
{
    SignalQueue::deleteHandler(SIGALRM, boost::ref(gc));
}


/**
* Retrieves a bidirectional iterator to the beginning of the list.
* @return An iterator to the first item of the list, or just past the end of the
*       list if it is empty.
*/
template <typename V>
typename WaitList<V>::iterator
WaitList<V>::begin()
{
    return objs.begin();
}


/**
* Retrieves a constant bidirectional iterator to the beginning of the list.
* @return A const_iterator to the first item of the list, or just past the end 
*       of the list if it is empty.
*/
template <typename V>
typename WaitList<V>::const_iterator
WaitList<V>::begin() const
{
    return objs.begin();
}


/**
* Retrieves a bidirectional iterator to just past the end of the list.
* @return An iterator pointing just past the end of the list
*/
template <typename V>
typename WaitList<V>::iterator
WaitList<V>::end()
{
    return objs.end();
}


/**
* Retrieves a constant bidirectional iterator to just past the end of the list.
* @return A const_iterator pointing just past the end of the list
*/
template <typename V>
typename WaitList<V>::const_iterator
WaitList<V>::end() const
{
    return objs.end();
}


/**
* Adds an object to the back of the list.
* @param rec The object to add.
* @sideeffect Schedules a timer interrupt through Timer.
*/
template <typename V>
void
WaitList<V>::add(const value_type& rec)
{
    objs.push_back(WaitWrapper(rec, timeout));
    Timer::getTimer().schedule(timeout);
}


/**
* Removes an object from the list.
* @param i An iterator pointing to the object to remove.
*/
template <typename V>
typename WaitList<V>::iterator
WaitList<V>::erase(iterator& i)
{
    return objs.erase(i);
}


/**
* Retrieves the number of elements in the list.
* @return The number of elements in the list.
*/
template <typename V>
std::size_t
WaitList<V>::size() const
{
    return objs.size();
}


/**
* Checks if the list is empty.
* @return \b true if the list is empty; \b false otherwise.
*/
template <typename V>
bool
WaitList<V>::empty() const
{
    return objs.empty();
}


/**
* Constructor for WaitList::WaitGC.
* @param l A reference to the list of objects contained by the parent WaitList.
*/
template <typename V>
WaitList<V>::WaitGC::WaitGC(std::list<WaitWrapper>& l)
: objs(l)
{}


/**
* Call operator for WaitList::WaitGC.  Removes objects from the front of \a objs
* that have expired.
*/
template <typename V>
void
WaitList<V>::WaitGC::operator()()
{
    // remove all entries that have timed out
    while ((objs.begin() != objs.end()) && (difftime(time(NULL), objs.begin()->timeout)>0))
    {
        objs.pop_front();
    }
}

} // namespace LibWheel
