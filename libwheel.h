/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
* 
* This file is part of LibWheel
**************************************************/

/**
* @file libwheel.h
* @author Rennie deGraaf
* @date 2007/05/30
*
* Miscellaneous definitions and useful macros for LibWheel.
*/

#ifndef LIBWHEEL_H
    #define LIBWHEEL_H
    
    /**
    * Allows a program to check exceptions in debug builds while skipping the
    * checks in release builds. C++ checks that any exceptions thown match 
    * \c throw() specifiers at run-time, rather than at compile-time, so there's
    * often little point in leaving \c throw() specifiers in release builds.  
    *
    * To define a function that throws exceptions ExceptA and ExceptB, define it
    * as follows (note the double brackets):
    *   @code
    *     int foo() THROW((ExceptA, ExceptB));
    *   @endcode
    *
    * @param x A bracketed list of exceptions that may be thrown.
    */
    #ifdef DEBUG
        #define THROW(x) throw x
    #else
        #define THROW(x)
    #endif

    /** Used internally by QUOTE(x) due to work around precedence rules.  Don't
        use directly. */
    #define XQUOTE(x) #x
    
    /** Quote a macro argument */
    #define QUOTE(x) XQUOTE(x)
    
    /**
    * @namespace LibWheel
    * A set of reusuable software components written in various languages.
    */

#endif /* LIBWHEEL_H */
