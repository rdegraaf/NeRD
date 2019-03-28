/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
*
* This file is part of LibWheel.
**************************************************/

/**
* @file util.hpp
* @author Rennie deGraaf 
* @date 2007/06/13
*
* Declarations for miscellaneous LibWheel functions and classes that don't fit
* anywhere else.
*/

#ifndef LIBWHEEL_UTIL_HPP
    #define LIBWHEEL_UTIL_HPP
    
    #include <stdexcept>
    #include <string>
    #include <netinet/in.h>
    
    namespace LibWheel
    {
    
        // documented in util.cpp
        std::string ipv4_to_string(in_addr_t a);
        int open_files();
        void close_files_on_exec(int maxfd);
	void write_pid(const char* file);
    
        /**
        * Determines the size of an array, in elements.
        * @param _ A reference to an array.
        * @return The number of elements in the array
        * @note This only words for arrays, not pointers.
        */
        template <typename T, std::size_t N>
        static inline std::size_t
        arraySize(T (&)[N])
        {
            return N;
        }
        
        
        /**
        * Exception thrown when an I/O error occurs.
        */
        class IOException : public std::runtime_error
        {
          public:
            IOException(const std::string& s);
        };

        /**
        * Exception thrown when a socket error occurs.
        */
        class SocketException : public std::runtime_error
        {
          public:
            SocketException(const std::string& s);
        };

        /**
        * Exception throws when a parsing error occurs.
        */
        class ParseError : public std::runtime_error
        {
          public:
            ParseError(const std::string& s);
        };

    } // namespace LibWheel

#endif /* LIBWHEEL_UTIL_HPP */
