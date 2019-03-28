/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
*
* This file is part of LibWheel.
**************************************************/

/**
* @file dns.hpp
* @author Rennie deGraaf 
* @date 2007/06/01
*
* Functions and classes for working with the Domain Name System (DNS).
*/

#ifndef LIBWHEEL_DNS_HPP
    #define LIBWHEEL_DNS_HPP
    
    #include <stdexcept>
    #include <vector>
    #include <string>
    #include <netinet/in.h>
    #include "libwheel.h"
    
    namespace LibWheel
    {
        /**
        * Exception thrown when a DNS lookup fails.
        */ 
        class DNSFailure : public std::runtime_error
        {
          public:
            DNSFailure(const std::string& s, int err);
            const int error; ///< The DNS error code.
        };

        /**
        * Exception thrown when an error is encountered parsing a DNS record.
        */
        class DNSError : public std::runtime_error
        {
          public:
            DNSError(const std::string& s);
        };

        const std::vector<std::string> getDnsTxt(in_addr_t addr) THROW((DNSFailure, DNSError));
    } // namespace LibWheel

#endif /* LIBWHEEL_DNS_HPP */
