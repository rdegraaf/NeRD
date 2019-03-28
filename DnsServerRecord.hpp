/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
**************************************************/

/**
* @file DnsServerRecord.hpp
* @author Rennie deGraaf
* @date 2007/12/13
*
* A class to handle DNS server records for the Network Rerouter Daemon (nerd).
*/


#ifndef NERD_DNSSERVERRECORD_HPP
    #define NERD_DNSSERVERRECORD_HPP

    #include <string>
    #include <map>
    #include "libwheel.h"
    #include "util.hpp"

    namespace NERD
    {    
        /**
        * Holds a DNS TXT server record.
        */
        class DnsServerRecord
        {
          public:
            typedef std::string key_type;   ///< The type of keys in a DNS server record.
            typedef std::string value_type; ///< The type of values in a DNS server record.
            typedef std::size_t size_type;  ///< An appropriate type for the number of entries in a DNS server record
          private:
            typedef std::map<key_type, value_type> table_type; ///< The type of a DNS server record lookup table.
          public:
            typedef table_type::const_iterator const_iterator; ///< A type describing a constant bidirectional iterator for a DNS server record.
            DnsServerRecord(const std::string& s) THROW((LibWheel::ParseError));
            const_iterator getValue(const std::string& key) const;
            const_iterator begin() const;
            const_iterator end() const;
            size_type size() const;
            bool empty() const;
          private:
            void parseRecord(const std::string& s) THROW((LibWheel::ParseError));
          
            table_type record; ///< The parsed key-value pairs from the DNS TXT record.
        };
    
    } // namespace NERD

#endif /* NERD_DNSSERVERRECORD_HPP */
