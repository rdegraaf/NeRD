/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
**************************************************/

/**
* @file DnsServerRecord.cpp
* @author Rennie deGraaf
* @date 2007/12/13
*
* A class to handle DNS server records for the Network Rerouter Daemon (nerd).
*/


#include <vector>
#include <string>
#include <algorithm>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include "DnsServerRecord.hpp"

#include <iostream>

namespace NERD
{
    /**
    * Constructor for DnsServerRecord.  Parses a DNS TXT record into a lookup
    * table of key-value pairs.
    * @param s A DNS TXT record, consisting of a semicolon-separated list of
    *       key=value pairs.
    * @throw LibWheel::ParseError If \a s is improperly formatted or otherwise 
    *       cannot be parsed.
    * @see DnsServerRecord::parseRecord()
    */
    DnsServerRecord::DnsServerRecord(const std::string& s) THROW((LibWheel::ParseError))
    : record()
    {
        parseRecord(s);
    }
    
    
    /**
    * Parses a DNS TXT record into a lookup table of key-value pairs.
    * @param s A DNS TXT record, consisting of a semicolon-separated list of
    *       key=value pairs.
    * @throw LibWheel::ParseError If an entry is encountered with a null key, 
    *       with no key deliminator, or with a null value.
    */
    void
    DnsServerRecord::parseRecord(const std::string& s) THROW((LibWheel::ParseError))
    {
        //typedef std::vector<boost::iterator_range<const std::string> > rec_type;
        typedef std::vector<std::string> rec_type;
        rec_type recs;
        boost::algorithm::split(recs, s, boost::algorithm::is_any_of(";"));
        std::string::iterator deliminator;
        
        for (rec_type::iterator i=recs.begin(); i!=recs.end(); ++i)
        {
            // ignore empty tokens
            if (i->begin() == i->end())
                continue;
            
            // find the key deliminator
            for (deliminator=i->begin(); ((deliminator!=i->end()) && ((*deliminator) != '=')); ++deliminator);
            if (deliminator == i->begin())
                throw LibWheel::ParseError("Empty key");
            else if (deliminator == i->end())
                throw LibWheel::ParseError("No key deliminator");
            else if (deliminator+1 == i->end())
                throw LibWheel::ParseError("Empty value");

            record.insert(std::make_pair(std::string(i->begin(), deliminator), std::string(deliminator+1, i->end())));
        }
    }
    
    
    /**
    * Retrieve the value for a given key in a DNS server record.
    * @return \c An iterator to an std::pair containing \a key and the 
    *       associated value, or this->end() if \a key is not found.
    */
    DnsServerRecord::const_iterator
    DnsServerRecord::getValue(const std::string& key) const
    {
        return record.find(key);
    }
    
    
    /***
    * Retrieves a constant bidirectional iterator to the beginning of the 
    * record.
    * @return An const_iterator to the first key-value entry in the record, or
    *       just past the last entry if the record is empty.
    */
    DnsServerRecord::const_iterator
    DnsServerRecord::begin() const
    {
        return record.begin();
    }
    
    
    /**
    * Retrieves a constant bidirectional iterator to just past the last entry
    * in the record.
    * @return A const_iterator pointing just past the last entry in the record.
    */
    DnsServerRecord::const_iterator
    DnsServerRecord::end() const
    {
        return record.end();
    }


    /**
    * Retrieves the number of key-value entries in a record.
    * @return The number of key-value entries in the record.
    */
    DnsServerRecord::size_type
    DnsServerRecord::size() const
    {
        return record.size();
    }
    
    
    /**
    * Checks if a record is empty.
    * @return \b true if the record is empty; \b false otherwise.
    */
    bool
    DnsServerRecord::empty() const
    {
        return record.empty();
    }

} // namespace NERD
