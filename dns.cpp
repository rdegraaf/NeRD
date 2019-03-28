/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
*
* This file is part of LibWheel.
**************************************************/

/**
* @file dns.cpp
* @author Rennie deGraaf 
* @date 2007/06/01
*
* Definitions of functions and classes for working with the Domain Name System 
* (DNS).
*/

#include <stdexcept>
#include <string>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include "libwheel.h"
#include "util.hpp"
#include "dns.hpp"

namespace LibWheel
{
    /**
    * Constructor for DNSFailure.
    * @param s A string describing the reason for throwing the exception.
    * @param err The DNS error code.  See the man page for gethostbyname() for
    *       details.
    */
    DNSFailure::DNSFailure(const std::string& s, int err)
    : runtime_error(s), error(err)
    {}


    /**
    * Constructor for DNSError.
    * @param s A string describing the reason for throwing the exception.
    */
    DNSError::DNSError(const std::string& s)
    : runtime_error(s)
    {}


    /**
    * Retrieve a DNS TXT record for an IP address
    * @param addr The address to search, in host byte order.
    * @return The TXT records for \a addr
    * @throw DNSFailure If no TXT record for \a addr could be found.
    * @throw DNSError If the DNS TXT record for \a addr could not be parsed.
    */
    const std::vector<std::string>
    getDnsTxt(in_addr_t addr) THROW((DNSFailure, DNSError))
    {
        unsigned char response[NS_PACKETSZ];
        ns_msg handle;
        ns_rr rec;
        int retval;
        int resplen;
        std::vector<std::string> result;

        // reverse bytes and convert to string
        std::string name = ipv4_to_string(htonl(addr)) + ".in-addr.arpa";
        
        // perform the query
        resplen = res_query(name.c_str(), ns_c_in, ns_t_txt, response, sizeof(response));
        if (resplen == -1)
            throw DNSFailure(std::string("Error looking up TXT record for ") + name + ": " + hstrerror(h_errno), h_errno);

        // parse the result        
        retval = ns_initparse(response, resplen, &handle);
        if (retval == -1)
            throw DNSError(std::string("Error parsing DNS record: ns_initparse: ") + std::strerror(errno));

        // extract answer records
        for (int i=0; i<ns_msg_count(handle, ns_s_an); ++i)
        {
            retval = ns_parserr(&handle, ns_s_an, i, &rec);
            if (retval == -1)
                throw DNSError(std::string("Error parsing DNS record: ns_parserr: ") + std::strerror(errno));
            else if ((ns_rr_type(rec) != ns_t_txt) || (ns_rr_class(rec) != ns_c_in))
                throw DNSError("Error parsing DNS record: unexpected class or type");
            else if (ns_rr_rdlen(rec) > 0)
            {
                if (ns_rr_rdlen(rec) != ns_rr_rdata(rec)[0] + 1)
                    throw DNSError("Error parsing DNS record: inconsistent record lengths");
                else
                    result.push_back(std::string(&(ns_rr_rdata(rec)[1]), &(ns_rr_rdata(rec)[ns_rr_rdlen(rec)])));
                    //std::copy(&(ns_rr_rdata(rec)[1]), &(ns_rr_rdata(rec)[ns_rr_rdlen(rec)]), std::back_inserter(result));
            }
            else
                throw DNSError("Error parsing DNS record: empty record");
        }

        return result;
    }


} // namespace LibWheel
