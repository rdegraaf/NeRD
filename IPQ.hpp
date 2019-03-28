/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
**************************************************/

/**
* @file IPQ.hpp
* @author Rennie deGraaf
* @date 2007/06/06
*
* A C++ interface to libipq.
*
* @todo Clean up namespace pollution from C header files.
* @todo Use different exceptions for different types of errors.
*/


#ifndef IPQ_IPQ_HPP
    #define IPQ_IPQ_HPP

    #include <exception>
    #include <stdexcept>
    #include <string>
    #include <iostream>
    #include <cstddef>
    #include <boost/utility.hpp>
    #include <boost/cstdint.hpp>
    #include <boost/function.hpp>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <sys/time.h>
    #include "auto_array.hpp"
    #include "libwheel.h"

    extern "C"
    {
    #include <libipq.h>
    }


    /**
    * A C++ interface to libipq, the old iptables userspace-queueing system.
    */
    namespace IPQ
    {
        /**
        * Base class for exceptions thrown by IPQ methods.
        */
        class IpqException : public std::runtime_error
        {
          public:
            IpqException(const std::string& d);
            virtual ~IpqException() throw();
        };

        class IpqPacket; // forward declaration


        /**
        * A program's link to libipq.  Only one program can use libipq at a 
        * time.
        * @warning This class is not thread-safe.
        * @bug Connect() does not detect if other another program is using 
        *       libipq.  Instead, if another program is connected, recvPacket() 
        *       will throw an exception.  This is due to a limitation in libipq.
	* @bug Due to a bug in Netfilter, changing the source IP address of a
	*       packet to a non-local address and then setting a verdict of 
	*       NF_ACCEPT will cause it to be dropped.  This has been observed
	*       when the packet was queued from the OUTPUT chain of the mangle
	*       table.  A work-around is to set a verdict of NF_STOP instead of
	*       NF_ACCEPT, but be aware that this results in the packet being
	*       treated differently by iptables.  Kernels prior to 2.6.12 do not
	*       have NF_STOP; defining NO_NF_STOP enables another work-around:
	*       all packets are immediately dropped, and packets that are to be
	*       accepted are re-injected through raw sockets.  In this case, 
	*       care must be taken to ensure that infinite queueing loops do not
	*       occur.  Also, this work-around only works for IP packets.
        */
        class IpqSocket : public boost::noncopyable
        {
          public:
            /** The amount of packet information to copy to userspace. */
            enum CopyMode {META,    ///< Copy packet medatada only.
                           PACKET   ///< Copy both packet metadata and contents.
            };
            
            /** The verdict to set on a packet. */
            enum Verdict {ACCEPT,   ///< Accept the packet and continue iptables traversal.
                          DROP,     ///< Drop the packet.
                          STOP      ///< Accept the packet, but don't continue iptables traversal.
            };

            static IpqSocket& getSocket();
            
            void connect() THROW((IpqException));
            void setCopyMode(CopyMode mode, std::size_t range=65535) THROW((IpqException));
            IpqPacket* recvPacket(bool noblock=false) THROW((IpqException));
            void waitForPacket() THROW((IpqException));
            void waitForPacket(int func_fd, boost::function<void()> func);
            void sendResponse(IpqPacket* pkt, Verdict v) THROW((IpqException));
            void close() THROW((IpqException));
#ifdef DEBUG
            unsigned long getPacketsReceived() const;
            unsigned long getPacketsAccepted() const;
            unsigned long getPacketsDropped() const;
#endif /* DEBUG */            
          protected:
            IpqSocket();
            ~IpqSocket();
          private:
            bool isConnected;               ///< \b true on sockets that are connected; \b false otherwise.
            CopyMode copyMode;              ///< The amount of packet data to copy from kernelspace.
            struct ipq_handle* ipqHandle;   ///< Handle to libipq.
#ifdef DEBUG
            unsigned long packetsReceived;  ///< The number of packets that have been received.
            unsigned long packetsAccepted;  ///< The number of packets for which ACCEPT or STOP verdicts have been set.
            unsigned long packetsDropped;   ///< The number of packets for which DROP verdicts have been set.
#endif /* DEBUG */
#ifdef NO_NF_STOP
            int raw_sock; ///< A raw socket for re-injecting accepted packets.
	    ssize_t sendRawPacket(in_addr_t daddr, const boost::uint8_t* pkt, std::size_t len) const;
#endif /* NO_NF_STOP */
        };


        /**
        * Base class for packets received via IpqSocket.  Contains all packet
        * metadata fields, plus the original packet message from kernelspace.
        *
        * A verdict must be set on each packet exactly once.  When 
        * IpqSocket::sendResponse() is used to set a verdict on a packet, the 
        * packet is flagged so that no new verdict can be set.  If no verdict is
        * set, the  destructor to IpqPacket will set a verdict of DROP.
        *
        * @note Allowing copies of IpqPackets to be made would break the 
        *       responseSent checking.  If it becomes necessary to make copies 
        *       at some point, create an IpqPacketBuffer class that contains all
        *       of the data and getters, but not responseSet or the setters.  
        *       Have IpqPacket inherit that, add the setters, give it a private 
        *       copy constructor and assignment operator, and write an 
        *       assignment operator that allows IpqPackets to be safely assigned
        *       to IpqPacketBuffers.  The only way to create an IpqPacket should 
        *       be from within IpqSocket::recvPacket().
        */
        class IpqPacket : public boost::noncopyable
        {
          public:
            virtual ~IpqPacket();
            unsigned long getNfId() const;
            unsigned long getNfMark() const;
            void getTimestamp(struct timeval& time) const;
            unsigned getNfHook() const;
            const char (&getIndevName() const)[IFNAMSIZ];
            const char (&getOutdevName() const)[IFNAMSIZ];
            unsigned short getHwProtocol() const;
            unsigned short getHwType() const;
            const unsigned char (&getHwSource(unsigned short& addrlen) const)[8];
            const boost::uint8_t* getPacket(std::size_t& size) const;
            boost::uint8_t* getPacket(std::size_t& size);
            virtual void print(std::ostream& out) const;
          protected:
            IpqPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen);
            boost::uint8_t* doGetPacket(std::size_t& size) const;
            virtual void updateChecksums();
            static IpqPacket* createPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen);

            LibWheel::auto_array<boost::uint8_t> packet;  ///< The packet message received from kernelspace.
            std::size_t packetLen;  ///< the length of the packet message in IpqPacket::packet, in bytes.
            bool dirty;  ///< \b true if the packet has been modified but checksums have not been updated; \b false otherwise.
#ifdef NO_NF_STOP
            bool modified; ///< \b true the packet has been modified; \b false otherwise.
#endif
          private:
            friend IpqPacket* IpqSocket::recvPacket(bool); ///< Allow IpqSocket::recvPacket() to access createPacket().
            friend void IpqSocket::sendResponse(IpqPacket*, Verdict); ///< Allow IpqSocket::sendResponse() to access IpqPacket::responseSent and IpqPacket::dirty.

            bool responseSent;  ///< \b true if a verdict has been set on this packet; \b false otherwise.
        };


        /**
        * A complete IPv4 packet received via IpqSocket.  Contains IP header
        * fields and the IP payload.
        * @note This class does not reassemble IP fragments.
        */
        class IpqIpPacket : public IpqPacket
        {
          public:
            in_addr_t getIpSource() const;
            in_addr_t getIpDest() const;
            boost::uint8_t getProtocol() const;
            boost::uint16_t getId() const;
            boost::uint16_t getFragOffset() const;
            bool getMoreFrags() const;
            const struct iphdr& getIpHeader() const;
            struct iphdr& getIpHeader();
            const boost::uint8_t* getIpPayload(std::size_t& size) const;
            boost::uint8_t* getIpPayload(std::size_t& size);
            virtual void print(std::ostream& out) const;
            virtual ~IpqIpPacket();
          protected:
            IpqIpPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen);
            struct iphdr& doGetIpHeader() const;
            boost::uint8_t* doGetIpPayload(std::size_t& size) const;
            virtual void updateChecksums();

            friend IpqPacket* IpqPacket::createPacket(LibWheel::auto_array<boost::uint8_t>, std::size_t); ///< Allow IpqSocket::createPacket() to access the contstructor.
        };


        /**
        * An complete IPv4/TCP packet that was received via IpqSocket. Contains
        * TCP header fields and the TCP payload.
        */
        class IpqTcpPacket : public IpqIpPacket
        {
          public:
            in_port_t getTcpSource() const;
            in_port_t getTcpDest() const;
	    bool getTcpFin() const;
	    bool getTcpSyn() const;
	    bool getTcpRst() const;
	    bool getTcpPsh() const;
	    bool getTcpAck() const;
	    bool getTcpUrg() const;
            const struct tcphdr& getTcpHeader() const;
            struct tcphdr& getTcpHeader();
            const boost::uint8_t* getTcpPayload(std::size_t& size) const;
            boost::uint8_t* getTcpPayload(std::size_t& size);
            virtual void print(std::ostream& out) const;
            virtual ~IpqTcpPacket();
          protected:
            IpqTcpPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen);
            struct tcphdr& doGetTcpHeader() const;
            boost::uint8_t* doGetTcpPayload(std::size_t& size) const;
            virtual void updateChecksums();

            friend IpqPacket* IpqPacket::createPacket(LibWheel::auto_array<boost::uint8_t>, std::size_t); ///< Allow IpqSocket::createPacket() to access the contstructor.
        };


        /**
        * An complete IPv4/UDP packet that was received via IpqSocket. Contains
        * UDP header fields and the UDP payload.
        */
        class IpqUdpPacket : public IpqIpPacket
        {
          public:
            in_port_t getUdpSource() const;
            in_port_t getUdpDest() const;
            const struct udphdr& getUdpHeader() const;
            struct udphdr& getUdpHeader();
            const boost::uint8_t* getUdpPayload(std::size_t& size) const;
            boost::uint8_t* getUdpPayload(std::size_t& size);
            virtual void print(std::ostream& out) const;
            virtual ~IpqUdpPacket();
          protected:
            IpqUdpPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen);
            struct udphdr& doGetUdpHeader() const;
            boost::uint8_t* doGetUdpPayload(std::size_t& size) const;
            virtual void updateChecksums();

            friend IpqPacket* IpqPacket::createPacket(LibWheel::auto_array<boost::uint8_t>, std::size_t); ///< Allow IpqSocket::createPacket() to access the contstructor.
        };

    }

#endif /* IPQ_IPQ_HPP */
