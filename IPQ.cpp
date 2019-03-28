/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
**************************************************/

/**
* @file IPQ.cpp
* @author Rennie deGraaf
* @date 2007/06/06
*
* Implementation of a C++ interface to libipq.
*/



#include <string>
#include <iostream>
#include <iomanip>
#include <cstddef>
#include <cerrno>
#include <cstring>
#include <boost/lexical_cast.hpp>
#include <boost/cstdint.hpp>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include "IPQ.hpp"
#include "auto_array.hpp"
#include "util.hpp"

extern "C" 
{
#include <libipq.h>
}

/// old versions of linux/netfilter.h don't define NF_STOP
#ifndef NF_STOP
    #define NF_STOP 5
#endif

namespace IPQ
{

/**
* Compute an IP checksum (as described in RFC 791).  This implementation was
* adapted from RFC 1071.
* @param init The sum of previously-summed data.  Use this for computing TCP 
*       checksums; normally, this can be set to 0.
* @param buf The buffer to check.
* @param len The size of \a buffer, in bytes.
*/
boost::uint16_t ip_checksum(boost::uint32_t init, boost::uint8_t* buf, std::size_t len)
{
    boost::uint32_t sum = init;
    boost::uint16_t* shorts = reinterpret_cast<boost::uint16_t*>(buf);

    while (len > 1)
    {
        sum += *shorts++;
        len -= 2;
    }

    if (len == 1)
        sum += *reinterpret_cast<boost::uint8_t*>(shorts);

    while (sum >> 16)	
        sum = (sum >> 16) + (sum & 0xFFFF);

    return ~sum;
}


/**
* Constructor for IpqException.
*/
IpqException::IpqException(const std::string& d)
: runtime_error(d)
{}


/**
* Destructor for IpqException.
*/
IpqException::~IpqException() throw()
{}


/**
* Retrieve the global libipq handle.
* @return A reference to the global libipq handle.
*/
IpqSocket&
IpqSocket::getSocket()
{
    static IpqSocket sock;
    return sock;
}


/**
* Connect to libipq.  Sets the default copy mode to metadata only.  If
* NO_NF_STOP is defined, open raw_sock as well.
* @throw IpqException If the socket is already connected or there is an error 
*       connecting.
*/
void
IpqSocket::connect() THROW((IpqException))
{
    if (isConnected)
        throw IpqException("Socket already connected");
    
    // open library handle
    ipqHandle = ipq_create_handle(0, PF_INET);
    if (ipqHandle == NULL)
        throw IpqException(std::string("Error opening handle: ") + ::ipq_errstr());
    isConnected = true;

    // set default copy mode
    setCopyMode(META, 0);

#ifdef NO_NF_STOP
    raw_sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock == -1)
        throw IpqException(std::string("Error opening raw socket: ") + std::strerror(errno));
#endif
    return;
}


/**
* Sets the libipq copy mode.
* @param mode The libipq copy mode.
* @param range The number of packet payload bytes to copy (default: 65535).  
*       This is only used if \a mode is PACKET.
* @throw IpqException if the socket is not connected, the mode is invalid, or 
*       there is an error setting the mode.
*/
void 
IpqSocket::setCopyMode(CopyMode mode, std::size_t range) THROW((IpqException))
{
    static boost::uint8_t mode_table[] = 
    {
        IPQ_COPY_META,
        IPQ_COPY_PACKET
    };
    
    if (!isConnected)
        throw IpqException("Socket not connected");
    
    if (static_cast<std::size_t>(mode) >= LibWheel::arraySize(mode_table))
        throw IpqException("Invalid mode");

    if (ipq_set_mode(ipqHandle, mode_table[mode], range) == -1)
        throw IpqException(std::string("Error setting IPQ copy mode: ") + ipq_errstr());
}


/**
* Sets the verdict on a packet.  If the packet was changed, the original packet
* will be replaced with the modified version.  If a verdict was already set on
* \a pkt, no action is taken beyond updating the packet checksums.
* @param pkt The packet whose verdict to set.
* @param v The verdict to set.
* @throw IpqException If the verdict is invalid or there was an error setting 
*       the verdict.
* @note If NO_NF_STOP is set, a verdict cannot be safely set, so a copy of the
*       packet in injected through a raw socket.  Care must be taken to avoid
*       infinite loops.
*/
void
IpqSocket::sendResponse(IpqPacket* pkt, Verdict v) THROW((IpqException))
{
    std::size_t buflen;
    boost::uint8_t* buf;
    int status;
    static unsigned int verdict_table[] = 
    {
        NF_ACCEPT,
        NF_DROP,
        NF_STOP,
    };

    // make sure that we have a valid verdict
    if (static_cast<std::size_t>(v) >= LibWheel::arraySize(verdict_table))
        throw IpqException("Invalid verdict");
    
    // check if the packet has been modified
    if (pkt->dirty == true)
        pkt->updateChecksums();
    
    // make sure that a response hasn't already been sent
    if (pkt->responseSent == false)
    {
        buf = pkt->getPacket(buflen);
#ifdef NO_NF_STOP
        /* If NF_STOP isn't supported, the packet has already been dropped.  If 
        we want to keep it, we need to re-inject it through a raw socket. */
        if ((v != DROP) && (pkt->modified))
        {
            IpqIpPacket* ippkt = dynamic_cast<IpqIpPacket*>(pkt);
	    if (ippkt == NULL)
                throw IpqException("Error re-injecting packet: not an IP packet");
            status = sendRawPacket(ippkt->getIpDest(), buf, buflen);
            if (status == -1)
                throw IpqException(std::string("Error re-injecting packet: ") + std::strerror(errno));
            else if (status != static_cast<int>(buflen))
                throw IpqException("Error re-injecting packet: message truncated");
        }
#else
        status = ipq_set_verdict(ipqHandle, pkt->getNfId(), verdict_table[v], buflen, buf);
        if (status == -1)
            throw IpqException(std::string("Error setting verdict: ") + ipq_errstr());
#endif
    
        pkt->responseSent = true;

#ifdef DEBUG
        if (v == DROP)
            packetsDropped++;
        else
            packetsAccepted++;
#endif
    }

}


/**
* Close the libipq handle.  If the handle is not open, no action is taken.
* @throw IpqException If an error was encountered closing the handle.
* @warning Do not close the handle without ensuring that verdicts have been set
*       on all packets received.  Since the destructor to IpqPacket attempts to
*       set a verdict on unresponded packets, Bad Things (tm) will happen if the
*       handle is closed.
*/
void
IpqSocket::close() THROW((IpqException))
{
    if (isConnected)
    {
        // close library handle
        if (ipq_destroy_handle(ipqHandle) == -1)
            throw IpqException(std::string("Error closing IPQ handle: ") + ipq_errstr());

#ifdef NO_NF_STOP
        /* close the raw socket */
        ::close(raw_sock);
#endif
        isConnected = false;
    }
    return;
}


/**
* Receive a packet from libipq.
* @param noblock If \b true, throw an IpqException if no packet is available.  
*       If \b false, block until a packet becomes available.  (default: \b 
*       false)
* @return A dynamically-allocated packet object, which may be an IpqPacket or 
*       any of its subclasses.  It must be freed using \b delete, and a verdict
*       \e should be set on it using IpqSocket::sendResponse().
* @throw IpqException If there was an error reading from the socket, no packet
*       was immediately available and \a noblock was set, or a libipq error
*       message was received.
* @note If \a noblock was not set, then this method may block indefinately.
* @note If NO_NF_STOP is defined, the packet is immediately dropped.  It may 
*       be re-injected using IpqSocket::sendResponse().
*/
IpqPacket*
IpqSocket::recvPacket(bool noblock) THROW((IpqException))
{
    struct nlmsghdr nlh;
    socklen_t addrlen;
    int flags;
    int status;
    
    // get a message header
    addrlen = sizeof(ipqHandle->peer);
    flags = MSG_PEEK | (noblock ? MSG_DONTWAIT : 0);
    status = recvfrom(ipqHandle->fd, reinterpret_cast<void*>(&nlh), sizeof(nlh), flags, reinterpret_cast<struct sockaddr*>(&ipqHandle->peer), &addrlen);
    if (status == -1)
    {
        throw IpqException(std::string("Error reading from socket: ") + std::strerror(errno));
    }
    /* don't check this here, because it results in the packet never being removed from the queue */
    /*else if ((status != sizeof(nlh)) 
             || (addrlen != sizeof (ipqHandle->peer)) 
             || (ipqHandle->peer.nl_pid != 0)
             || (nlh.nlmsg_pid != 0))
    {
        throw IpqException(std::string("Error reading from socket: ") + std::strerror(EPROTO));
    }*/

    // read a packet
    LibWheel::auto_array<boost::uint8_t> buf(new boost::uint8_t[nlh.nlmsg_len]);
    flags = noblock ? MSG_DONTWAIT : MSG_WAITALL;
    status = recvfrom(ipqHandle->fd, reinterpret_cast<void*>(buf.get()), nlh.nlmsg_len, flags, reinterpret_cast<struct sockaddr*>(&ipqHandle->peer), &addrlen);
    if (status == -1)
    {
        throw IpqException(std::string("Error reading from socket: ") + std::strerror(errno));
    }
    else if ((static_cast<unsigned>(status) != nlh.nlmsg_len) 
             || (addrlen != sizeof (ipqHandle->peer)) 
             || (ipqHandle->peer.nl_pid != 0))
	     /* nlh.nlmsg_pid is supposed to be the PID of the source process, or 0 for the kernel, but it
	     seems to be getting set to the PID of the recipient somewhere in Linux 2.6.9.
	     Is that supposed to happen for error messages? */
             // || (nlh.nlmsg_pid != 0))
    {
        /*std::cout << "status: " << status << "; expected: " << sizeof(nlh) << std::endl;
        std::cout << "addrlen: " << addrlen << "; expected: " << sizeof(ipqHandle->peer) << std::endl;
        std::cout << "nl_pid:  " << ipqHandle->peer.nl_pid << "; expected: 0" << std::endl;
        std::cout << "nlmsg_pid: " << nlh.nlmsg_pid << "; expected: 0" << std::endl;*/
        throw IpqException(std::string("Error reading from socket: ") + std::strerror(EPROTO));
    }
    else if ((reinterpret_cast<struct nlmsghdr*>(buf.get()))->nlmsg_flags & MSG_TRUNC)
    {
        throw IpqException("Error reading from socket: message truncated");
    }

    // get the packet type
    switch (ipq_message_type(buf.get()))
    {
      case IPQM_PACKET:
      {
      	IpqPacket* pkt = IpqPacket::createPacket(buf, nlh.nlmsg_len);
#ifdef NO_NF_STOP
        /* If NF_STOP isn't supported, drop the packet immediately */
	size_t plen;
        boost::uint8_t* p = pkt->getPacket(plen);
        status = ipq_set_verdict(ipqHandle, pkt->getNfId(), NF_DROP, plen, p);
        if (status  == -1)
            throw IpqException(std::string("Error setting verdict: ") + ipq_errstr());
#endif

#ifdef DEBUG
        packetsReceived++;
#endif
        return pkt;
      }
      case NLMSG_ERROR:
        throw IpqException(std::string("Error: ") + std::strerror(ipq_get_msgerr(buf.get())));
      default:
        throw IpqException(std::string("Unexpected return from ipq_message_type: ") + boost::lexical_cast<std::string>(static_cast<unsigned>(ipq_message_type(buf.get()))));
    }
}


/**
* Wait for a packet to become available.  
* @throw IpqException If an error was encountered checking for a packet.
* @note This method may block indefinately.
*/
void
IpqSocket::waitForPacket() THROW((IpqException))
{
    fd_set fds;
    int ret;
    
    FD_ZERO(&fds);
    FD_SET(ipqHandle->fd, &fds);
    ret = select(ipqHandle->fd+1, &fds, NULL, NULL, NULL);
    if (ret != 1)
    {
        throw IpqException(std::string("Error waiting for packet: ") + std::strerror(errno));
    }
    return;
}


/**
* Wait for a packet to become available.  If input becomes available on \a 
* func_fd before a packet arrives, call \a func, and resume waiting.  
* @note This method may block indefinately.
*/
void 
IpqSocket::waitForPacket(int func_fd, boost::function<void()> func)
{
    fd_set fds;
    int max_fd;
    int ret;
    
    max_fd = (func_fd > ipqHandle->fd) ? func_fd : ipqHandle->fd;
    while (1)
    {
        FD_ZERO(&fds);
        FD_SET(ipqHandle->fd, &fds);
        FD_SET(func_fd, &fds);
        do
        {
            ret = select(max_fd+1, &fds, NULL, NULL, NULL);
        } while ((ret == -1) && (errno == EINTR));
        if (ret == -1)
        {
            throw IpqException(std::string("Error waiting for packet: ") + std::strerror(errno));
        }
        else if (FD_ISSET(func_fd, &fds))
        {
            func();
            if (ret == 2)
                return;
        }
        else
            return;
    }
}

#ifdef DEBUG
/**
* Retrieve the number of packets that have been received from libipq.
* @return The number of packets received.
*/
unsigned long
IpqSocket::getPacketsReceived() const
{
    return packetsReceived;
}


/**
* Retrieve the number of packets for which a verdict of ACCEPT or STOP was set.
* @return The number of packets accepted.
*/
unsigned long
IpqSocket::getPacketsAccepted() const
{
    return packetsAccepted;
}


/**
* Retrieve the number of packets for which a verdict of DROP was set.
* @return The number of packets dropped.
*/
unsigned long
IpqSocket::getPacketsDropped() const
{
    return packetsDropped;
}
#endif /* DEBUG */


/**
* Constructor for IpqSocket.  Initialize an unconnected libipq handle.
*/
IpqSocket::IpqSocket()
: isConnected(false), copyMode(META), ipqHandle(NULL)
#ifdef DEBUG
    , packetsReceived(0), packetsAccepted(0), packetsDropped(0)
#endif
#ifdef NO_NF_STOP
    , raw_sock()
#endif
{}


/**
* Destructor for IpqSocket.  If the handle is open, close it and discard any
* exceptions thrown.
*/
IpqSocket::~IpqSocket()
{
    try
    {
        close();
    }
    catch (const IpqException& e)
    {}
}


#ifdef NO_NF_STOP
ssize_t
IpqSocket::sendRawPacket(in_addr_t daddr, const boost::uint8_t* pkt, std::size_t len) const
{
    struct sockaddr_in addr;
    
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(daddr);
    addr.sin_port = 0;
    
	// truncation
    return sendto(raw_sock, pkt, len, MSG_DONTWAIT, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
}
#endif


/**
* Destructor for IpqPacket.  If no response has been set for this packet, 
* attempt to set a response of DROP, and discard any exceptions thrown.
*/
IpqPacket::~IpqPacket()
{
    if (!responseSent)
    {
        try
        {
            IpqSocket::getSocket().sendResponse(this, IpqSocket::DROP);
        }
        catch (const IpqException& e)
        {}
    }
}


/**
* Retrieve the Netfilter ID of a packet.
* @return The packet's Netfilter ID.
*/
unsigned long
IpqPacket::getNfId() const
{
    return ipq_get_packet(packet.get())->packet_id;
}


/**
* Retrieve the Netfilter mark value of a packet.
* @return The packet's Netfilter mark value.
*/
unsigned long
IpqPacket::getNfMark() const
{
    return ipq_get_packet(packet.get())->mark;
}


/**
* Retrieve the arrival time of a packet.
* @return The packet's arrival time.
*/
void
IpqPacket::getTimestamp(struct timeval& time) const
{
    time.tv_sec = ipq_get_packet(packet.get())->timestamp_sec;
    time.tv_usec = ipq_get_packet(packet.get())->timestamp_usec;
}


/**
* Retrieve the number of the Netfilter hook on which the packet arrived.
* @return The number of the Netfilter hook on which the packet arrived.
*/
unsigned
IpqPacket::getNfHook() const
{
    return ipq_get_packet(packet.get())->hook;
}


/**
* Retrieve the name of the interface on which the packet arrived, if available.
* @return A reference to the packet's arrival interface name.
*/
const char (&IpqPacket::getIndevName() const)[IFNAMSIZ]
{
    return ipq_get_packet(packet.get())->indev_name;
}


/**
* Retrieve the name of the interface on which the packet will leave, if 
* available.
* @return A reference to the packet's outbound interface name.
*/
const char (&IpqPacket::getOutdevName() const)[IFNAMSIZ]
{
    return ipq_get_packet(packet.get())->outdev_name;
}


/**
* Retrieve the hardware protocol number of the packet.
* @return The packet's hardware protocol number.
*/
unsigned short
IpqPacket::getHwProtocol() const
{
    return ntohs(ipq_get_packet(packet.get())->hw_protocol);
}


/**
* Retrieve the hardware type on which the packet arrived.
* @return The packet's arrival hardware type.
*/
unsigned short
IpqPacket::getHwType() const
{
    return ipq_get_packet(packet.get())->hw_type;
}


/**
* Retrieve the source hardware address of the packet.
* @param[out] addrlen A reference to a location to write the actual length of 
*       the address, in bytes.
* @return A reference to the packet's source hardware address.
*/
const unsigned char (&IpqPacket::getHwSource(unsigned short& addrlen) const)[8]
{
    addrlen = ipq_get_packet(packet.get())->hw_addrlen;
    return ipq_get_packet(packet.get())->hw_addr;
}


/**
* Retrieve the packet.  It will only be available if the copy mode on the libipq
* handle used to receive it was IpqSocket::PACKET and the copy range was greater
* than zero.
* @param[out] size A reference to a location to write the length of the 
*       payload, in bytes.
* @return A const pointer to the packet.
*/
const boost::uint8_t*
IpqPacket::getPacket(std::size_t& size) const
{
    return doGetPacket(size);
}


/**
* Retrieve the packet.  It will only be available if the copy mode on the libipq
* handle used to receive it was IpqSocket::PACKET and the copy range was greater
* than zero.
* @param[out] size A reference to a location to write the length of the 
*       payload, in bytes.
* @return A pointer to the packet.
* @note This method sets the packet's dirty flag, requiring that the packet's
*       checksums be recomputed before a verdict is set.
*/
boost::uint8_t*
IpqPacket::getPacket(std::size_t& size)
{
    dirty = true;
    return doGetPacket(size);
}


/**
* Print a packet to stdout in an easy-to-read format.
*/
void 
IpqPacket::print(std::ostream& out) const
{
    struct timeval time;
    getTimestamp(time);
    int fill = out.fill();
    int width = out.width();
    unsigned short addrlen;
    const unsigned char (&addr)[8] = getHwSource(addrlen);
    
    out << "IPQ headers:"
        << "\n  Packet ID:              " << getNfId()
        << "\n  Timestamp:              " << time.tv_sec << '.' << std::setfill('0') << std::setw(6) << time.tv_usec
        << "\n  Mark:                   " << getNfMark()
        << "\n  Hook:                   " << getNfHook()
        << "\n  Input device:           " << getIndevName()
        << "\n  Output device:          " << getOutdevName()
        << "\n  Hardware protocol:      " << getHwProtocol()
        << "\n  Hardware type:          " << getHwType()
        << "\n  Hardware addresss:      ";
    for (unsigned i=0; i<addrlen; ++i)
        out << std::hex << static_cast<unsigned>(addr[i]) << std::dec;
    out << "\n  Payload length:         " << ipq_get_packet(packet.get())->data_len
        << std::endl;  

    out.width(width);
    out.fill(fill);
}


/**
* Constructor for IpqPacket.  Initialize an IpqPacket from a libipq packet
* message.
*/
IpqPacket::IpqPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen)
: packet(buf), packetLen(buflen), dirty(false), 
#ifdef NO_NF_STOP
modified(false),
#endif
responseSent(false)
{}


/**
* Retrieve the packet.  It will only be available if the copy mode on the libipq
* handle used to receive it was IpqSocket::PACKET and the copy range was greater
* than zero.
* @param[out] size A reference to a location to write the length of the 
*       payload, in bytes.
* @return A pointer to the packet.
*/
boost::uint8_t*
IpqPacket::doGetPacket(std::size_t& size) const
{
    size = ipq_get_packet(packet.get())->data_len;
    return ipq_get_packet(packet.get())->payload;
}


/**
* Update the packet's checksums and clear the dirty flag.
*/
void
IpqPacket::updateChecksums()
{
    dirty = false;
}


/**
* Create an IpqPacket or one of its subclasses from a libipq packet message.
* A packet will be deemed to be an IPv4 packet if it has a full IPv4 header and
* the data length indicated by the header matches the packet's length.  
* A packet will be deemed to be a TCP or UDP packet if it is an IPv4 packet and
* it has a full TCP or UDP header.
* @return A pointer to a dynamically-allocated IpqPacket, or one of its 
*       subclasses.  This pointer must be freed using \b delete, and a verdict 
*       should be set on it using IpqSocket::sendResponse().
*/
IpqPacket*
IpqPacket::createPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen)
{
    ipq_packet_msg_t* pkt;
    struct iphdr* iph;
    
    pkt = ipq_get_packet(buf.get());

    iph = reinterpret_cast<struct iphdr*>(pkt->payload);
    if ((pkt->data_len >= sizeof(struct iphdr)) && (pkt->data_len >= iph->ihl*4) && (iph->version == 4) && (pkt->data_len == ntohs(iph->tot_len)))
    {
        // assume IPv4 with full header present
        struct tcphdr* tcph = reinterpret_cast<struct tcphdr*>(reinterpret_cast<boost::uint8_t*>(iph) + iph->ihl*4);
        if ((iph->protocol == IPPROTO_TCP) && (pkt->data_len >= iph->ihl*4 + sizeof(struct tcphdr)) && (pkt->data_len >= iph->ihl*4 + tcph->doff*4))
        {
            // assume TCP with full header present
            return new IpqTcpPacket(buf, buflen);
        }
        else if ((iph->protocol == IPPROTO_UDP) && (pkt->data_len >= iph->ihl*4 + sizeof(struct udphdr)))
        {
            // assume UDP with full header present
            return new IpqUdpPacket(buf, buflen);
        }
        else
        {
            // some other IP protocol
            return new IpqIpPacket(buf, buflen);
        }
    }
    else
    {
        // not able to determine the type of the packet
        return new IpqPacket(buf, buflen);
    }
}
    

/**
* Retrieve the source IP address of a packet.
* @return The packet's source IP address.
*/
in_addr_t
IpqIpPacket::getIpSource() const
{
    return ntohl(getIpHeader().saddr);
}


/**
* Retrieve the destination IP address of a packet.
* @return The packet's destination IP address.
*/
in_addr_t
IpqIpPacket::getIpDest() const
{
    return ntohl(getIpHeader().daddr);
}


/**
* Retrieve the encapsulated protocol number of a packet.
* @return The packet's encapsulated protocol number.
*/
boost::uint8_t
IpqIpPacket::getProtocol() const
{
    return getIpHeader().protocol;
}


/**
* Retrieve the IP ID of a packet.
* @return The packet's IPID.
*/
boost::uint16_t
IpqIpPacket::getId() const
{
    return ntohs(getIpHeader().id);
}


/**
* Retrieve the fragment offset of a packet, in bytes.  If not zero, then this
* is a non-leading fragment.
* @return The packet's fragment offset.
*/
boost::uint16_t
IpqIpPacket::getFragOffset() const
{
    return ntohs(getIpHeader().frag_off & 0x1fff)*8;
}


/**
* Retrieve the "more fragments to follow" flag of a packet.
* @return \b true if the packet's "more fragments" flag is set; \b false 
*       otherwise.
*/
bool
IpqIpPacket::getMoreFrags() const
{
    return (getIpHeader().frag_off & 0x2000);
}


/**
* Retrieve the complete IP header of a packet.
* A const reference to the packet's IP header.
*/
const struct iphdr&
IpqIpPacket::getIpHeader() const
{
    return doGetIpHeader();
}


/**
* Retrieve the complete IP header of a packet.
* A reference to the packet's IP header.
* @note This method sets the packet's dirty flag, requiring that the packet's
*       checksums be recomputed before a verdict is set.
*/
struct iphdr&
IpqIpPacket::getIpHeader()
{
    dirty = true;
    return doGetIpHeader();
}


/**
* Retrive the IP payload of a packet.
* @param[out] size A reference to a location to store the packet's IP payload 
*       size, in bytes..
* @return A const pointer to the packet's IP payload.
*/
const boost::uint8_t*
IpqIpPacket::getIpPayload(std::size_t& size) const
{
    return doGetIpPayload(size);
}


/**
* Retrive the IP payload of a packet.
* @param[out] size A reference to a location to store the packet's IP payload 
*       size, in bytes..
* @return A pointer to the packet's IP payload.
* @note This method sets the packet's dirty flag, requiring that the packet's
*       checksums be recomputed before a verdict is set.
*/
boost::uint8_t*
IpqIpPacket::getIpPayload(std::size_t& size)
{
    dirty = true;
    return doGetIpPayload(size);
}


/**
* Print an IP packet to stdout in an easy-to-read format.
*/
void 
IpqIpPacket::print(std::ostream& out) const
{
    out << "IP headers:"
        << "\n  Source address:         " << LibWheel::ipv4_to_string(getIpSource())
        << "\n  Destination address:    " << LibWheel::ipv4_to_string(getIpDest())
        << "\n  Protocol:               " << static_cast<unsigned>(getProtocol())
        << "\n  IPID:                   " << getId()
        << "\n  Fragment offset:        " << getFragOffset()
        << "\n  More fragments:         " << (getMoreFrags() ? "yes" : "no")
        << std::endl;
    IpqPacket::print(out);
}


/**
* Destructor for IpqIpPacket.
*/
IpqIpPacket::~IpqIpPacket()
{}


/**
* Constructor for IpqIpPacket.  Initializes an IpqIpPacket from a libipq packet
* message.
*/
IpqIpPacket::IpqIpPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen)
: IpqPacket(buf, buflen)
{}


/**
* Retrieve the complete IP header of a packet.
* A reference to the packet's IP header.
*/
struct iphdr&
IpqIpPacket::doGetIpHeader() const
{
    return *reinterpret_cast<struct iphdr*>(ipq_get_packet(packet.get())->payload);
}


/**
* Retrive the IP payload of a packet.
* @param[out] size A reference to a location to store the packet's IP payload 
*       size, in bytes..
* @return A const pointer to the packet's IP payload.
*/
boost::uint8_t*
IpqIpPacket::doGetIpPayload(std::size_t& size) const
{
    ipq_packet_msg_t* pkt = ipq_get_packet(packet.get());
    struct iphdr* iph = reinterpret_cast<struct iphdr*>(pkt->payload);

    size = pkt->data_len - iph->ihl*4;
    if (size > 0)
        return pkt->payload + iph->ihl*4;
    else
        return NULL;
}


/**
* Update the checksums on an IP packet.
* @note If NO_NF_STOP is defined, then the \c modified flag is set if the old
*       checksum value is different than the new one.
*/
void
IpqIpPacket::updateChecksums()
{
    struct iphdr* iph = &getIpHeader();
#ifdef NO_NF_STOP
    u_int16_t old_check = iph->check;
#endif
    iph->check = 0;
    iph->check = ip_checksum(0, reinterpret_cast<boost::uint8_t*>(iph), iph->ihl*4);
    IpqPacket::updateChecksums();
#ifdef NO_NF_STOP
    if (iph->check != old_check)
        modified = true;
#endif
}


/**
* Retrieve the TCP source port of a packet.
* @return The packet's TCP source port.
*/
in_port_t
IpqTcpPacket::getTcpSource() const
{
    return ntohs(getTcpHeader().source);
}


/**
* Retrieve the TCP destination port of a packet.
* @return The packet's TCP destination port.
*/
in_port_t
IpqTcpPacket::getTcpDest() const
{
    return ntohs(getTcpHeader().dest);
}


/**
* Retrieve the value of the TCP FIN flag.
* @return \b true if the FIN flag is set; \b false otherwise.
*/
bool
IpqTcpPacket::getTcpFin() const
{
    return getTcpHeader().fin;
}


/**
* Retrieve the value of the TCP SYN flag.
* @return \b true if the SYN flag is set; \b false otherwise.
*/
bool
IpqTcpPacket::getTcpSyn() const
{
    return getTcpHeader().syn;
}


/**
* Retrieve the value of the TCP RST flag.
* @return \b true if the RST flag is set; \b false otherwise.
*/
bool
IpqTcpPacket::getTcpRst() const
{
    return getTcpHeader().rst;
}


/**
* Retrieve the value of the TCP PSH flag.
* @return \b true if the PSH flag is set; \b false otherwise.
*/
bool
IpqTcpPacket::getTcpPsh() const
{
    return getTcpHeader().psh;
}


/**
* Retrieve the value of the TCP ACK flag.
* @return \b true if the ACK flag is set; \b false otherwise.
*/
bool
IpqTcpPacket::getTcpAck() const
{
    return getTcpHeader().ack;
}


/**
* Retrieve the value of the TCP URG flag.
* @return \b true if the URG flag is set; \b false otherwise.
*/
bool
IpqTcpPacket::getTcpUrg() const
{
    return getTcpHeader().urg;
}


/**
* Retrieve the complete TCP header of a packet.
* A const reference to the packet's TCP header.
*/
const struct tcphdr&
IpqTcpPacket::getTcpHeader() const
{
    return doGetTcpHeader();
}


/**
* Retrieve the complete TCP header of a packet.
* A reference to the packet's TCP header.
* @note This method sets the packet's dirty flag, requiring that the packet's
*       checksums be recomputed before a verdict is set.
*/
struct tcphdr&
IpqTcpPacket::getTcpHeader()
{
    dirty = true;
    return doGetTcpHeader();
}

/**
* Retrive the TCP payload of a packet.
* @param[out] size A reference to a location to store the packet's TCP payload 
*       size, in bytes..
* @return A const pointer to the packet's TCP payload.
*/
const boost::uint8_t*
IpqTcpPacket::getTcpPayload(std::size_t& size) const
{
    return doGetTcpPayload(size);
}

/**
* Retrive the IP payload of a packet.
* @param[out] size A reference to a location to store the packet's TCP payload 
*       size, in bytes..
* @return A pointer to the packet's TCP payload.
* @note This method sets the packet's dirty flag, requiring that the packet's
*       checksums be recomputed before a verdict is set.
*/
boost::uint8_t*
IpqTcpPacket::getTcpPayload(std::size_t& size)
{
    dirty = true;
    return doGetTcpPayload(size);
}


/**
* Print a TCP packet to stdout in an easy-to-read format.
*/
void 
IpqTcpPacket::print(std::ostream& out) const
{
    out << "TCP headers:"
        << "\n  Source port:            " << getTcpSource()
        << "\n  Destination port:       " << getTcpDest()
        << "\n  Flags:                  " << (getTcpFin() ? "FIN " : "")
                                          << (getTcpSyn() ? "SYN " : "")
                                          << (getTcpRst() ? "RST " : "")
                                          << (getTcpPsh() ? "PSH " : "")
                                          << (getTcpAck() ? "ACK " : "")
                                          << (getTcpUrg() ? "URG " : "")
        << std::endl;
    IpqIpPacket::print(out);
}


/**
* Destructor for IpqTcpPacket.
*/
IpqTcpPacket::~IpqTcpPacket()
{}


/**
* Constructor for IpqTcpPacket.  Initializes an IpqTcpPacket from a libipq packet
* message.
*/
IpqTcpPacket::IpqTcpPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen)
: IpqIpPacket(buf, buflen)
{}


/**
* Retrieve the complete TCP header of a packet.
* A reference to the packet's TCP header.
*/
struct tcphdr&
IpqTcpPacket::doGetTcpHeader() const
{
    boost::uint8_t* iph = ipq_get_packet(packet.get())->payload;
    return *reinterpret_cast<struct tcphdr*>(iph + reinterpret_cast<struct iphdr*>(iph)->ihl*4);
}


/**
* Retrive the TCP payload of a packet.
* @param[out] size A reference to a location to store the packet's TCP payload 
*       size, in bytes..
* @return A pointer to the packet's TCP payload.
*/
boost::uint8_t*
IpqTcpPacket::doGetTcpPayload(std::size_t& size) const
{
    ipq_packet_msg_t* pkt = ipq_get_packet(packet.get());
    struct iphdr* iph = reinterpret_cast<struct iphdr*>(pkt->payload);
    struct tcphdr* tcph = reinterpret_cast<struct tcphdr*>(iph + iph->ihl*4);
    
    size = pkt->data_len - (iph->ihl*4 + tcph->doff*4);
    if (size > 0)
        return pkt->payload + iph->ihl*4 + tcph->doff*4;
    else
        return NULL;
}


/**
* Update the checksums on an TCP packet.
* @note If NO_NF_STOP is defined, then the \c modified flag is set if the old
*       checksum value is different than the new one.
*/
void
IpqTcpPacket::updateChecksums()
{
    ipq_packet_msg_t* pkt = ipq_get_packet(packet.get());
    struct iphdr* iph = &getIpHeader();
    struct tcphdr* tcph = &getTcpHeader();
    unsigned cksum = 0;
#ifdef NO_NF_STOP
    u_int16_t old_check = tcph->check;
#endif
    
    // calculate checksum on pseudoheader
    cksum += (iph->saddr >> 16) & 0x0000ffff;
    cksum += iph->saddr & 0x0000ffff;
    cksum += (iph->daddr >> 16) & 0x0000ffff;
    cksum += iph->daddr & 0x0000ffff;
    cksum += htons(iph->protocol & 0x00ff);
    cksum += htons(pkt->data_len - iph->ihl*4);

    // compute full checksum
    tcph->check = 0;
    tcph->check = ip_checksum(cksum, reinterpret_cast<boost::uint8_t*>(tcph), pkt->data_len - iph->ihl*4);
#ifdef NO_NF_STOP
    if (tcph->check != old_check)
        modified = true;
#endif
    
    IpqIpPacket::updateChecksums();
}


/**
* Retrieve the UDP source port of a packet.
* @return The packet's UDP source port.
*/
in_port_t
IpqUdpPacket::getUdpSource() const
{
    return ntohs(getUdpHeader().source);
}


/**
* Retrieve the UDP destination port of a packet.
* @return The packet's UDP destination port.
*/
in_port_t
IpqUdpPacket::getUdpDest() const
{
    return ntohs(getUdpHeader().dest);
}


/**
* Retrieve the complete UDP header of a packet.
* A const reference to the packet's UDP header.
*/
const struct udphdr&
IpqUdpPacket::getUdpHeader() const
{
    return doGetUdpHeader();
}


/**
* Retrieve the complete UDP header of a packet.
* A reference to the packet's UDP header.
* @note This method sets the packet's dirty flag, requiring that the packet's
*       checksums be recomputed before a verdict is set.
*/
struct udphdr&
IpqUdpPacket::getUdpHeader()
{
    dirty = true;
    return doGetUdpHeader();
}


/**
* Retrive the UDP payload of a packet.
* @param[out] size A reference to a location to store the packet's UDP payload 
*       size, in bytes..
* @return A pointer to the packet's UDP payload.
*/
const boost::uint8_t*
IpqUdpPacket::getUdpPayload(std::size_t& size) const
{
    return doGetUdpPayload(size);
}


/**
* Retrive the UDP payload of a packet.
* @param[out] size A reference to a location to store the packet's UDP payload 
*       size, in bytes..
* @return A pointer to the packet's UDP payload.
* @note This method sets the packet's dirty flag, requiring that the packet's
*       checksums be recomputed before a verdict is set.
*/
boost::uint8_t*
IpqUdpPacket::getUdpPayload(std::size_t& size)
{
    dirty = true;
    return doGetUdpPayload(size);
}


/**
* Print a TCP packet to stdout in an easy-to-read format.
*/
void 
IpqUdpPacket::print(std::ostream& out) const
{
    out << "UDP headers:"
        << "\n  Source port:            " << getUdpSource()
        << "\n  Destination port:       " << getUdpDest()
        << std::endl;
    IpqIpPacket::print(out);
}


/**
* Destructor for IpqUdpPacket.
*/
IpqUdpPacket::~IpqUdpPacket()
{}


/**
* Constructor for IpqTcpPacket.  Initializes an IpqTcpPacket from a libipq packet
* message.
*/
IpqUdpPacket::IpqUdpPacket(LibWheel::auto_array<boost::uint8_t> buf, std::size_t buflen)
: IpqIpPacket(buf, buflen)
{}


/**
* Retrieve the complete UDP header of a packet.
* A reference to the packet's UDP header.
*/
struct udphdr&
IpqUdpPacket::doGetUdpHeader() const
{
    boost::uint8_t* iph = ipq_get_packet(packet.get())->payload;
    return *reinterpret_cast<struct udphdr*>(iph + reinterpret_cast<struct iphdr*>(iph)->ihl*4);
}


/**
* Retrive the UDP payload of a packet.
* @param[out] size A reference to a location to store the packet's UDP payload 
*       size, in bytes..
* @return A pointer to the packet's UDP payload.
*/
boost::uint8_t*
IpqUdpPacket::doGetUdpPayload(std::size_t& size) const
{
    ipq_packet_msg_t* pkt = ipq_get_packet(packet.get());
    struct iphdr* iph = reinterpret_cast<struct iphdr*>(pkt->payload);
    
    size = pkt->data_len - (iph->ihl*4 + sizeof(struct udphdr));
    if (size > 0)
        return pkt->payload + iph->ihl*4 + sizeof(struct udphdr);
    else
        return NULL;
}


/**
* Update the checksums on an UDP packet.
* @note If NO_NF_STOP is defined, then the \c modified flag is set if the old
*       checksum value is different than the new one.
*/
void
IpqUdpPacket::updateChecksums()
{
    struct udphdr* udph = &getUdpHeader();
    
    if (udph->check != 0)
    {
        ipq_packet_msg_t* pkt = ipq_get_packet(packet.get());
        struct iphdr* iph = &getIpHeader();
        unsigned cksum = 0;
#ifdef NO_NF_STOP
        u_int16_t old_check = udph->check;
#endif
    
        // calculate checksum on pseudoheader
        cksum += (iph->saddr >> 16) & 0x0000ffff;
        cksum += iph->saddr & 0x0000ffff;
        cksum += (iph->daddr >> 16) & 0x0000ffff;
        cksum += iph->daddr & 0x0000ffff;
        cksum += htons(iph->protocol & 0x00ff);
        cksum += htons(pkt->data_len - iph->ihl*4);

        // compute full checksum
        udph->check = 0;
        udph->check = ip_checksum(cksum, reinterpret_cast<boost::uint8_t*>(udph), pkt->data_len - iph->ihl*4);
        if (udph->check == 0)
            udph->check = 0xffff;
#ifdef NO_NF_STOP
        if (udph->check != old_check)
            modified = true;
#endif
    }
    
    IpqIpPacket::updateChecksums();
}


} // namespace IPQ

