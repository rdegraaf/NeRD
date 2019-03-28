/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
**************************************************/

/**
* @file nerd.cpp
* @author Rennie deGraaf
* @date 2007/12/13
*
* Main module for the Network Rerouter Daemon (nerd).
*/


#include <stdexcept>
#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <ext/hash_map>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "Logmsg.hpp"
#include "Signals.hpp"
#include "IPQ.hpp"
#include "WaitList.hpp"
#include "util.hpp"
#include "spc_sanitize.h"
#include "drop_priv.h"
#include "dns.hpp"
#include "DnsServerRecord.hpp"
#include "libwheel.h"
#include "nerd.h"


#define LOCALHOST_IP 0x7f000001     ///< 127.0.0.1, as an integer in HBO.
#define MAGIC_PORT 1                ///< To servers, client connections will appear to come from this port on localhost.
#define PIDFILE "/var/run/nerd.pid"  ///< When in daemon mode, write the PID to this file.

/**
* Functions and classes specific to the Network Rerouter Daemon (nerd).
*/
namespace NERD
{

/**
* The main class for the Network Rerouter Daemon (nerd).  Responsible for
* receiving packets from kernelspace via libipq, launching servers to handle
* them, creating and tracking connections, and forwarding packets.
*
* Packets are received from kernelspace in operator(), from which they are 
* passed to handlePacket() for handling.  If a packet is part of an existing 
* connection, it are redirected to its destination server from there.  
* Otherwise, createConnection() is called to create a connection.  If an
* appropriate server can be found (see findServer()), then the server is 
* launched and the packet queued pending a message from the server indicating
* the port that it is using.  Otherwise, the packet is accepted without
* modification.
*
* Servers are responsible for writing their listen port numbers to stdout (file 
* descriptor 1) as two-byte messages in network byte order.  If this does not
* occur within 10 seconds of a server starting, then it is assumed to be 
* malfunctioning, is sent a SIGINT, and is dropped.  The initial packet 
* associated with such a server is accepted unmodified.
*
* Notification that a server has written its port number back comes through 
* SIGIO signals, which are handled synchronously by a functor of type 
* ConnectionServer::ServerWritebackHandler in operator() via 
* LibWheel::SignalQueue.  This functor creates redirection rules for packets
* travelling both too and from the server.  
*
* Connections are closed when SIGCHLD is received from their server processes, 
* indicating that they have exited.  A function of type ServerExitHandler is
* responsible for handling SIGCHID, again through LibWheel::SignalQueue.  
* Connection redirection rules persist for \c NERD_CONNECTION_TIMEOUT seconds 
* after their servers exit.
*
* SIGALRM is used internally to implement timeouts.  As with all other signals
* used in this program, it is handled synchronously through 
* LibWheel::SignalQueue.
*
* @bug As described above, servers that have not responded within 10 seconds are
*       assumed to be malfunctioning and are dropped.  However, if the server is
*       in fact still running, it will exit when it receives the SIGINT or at
*       some later time.  This will result in a warning message indicating that
*       SIGCHLD was received from a process for which no record exists.  This 
*       could probably be fixed, but an extra log message is not currently 
*       considered to be a problem worthy of the effort required to fix it.
*/
class ConnectionServer
{
  public:
    ConnectionServer(const std::string& root, bool verb, bool restrict) THROW((IPQ::IpqException, LibWheel::IOException, LibWheel::SocketException));
    ~ConnectionServer();
    void operator()();
    void printStats() const;
  private:
    /** 
    * Exception thrown by getRedirectRule() when a packet does not match any 
    * existing connection record.
    */
    class UnknownConnectionException : public std::runtime_error
    {
      public:
        UnknownConnectionException(const std::string& s);
    };

    /**
    * Exception thrown by findServer() when no server program can be found to 
    * handle a new connection.
    */
    class UnknownServerException : public std::runtime_error
    {
      public:
        UnknownServerException(const std::string& s);
    };
    
    /**
    * The source and destination addresses of IP packets travelling in one 
    * direction in a connection.
    */
    struct AddressPair
    {
        const boost::uint32_t srcAddr; ///< Packet source IP address.
        const boost::uint32_t dstAddr; ///< Packet destination IP address.
        const boost::uint16_t srcPort; ///< Packet source port.
        const boost::uint16_t dstPort; ///< Packet destination port.
        const boost::uint8_t protocol; ///< Packet transport protocol number.
        AddressPair(const IPQ::IpqTcpPacket* pkt);
        AddressPair(boost::uint32_t sa, boost::uint32_t da, boost::uint16_t sp, boost::uint16_t dp, boost::uint8_t prot);
        bool operator==(const AddressPair& a) const;
    };
    
    /**
    * A functor that computes a hash of an AddressPair, suitable for use with
    * __gnu_cxx::hash_map.
    */
    class AddressPairHash
    {
      public:
        size_t operator()(const AddressPair& addr) const;
      private:
        __gnu_cxx::hash<boost::uint32_t> hash32; ///< A hasher for unsigned 32-bit integers.
        __gnu_cxx::hash<boost::uint16_t> hash16; ///< A hasher for unsigned 16-bit integers.
        __gnu_cxx::hash<boost::uint8_t> hash8;   ///< A hasher for unsigned 8-bit integers.
    };
    
    /**
    * A look-up table mapping the addresses of packets to redirection rules.
    */
    typedef __gnu_cxx::hash_map<AddressPair, AddressPair, AddressPairHash> RedirectionTable;

    
    /**
    * A description of a connection managed by a server program.
    */
    class Connection
    {
      public:
        Connection(const IPQ::IpqTcpPacket* pkt, boost::uint32_t rsaddr, boost::uint32_t rdaddr, boost::uint16_t rsport, boost::uint16_t rdport, const std::string& name);
        const AddressPair& getForwardAddr() const;
        const AddressPair& getReverseAddr() const;
        const std::string& getName() const;
      private:
        const AddressPair forwardAddr; ///< The addresses of packets sent by a client to a server.
        const AddressPair reverseAddr; ///< The addresses of packets sent by a server to a client.
        const std::string serverName;  ///< The name of the server program handling a connection
    };
    
    /**
    * A look-up table mapping server process IDs to the connections that they
    * manage.
    */
    typedef __gnu_cxx::hash_map<pid_t, Connection> ServerTable;
    
    /**
    * Information pertaining to a server that is starting up to handle a 
    * connection.
    */
    struct PendingConnection
    {
        boost::shared_ptr<IPQ::IpqTcpPacket> packet; ///< The packet that is initiating the connection to be handled by this server; to be redirected to the server once it is running.
        const int pipefd; ///< The read end of a pipe from which to read the port number that the server is using; the write end is the server's stdout.
        const std::string serverName; ///< The name of the server program.
        const pid_t pid; ///< The process ID of the server program.
        PendingConnection(IPQ::IpqTcpPacket* pkt, int fd, const std::string& name, pid_t p);
    };
    
  public:
    /**
    * A list of pending connections.
    * @note This type is public because specializations of LibWheel::WaitList
    *       are outsideof this class.
    */
    typedef LibWheel::WaitList<PendingConnection> PendingConnectionList;

    /**
    * A list of redirection rules that are scheduled to be deleted at their 
    * expiry of timers.
    * @note This type is public because specializations of LibWheel::WaitList
    *       are outsideof this class.
    */
    typedef LibWheel::WaitList<std::pair<RedirectionTable*, RedirectionTable::iterator> > TimeoutList;

  private:  
    /**
    * Information about a server program to be started.
    */
    struct ServerRecord
    {
        const std::string serverAddr; ///< The IP address to be emulated by a server program, as a string.
        const std::string serverPort; ///< The port number to be emulated by a server program, as a string.
        const std::string serverProto; ///< The transport protocol of \c serverPort.
        std::string serverProgram; ///< The name of a server program.
        std::string serverDnsRecord; ///< The DNS TXT record for \c serverAddr.
        ServerRecord(const std::string& addr, const std::string& port, const std::string& proto);
    };
    
    /**
    * Functor to handle SIGCHLD signals received through LibWheel::SignalQueue.
    * Performs appropriate actions when a child process exits; see operator()()
    * for details.
    */ 
    class ServerExitHandler
    {
      public:
        ServerExitHandler(PendingConnectionList& pcl, RedirectionTable& rt, ServerTable& st, TimeoutList& tl, bool v);
        void operator()();
      private:
        PendingConnectionList::iterator findPendingConnection(pid_t pid);
        
        PendingConnectionList& pendingConnections; ///< A reference to the containing ConnectionServer's list of pending connections.
        RedirectionTable& redirections; ///< A reference to the containing ConnectionServer's table of redirection rules.
        ServerTable& servers; ///< A reference to the containing ConnectionServer's look-up table of active servers.
        TimeoutList& timeoutList; ///< A reference to the containing ConnectionServer's list of redirection rules awaiting removal.
        bool verbose; ///< \b true to log extra messages; \b false otherwise.
    };
    
    /**
    * Functor to handle SIGIO signals received through LibWheel::SignalQueue.
    * When a server process writes its listen port number to its stdout, that
    * triggers a SIGIO; this functor determines which servers have called back
    * and finishes setting up connections to them.  See operator()() for details.
    */
    class ServerWritebackHandler
    {
      public:
        ServerWritebackHandler(PendingConnectionList& pcl, RedirectionTable& rt, ServerTable& st, IPQ::IpqSocket& s);
        void operator()();
      private:
        PendingConnectionList& pendingConnections; ///< A reference to the containing ConnectionServer's list of pending connections.
        RedirectionTable& redirections; ///< A reference to the containing ConnectionServer's table of redirection rules.
        ServerTable& servers; ///< A reference to the containing ConnectionServer's look-up table of active servers.
        IPQ::IpqSocket& sock; ///< A handle to libipq.
    };
    
    // private methods
    void handlePacket(IPQ::IpqPacket* pkt);
    const AddressPair& getRedirectRule(const IPQ::IpqTcpPacket* pkt) const THROW((UnknownConnectionException));
    const AddressPair& getRedirectRule(const IPQ::IpqUdpPacket* pkt) const THROW((UnknownConnectionException));
    void createConnection(IPQ::IpqTcpPacket* pkt);
    void createConnection(IPQ::IpqUdpPacket* pkt);
    void findServer(ServerRecord& rec, in_addr_t addr) const THROW((UnknownServerException));
    bool isExecutable(const std::string& file) const;
    
    // private member variables
    IPQ::IpqSocket& sock;                    ///< A handle to libipq.
    const std::string serverRoot;            ///< The directory in which to search for server programs.
    bool verbose;                            ///< \b true to log extra messages; \b false otherwise
    PendingConnectionList pendingConnections;///< The list of servers (and associated initial packets) which have been started but have not yet responded with packet numbers.
    RedirectionTable redirections;           ///< A hash table of rules governing packet redirections for open conncetions.
    TimeoutList timeoutList;                 ///< A list of redirection rules to be deleted when timeouts expire.
    ServerTable servers;                     ///< A hash table of server process IDs and the connections that they handle.
    ServerExitHandler exitHandler;           ///< The functor that handles SIGCHLD signals when servers exit.
    ServerWritebackHandler writebackHandler; ///< The functor that handles SIGIO signals when servers write back their port numbers.
    bool restrict_servers;                   ///< \b true to limit the privileges of server programs; \b false otherwise.
    int magic_sock;                          ///< A socket bound to 127.0.0.1:MAGIC_PORT/TCP.
};


/**
* Functor to print current server statistics.
*/
class StatPrinter
{
  public:
    StatPrinter(const ConnectionServer& cs);
    void operator()() const;
  private:
    const ConnectionServer& connectionServer; ///< A reference to a server object whose statistica are to be printed.
};
    
} // namespace NERD


/* Specializations of WaitList.  C++ requires that template specializations be 
   in the same namespace as the template. */
namespace LibWheel
{

/**
* Specialization of LibWheel::WaitList::erase() for PendingConnectionList.  
* Closes the pipe from a server process, as well as removing an object from the
* list.
*/
template <>
NERD::ConnectionServer::PendingConnectionList::iterator
NERD::ConnectionServer::PendingConnectionList::erase(iterator& i)
{
    int retval;
    retval = uninterruptible_close(i->value.pipefd);
    if (retval == -1)
    {
        LibWheel::logmsg(LibWheel::logmsg_err, "Error closing pipe: %s", std::strerror(errno));
    }
    return objs.erase(i);
}

/**
* Specialization of LibWheel::WaitList::WaitGC::operator() for 
* PendingConnectionList.  Cleans up after and kills server processes that are
* deemed to have failed, as well as removing the objects from the list.
*/
template <>
void
NERD::ConnectionServer::PendingConnectionList::WaitGC::operator()()
{
    int retval;
    
    // remove all servers that haven't sent us a port number within <timeout> seconds
    while ((objs.begin() != objs.end()) && (difftime(time(NULL), objs.begin()->timeout)>=0))
    {
        LibWheel::logmsg(LibWheel::logmsg_warning, "Server %s (pid %d) not responding; dropping connection", objs.begin()->value.serverName.c_str(), objs.begin()->value.pid);
        
        // close the pipe
        retval = uninterruptible_close(objs.begin()->value.pipefd);
        if (retval == -1)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Error closing pipe: %s", std::strerror(errno));
        }
        
        // try to kill the process
        if (objs.begin()->value.pid > 0)
            (void)kill(objs.begin()->value.pid, SIGINT);
        
        objs.pop_front();
    }
}


/**
* Specialization of LibWheel::WaitList::erase() for TimeoutList.  Removes
* a redirection rule from the redirection hash table, as well as removing the
* object from the list.
*/
template <>
NERD::ConnectionServer::TimeoutList::iterator
NERD::ConnectionServer::TimeoutList::erase(iterator& i)
{
    i->value.first->erase(i->value.second);
    return objs.erase(i);
}


/**
* Specialization of LibWheel::WaitList::WaitGC::operator() for TimeoutList.
* Removes expired redirection rules from the redirection hash table, as well as
* removing the objects from the list.
*/
template <>
void
NERD::ConnectionServer::TimeoutList::WaitGC::operator()()
{
    // remove all connections that have timed out
    while ((objs.begin() != objs.end()) && (difftime(time(NULL), objs.begin()->timeout)>=0))
    {
        //LibWheel::logmsg(LibWheel::logmsg_info, "Deleting connection");
        objs.begin()->value.first->erase(objs.begin()->value.second);
        
        objs.pop_front();
    }
}

} // namespace LibWheel


namespace NERD
{

/**
* Constructor for ConnectionServer.  Connect to libipq, register handlers for
* SIGCHLD and SIGIO with LibWheel::SignalQueue, and perform other initialization
* tasks.
* @param root The directory in which to search for server programs.
* @param verb \b true to enable verbose logging; \b false otherwise.
* @param restrict \b true to restrict server privileges; false otherwise.
* @throw IPQ::IpqException If there is an error initializing libipq.
* @throw LibWheel::IOException If \a root is not a readable directory.
* @throw LibWheel::SocketException If MAGIC_PORT cannot be bound to.
*/
ConnectionServer::ConnectionServer(const std::string& root, bool verb, bool restrict) THROW((IPQ::IpqException, LibWheel::IOException, LibWheel::SocketException))
: sock(IPQ::IpqSocket::getSocket()), serverRoot(root), verbose(verb), pendingConnections(NERD_SERVER_TIMEOUT), redirections(), timeoutList(NERD_CONNECTION_TIMEOUT), exitHandler(pendingConnections, redirections, servers, timeoutList, verbose), writebackHandler(pendingConnections, redirections, servers, sock), restrict_servers(restrict), magic_sock()
{
    int retval;
    struct stat statbuf;
    struct sockaddr_in magic_addr;
    
    // initialize IPQ
    sock.connect();
    sock.setCopyMode(IPQ::IpqSocket::PACKET, 65535);
    
    // ensure that serverRoot is a readable directory
    retval = ::stat(serverRoot.c_str(), &statbuf);
    if (retval == -1)
    {
        throw LibWheel::IOException(std::string("Error accessing ") + serverRoot + ": " + std::strerror(errno));
    }
    if (!S_ISDIR(statbuf.st_mode))
    {
        throw LibWheel::IOException(std::string("Error: ") + serverRoot + " is not a directory");
    }
    
    // bind to the magic port, to make sure that nothing else is using it
    magic_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (magic_sock == -1)
    {
        throw LibWheel::SocketException(std::string("Error binding to 127.0.0.1:" QUOTE(MAGIC_PORT)) + "/TCP: " + std::strerror(errno));
    }
    std::memset(&magic_addr, 0, sizeof(magic_addr));
    magic_addr.sin_family = AF_INET;
    magic_addr.sin_addr.s_addr = htonl(LOCALHOST_IP);
    magic_addr.sin_port = htons(MAGIC_PORT);
    retval = bind(magic_sock, reinterpret_cast<struct sockaddr*>(&magic_addr), sizeof(magic_addr));
    if (retval == -1)
    {
        throw LibWheel::SocketException(std::string("Error binding to 127.0.0.1:" QUOTE(MAGIC_PORT)) + "/TCP: " + std::strerror(errno));
    }
    
    // set signal handlers
    LibWheel::SignalQueue::setHandler(SIGCHLD, LibWheel::SignalQueue::HANDLE);
    LibWheel::SignalQueue::addHandler(SIGCHLD, boost::ref(exitHandler));
    LibWheel::SignalQueue::setHandler(SIGIO, LibWheel::SignalQueue::HANDLE);
    LibWheel::SignalQueue::addHandler(SIGIO, boost::ref(writebackHandler));
}


/**
* Destructor for ConnectionServer.  Unregisters signal handlers for SIGIO and 
* SIGCHLD from LibWheel::SignalQueue and shuts down libipq.
*/
ConnectionServer::~ConnectionServer()
{
    // clear signal handlers
    LibWheel::SignalQueue::deleteHandler(SIGIO, boost::ref(writebackHandler));
    LibWheel::SignalQueue::deleteHandler(SIGCHLD, boost::ref(exitHandler));

    close(magic_sock);

    // shut down IPQ
    try
    {
        sock.close();
    }
    catch (const IPQ::IpqException& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_err, "%s", e.what());
    }
}


/**
* Main loop for ConnectionServer.  Receive packets from libipq and pass them off
* to ConnectionServer::handlePacket for processing; stop when SIGINT is 
* received.  All signals that arrive through SignalQueue are also processed from
* this method.
*/
void
ConnectionServer::operator()()
{
    try
    {
        // loop forever, processing packets
        // send the process a SIGINT to stop 
        while (1)
        {

            try
            {
                // wait for a packet, and handle signals that arrive.
                sock.waitForPacket(LibWheel::SignalQueue::getReadFD(), LibWheel::SignalQueue::handleNext);
                IPQ::IpqPacket* packet = sock.recvPacket(true);

                // handle the packet
                handlePacket(packet);

                // packet will be released and freed elsewhere
            }
            catch (const IPQ::IpqException& e)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "Error processing packet: %s", e.what());
            }

        }
    }
    catch (const LibWheel::Interrupt& e) // thrown when SIGINT is caught
    {
        LibWheel::logmsg(LibWheel::logmsg_notice, "SIGINT caught; exiting normally\n");
    }
}


/**
* Print current server status to LibWheel::logmsg.
*/
void
ConnectionServer::printStats() const
{
    LibWheel::logmsg(LibWheel::logmsg_info, "-----Current server status-----");
    LibWheel::logmsg(LibWheel::logmsg_info, "Total connections tracked:     %6d", redirections.size()/2);
    LibWheel::logmsg(LibWheel::logmsg_info, "Connections awating deletion:  %6d", timeoutList.size()/2);
    LibWheel::logmsg(LibWheel::logmsg_info, "Connections pending:           %6d", pendingConnections.size());
    LibWheel::logmsg(LibWheel::logmsg_info, "Servers running:               %6d", servers.size());
#ifdef DEBUG
    LibWheel::logmsg(LibWheel::logmsg_info, "Open files:                    %6d", LibWheel::open_files());
    //struct rusage usage;
    //(void)getrusage(RUSAGE_SELF, &usage);
    //LibWheel::logmsg(LibWheel::logmsg_info, "Memory usage:                  %6ld kB", usage.ru_ixrss+usage.ru_idrss);
    LibWheel::logmsg(LibWheel::logmsg_info, "Packets received:              %6lu", sock.getPacketsReceived());
    LibWheel::logmsg(LibWheel::logmsg_info, "Packets accepted:              %6lu", sock.getPacketsAccepted());
    LibWheel::logmsg(LibWheel::logmsg_info, "Packets dropped:               %6lu", sock.getPacketsDropped());
#endif
}


/**
* Constructor for UnknownConnectionException.
* @param s A string describing the reason for throwing the exception.
*/
ConnectionServer::UnknownConnectionException::UnknownConnectionException(const std::string& s)
: runtime_error(s)
{}


/**
* Constructor for UnknownServerException.
* @param s A string describing the reason for throwing the exception.
*/
ConnectionServer::UnknownServerException::UnknownServerException(const std::string& s)
: runtime_error(s)
{}


/**
* Constructor for AddressPair. Initialize an AddressPair from a TCP packet.
* @param pkt A TCP packet.
*/
ConnectionServer::AddressPair::AddressPair(const IPQ::IpqTcpPacket* pkt)
: srcAddr(pkt->getIpHeader().saddr), dstAddr(pkt->getIpHeader().daddr), srcPort(pkt->getTcpHeader().source), dstPort(pkt->getTcpHeader().dest), protocol(IPPROTO_TCP)
{}


/**
* Constructor for AddressPair.  Initialize an AddressPair from components.
* @param sa The source IP address for the AddressPair.
* @param da The destination IP address for the AddressPair.
* @param sp The source port number for the AddressPair.
* @param dp The destination port number for the AddressPair.
* @param prot The transport protocol number for the AddressPair.
*/
ConnectionServer::AddressPair::AddressPair(boost::uint32_t sa, boost::uint32_t da, boost::uint16_t sp, boost::uint16_t dp, boost::uint8_t prot)
: srcAddr(sa), dstAddr(da), srcPort(sp), dstPort(dp), protocol(prot)
{}


/**
* Comparison operator for AddressPair.  Compare two AddressPairs.
* @param b Another AddressPair.
* @return \b true if all fields of this AddressPair are equal to those of \a b;
*       \b false otherwise.
*/
bool 
ConnectionServer::AddressPair::operator==(const AddressPair& b) const
{
    return ((srcAddr == b.srcAddr)
        && (dstAddr == b.dstAddr)
        && (srcPort == b.srcPort)
        && (dstPort == b.dstPort)
        && (protocol == b.protocol));
}


/**
* Compute a hash of an AddressPair. 
* @param a An AddressPair whose hash is to be computed.
* @return A hash of \a a.
* @bug I haven't done any analysis of it, but this hash function probably isn't 
*       very good.
*/
size_t 
ConnectionServer::AddressPairHash::operator()(const AddressPair& a) const
{
    return hash32(a.srcAddr) ^ hash32(a.dstAddr) ^ hash16(a.srcPort) ^ (hash16(a.dstPort)<<16) ^ hash8(a.protocol);
}
    

/**
* Constructor for Connection.
* @param pkt A TCP packet from which to take the addresses of packets sent from
*       a client to a server.
* @param rsaddr The source IP address of packets sent from a server to a client.
* @param rdaddr The destination IP address of packets sent from a server to a client.
* @param rsport The source port number of packets sent from a server to a client.
* @param rdport The source port number of packets sent from a server to a client.
* @param name The name of the server program handling this connection.
*/
ConnectionServer::Connection::Connection(const IPQ::IpqTcpPacket* pkt, boost::uint32_t rsaddr, boost::uint32_t rdaddr, boost::uint16_t rsport, boost::uint16_t rdport, const std::string& name)
: forwardAddr(pkt), reverseAddr(rsaddr, rdaddr, rsport, rdport, IPPROTO_TCP), serverName(name)
{}


/**
* Retrieve the addresses of packets sent from a client to a server for a 
* Connection.
* @return The addresses of packet sent from a client to a server on this 
*       Connection.
*/
const ConnectionServer::AddressPair&
ConnectionServer::Connection::getForwardAddr() const
{
    return forwardAddr;
}

 
/**
* Retrieve the addresses of packets sent from a server to a client for a 
* Connection.
* @return The addresses of packet sent from a server to a client on this 
*       Connection.
*/
const ConnectionServer::AddressPair&
ConnectionServer::Connection::getReverseAddr() const
{
    return reverseAddr;
}


/**
* Retrieve the name of the server program handling a connection.
* @return The name of the server program handling this connection.
*/
const std::string& 
ConnectionServer::Connection::getName() const
{
    return serverName;
}


/**
* Constructor for PendingConnection.
* @param pkt A packet that opens a connection.
* @param fd The read end if a pipe to the server program that is to handle the connection.
* @param name The name of the server program that is to handle the connection.
* @param p The process ID of the server that is to handle the connection.
*/
ConnectionServer::PendingConnection::PendingConnection(IPQ::IpqTcpPacket* pkt, int fd, const std::string& name, pid_t p)
: packet(pkt), pipefd(fd), serverName(name), pid(p)
{}


/**
* Constructor for ServerRecord.
* @param addr The IP address that is to be emulated by the server, as a string.
* @param port The port number that is to be emulated by the server, as a string.
* @param proto The transport protocol of \a port.
*/
ConnectionServer::ServerRecord::ServerRecord(const std::string& addr, const std::string& port, const std::string& proto)
: serverAddr(addr), serverPort(port), serverProto(proto), serverProgram(), serverDnsRecord()
{}


/**
* Constructor for ServerExitHandler.
* @param pcl A reference to the containing ConnectionServer's list of pending connections.
* @param rt A reference to the containing ConnectionServer's look-up table of redirection rules.
* @param st A reference to the containing ConnectionServer's look-up table of active servers.
* @param tl A reference to the containing ConnectionServer's list of connections to drop.
* @param v \b true to enable verbose logging; \b false otherwise.
*/
ConnectionServer::ServerExitHandler::ServerExitHandler(PendingConnectionList& pcl, RedirectionTable& rt, ServerTable& st, TimeoutList& tl, bool v)
: pendingConnections(pcl), redirections(rt), servers(st), timeoutList(tl), verbose(v)
{}


/**
* Call operator for ServerExitHandler.  For each child process that has exited,
* retrieve the PID and exit status.  If the child was associated with an active
* connection, remove its associated redirection rules, and remove it from the
* active connections table.  Otherwise, if the child was associated with a 
* pending connection, remove it from the pending connections list.
*
* Redirection rules for servers that have exited are added to \c timeoutList;
* they will be deleted \c NERD_CONNECTION_TIMEOUT seconds after their server
* exited.
* @sideeffect May write messages to LibWheel::logmsg.
*/
void
ConnectionServer::ServerExitHandler::operator()()
{
    pid_t pid;
    int status;
    
    // clean up after all servers that have exited
    do
    {
        pid = waitpid(-1, &status, WNOHANG);
        if (pid == -1)
        {
            /* according to the man page, waitpid() is supposed to return 0 when
               WNOHANG is set and no processes have exited, but it seems to 
               return -1 anyway */
            if (errno != ECHILD)
                LibWheel::logmsg(LibWheel::logmsg_err, "Error retrieving process exit status: %s", std::strerror(errno));
        }
        else if (pid != 0) // something exited
        {
            ServerTable::iterator i = servers.find(pid);
            if (i == servers.end())
            {
                // not an active server; maybe it's pending?
                PendingConnectionList::iterator j = findPendingConnection(pid);
                if (j == pendingConnections.end())
                {
                    // out of options
                    LibWheel::logmsg(LibWheel::logmsg_warning, "No server record found for child pid %d", pid);
                }
                else
                {
                    pendingConnections.erase(j);
                }
            }
            else
            {
                // check for abnornal termination
                if (WIFSIGNALED(status))
                    LibWheel::logmsg(LibWheel::logmsg_warning, "Server %s (pid %d) exited abnormally by signal %d", i->second.getName().c_str(), pid, WTERMSIG(status));
                else if (WIFEXITED(status) && (WEXITSTATUS(status) != EXIT_SUCCESS))
                    LibWheel::logmsg(LibWheel::logmsg_warning, "Server %s (pid %d) exited abnormally with status %d", i->second.getName().c_str(), pid, WEXITSTATUS(status));
                else if (verbose)
                    LibWheel::logmsg(LibWheel::logmsg_notice, "Server %s (pid %d) exited normally", i->second.getName().c_str(), pid);

                // remove connection entries
                RedirectionTable::iterator redir = redirections.find(i->second.getForwardAddr());
                if (redir == redirections.end())
                    LibWheel::logmsg(LibWheel::logmsg_warning, "No forward connection found");
                else
                    timeoutList.add(std::make_pair(&redirections, redir));
                redir = redirections.find(i->second.getReverseAddr());
                if (redir == redirections.end())
                    LibWheel::logmsg(LibWheel::logmsg_warning, "No reverse connection found");
                else
                    timeoutList.add(std::make_pair(&redirections, redir));

                // remove the server entry;
                servers.erase(i);
            }
        }
    } while (pid > 0);
}


/**
* Look up a pending connection given the PID of its server.
* @param pid The process ID of a server.
* @return An iterator into the pending connections list if a patching element
*       is found, or to just past the end of the list if none is found.
* @note This is an O(n) operation in the number of pending connections.
*/
ConnectionServer::PendingConnectionList::iterator
ConnectionServer::ServerExitHandler::findPendingConnection(pid_t pid)
{
    for (PendingConnectionList::iterator i=pendingConnections.begin(); i!=pendingConnections.end(); ++i)
    {
        if (i->value.pid == pid)
            return i;
    }
    return pendingConnections.end();
}


/**
* Constructor for ServerWritebackHandler.
* @param pcl A reference to the containing ConnectionServer's list of pending connections.
* @param rt A reference to the containing ConnectionServer's look-up table of redirection rules.
* @param st A reference to the containing ConnectionServer's look-up table of active servers.
* @param s A handle to libipq.
*/
ConnectionServer::ServerWritebackHandler::ServerWritebackHandler(PendingConnectionList& pcl, RedirectionTable& rt, ServerTable& st, IPQ::IpqSocket& s)
: pendingConnections(pcl), redirections(rt), servers(st), sock(s)
{}


/**
* Call operator for ServerWritebackHandler.  For all pending servers that have
* written data to stdout (the write ends of pipes whose read ends are held in
* the list of pending connections), read a port number, establish redirection
* rules for packet travelling to and from the server, add the server to the
* active servers table and remove it from the pending connections list, and
* forward the inital packet to the server.
* @note This is an O(n) operation in the number of pending connections.
* @sideeffect May write messages to LibWheel::logmsg.
*/
void
ConnectionServer::ServerWritebackHandler::operator()()
{
    int retval;
    boost::uint16_t port;
    
    // check for clients that have responded and create connection records for them
    for (PendingConnectionList::iterator i=pendingConnections.begin(); i!=pendingConnections.end(); )
    {
        // try to read a port number
        retval = LibWheel::uninterruptible_read(i->value.pipefd, reinterpret_cast<boost::uint8_t*>(&port), 2);
        if (retval == -1)
        {
            if (errno != EAGAIN)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "Error reading from server (pid %d): %s", i->value.pid, std::strerror(errno));
                i = pendingConnections.erase(i);
            }
            else
            {
                ++i;
            }
        }
        else if (retval != 2)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Error reading from server (pid %d): message truncated", i->value.pid);
            i = pendingConnections.erase(i);
        }
        else
        {
            LibWheel::logmsg(LibWheel::logmsg_info, "Forwarding TCP connection %s:%hu->%s:%hu to 127.0.0.1:%hu", LibWheel::ipv4_to_string(i->value.packet->getIpSource()).c_str(), i->value.packet->getTcpSource(), LibWheel::ipv4_to_string(i->value.packet->getIpDest()).c_str(), i->value.packet->getTcpDest(), ntohs(port));

            // create a connection
            Connection conn(i->value.packet.get(), htonl(LOCALHOST_IP), htonl(LOCALHOST_IP), port, htons(MAGIC_PORT), i->value.serverName);
            servers.insert(std::make_pair(i->value.pid, conn));
            redirections.insert(std::make_pair(conn.getForwardAddr(), AddressPair(htonl(LOCALHOST_IP), htonl(LOCALHOST_IP), htons(MAGIC_PORT), port, IPPROTO_TCP)));
            redirections.insert(std::make_pair(conn.getReverseAddr(), AddressPair(i->value.packet->getIpHeader().daddr, i->value.packet->getIpHeader().saddr, i->value.packet->getTcpHeader().dest, i->value.packet->getTcpHeader().source, IPPROTO_TCP)));

            // forward the packet
            i->value.packet->getIpHeader().saddr = htonl(LOCALHOST_IP);
            i->value.packet->getIpHeader().daddr = htonl(LOCALHOST_IP);
            i->value.packet->getTcpHeader().source = htons(MAGIC_PORT);
            i->value.packet->getTcpHeader().dest = port;

            // release the packet to continue iptables traversal
            sock.sendResponse(i->value.packet.get(), IPQ::IpqSocket::ACCEPT);

            i = pendingConnections.erase(i);
        }
    }
}


/**
* Handle a packet.  If the packet is part of a pre-existing connection, redirect
* the packet accordingly.  Otherwise, attempt to create a connection for the 
* packet.  
*
* Currently, IP fragments and non-TCP/IP packets are not supported.  Packets of
* these types will be accepted unmodified, and messages will be logged to 
* LibWheel::logmsg.
* @param packet The packet to redirect.
* @bug There is a bug in netfilter that causes locally-generated outbound 
*       packets with non-local source IP addresses to be dropped.  Since packets
*       returning to a client program from a server match this description after
*       being redirected, they must be accepted with NF_STOP rather than 
*       NF_ACCEPT.  This means that they do not continue iptables traversal, 
*       and cannot be filtered elsewhere in iptables.
*/
void
ConnectionServer::handlePacket(IPQ::IpqPacket* packet)
{
    IPQ::IpqIpPacket* ippkt = dynamic_cast<IPQ::IpqIpPacket*>(packet);
    
    if (ippkt != NULL)
    {
        IPQ::IpqTcpPacket* tcppkt;
        IPQ::IpqUdpPacket* udppkt;

        if (ippkt->getMoreFrags() || (ippkt->getFragOffset() != 0))
        {
            LibWheel::logmsg(LibWheel::logmsg_warning, "IP fragment reassembly is not supported at this time");
            sock.sendResponse(packet, IPQ::IpqSocket::ACCEPT);
            delete packet;
        }
        else if ((tcppkt = dynamic_cast<IPQ::IpqTcpPacket*>(packet)) != NULL)
        {
            try
            {
                const AddressPair& rule = getRedirectRule(tcppkt);
                
                // re-write the packet's source and destination addresses
                LibWheel::logmsg(LibWheel::logmsg_info, "Rewriting addresses of TCP packet %s:%hu->%s:%hu to %s:%hu->%s:%hu", LibWheel::ipv4_to_string(tcppkt->getIpSource()).c_str(), tcppkt->getTcpSource(), LibWheel::ipv4_to_string(tcppkt->getIpDest()).c_str(), tcppkt->getTcpDest(), LibWheel::ipv4_to_string(ntohl(rule.srcAddr)).c_str(), ntohs(rule.srcPort), LibWheel::ipv4_to_string(ntohl(rule.dstAddr)).c_str(), ntohs(rule.dstPort));
                    
                tcppkt->getIpHeader().saddr = rule.srcAddr;
                tcppkt->getIpHeader().daddr = rule.dstAddr;
                tcppkt->getTcpHeader().source = rule.srcPort;
                tcppkt->getTcpHeader().dest = rule.dstPort;
                    
                // release the packet to continue iptables traversal
                if (rule.srcAddr == htonl(LOCALHOST_IP))
                {
                    sock.sendResponse(packet, IPQ::IpqSocket::ACCEPT);
                }
                else
                {
                    // this should really be ACCEPT, but netfilter has a bug 
                    // that causes packets on local output with non-local source 
                    // addresses to be dropped; the work-around is to return 
                    // NF_STOP
                    sock.sendResponse(packet, IPQ::IpqSocket::STOP);
                }

                delete packet;
            }
            catch (const UnknownConnectionException& e)
            {
                createConnection(tcppkt);
            }
        }
        else if ((udppkt = dynamic_cast<IPQ::IpqUdpPacket*>(packet)) != NULL)
        {
            try
            {
                const AddressPair& rule = getRedirectRule(udppkt);
                
                // re-write the packet's source and destination addresses
                LibWheel::logmsg(LibWheel::logmsg_info, "Rewriting addresses of UDP packet %s:%hu->%s:%hu to %s:%hu->%s:%hu", LibWheel::ipv4_to_string(udppkt->getIpSource()).c_str(), udppkt->getUdpSource(), LibWheel::ipv4_to_string(udppkt->getIpDest()).c_str(), udppkt->getUdpDest(), LibWheel::ipv4_to_string(ntohl(rule.srcAddr)).c_str(), ntohs(rule.srcPort), LibWheel::ipv4_to_string(ntohl(rule.dstAddr)).c_str(), ntohs(rule.dstPort));
                
                udppkt->getIpHeader().saddr = rule.srcAddr;
                udppkt->getIpHeader().daddr = rule.dstAddr;
                udppkt->getUdpHeader().source = rule.srcPort;
                udppkt->getUdpHeader().dest = rule.dstPort;

                // release the packet to continue iptables traversal
                if (rule.srcAddr == htonl(LOCALHOST_IP))
                {
                    sock.sendResponse(packet, IPQ::IpqSocket::ACCEPT);
                }
                else
                {
                    // this should really be ACCEPT, but netfilter has a bug 
                    // that causes packets on local output with non-local source 
                    // addresses to be dropped; the work-around is to return 
                    // NF_STOP
                    sock.sendResponse(packet, IPQ::IpqSocket::STOP);
                }

                delete packet;
            }
            catch (const UnknownConnectionException& e)
            {
                createConnection(udppkt);
            }
        }
        else
        {
            LibWheel::logmsg(LibWheel::logmsg_warning, "Packet received with unsupported transport protocol #%hu", ippkt->getProtocol());
            sock.sendResponse(packet, IPQ::IpqSocket::ACCEPT);
            delete packet;
        }
    }
    else
    {
        LibWheel::logmsg(LibWheel::logmsg_warning, "Non-IP packet received\n");
        sock.sendResponse(packet, IPQ::IpqSocket::ACCEPT);
        delete packet;
    }
}


/**
* Looks up a redirection rule for a TCP packet.
* @param pkt The packet to look up.
* @return The redirection rule for \a pkt, if it exists.
* @throw UnknownConnectionException If no redirection rule for \a pkt exists.
*/
const ConnectionServer::AddressPair&
ConnectionServer::getRedirectRule(const IPQ::IpqTcpPacket* pkt) const THROW((UnknownConnectionException))
{
    AddressPair addr(pkt);
    RedirectionTable::const_iterator result = redirections.find(addr);
    if (result != redirections.end())
        return result->second;
    
    throw UnknownConnectionException("No matching connection found");
}


/**
* Looks up a redirection rule for a UDP packet.  UDP connection are not 
* currently implemented, so this method simply throws an 
* UnknownConnectionException.
* @return Theoretically, the redirection rule for the packet, but this is not
*       currently implemented.
* @throw UnknownConnectionException If no redirection rule for the packet 
*       exists.
*/
const ConnectionServer::AddressPair&
ConnectionServer::getRedirectRule(const IPQ::IpqUdpPacket*) const THROW((UnknownConnectionException))
{
    throw UnknownConnectionException("No matching connection found");
}


/**
* Creates a TCP connection.  If a program can be found to handle the connection 
* (see ConnectionServer::findServer()), then this program fork()s and attempts
* to execute it in the child process.  If no server can be found, if it cannot
* be launched, or some other error occurs, the packet is immediately accepted 
* and a message may be logged to LibWheel::logmsg.
*
* The child process is executed with stdout set to the write end of a pipe whose
* read end is held by the parent.  The read end is set in non-blocking, 
* signal-driven mode; its file descriptor, along with the packet, the server
* program name, and the child process' PID, is added to a list accessible to the
* SIGIO handler (which works through LibWheel::SignalQueue).  This handler is
* responsible for creating the connection and accepting the packet.
*
* If \c restrict_servers is set, the child program is executed under the UID
* and GID of the owner of the program.  If the program is accessed through a 
* symbolic link, the UID and GID of the link must match those of the target.
*
* @param pkt A packet that initializes a TCP connection.  If the TCP SYN flag
*       is not set on \a pkt, a message is logged and it is accepted 
*       immediately.
* @bug Checking program ownership and using \c execve() to launch it results in
*       a TOCTOU race condition.  The solution is to use \c fexecve().  However,
*       Linux does not currently implement the \c fexecve() system call, and its
*       emulation in glibc does not work on Linux kernels prior to 2.6.22-rc1
*       if the calling program has called \c setuid() or \c seteuid().  This
*       \e may have been fixed in Linux 2.6.22-rc1.  When a version of \c 
*       fexecve() that \e does work becomes available, undefine the macro
*       \c BROKEN_FEXECVE in the makefile to use \c fexecve() instead of \c
*       execve().
* @sideeffect Writes messages to LibWheel::logmsg.
*/
void 
ConnectionServer::createConnection(IPQ::IpqTcpPacket* pkt)
{
    int retval;
    int fds[2];
    pid_t child_pid;
    
    /*pkt->print(std::cout);
    std::cout << std::endl;*/
    
    // make sure we're looking at a SYN packet
    if (!pkt->getTcpHeader().syn || pkt->getTcpHeader().fin || pkt->getTcpHeader().rst
      || pkt->getTcpHeader().psh || pkt->getTcpHeader().ack || pkt->getTcpHeader().urg)
    {
        if (verbose)
            LibWheel::logmsg(LibWheel::logmsg_err, "Cannot create TCP connection: not a SYN packet");
        sock.sendResponse(pkt, IPQ::IpqSocket::ACCEPT);
        delete pkt;
        return;
    }
    
    try
    {
        // get the name of the server to run
        ServerRecord server(LibWheel::ipv4_to_string(pkt->getIpDest()), boost::lexical_cast<std::string>(pkt->getTcpDest()), "TCP");
        findServer(server, pkt->getIpDest());
        
        // set up a pipe
        retval = pipe(fds);
        if (retval == -1)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Cannot launch server: Error opening pipe: %s", std::strerror(errno));
            delete pkt;
            return;
        }
        retval = fcntl(fds[0], F_SETOWN, getpid());
        if (retval == -1)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Cannot launch server: Error configuring pipe: %s", std::strerror(errno));
            delete pkt;
            return;
        }
        retval = fcntl(fds[0], F_SETFL, O_ASYNC|O_NONBLOCK);
        if (retval == -1)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Cannot launch server: Error configuring pipe: %s", std::strerror(errno));
            delete pkt;
            return;
        }
        
        // fork a child process
        child_pid = fork();
        if (child_pid == -1)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Cannot launch server: Error forking: %s", std::strerror(errno));
            delete pkt;
            return;
        }
        else if (child_pid != 0) // parent process
        {
            // close the write end of the pipe
            retval = LibWheel::uninterruptible_close(fds[1]);
            if (retval == -1)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "Error closing pipe: %s", std::strerror(errno));
            }
            
            // store connection metadata for signal handler
            // It's not a bug to add this to the list after the fork, because
            // SIGIO is handled synchronously (by SignalQueue).
            pendingConnections.add(PendingConnection(pkt, fds[0], server.serverProgram, child_pid));
    
            LibWheel::logmsg(LibWheel::logmsg_info, "Launching server %s", server.serverProgram.c_str());
        }
        else // child process 
        {
            struct stat linkstat;
            struct stat filestat;
            int server_fd;
            char* server_args[5];
            char* server_env[1];
                
            // close the read end of the pipe and set the write end to NERD_PIPE_FD
            retval = LibWheel::uninterruptible_close(fds[0]);
            if (retval == -1)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "Error closing pipe: %s", std::strerror(errno));
            }
            retval = dup2(fds[1], NERD_PIPE_FD);
            if (retval == -1)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "Error setting pipe file descriptor: %s", std::strerror(errno));
                std::exit(EXIT_FAILURE);
            }
            
            // if we want to drop privileges, get the link owner before opening
            if (restrict_servers)
            {
                retval = lstat(server.serverProgram.c_str(), &linkstat);
                if (retval == -1)
                {
                    LibWheel::logmsg(LibWheel::logmsg_err, "Error determing ownership of server %s: %s", server.serverProgram.c_str(), std::strerror(errno));
                    std::exit(EXIT_FAILURE);
                }
            }
            
            // open the server file
            server_fd = open(server.serverProgram.c_str(), O_RDONLY);
            if (server_fd == -1)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "Error opening server %s: %s", server.serverProgram.c_str(), std::strerror(errno));
                std::exit(EXIT_FAILURE);
            }

            // close open files on execve
            LibWheel::close_files_on_exec(NERD_PIPE_FD);
            
            // drop privileges
            if (restrict_servers)
            {
                // first, make sure that the link and target owners are the same
                retval = fstat(server_fd, &filestat);
                if (retval == -1)
                {
                    LibWheel::logmsg(LibWheel::logmsg_err, "Error determing ownership of server %s: %s", server.serverProgram.c_str(), std::strerror(errno));
                    std::exit(EXIT_FAILURE);
                }
                else if ((filestat.st_uid != linkstat.st_uid) || (filestat.st_gid != linkstat.st_gid))
                {
                    LibWheel::logmsg(LibWheel::logmsg_err, "Cannot launch server %s: Permission denied (The symbolic link %s and its target have different owners.)", server.serverProgram.c_str(), server.serverProgram.c_str());
                    std::exit(EXIT_FAILURE);
                }
            
                LibWheel::drop_priv(linkstat.st_uid, linkstat.st_gid);
            }
            
            // launch the server
            server_args[0] = strdup(server.serverProgram.c_str());
            server_args[1] = strdup(server.serverAddr.c_str());
            server_args[2] = strdup(server.serverPort.c_str());
            server_args[3] = strdup(server.serverDnsRecord.c_str());
            server_args[4] = NULL;
            server_env[0] = NULL;
#ifdef BROKEN_FEXECVE
            /* WARNING: TOCTOU race condition here.  The way to solve it is to
               use fexecve().  However, Linux emulates fexecve with a library call
               that looks up the file for the given fd in /proc/self/fd, but 
               after dropping privileges, we don't have access to /proc/self/fd
               anymore.  Kernels after 2.6.22-rc1 include a patch that allows
               processes that have called setuid() to access /proc/self/fd, so 
               fexecve() should work on them. */
            retval = execve(server.serverProgram.c_str(), server_args, server_env);
#else
            retval = fexecve(server_fd, server_args, server_env);
#endif
            if (retval == -1)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "Cannot launch server %s: %s", server.serverProgram.c_str(), std::strerror(errno));
                std::exit(EXIT_FAILURE);
            }
        }
    }
    catch (const UnknownServerException& e)
    {
        if (verbose)
            LibWheel::logmsg(LibWheel::logmsg_warning, "No appropriate server found to handle connection to %s:%hu/TCP", LibWheel::ipv4_to_string(pkt->getIpDest()).c_str(), pkt->getTcpDest());
        sock.sendResponse(pkt, IPQ::IpqSocket::ACCEPT);
    }
}


/**
* Creates a UDP connection.  This is not currently implemented, so a warning is
* logged and the packet is accepted.
* @param pkt A packet that initializes a UDP connection.
*/
void 
ConnectionServer::createConnection(IPQ::IpqUdpPacket* pkt)
{
    if (verbose)
        LibWheel::logmsg(LibWheel::logmsg_warning, "UDP connection forwarding is not supported at this time");
    sock.sendResponse(pkt, IPQ::IpqSocket::ACCEPT);
}


/**
* Attempts to find a server program to run in response to a connection request.
* The following attempts are made:
*   -# search for a program named \a rec.serverAddr:rec.serverPort in \c 
*      serverRoot (example: 10.1.1.1:23)
*   -# search for a program named \a rec.serverAddr in \c serverRoot (example: 
*      10.1.1.1)
*   -# perform a DNS query for a TXT record for \a serverAddr to get a 
*      semicolon-separated list of key=value pairs, and search for a program
*      whose name is given by the value associated with the key 
*      P<rec.serverPort> in \c serverRoot (example: 
*      D=foobar.com;P25=smtpserver;P80=webserver).  If more than one DNS TXT
*      record is found, only the first one is used and a warning is logged.
*   .
* If no server program is found using any of these methods, an
* UnknownServerException is thrown.
* @param rec A description of the connection requested.  The following fields
*       must be set when this function is called:
*       - ServerRecord::serverAddr
*       - ServerRecord::serverPort
*       - ServerRecord::serverProto
*       .
*       When this function returns, the ServerRecord::serverProgram filled will 
*       be filled with the name of the program to run, and the 
*       ServerRecord::serverDnsRecord field may be filled with the DNS TXT 
*       record for the server's IP address.
* @param addr The IP address of the requested server, in host byte order.
* @throw UnknownServerException If no server program can be found for the 
*       requested server.
* @sideeffect May write messages to LibWheel::logmsg.
*/
void
ConnectionServer::findServer(ServerRecord& rec, in_addr_t addr) const THROW((UnknownServerException))
{
    std::string name;

    // first, try SERVER_DIR/<addr>:<port>
    name = serverRoot + '/' + rec.serverAddr + ':' + rec.serverPort;
    if (isExecutable(name))
    {
        rec.serverProgram = name;
        rec.serverDnsRecord = "";
        return;
    }
    
    // next, try SERVER_DIR/<addr>
    name = serverRoot + '/' + rec.serverAddr;
    if (isExecutable(name))
    {
        rec.serverProgram = name;
        rec.serverDnsRecord = "";
        return;
    }
    
    // finally, try DNS lookup
    try
    {
        std::vector<std::string> dnstxt = LibWheel::getDnsTxt(addr);
        if (dnstxt.size() > 1)
            LibWheel::logmsg(LibWheel::logmsg_warning, "Warning: more than one DNS TXT record found for %s", LibWheel::ipv4_to_string(addr).c_str());
        if (verbose)
            LibWheel::logmsg(LibWheel::logmsg_info, "DNS TXT record found: %s", dnstxt[0].c_str());

        // parse the record and look for a server program name
        DnsServerRecord dnsrec(dnstxt[0]);
        DnsServerRecord::const_iterator entry = dnsrec.getValue(std::string("P")+rec.serverPort);
        if (entry != dnsrec.end())
        {
            name = serverRoot + '/' + entry->second;
            if (isExecutable(name))
            {
                rec.serverProgram = name;
                rec.serverDnsRecord = dnstxt[0];
                return;
            }
        }
    }
    catch (const LibWheel::DNSFailure& e)
    {}
    catch (const LibWheel::DNSError& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_err, "DNS error: %s", e.what());
    }
    catch (const LibWheel::ParseError& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_err, "Error parsing DNS TXT record: %s", e.what());
    }

    throw UnknownServerException("No server found");
}


/**
* Determines if a file is executable.
* @param file The file to check for executability.
* @return \b true if \a file exists and is executable by the current user; \b
*       false otherwise.
* @note If \a file cannot be accessed or exists but is not executable, a message
*        is logged to LibWheel::logmsg.
*/
bool
ConnectionServer::isExecutable(const std::string& file) const
{
    int retval;
    struct stat statbuf;
    
    // check that the file exists and is is a regular file
    retval = ::stat(file.c_str(), &statbuf);
    if (retval == -1)
    {
        if (errno != ENOENT)
            LibWheel::logmsg(LibWheel::logmsg_err, "Cannot execute server %s: %s", file.c_str(), std::strerror(errno));
        return false;
    }
    
    // check at the file is executable by the current user
    retval = ::access(file.c_str(), F_OK|X_OK);
    if (retval == -1)
    {
        if (errno != ENOENT)
            LibWheel::logmsg(LibWheel::logmsg_err, "Cannot execute server %s: %s", file.c_str(), std::strerror(errno));
        return false;
    }
    
    return true;
}


/**
* Initialize a StatPrinter.
*/
StatPrinter::StatPrinter(const ConnectionServer& cs)
: connectionServer(cs)
{}


/**
* Print the current statistics for a ConnectionServer.
* @sideeffect Writes messages to LibWheel::logmsg.
*/
void
StatPrinter::operator()() const
{
    connectionServer.printStats();
}


/** 
* Print version info to stderr.
*/
static void 
print_version()
{
    std::cerr << "Network Rerouter Daemon v" <<  NERD_VERSION
#ifdef DEBUG
              << " (debug build)"
#endif
              << "\nCopyright (c) Rennie deGraaf, 2007.  All rights reserved."
              << std::endl;
}


/**
* Print a help message to stderr.
*/
static void
print_help(const char* progname)
{
    std::cerr << "Usage: " << progname  << "[-D] [-V] [-h] [-v]\n"
              << "where -D - run the program as a daemon\n"
              << "      -V - enable verbose logging\n"
              << "      -h - print this message\n"
              << "      -v - print version information\n"
              << std::endl;
}


/**
* Parse command-line arguments.  See the documentation for main() for details.
* @param argc The number of command-line arguments.
* @param argv A null-terminated array of command-line arguments
* @param[out] daemon Set to true on return to run in daemon mode, or false to
*       run in console mode.
* @param[out] verbose Set to true on return to enable verbose logging; false
*       for normal logging.
*/
static void 
parse_args(int argc, char** argv, bool& daemon, bool& verbose)
{
    char* short_options = "DhvV";
    static struct option long_options[] = {
        {"daemon", 0, 0, 'D'},
        {"verbose", 0, 0, 'V'},
        {"help", 0, 0, 'h'},
        {"version", 0, 0, 'v'},
        {0, 0, 0, 0}
    };
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 'D':
                daemon = true;
                break;
            case 'V':
                verbose = true;
                break;
            case 'h':
                print_version();
                print_help(argv[0]);
                std::exit(EXIT_SUCCESS);
            case 'v':
                print_version();
                std::exit(EXIT_SUCCESS);
            case '?':
                if (isprint(optopt))
                    std::cerr << "Unrecognized option -" << static_cast<char>(optopt) << std::endl;
                else
                    std::cerr << "Unrecognized option character 0x" << std::hex << optopt << std::dec << std::endl;
                std::exit(EXIT_FAILURE);
            case '0':
            default:
                std::cerr << "getopt() returned an unexpected value" << std::endl;
                std::exit(EXIT_FAILURE);
        }
    }
    
    if (optind < argc)
    {
        std::cerr << "Unrecognized garbage on the command line: ";
        while (optind < argc)
            std::cerr << argv[optind++] << ' ';
        std::cerr << std::endl;
        std::exit(EXIT_FAILURE);
    }

}

} // namespace NERD


/**
* Entry point for the Network Rerouter Daemon (nerd).
*
* The following command-line arguments are accepted:
*   - -D (--daemon) Detach from the console and run as a daemon.
*   - -V (--verbose) Log extra status messages.
*   - -h (--help) Print a help message and exit.
*   - -v (--version) Print a version message and exit.
*   .
* By default, status and error messages are logged to stderr; in daemon mode,
* they are sent to syslog.  In debug builds (in which the macro \c DEBUG is 
* defined), verbose logging is automatically enabled and daemon mode is 
* disabled. 
*
* The following signals can be sent to the program:
*   - SIGINT (^C) Stop processing packets, clean up and exit normally.
*   - SIGUSR1 Print status information to the log device (stderr in console 
*     mode, or syslog in daemon mode).
*   .
*
* This program needs root privileges to run.  It will log an error message and
* exit if run as any other user.
*/
int 
main(int argc, char* argv[])
{
    bool make_daemon = false;
    bool verbose = false;
    int ret = EXIT_SUCCESS;
    /*uid_t ruid;
    gid_t rgid;*/
    
    // initialize the logmsg facility (spc_sanitize_* needs it)
    LibWheel::logmsg.open(LibWheel::logmsg_stderr, 0, argv[0]);
    
    // sanitize the system
    LibWheel::spc_sanitize_environment(0, NULL);
    LibWheel::spc_sanitize_files(2);
    
    // parse command-line arguments
    NERD::parse_args(argc, argv, make_daemon, verbose);

#ifdef DEBUG
    if ((verbose == false) || (make_daemon = true))
        std::cerr << "This is a debug build; enabling verbose logging and disabling daemon mode" << std::endl;
    verbose = true;
    make_daemon = false;
#endif
    
    // make sure that we're running as root
    if (geteuid() != 0)
    {
        std::cerr << "This program requires superuser privileges" << std::endl;
        LibWheel::logmsg.close();
        std::exit(EXIT_FAILURE);
    }
    
    // get the uid and gid for the restricted user and group
    /*ruid = LibWheel::get_user_uid(NERD_RESTRICTED_USER);
    if (ruid == (uid_t)-1)
    {
        std::cerr << "Error: user \""NERD_RESTRICTED_USER"\" does not exist" << std::endl;
        LibWheel::logmsg.close();
        return EXIT_FAILURE;
    }
    rgid = LibWheel::get_group_gid(NERD_RESTRICTED_GROUP);
    if (rgid == (gid_t)-1)
    {
        std::cerr << "Error: group \""NERD_RESTRICTED_GROUP"\" does not exist" << std::endl;
        LibWheel::logmsg.close();
        return EXIT_FAILURE;
    }
    if ((ruid == 0) || (rgid == 0))
    {
        std::cerr << "WARNING: Running servers with root privileges!" << std::endl;
    }*/

    // set up exit signal handlers
    LibWheel::Thrower<LibWheel::Interrupt> sigint_handler;
    LibWheel::SignalQueue::setHandler(SIGINT, LibWheel::SignalQueue::HANDLE);
    LibWheel::SignalQueue::addHandler(SIGINT, boost::ref(sigint_handler));
    
    try
    {
        NERD::ConnectionServer server(NERD_SERVER_ROOT, verbose, true);

        // drop privileges
        /* ip_queue requires root privileges even after opening.  We'll drop
           privileges before executing servers instead */
        //drop_priv(ruid, rgid);

        // we've finished initializing; time to summon Beelzebub
        if (make_daemon)
        {
            // Ia Ia Cthulhu Fhtagn!
            daemon(0, 0);

            // stderr is closed; switch to syslog
            LibWheel::logmsg.open(LibWheel::logmsg_syslog, 0, argv[0]);
	    
	    // write our PID to /var/run/nerd.pid
            LibWheel::write_pid(PIDFILE);
        }
        
        // register SIGUSR1 to print status
        NERD::StatPrinter statPrinter(server);
        LibWheel::SignalQueue::setHandler(SIGUSR1, LibWheel::SignalQueue::HANDLE);
        LibWheel::SignalQueue::addHandler(SIGUSR1, boost::ref(statPrinter));
        
        // run the server
        server();
    }
    catch (const LibWheel::IOException& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_crit, "I/O error: %s", e.what());
        ret = EXIT_FAILURE;
    }
    catch (const LibWheel::SocketException& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_crit, "Socket error: %s", e.what());
        ret = EXIT_FAILURE;
    }
    catch (const IPQ::IpqException& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_crit, "Error in ip_queue: %s", e.what());
        ret = EXIT_FAILURE;
    }
    
    // clean up
    if (make_daemon)
        (void)unlink(PIDFILE);
    LibWheel::logmsg.close();
    return ret;
}
