/*************************************************
* $Id$
* 
* The external interface to the Network Rerouter Daemon (nerd).
**************************************************/

/**
* @file nerd.h
* @author Rennie deGraaf
* @date 2007/12/13
*
* The public interface to the Network Rerouter Daemon (nerd).
*/

#ifndef NERD_H
    #define NERD_H

    /** Version of NERD described by this file. */
    #define NERD_VERSION             "0.3.1"

    /** Servers (or symbolic links to them) must be stored in this directory. */
    #define NERD_SERVER_ROOT         "/var/nerd/servers"

    /** Servers must write the local port number that they are using to this
        file descriptor in network byte order within NERD_SERVER_TIMEOUT
        seconds of starting. */
    #define NERD_PIPE_FD             1
    
    /** If NERD has not received a port number from a server within this many
        seconds of it starting, it will assume that the server crashed and stop
        waiting. */
    #define NERD_SERVER_TIMEOUT      10
    
    /** After a server exits, packets will still be forwarded to it for this 
        many seconds.  This should correspond to the duration of the TIME_WAIT
        TCP state. */
    #define NERD_CONNECTION_TIMEOUT  60

#endif /* NERD_H */
