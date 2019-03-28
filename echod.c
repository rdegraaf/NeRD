/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
**************************************************/

/**
* @file echod.c
* @author Rennie deGraaf
* @date 2007/12/13
*
* An echo server, written as an example server program for nerd.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nerd.h"

#define BUFLEN 1024 /**< Read buffer size */

/**
* An echo server for nerd.  It opens and binds a socket, writes the local port 
* number to the nerd server via file descriptor 3, accepts a single connection, 
* echoes anything that the client sends, and exits when the client breaks the
* connection.
*/
int main(int argc, char** argv)
{
    int retval;
    int sock_fd;
    int client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen;
    ssize_t bytes;
    ssize_t count;
    unsigned char buf[BUFLEN];
    
    /*sleep(15);*/
    
    /* check command-line arguments */
    if ((argc < 3) || (argc > 4))
    {
        fprintf(stderr, "Usage: %s <client address> <client port> [<DNS record>]\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    /* set up a socket to receive connections */
    sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1)
    {
        fprintf(stderr, "Error opening socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0; /* use any port */
    retval = bind(sock_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (retval == -1)
    {
        fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    retval = listen(sock_fd, 1);
    if (retval == -1)
    {
        fprintf(stderr, "Error setting listen queue: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    /* send the listen port number to the connection server */
    addrlen = sizeof(addr);
    retval = getsockname(sock_fd, (struct sockaddr*)&addr, &addrlen);
    if (retval == -1)
    {
        fprintf(stderr, "Error getting socket name: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (addrlen != sizeof(struct sockaddr_in))
    {
        fprintf(stderr, "Invalid response from getsockname(): %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    retval = write(NERD_PIPE_FD, &addr.sin_port, sizeof(addr.sin_port));
    if (retval == -1)
    {
        fprintf(stderr, "Error writing port number to parent: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
  
    fprintf(stderr, "running with effective UID %u (real %u), effective GID %u (real %u)\n", geteuid(), getuid(), getegid(), getgid());
    fprintf(stderr, "emulated server address: %s:%s\n", argv[1], argv[2]);
    if (argc == 4) fprintf(stderr, "emulated server DNS record: %s\n", argv[3]);
    fprintf(stderr, "actual server port: %hu\n", ntohs(addr.sin_port));
    
    /* accept a connection */
    addrlen = sizeof(addr);
    client_fd = accept(sock_fd, (struct sockaddr*)&addr, &addrlen);
    if (client_fd == -1)
    {
        fprintf(stderr, "Error accepting connection: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    /* process data until the socket closes */
    while (1)
    {
        bytes = read(client_fd, buf, BUFLEN);
        if (bytes == -1)
        {
            fprintf(stderr, "Error reading from server: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        else if (bytes == 0) /* end of file */
            break;
        
        count = 0;
        do
        {
            retval = write(client_fd, &buf[count], bytes-count);
            if (retval == -1)
            {
                fprintf(stderr, "Error writing to server: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }
            count+=retval;
        } while (count != bytes);
    }

    /* clean up */    
    retval = close(sock_fd);
    if (retval == -1)
    {
        fprintf(stderr, "Error closing socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
