/*************************************************
* Copyright (c) Rennie deGraaf, 2005, 2007.  All rights reserved.
* $Id: drop_priv.c 15 2005-07-26 07:02:21Z degraaf $
*
* Functions to drop process privileges
* get_user_uid() - get a UID for a user name
* get_group_gid() - get a GID for a group name
* drop_priv() - set the current PID and GID
*
* This file is part of the libwheel project.
*
* libwheel is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* libwheel is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with libwheel; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
**************************************************/

/**
* @file drop_priv.c
* @author Rennie deGraaf
* @date 2007/05/28
*
* Functions to facilitate dropping privileges from root-owned processes.
*/


#define _BSD_SOURCE /* for setgroups(), setreuid(), setregid(), setegid(), seteuid() */

#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "logmsg.h"

/**
* Looks up the UID for a given user name.
* @param name The user name to look up.
* @return The UID corresponding to \a name on success, or -1 on failure.
* @warning Not thread-safe.
*/
uid_t get_user_uid(const char* name)
{
    struct passwd* pw;
    pw = getpwnam(name);
    if (pw == NULL)
        return -1;
    return pw->pw_uid;
}


/**
* Looks up the GID for a given group name
* @param name The group name to look up.
* @return The GID corresponding to \a name on success, or -1 on failure.
* @warning Not thread-safe.
*/
gid_t get_group_gid(const char* name)
{
    struct group* gr;
    gr = getgrnam(name);
    if (gr == NULL)
        return -1;
    return gr->gr_gid;
}


/**
* Drops privileges by setting the effective and real UID and GID to specified 
* values.  
* @param newuid The new UID to set, or -1 to leave the UID unchanged.
* @param newgid The new GUD to set, ot -1 to leave the GID unchanged.
* @note On failure, logs a message through the logmsg facility and calls \c 
*       abort().
* @note This function was designed to permanently drop privileges from 
*       root-owned processes.  It may also work for permanently dropping 
*       privileges from SETUID-root processes.
* @note This function may not work properly on BSD.
*/
void drop_priv(const uid_t newuid, const gid_t newgid)
{
    uid_t olduid;
    gid_t oldgid;
    int retval;
    
    /* get current user and group */
    olduid = geteuid();
    oldgid = getegid();
    
    if (newgid != (gid_t)-1)
    {
        /* if we have superuser privileges, drop ancillary groups */
        if (olduid == 0)
        {
            retval = setgroups(1, &newgid);
            if (retval == -1)
            {
                LOGMSG_LIB(setgroups);
                LOGMSG_FATAL_EXIT();
                abort();
            }
        }
        
        /* make sure it isn't the current gid */
        if (newgid != oldgid)
        {        
            /* change gid */
            retval = setregid(newgid, newgid);
            if (retval == -1)
            {
                LOGMSG_LIB(setregid);
                LOGMSG_FATAL_EXIT();
                abort();
            }
        }
    }

    if (newuid != (uid_t)-1)
    {
        /* make sure it isn't the current uid */
        if (newuid != olduid)
        {
            /* change uid */
            retval = setreuid(newuid, newuid);
            if (retval == -1)
            {
                LOGMSG_LIB(setreuid);
                LOGMSG_FATAL_EXIT();
                abort();
            }
        }
    }
    
    /* make sure privileges cannot be regained */
    if (newgid != (gid_t)-1 && oldgid != newgid && newuid != 0)
    {
        if (setegid(oldgid) != -1 || getegid() != newgid)
        {
            logmsg(logmsg_crit, "drop_priv: new GID not set correctly (%s:%i)", __FILE__, __LINE__);
            LOGMSG_FATAL_EXIT();
            abort();
        }
    }
    if (newuid != (uid_t)-1 && olduid != newuid)
    {
        if (seteuid(olduid) != -1 || geteuid() != newuid)
        {
            logmsg(logmsg_crit, "drop_priv: new UID not set correctly (%s:%i)", __FILE__, __LINE__);
            LOGMSG_FATAL_EXIT();
            abort();
        }
    }
}
