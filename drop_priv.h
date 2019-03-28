/*************************************************
* Copyright (c) Rennie deGraaf, 2005.  All rights reserved.
* $Id: drop_priv.h 14 2005-07-26 02:00:59Z degraaf $
*
* Functions to drop process privileges
* See drop_priv.c for further details.
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
* @file drop_priv.h
* @author Rennie deGraaf
* @date 2007/05/28
*
* Declarations of functions to facilitate dropping privileges from root-owned 
* processes.
*/

#ifndef DROP_PRIV_H
#define DROP_PRIV_H

    #include <sys/types.h>

    #ifdef __cplusplus
    extern "C" {
    namespace LibWheel {
    #endif

    uid_t get_user_uid(const char* name); 
    gid_t get_group_gid(const char* name); 
    void drop_priv(const uid_t newuid, const gid_t newgid); 

    #ifdef __cplusplus
    }}
    #endif

#endif /* DROP_PRIV_H */
