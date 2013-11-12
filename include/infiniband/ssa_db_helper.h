/*
 * Copyright (c) 2013-2013 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef _SSA_DB_HELPER_H_
#define _SSA_DB_HELPER_H_

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else                           /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif                          /* __cplusplus */

BEGIN_C_DECLS

#include <infiniband/ssa_db.h>

enum ssa_db_helper_mode {
	SSA_DB_HELPER_STANDARD,
	SSA_DB_HELPER_DEBUG,
	SSA_DB_HELPER_HUMAN
};


/****f* SSA DB helper
 * NAME
 *       ssa_db_save
 *
 * DESCRIPTION
 *       Save the distributed SMDB to file system
 *
 * SYNOPSIS
 * */
void ssa_db_save(const char * path_dir, const struct ssa_db *p_ssa_db,
		 enum ssa_db_helper_mode mode);
/*
* PARAMETERS
*        path_dir
*                [in] Path to the directory where the SMDB will be saved
*
*        p_data
*                [in] The pointer to SMDB that is supposed to be distributed
*
*	 mode
*		 [in] The mode of saving the data to disk
*
*  RETURN VALUE
*        This function does not return a value.
*
*  SEE ALSO
*
* *********/

/****f* SSA DB helper
 * NAME
 *       ssa_db_load
 *
 * DESCRIPTION
 *       Load the distributed SMDB from file system
 *
 * SYNOPSIS
 * */
struct ssa_db *ssa_db_load(const char * path_dir, enum ssa_db_helper_mode mode);
/*
* PARAMETERS
*        path_dir
*                [in] Path to the directory where the SMDB will be loaded from
*
*        mode
*                [in] The mode of data loaded from disk
*
*  RETURN VALUE
*        This function returns ssa_db structure with loaded data
*
*  SEE ALSO
*
* *********/
END_C_DECLS
#endif				/* _SSA_DB_HELPER_H_ */
