/*
 * Copyright 2004-2014 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the terms of the
 * OpenIB.org BSD license included below:
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

#ifndef SSA_PATH_RECORD_DATA_H
#define SSA_PATH_RECORD_DATA_H

/*
 * Internal API for data
 */

#define LFT_NO_PATH 255
#define MAX_LOOKUP_LID 0xBFFF
#define MAX_LOOKUP_PORT 254
#define MAX_LFT_BLOCK_NUM (MAX_LOOKUP_LID / 64)
#define NO_REAL_PORT_NUM -1

/*
 * SMDB index improves the speed of data retrieval operations on a smdb tables.
 * For this propose we use lookup tables that replaces runtime iteration by
 * indexing operation.
 *
 *@epoch  Corresponds to smdb epoch. If they are different, the index will
 *        be rebuilt automatically.
 *
 *@is_switch_lookups - lookup table. Index: LID, value: boolean flag is switch.
 *@lft_top_lookup - lookup table. Index: LID. Value: LFT top LID.
 *@lft_block_lookup - lookup table for LFT blocks.
 *                    The table allows lookup by pair (LID, block num).
 *                    Index is a LID.
 *                    If LID is for CA port, the corresponding value in lft_block_lookup is NULL.
 *                    If not, the value is pointer to dynamically allocated lookup
 *                    table for switch's LFT blocks. The table's length is MAX_LFT_BLOCK_NUM.
 *@ca_port_lookup - lookup table for CA ports.
 *                  Index: LID , value: index in SSA_TABLE_ID_PORT table.
 *@switch_port_lookup - lookup table for switch ports. The table allows lookup by pair (LID, port num).
 *						Index is a LID.
 *                      If LID is for CA port, the corresponding value in switch_port_lookup is NULL.
 *                      If not, the value is pointer to dynamically allocated lookup
 *                      table for switch's ports. The table's length is MAX_LOOKUP_PORT.
 *                      
 *@ca_link_lookup - lookup table for links from CA.
 *                  Index: LID, value: index in SSA_TABLE_ID_LINK table.
 *@switch_link_lookup - lookup table for links from switch ports.
 *                      The table allows lookup by pair (LID, port num).
 *						Index is a LID.
 *                      If LID is for CA port, the corresponding value in switch_link_lookup is NULL.
 *                      If not, the value is pointer to dynamically allocated lookup
 *                      table for switch's links. The table's length is MAX_LOOKUP_PORT.
 */
struct ssa_pr_smdb_index {
	uint64_t epoch;
	uint8_t  is_switch_lookup[MAX_LOOKUP_LID + 1];
	uint16_t lft_top_lookup[MAX_LOOKUP_LID + 1];
	uint64_t *lft_block_lookup[MAX_LOOKUP_LID + 1];
	uint64_t ca_port_lookup[MAX_LOOKUP_LID + 1];
	uint64_t *switch_port_lookup[MAX_LOOKUP_LID + 1];
	uint64_t ca_link_lookup[MAX_LOOKUP_LID + 1];
	uint64_t *switch_link_lookup[MAX_LOOKUP_LID + 1];
};

/*
 * ssa_pr_build_indexes - builds index for smdb database
 * @p_index: Pointer to an index
 * @p_smdb: Pointer to smdb database
 *
 * @return value: 0 - success; otherwise - failure
 *
 * The function builds an index for smdb database.
 */
int ssa_pr_build_indexes(struct ssa_pr_smdb_index *p_index,
			 const struct ssa_db *p_smdb);

/*
 * ssa_pr_destroy_indexes - destroys an smdb index
 * @p_index: Pointer to an index
 *
 * The function destroys smdb index and deallocates all resources.
 */
void ssa_pr_destroy_indexes(struct ssa_pr_smdb_index *p_index);

/*
 * ssa_pr_rebuild_indexes - rebuilds an smdb index
 * @p_index: pointer to an index
 * @p_smdb: pointer to smdb database
 *
 * @return value: 0 - success; otherwise - failure
 *
 * The function rebuilds an smdb index if needed. The decision to rebuild or not
 * is based on epoch of index and database.
 */
int ssa_pr_rebuild_indexes(struct ssa_pr_smdb_index *p_index,
			   const struct ssa_db *p_smdb);

/*
 * find_guid_to_lid_rec_by_guid - search in SSA_TABLE_ID_GUID_TO_LID table
 * @p_smdb: Pointer to smdb database
 * @port_guid: GUID in network order
 *
 * @return value: pointer to found record. NULL - failure.
 *
 * The function iterates SSA_TABLE_ID_GUID_TO_LID table and searches for a
 * record with given GUID
 */
const struct ep_guid_to_lid_tbl_rec
*find_guid_to_lid_rec_by_guid(const struct ssa_db *p_smdb,
			      const be64_t port_guid);

/*
 * find_port - search in SSA_TABLE_ID_PORT table
 * @p_smdb: Pointer to smdb database
 * @p_index: Pointer to an smdb index. It's used for boot retrieval operations
 * @lid: LID in network order.
 * @port_num: Port number. For CA, parameter is not relevant.
 *
 * @return value: pointer to found record. NULL - failure.
 *
 * The function searches for port record
 */
const struct ep_port_tbl_rec *find_port(const struct ssa_db *p_smdb,
					const struct ssa_pr_smdb_index *p_index,
					const be16_t lid, const int port_num);

/*
 * find_destination_port - search in SSA_TABLE_ID_LFT_BLOCK table
 * @p_smdb: Pointer to smdb database
 * @p_index: Pointer to an smdb index. It's used for boot retrieval operations
 * @source_lid: switch's LID in network order
 * @dest_lid: destination LID in network order
 *
 * @return value: pointer to found record. NULL - failure.
 *
 * The function searches for link record in LFT table
 */
int find_destination_port(const struct ssa_db *p_smdb,
			  const struct ssa_pr_smdb_index *p_index,
			  const be16_t source_lid, const be16_t dest_lid);

/*
 * find_linked_port - search in SSA_TABLE_ID_LINK table for a linked port
 * @p_smdb: Pointer to smdb database
 * @p_index: Pointer to an smdb index. It's used for boot retrieval operations
 * @from_lid: source LID in network order.
 * @from_port_num: source port number. For CA, parameter is not relevant.
 *
 * @return value: pointer to found record. NULL - failure.
 *
 * The function searches for link record and if it's found returns pointer to
 * linked port
 */
const struct ep_port_tbl_rec
*find_linked_port(const struct ssa_db *p_smdb,
		  const struct ssa_pr_smdb_index *p_index,
		  const be16_t from_lid, const int from_port_num);

#endif /* SSA_PATH_RECORD_DATA_H */
