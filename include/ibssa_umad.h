/*
 * Copyright (c) 2012 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2012 Intel Corporation. All rights reserved.
 * Copyright (c) 2012 Lawrence Livermore National Securities.  All rights reserved.
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

#ifndef __IBSSA_UMAD_H__
#define __IBSSA_UMAD_H__

#include <byteswap.h>

#include <infiniband/umad.h>

/*
 * These defines should be in umad
 * Once we get them accepted there we can remove this file.
 */

typedef uint16_t be16_t;
typedef uint32_t be32_t;
typedef uint64_t be64_t;

enum {
	UMAD_METHOD_GET          = 0x01,
	UMAD_METHOD_GET_RESP	 = 0x81,
	UMAD_METHOD_SET          = 0x02,
	UMAD_METHOD_SEND         = 0x03,
	UMAD_METHOD_TRAP         = 0x05,
	UMAD_METHOD_REPORT       = 0x06,
	UMAD_METHOD_REPORT_RESP	 = 0x86,
	UMAD_METHOD_TRAP_REPRESS = 0x07,
	UMAD_METHOD_RESP         = 0x80

};

struct ib_mad_hdr {
	uint8_t	  base_version;
	uint8_t	  mgmt_class;
	uint8_t	  class_version;
	uint8_t	  method;
	be16_t  status;
	be16_t  cs_reserved;
	be64_t  tid;
	be16_t  attr_id;
	be16_t  resv;
	be32_t  attr_mod;
};

#ifndef ntohll
  #if __BYTE_ORDER == __LITTLE_ENDIAN
    static inline uint64_t ntohll(uint64_t x)
    {
        return bswap_64(x);
    }
  #elif __BYTE_ORDER == __BIG_ENDIAN
    static inline uint64_t ntohll(uint64_t x)
    {
        return x;
    }
  #endif
#endif
#ifndef htonll
  #define htonll ntohll
#endif

#endif /* __IBSSA_UMAD_H__ */

