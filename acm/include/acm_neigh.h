/*
 * Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
 * below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(ACM_NEIGH_H)
#define ACM_NEIGH_H

#include <sys/socket.h>
#include <netinet/in.h>

/* Add operation is done with replace flag so replacement can be done in 1 operation rather than delete followed by add */
int ipv4_neighbor_add(int neighsock, int ifindex, in_addr_t ipaddr,
		      char *lla, int llalen);
int ipv4_neighbor_delete(int neighsock, int ifindex, in_addr_t ipaddr);

int ipv6_neighbor_add(int neighsock, int ifindex, struct in6_addr *ipaddr,
		      char *lla, int llalen);
int ipv6_neighbor_delete(int neighsock, int ifindex, struct in6_addr *ipaddr);

int open_neighsock();
void close_neighsock(int neighsock);
int neigh_get_message(int neighsock);

#endif /* ACM_NEIGH_H */
