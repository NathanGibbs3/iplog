/*
** iplog_options.h - iplog command line argument handler data.
** Copyright (C) 1999-2001 Ryan McCabe <odin@numb.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License, version 2,
** as published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
**
** $Id: iplog_options.h,v 1.18 2001/01/01 16:02:14 odin Exp $
*/

#ifndef __IPLOG_OPTIONS_H
#define __IPLOG_OPTIONS_H

extern u_int32_t flags;

#define SMURF		0x00000001
#define PORTSCAN	0x00000002
#define GET_IDENT	0x00000004
#define DNS_CACHE	0x00000008
#define UDP_RES		0x00000010
#define ICMP_RES	0x00000020
#define TRACEROUTE	0x00000040
#define BOGUS		0x00000080
#define FIN_SCAN	0x00000100
#define NULL_SCAN	0x00000200
#define SYN_FLOOD	0x00000400
#define LOG_TCP		0x00000800
#define LOG_UDP		0x00001000
#define LOG_ICMP	0x00002000
#define TCP_RES		0x00004000
#define XMAS_SCAN	0x00008000
#define PING_FLOOD	0x00010000
#define NO_RESOLV	0x00020000
#define UDP_SCAN	0x00040000
#define FOOL_NMAP	0x00080000
#define NO_FORK		0x00100000
#define LOG_STDOUT	0x00200000
#define IGNORE_NS	0x00400000
#define LOG_IP		0x00800000
#define PROMISC		0x01000000
#define VERBOSE		0x02000000
#define LOG_FRAG	0x04000000
#define LOG_DEST	0x08000000
#define SCANS_ONLY	0x10000000
#define SYN_SCAN	0x20000000

#define opt_enabled(x)	((flags & (x)) != 0)


#define ANY_SCAN \
(PORTSCAN | NULL_SCAN | FIN_SCAN | XMAS_SCAN | UDP_SCAN | PING_FLOOD | SMURF)

#define AUTHORS "Ryan McCabe <odin@numb.org> & Nathan Gibbs (nathan@cmpublishers.com)"
#define WEBPAGE "http://www.cmpublishers.com/oss"

int get_facility(const u_char *new_facility);
int get_priority(const u_char *new_priority);

#endif /* __IPLOG_OPTIONS_H */

/* vim:ts=4:sw=8:tw=0 */
