/*
** iplog_pcap.h - iplog pcap management data.
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
** $Id: iplog_pcap.h,v 1.14 2001/01/01 16:02:14 odin Exp $
*/

#ifndef __IPLOG_PCAP_H
#define __IPLOG_PCAP_H

#include <net/if.h>

#ifdef __linux__
#	include <linux/if_ether.h>
#else
#	include <netinet/if_ether.h>
#	define ethhdr	ether_header
#endif /* ! linux */

#ifndef DLT_ATM_RFC1483
#	define DLT_ATM_RFC1483	100
#endif

#ifndef DLT_RAW
#	define DLT_RAW			101
#endif

#ifndef DLT_SLIP_BSDOS
#	define DLT_SLIP_BSDOS	102
#endif

#ifndef DLT_PPP_BSDOS
#	define DLT_PPP_BSDOS	103
#endif

#define SNAPLEN				1500

struct pcap_data {
	struct pcap_data *next;
	struct pcap_data *prev;
	int dl;
	pcap_t *pd;
	ipaddr_t *addr;
	size_t num_addr;
	u_char name[IFNAMSIZ];
};

int setup_pcap(struct pcap_data **plist, const u_char *ifstring);
bool ifflag_isset(const u_char *ifname, short test_flag);

#endif /* __IPLOG_PCAP_H */

/* vim:ts=4:sw=8:tw=0 */
