/*
** iplog_scan.h - iplog scan/flood detector data.
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
** $Id: iplog_scan.h,v 1.20 2001/01/01 16:02:14 odin Exp $
*/

#ifndef __IPLOG_SCAN_H
#define __IPLOG_SCAN_H

#define SCAN_PORT		0
#define SCAN_NULL		1
#define SCAN_FIN		2
#define SCAN_SYN		3
#define SCAN_XMAS		4
#define SCAN_UDP		5
#define SCAN_SMURF		6
#define SCAN_PING		7
#define SCAN_TOTAL		8

/* You may want to tune the following definitions. */

/*
** Size of the scan table when promisc mode is enabled.
** This must be a power of 2.
*/

#define SCAN_TSIZE_P	256

/*
** Size of the scan table when promisc mode is not enabled.
** This must be a power of 2
*/

#define SCAN_TSIZE_N	128

/*
** Maximum number of entries for each hash.
*/

#define SCAN_MAXENT		4

/*
** Number of packets that must be received to trigger each of
** the scans and floods.
*/

#define PS_THOLD		15
#define NS_THOLD		10
#define FS_THOLD		10
#define SS_THOLD		10
#define XS_THOLD		10
#define UDP_THOLD		25
#define SMURF_THOLD		90
#define PING_THOLD		70

/*
** Timeout values for each of the scan and flood types.
*/

#define PS_TIMEOUT		50
#define NS_TIMEOUT		50
#define FS_TIMEOUT		50
#define SS_TIMEOUT		50
#define XS_TIMEOUT		50
#define UDP_TIMEOUT		50
#define SMURF_TIMEOUT	30
#define PING_TIMEOUT	60

/*
** Number of destination ports to log.
*/

#define SCAN_DST_PORTS	10

/*
** Number of source ports to log.
*/

#define SCAN_SRC_PORTS	5


struct scan_data {
	struct scan_data *next;
	struct scan_data *prev;
	ipaddr_t src_addr;
	ipaddr_t dst_addr;
	time_t last;
	struct scan_t {
		u_short count;
		bool logged;
	  	in_port_t sports[SCAN_SRC_PORTS];
		in_port_t dports[SCAN_DST_PORTS];
		u_short sports_count;
		u_short dports_count;
		time_t expire;
		u_long bytes;
	} *type[SCAN_TOTAL];
};

struct scan_list {
	struct scan_data *head;
	pthread_mutex_t lock;
	u_long cnt;
};

struct scan_info {
	u_char *name;
	bool (*resolv)(void);
	u_long timeout;
	u_long threshold;
};

bool check_scan(const struct ip *ip, u_char, u_long, int sport, int dport);
void destroy_scan_table(void);
void expire_scans(void);
void init_scan_table(size_t tsize);

#endif /* ! __IPLOG_SCAN_H */
