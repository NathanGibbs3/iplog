/*
** iplog_config.h - iplog configuration data.
** Copyright (C) 2001 Ryan McCabe <odin@numb.org>
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
** $Id: iplog_config.h,v 1.4 2001/01/01 16:02:14 odin Exp $
*/

#ifndef __IPLOG_CONFIG_H
#define __IPLOG_CONFIG_H

#define STATE_INITIAL		0x00
#define STATE_COMMENT		0x01
#define STATE_FILTER		0x02
#define STATE_SET			0x03
#define STATE_NEED_BOOL		0x04
#define STATE_USER			0x05
#define STATE_GROUP			0x06
#define STATE_LOGFILE		0x07
#define STATE_FACILITY		0x08
#define STATE_PRIORITY		0x09
#define STATE_PROMISC		0x0a
#define STATE_INTERFACE		0x0b
#define STATE_NEED_ARANGE	0x0c
#define STATE_NEED_PRANGE	0x0d
#define STATE_NEED_ITYPE	0x0e
#define STATE_FILTER_PROT	0x0f
#define STATE_LOCKFILE		0x10

struct state_stack {
	struct state_stack *next;
	u_int state;
};

#define NS_FILE "/etc/resolv.conf"

#define ADDR_MATCH_ALL 0
#define MASK_MATCH_ONE 0xffffffff
#define MASK_MATCH_ALL 0
#define TYPE_MATCH_ALL 0xffff

#define EVERYTHING "*"

enum { FIL_TCP, FIL_UDP, FIL_ICMP };

struct filter_data {
	struct filter_data *next;
	struct port_range {
		in_port_t min;
		in_port_t max;
		bool not;
	} sport, dport;
	struct addr_entry {
		ipaddr_t addr;
		ipaddr_t mask;
		bool not;
	} src, dst;
	bool not;
};

int add_dns_ignore_rules(void);
void parse_config(const u_char *);
void destroy_filter_list(u_int prot);
bool icmp_filter(u_int, const struct ip *, u_char);
bool tcp_filter(u_int, const struct ip *, in_port_t, in_port_t);

#define udp_filter	tcp_filter

#endif /* __IPLOG_CONFIG_H */
/* vim:ts=4:sw=8:tw=0 */
