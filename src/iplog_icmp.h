/*
** iplog_icmp.h - iplog ICMP traffic logger data.
** Copyright (C) 1999 behe <eric@ojnk.net>, Ryan McCabe <odin@numb.org>
** Copyright (C) 2000-2001 Ryan McCabe <odin@numb.org>
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
** $Id: iplog_icmp.h,v 1.8 2001/01/01 16:02:14 odin Exp $
*/

#ifndef __IPLOG_ICMP_H
#define __IPLOG_ICMP_H

static const char *icmp_types[] = {
	"ICMP_ECHO_REPLY",
	"1",
	"2",
	"ICMP_DEST_UNREACHABLE",
	"ICMP_SOURCE_QUENCH",
	"ICMP_REDIRECT",
	"6",
	"7",
	"ICMP_ECHO",
	"ICMP_ROUTER_ADVERT",
	"ICMP_ROUTER_SOLICIT",
	"ICMP_TIME_EXCEEDED",
	"ICMP_PARAMETER_PROBLEM",
	"ICMP_TIMESTAMP",
	"ICMP_TIMESTAMP_REPLY",
	"ICMP_INFO_REQUEST",
	"ICMP_INFO_REPLY",
	"ICMP_ADDRESS_REQUEST",
	"ICMP_ADDRESS_REPLY"
};

static const char *icmp_codes[] = {
	"echo reply",
	NULL,
	NULL,
	"destination unreachable",
	"source quench",
	"redirect message",
	NULL,
	NULL,
	"echo",
	"path of router advertisement",
	"router solicitation",
	"time exceeded",
	"parameter problem",
	"timestamp request",
	"timestamp reply",
	"info request",
	"info reply",
	"address mask request",
	"address mask reply"
};

static const char *icmp_unreach[] = {
	"network is unreachable",
	"host is unreachable",
	"protocol is unreachable",
	"port is unreachable",
	"fragmentation needed, IP_DF set",
	"source route failed",
	"network is unreachable(?)",
	"host is unreachable(?)",
	"host is isolated from source",
	"network is unreachable because of admin prohibited filter",
	"host is unreachable because of admin prohibited filter",
	"network is unreachable because tos is prohibited",
	"host is unreachable because tos is prohibited",
	"packet filtered",
	"precedence violation",
	"precedence cutoff",
	"undefined destination unreachable code",
};

static const char *icmp_redir[] = {
	"ICMP: (%s) redirect %s to network %s",
	"ICMP: (%s) redirect %s to host %s",
	"ICMP: (%s) redirect-tos %s to network %s",
	"ICMP: (%s) redirect-tos %s to host %s"
};

#endif /* __IPLOG_ICMP_H */

/* vim:ts=4:sw=8:tw=0 */
