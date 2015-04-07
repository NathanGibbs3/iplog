/*
** iplog_dns.h - iplog DNS cache data.
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
** $Id: iplog_dns.h,v 1.12 2001/01/01 16:02:14 odin Exp $
*/

#ifndef __IPLOG_DNS_H
#define __IPLOG_DNS_H

/* Expire DNS cache entries 1 hour after last access. */
#define DNS_TIMEOUT		3600

/*
** Size of the DNS cache when promisc mode is enabled.
** This must be a power of 2.
*/
#define DNS_MAXSIZE_P	256

/*
** Size of the DNS cache when promisc mode is not enabled.
** This must be a power of 2.
*/
#define DNS_MAXSIZE_N	128

/* Maximum entries for each hash */
#define DNS_MAX_ENT		4

struct dns_entry {
	struct dns_data *head;
	u_long cnt;
	pthread_mutex_t lock;
};

struct dns_data {
	struct dns_data *next;
	struct dns_data *prev;
	u_char *host;
	ipaddr_t addr;
	time_t expire;
};

u_char *get_dns_cache(ipaddr_t addr, u_char *buf, size_t len);
void destroy_dns_cache(void);
void init_dns_table(size_t tlen);

#endif /* __IPLOG_DNS_H */

/* vim:ts=4:sw=8:tw=0 */
