/*
** iplog_input.h - iplog IP input data.
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
** $Id: iplog_input.h,v 1.8 2001/01/01 16:02:14 odin Exp $
*/

#ifndef __IPLOG_INPUT_H
#define __IPLOG_INPUT_H

#ifndef IP_OFFMASK
#	define IP_OFFMASK 0x1fff
#endif

#define FRAG_MAX	5
#define FRAG_TSIZE	32
#define FRAG_TTL	60

#define FRAGHASH(a, b, c, d) ((a ^ b ^ c ^ d) & (FRAG_TSIZE - 1))

void destroy_frag_table(void);
void expire_frags(void);
void parse_packet(struct ip *ip);
void init_frag_table(size_t f_size);

struct frag_data {
	struct frag_data *next;
	struct frag_data *prev;
	u_char prot;
	u_char rf;
	u_short id;
	ipaddr_t saddr;
	ipaddr_t daddr;
	time_t expire;
	u_long bytes;
	u_long t_len;
	struct ip header;
	struct ip_fragment {
		struct ip_fragment *next;
		u_char *data;
		u_int off;
		u_int len;
	} *frag;
};

struct frag_list {
	struct frag_data *head;
	u_int count;
	pthread_mutex_t lock;
};


#endif /* __IPLOG_INPUT_H */

/* vim:ts=4:sw=8:tw=0 */
