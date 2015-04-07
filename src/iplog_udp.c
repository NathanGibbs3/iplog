/*
** iplog_udp.c - iplog UDP traffic logger.
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
** $Id: iplog_udp.c,v 1.21 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>

#include <pthread.h>

#include <iplog.h>
#include <iplog_config.h>
#include <iplog_options.h>
#include <iplog_scan.h>

struct udp_data {
	pthread_mutex_t lock;
	ipaddr_t t_host;
	time_t t_time;
};

extern struct filter_data *filters[3];

static struct udp_data udp_data = {
	lock:	PTHREAD_MUTEX_INITIALIZER,
	t_host:	0,
	t_time:	0
};

/*
** Returns true if host resolution is enabled for UDP datagrams, false if
** it isn't.
*/

bool udp_res(void) {
	return (opt_enabled(UDP_RES));
}

/*
** UDP datagram handler.
*/

int udp_parser(const struct ip *ip) {
	struct udphdr *udp = (struct udphdr *) ((char *) ip + __IP_HDR_LENGTH(ip));
	u_char buf[MAX_HSTLEN], sbuf[MAX_SRVLEN];
	u_long len;

	if (udp_filter(FIL_UDP, ip, udp->uh_sport, udp->uh_dport))
		return (0);

	len = ntohs(ip->ip_len) - __IP_HDR_LENGTH(ip);

	if (opt_enabled(SMURF) && udp->uh_sport == htons(7) &&
		check_scan(ip, SCAN_SMURF, len, udp->uh_sport, udp->uh_dport) != 0)
	{
		return (0);
	}

	if (opt_enabled(TRACEROUTE) && ip->ip_ttl == 1) {
		pthread_mutex_lock(&udp_data.lock);
		if (udp_data.t_host != ip->ip_src.s_addr ||
			(time(NULL) >= (udp_data.t_time + 15)))
		{
			udp_data.t_host = ip->ip_src.s_addr;
			time(&udp_data.t_time);

			pthread_mutex_unlock(&udp_data.lock);

			host_lookup(&ip->ip_src, udp_res(), buf, sizeof(buf));

			if (opt_enabled(LOG_DEST)) {
				u_char buf2[MAX_HSTLEN];

				host_lookup(&ip->ip_dst, udp_res(), buf2, sizeof(buf2));
				mysyslog("UDP: traceroute from %s to %s", buf, buf2);
			} else {
				mysyslog("UDP: traceroute from %s", buf);
			}
		} else
			pthread_mutex_unlock(&udp_data.lock);

		return (0);
	}

	if (opt_enabled(UDP_SCAN)) {
		if (check_scan(ip, SCAN_UDP, len, udp->uh_sport, udp->uh_dport) != 0)
			return (0);
	}

	if (opt_enabled(SCANS_ONLY))
		return (0);

	serv_lookup(udp->uh_dport, "udp", sbuf, sizeof(sbuf));
	host_lookup(&ip->ip_src, udp_res(), buf, sizeof(buf));

	if (opt_enabled(LOG_DEST)) {
		u_char buf2[MAX_HSTLEN];

		host_lookup(&ip->ip_dst, udp_res(), buf2, sizeof(buf2));
		mysyslog("UDP: dgram to %s:%s from %s:%u (%lu data bytes)",
			buf2, sbuf, buf, ntohs(udp->uh_sport),
			ntohs(udp->uh_ulen) - sizeof(*udp));
	} else {
		mysyslog("UDP: dgram to %s from %s:%u (%lu data bytes)",
			sbuf, buf, ntohs(udp->uh_sport),
			ntohs(udp->uh_ulen) - sizeof(*udp));
	}

	return (0);
}

/* vim:ts=4:sw=8:tw=0 */
