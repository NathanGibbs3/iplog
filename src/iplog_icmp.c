/*
** iplog_icmp.c - iplog ICMP traffic logger.
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
** $Id: iplog_icmp.c,v 1.23 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>
#include <time.h>

#include <iplog.h>
#include <iplog_config.h>
#include <iplog_options.h>
#include <iplog_icmp.h>
#include <iplog_scan.h>

extern struct filter_data *filters[3];

static void
print_router_advertisement(const struct icmp *, const u_char *, const u_char *);
static u_char *print_data(const struct icmp *icmp, u_char *buf, size_t len);

/*
** Returns true if host resolution is enabled for ICMP, false if it isn't.
*/

bool icmp_res(void) {
	return (opt_enabled(ICMP_RES));
}

/*
** ICMP packet handler.  Returns 0 on success, -1 on failure.
*/

int icmp_parser(const struct ip *ip) {
	struct icmp *icmp = (struct icmp *) ((char *) ip + __IP_HDR_LENGTH(ip));
	u_char src_host[MAX_HSTLEN], dst_host[MAX_HSTLEN], data_buf[MAX_HSTLEN];
	u_long len;

	if (icmp_filter(FIL_ICMP, ip, icmp->icmp_type))
		return (0);

	len = ntohs(ip->ip_len) - __IP_HDR_LENGTH(ip);

	if (opt_enabled(SMURF) && icmp->icmp_type == ICMP_ECHO_REPLY &&
		check_scan(ip, SCAN_SMURF, len, -1, -1) != 0)
	{
		return (0);
	}

	if (opt_enabled(PING_FLOOD) && icmp->icmp_type == ICMP_ECHO &&
		check_scan(ip, SCAN_PING, len, -1, -1) != 0)
	{
		return (0);
	}

	if (opt_enabled(SCANS_ONLY))
		return (0);

	host_lookup(&ip->ip_src, icmp_res(), src_host, sizeof(src_host));

	if (opt_enabled(LOG_DEST))
		host_lookup(&ip->ip_dst, icmp_res(), dst_host, sizeof(dst_host));

	switch (icmp->icmp_type) {
	case ICMP_TIME_EXCEEDED:
		print_data(icmp, data_buf, sizeof(data_buf));

		if (opt_enabled(LOG_DEST)) {
			mysyslog("ICMP: %s %s to %s (%s)", src_host,
				icmp_codes[ICMP_TIME_EXCEEDED], dst_host, data_buf);
		} else {
			mysyslog("ICMP: %s %s (%s)", src_host,
				icmp_codes[ICMP_TIME_EXCEEDED], data_buf);
		}
		break;

	case ICMP_ECHO_REPLY:
	case ICMP_ECHO:
		if (opt_enabled(LOG_DEST)) {
			mysyslog("ICMP: %s from %s to %s (%lu bytes)",
				icmp_codes[icmp->icmp_type], src_host, dst_host, len);
		} else {
			mysyslog("ICMP: %s from %s (%lu bytes)",
				icmp_codes[icmp->icmp_type], src_host, len);
		}
		break;

	case ICMP_DEST_UNREACHABLE:
		if (icmp->icmp_code >= UNREACHABLE_MAX) {
			if (opt_enabled(LOG_DEST)) {
				mysyslog("ICMP: %s (%d) from %s to %s",
					icmp_unreach[UNREACHABLE_MAX], icmp->icmp_code,
					src_host, dst_host);
			} else {
				mysyslog("ICMP: %s (%d) from %s",
					icmp_unreach[UNREACHABLE_MAX], icmp->icmp_code, src_host);
			}
		} else {
			u_char host[2 * MAX_HSTLEN + 10];

			print_data(icmp, data_buf, sizeof(data_buf));

			if (icmp->icmp_ip.ip_dst.s_addr != ip->ip_src.s_addr) {
				u_char dest[MAX_HSTLEN];

				host_lookup(&icmp->icmp_ip.ip_dst, icmp_res(),
							dest, sizeof(dest));

				snprintf(host, sizeof(host), "(from %s) %s", src_host, dest);
			} else
				snprintf(host, sizeof(host), "%s", src_host);

			if (opt_enabled(LOG_DEST)) {
				mysyslog("ICMP: %s: %s to %s (%s)",
					host, icmp_unreach[ICMP_DEST_UNREACHABLE],
					dst_host, data_buf);
			} else {
				mysyslog("ICMP: %s: %s to (%s)",
					host, icmp_unreach[ICMP_DEST_UNREACHABLE],
					data_buf);
			}
		}
		break;

	case ICMP_REDIRECT:
		if (icmp->icmp_code > REDIRECT_MAX) {
			if (opt_enabled(LOG_DEST)) {
				mysyslog("ICMP: undefined redirect code %d to %s from %s",
					icmp->icmp_code, dst_host, src_host);
			} else {
				mysyslog("ICMP: undefined redirect code %d from %s",
					icmp->icmp_code, src_host);
			}
		} else {
			u_char route[MAX_HSTLEN];

			host_lookup(&icmp->icmp_gwaddr, icmp_res(), route, sizeof(route));
			host_lookup(&icmp->icmp_ip.ip_dst, icmp_res(),
						data_buf, sizeof(data_buf));
			mysyslog(icmp_redir[icmp->icmp_code], route, src_host, data_buf);
		}
		break;

	case ICMP_TIMESTAMP_REPLY:
	{
		struct tm tsr_tm;
		u_long tsr_time;

		tsr_time = ntohl(icmp->icmp_ttime) / 1000;
		localtime_r((time_t *) &tsr_time, &tsr_tm);

		if (opt_enabled(LOG_DEST)) {
			mysyslog("ICMP: timestamp request to %s from %s (%.2d:%.02d:%.02d)",
				dst_host, src_host, tsr_tm.tm_hour,
				tsr_tm.tm_min, tsr_tm.tm_sec);
		} else {
			mysyslog("ICMP: timestamp request from %s (%.2d:%.02d:%.02d)",
				src_host, tsr_tm.tm_hour, tsr_tm.tm_min, tsr_tm.tm_sec);
		}

		break;
	}

	case ICMP_ADDRESS_REPLY:
	{
		struct in_addr iar_in;

		iar_in.s_addr = htonl(icmp->icmp_mask);
		host_lookup(&iar_in, icmp_res(), data_buf, sizeof(data_buf));

		if (opt_enabled(LOG_DEST)) {
			mysyslog("ICMP: %s to %s from %s (%s)",
				icmp_codes[ICMP_ADDRESS_REPLY], dst_host, src_host, data_buf);
		} else {
			mysyslog("ICMP: %s from %s (%s)",
				icmp_codes[ICMP_ADDRESS_REPLY], src_host, data_buf);
		}

		break;
	}

	case ICMP_PARAMETER_PROBLEM:
		if (opt_enabled(LOG_DEST)) {
			mysyslog("ICMP: %s to %s from %s (ptr %d)",
				icmp_codes[ICMP_PARAMETER_PROBLEM],
				dst_host, src_host, icmp->icmp_pptr);
		} else {
			mysyslog("ICMP: %s from %s (ptr %d)",
				icmp_codes[ICMP_PARAMETER_PROBLEM],
				src_host, icmp->icmp_pptr);
		}
		break;

	case ICMP_ROUTER_ADVERT:
		print_router_advertisement(icmp, src_host, dst_host);
		break;

	default:
		if (icmp->icmp_type > 18 || icmp_codes[icmp->icmp_type] == NULL) {
			if (opt_enabled(LOG_DEST)) {
				mysyslog("ICMP: undefined ICMP type %d to %s from %s",
					icmp->icmp_type, dst_host, src_host);
			} else {
				mysyslog("ICMP: undefined ICMP type %d from %s",
					icmp->icmp_type, src_host);
			}
		} else if (opt_enabled(LOG_DEST)) {
			mysyslog("ICMP: %s to %s from %s", icmp_codes[icmp->icmp_type],
				dst_host, src_host);
		} else {
			mysyslog("ICMP: %s from %s",
				icmp_codes[icmp->icmp_type], src_host);
		}
		break;
	}

	return (0);
}

/*
** Logs data encapsulated in ICMP packets.
*/

static u_char *print_data(const struct icmp *icmp, u_char *buf, size_t len) {
	struct tcphdr *data = (struct tcphdr *) ((struct icmp *) icmp + 1);

	if (icmp->icmp_ip.ip_p == IPPROTO_ICMP) {
		struct { u_char type, code; } *tmp = (typeof(tmp)) data;

		if (tmp->type == ICMP_DEST_UNREACHABLE || tmp->type == ICMP_REDIRECT) {
			snprintf(buf, len, "ICMP: %s code %u",
				icmp_types[min(tmp->type, ICMP_UNDEFINED)], tmp->code);
		} else {
			snprintf(buf, len, "ICMP: %s",
				icmp_types[min(tmp->type, ICMP_UNDEFINED)]);
		}
	} else {
		u_char pbuf[MAX_PRTLEN];

		snprintf(buf, len, "%s: dest port %u, source port %u",
			proto_lookup(icmp->icmp_ip.ip_p, pbuf, sizeof(pbuf)),
			ntohs(data->th_dport),
			ntohs(data->th_sport));
	}

	return (buf);
}

/*
** Logs ICMP router advertisement messages.
*/

static void print_router_advertisement(	const struct icmp *icmp,
										const u_char *src_host,
										const u_char *dst_host)
{
	struct id_rdiscovery *routers;
	u_int imin = 12, lifetime = ntohs(icmp->icmp_lifetime);
	u_char msg[MAX_IPLEN * 12 + 1], duration[32], lbuf[MAX_HSTLEN], i;

	routers = (struct id_rdiscovery *) &icmp->icmp_dun.id_rdiscovery;
	msg[0] = '\0';

	if (icmp->icmp_num_addr <= imin)
		imin = icmp->icmp_num_addr;

	for (i = 0 ; i < imin ; i++) {
		if (i > 0)
			xstrncat(msg, " -> ", sizeof(msg));

		host_lookup(&(routers++)->router_addr, false, lbuf, sizeof(lbuf));
		xstrncat(msg, lbuf, sizeof(msg));
	}

	if (lifetime < 60)
		snprintf(duration, sizeof(duration), "%u sec", lifetime);
	else {
		snprintf(duration, sizeof(duration), "%u min, %u sec",
				(lifetime / 60), (lifetime % 60));
	}

	if (opt_enabled(LOG_DEST)) {
		mysyslog("ICMP: %s to %s from %s: %s (lifetime %s)",
			icmp_codes[ICMP_ROUTER_ADVERT], dst_host, src_host, msg, duration);
	} else {
		mysyslog("ICMP: %s from %s: %s (lifetime %s)",
			icmp_codes[ICMP_ROUTER_ADVERT], src_host, msg, duration);
	}
}

/* vim:ts=4:sw=8:tw=0 */
