/*
** iplog_tcp.c - iplog TCP traffic logger.
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
** $Id: iplog_tcp.c,v 1.34 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>

#include <iplog.h>
#include <iplog_options.h>
#include <iplog_config.h>
#include <iplog_scan.h>

#define TH_BOG		0xc0
#define SYNFLOOD	20

static time_t synlast;
static ipaddr_t last_bogus;
static int syncount;
static int raw_sock;

static pthread_mutex_t syn_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t bogus_lock = PTHREAD_MUTEX_INITIALIZER;

/*
** Opens a raw socket for use for fooling nmap.  Returns true on success,
** false on failure.
*/

bool get_raw_sock(void) {
	raw_sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

	return (raw_sock != -1);
}

/*
** Checks whether a host should be resolved for a TCP packet.  Returns true
** if resolution is enabled, false if it is disabled.
*/

bool tcp_res(void) {
	bool res;

	if (opt_enabled(SYN_FLOOD)) {
		pthread_mutex_lock(&syn_lock);
		res = opt_enabled(TCP_RES) && (syncount != SYNFLOOD);
		pthread_mutex_unlock(&syn_lock);
	} else
		res = opt_enabled(TCP_RES);

	return (res);
}

/*
** TCP packet handler.
*/

int tcp_parser(const struct ip *ip) {
	struct tcphdr *tcp = (struct tcphdr *) ((char *) ip + __IP_HDR_LENGTH(ip));
	u_long len = ntohs(ip->ip_len) - __IP_HDR_LENGTH(ip);
	u_char lbuf[MAX_HSTLEN];
	u_char tcp_flags = tcp->th_flags;
	int ret;

	if (tcp_filter(FIL_TCP, ip, tcp->th_sport, tcp->th_dport))
		return (0);

	/*
	** This seems to be enough to confuse programs like nmap and queso
	** that try to determine the operating system by sending bogus
	** packets.  As a side effect, it causes several of nmap's "stealth"
	** scans not to work.
	*/

	if (opt_enabled(FOOL_NMAP) &&
		((tcp_flags & TH_BOG) || (tcp_flags == TH_PUSH) || (tcp_flags == 0) ||
		((tcp_flags & (TH_SYN | TH_FIN | TH_RST)) && (tcp_flags & TH_URG)) ||
		((tcp_flags & TH_SYN) && (tcp_flags & (TH_FIN | TH_RST)))))
	{
		u_char *spoof_pkt;
		struct ip *xip;
		struct tcphdr *xtcp;
		struct sockaddr_in fn_sin;
		time_t cur_time = time(NULL);

		spoof_pkt = xcalloc(1, sizeof(struct ip) + sizeof(struct tcphdr));

		memset(&fn_sin, 0, sizeof(fn_sin));

		xip = (struct ip *) spoof_pkt;
		xtcp = (struct tcphdr *) ((u_char *) spoof_pkt + sizeof(struct ip));

		xip->ip_hl = sizeof(struct ip) >> 2;
		xip->ip_v = 4;
		xip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
		xip->ip_tos = ip->ip_tos;
		xip->ip_id = 0xff;
		xip->ip_off = htons(cur_time & 1 ? IP_DF : 0);
		xip->ip_ttl = 0xff;
		xip->ip_p = ip->ip_p;
		xip->ip_dst.s_addr = ip->ip_src.s_addr;
		xip->ip_src.s_addr = ip->ip_dst.s_addr;
		xip->ip_sum = in_cksum((u_short *) xip, sizeof(struct ip));

		xtcp->th_sport = tcp->th_dport;
		xtcp->th_dport = tcp->th_sport;
		xtcp->th_seq = tcp->th_seq;
		xtcp->th_ack = tcp->th_ack;
		xtcp->th_x2 = tcp->th_x2;
		xtcp->th_off = sizeof(struct tcphdr) >> 2;
		xtcp->th_flags = cur_time ^ 0x12345678;
		xtcp->th_win = cur_time & 1;
		xtcp->th_urp = cur_time;

		xtcp->th_sum = in_cksum((u_short *) xtcp, sizeof(struct tcphdr));

		fn_sin.sin_family = AF_INET;
		fn_sin.sin_port = tcp->th_sport;
		fn_sin.sin_addr.s_addr = ip->ip_src.s_addr;

		ret = sendto(raw_sock, (char *) xip,
				sizeof(struct ip) + sizeof(struct tcphdr), 0,
				(struct sockaddr *)
				&fn_sin,
				sizeof(struct sockaddr_in));

		if (ret == -1)
			IDEBUG(("[%s:%d] sendto: %s", __FILE__, __LINE__, strerror(errno)));

		free(spoof_pkt);
	}

	if (opt_enabled(SYN_FLOOD)) {
		time_t now;

		pthread_mutex_lock(&syn_lock);
		time(&now);
		if (syncount > 0) {
			syncount -= (now - synlast);
			if (syncount < 0)
				syncount = 1;
			synlast = now;
		} else
			time(&synlast);
		pthread_mutex_unlock(&syn_lock);
	}

	/*
	** Clear bits 6 and 7, which are not valid TCP flags.
	** iplog's detection of some scans will not work if these bits are set.
	**
	** These flags are now used to support TCP ECN.  False positives may
	** result.
	*/
	tcp_flags &= ~0xc0;

	if (opt_enabled(NULL_SCAN) && !tcp_flags &&
		check_scan(ip, SCAN_NULL, len, tcp->th_sport, tcp->th_dport) != 0)
	{
		return (0);
	}

	if (opt_enabled(XMAS_SCAN)
		&& ((tcp_flags == (TH_FIN | TH_URG | TH_PUSH))
			|| (tcp_flags == TH_URG)
			|| (tcp_flags == TH_PUSH)
			|| (tcp_flags == (TH_FIN | TH_URG))
			|| (tcp_flags == (TH_FIN | TH_PUSH))
			|| (tcp_flags == (TH_URG | TH_PUSH)))
		&& check_scan(ip, SCAN_XMAS, len, tcp->th_sport, tcp->th_dport) != 0)
	{
		return (0);
	}

	if (opt_enabled(FIN_SCAN) && (tcp_flags == TH_FIN)
		&& check_scan(ip, SCAN_FIN, len, tcp->th_sport, tcp->th_dport) != 0)
	{
		return (0);
	}

	if (opt_enabled(BOGUS) && (tcp->th_flags & TH_BOG)) {
		pthread_mutex_lock(&bogus_lock);
		if (last_bogus != ip->ip_src.s_addr) {
			last_bogus = ip->ip_src.s_addr;
			pthread_mutex_unlock(&bogus_lock);

			host_lookup(&ip->ip_src, tcp_res(), lbuf, sizeof(lbuf));

			if (opt_enabled(LOG_DEST)) {
				u_char lbuf2[MAX_HSTLEN];

				host_lookup(&ip->ip_dst, tcp_res(), lbuf2, sizeof(lbuf2));

				mysyslog("TCP: Bogus TCP flags set by %s:%d (dest %s:%d)",
					lbuf, ntohs(tcp->th_sport), lbuf2, ntohs(tcp->th_dport));
			} else {
				mysyslog("TCP: Bogus TCP flags set by %s:%d (dest port %d)",
					lbuf, ntohs(tcp->th_sport), ntohs(tcp->th_dport));
			}
		} else
			pthread_mutex_unlock(&bogus_lock);

		return (0);
	}

	if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK)) {
		if (opt_enabled(SYN_SCAN) && (ntohs(ip->ip_off) & IP_DF) == 0 &&
			check_scan(ip, SCAN_SYN, len, tcp->th_sport, tcp->th_dport) != 0)
		{
			return (0);
		} else if (opt_enabled(PORTSCAN) &&
			check_scan(ip, SCAN_PORT, len, tcp->th_sport, tcp->th_dport) != 0)
		{
				return (0);
		}

		if (opt_enabled(SYN_FLOOD)) {
			pthread_mutex_lock(&syn_lock);
			if (syncount < SYNFLOOD)
				++syncount;
			pthread_mutex_unlock(&syn_lock);
		}

		if (opt_enabled(SCANS_ONLY))
			return (0);

		if (opt_enabled(GET_IDENT) && is_listening(tcp->th_dport)) {
			pthread_t pt;
			u_long buflen = ntohs(ip->ip_len);
			u_char *buf;

			buf = xmalloc(buflen);
			memcpy(buf, ip, buflen);
			pthread_create(&pt, NULL, get_ident_data, buf);
			pthread_detach(pt);

			return (0);
		} else {
			u_char sbuf[MAX_SRVLEN];

			serv_lookup(tcp->th_dport, "tcp", sbuf, sizeof(sbuf));
			host_lookup(&ip->ip_src, tcp_res(), lbuf, sizeof(lbuf));

			if (opt_enabled(LOG_DEST)) {
				u_char lbuf2[MAX_HSTLEN];

				host_lookup(&ip->ip_dst, tcp_res(), lbuf2, sizeof(lbuf2));

				mysyslog("TCP: to %s:%s from %s:%u",
					lbuf2, sbuf, lbuf, ntohs(tcp->th_sport));
			} else {
				mysyslog("TCP: to %s from %s:%u",
					sbuf, lbuf, ntohs(tcp->th_sport));
			}
		}
	}

	return (0);
}

/* vim:ts=4:sw=8:tw=0 */
