/*
** iplog_ident.c - iplog IDENT lookup routines.
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
** $Id: iplog_ident.c,v 1.22 2001/01/01 19:28:07 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define __FAVOR_BSD
#include <sys/socket.h>

#include <iplog.h>
#include <iplog_options.h>

#define TCP_FORMAT "%*d: %*X:%hx %*X:%*x %x %*X:%*X %*x:%*X %*x %*d %*d %*d"
#define TCP_LISTEN	0x0A
#define TCP_DATA	"/proc/net/tcp"

#ifndef __linux__
/*
** Stub functions for platforms other than Linux.
*/

bool is_listening(in_port_t unused) {
	(void) unused;
	return (false);
}

void *get_ident_data(void *unused) {
	(void) unused;
	return (NULL);
}
#else

/*
** Request IDENT (RFC 1413) info for the connection specified by "data."
** "data" is a pointer to an IP packet.
** This function is meant to run as its own thread.
*/

void *get_ident_data(void *data) {
	int sock;
	struct sockaddr_in id_sin;
	u_char buf[128], remote_user[64], lbuf[MAX_HSTLEN], sbuf[MAX_SRVLEN];
	ssize_t len, blen;
	struct ip *ip = (struct ip *) data;
	struct tcphdr *tcp = (struct tcphdr *) ((char *) ip + __IP_HDR_LENGTH(ip));

	sock = socket(PF_INET, SOCK_STREAM, 0);

	if (sock == -1) {
		IDEBUG(("[%s:%d] socket: %s", __FILE__, __LINE__, strerror(errno)));
		goto ident_fail;
	}

	id_sin.sin_family = AF_INET;
	id_sin.sin_addr.s_addr = ip->ip_src.s_addr;
	id_sin.sin_port = htons(113);

	if (connect(sock, (struct sockaddr *) &id_sin, sizeof(id_sin)) != 0) {
		IDEBUG(("[%s:%d] connect: %s", __FILE__, __LINE__, strerror(errno)));
		goto ident_fail;
	}

	snprintf(buf, sizeof(buf), "%d , %d\r\n",
		ntohs(tcp->th_sport), ntohs(tcp->th_dport));

	blen = strlen(buf);

	if (sock_write(sock, buf, blen) != blen) {
		IDEBUG(("[%s:%d] send: %s", __FILE__, __LINE__, strerror(errno)));
		goto ident_fail;
	}

	/* XXX: Fix this to handle being interrupted. */
	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 1) {
		IDEBUG(("[%s:%d] recv: %s", __FILE__, __LINE__, strerror(errno)));
		goto ident_fail;
	}

	buf[len] = '\0';

	if (sscanf(buf, "%*u , %*u : USERID :%*[^:]:%64s", remote_user) == 1) {
		if (opt_enabled(LOG_DEST)) {
			u_char lbuf2[MAX_HSTLEN];

			mysyslog("TCP: %s connection attempt to %s from %s@%s:%u",
				serv_lookup(tcp->th_dport, "tcp", sbuf, sizeof(sbuf)), 
				host_lookup(&ip->ip_dst, tcp_res(), lbuf2, sizeof(lbuf2)),
				remote_user,
				host_lookup(&ip->ip_src, tcp_res(), lbuf, sizeof(lbuf)),
				ntohs(tcp->th_sport));
		} else {
			mysyslog("TCP: %s connection attempt from %s@%s:%u",
				serv_lookup(tcp->th_dport, "tcp", sbuf, sizeof(sbuf)), remote_user,
				host_lookup(&ip->ip_src, tcp_res(), lbuf, sizeof(lbuf)),
				ntohs(tcp->th_sport));
		} 

		free(data);
		close(sock);
		return (NULL);
	} else
		IDEBUG(("[%s:%d] Bad ident response: %s", __FILE__, __LINE__, buf));

ident_fail:
	if (opt_enabled(LOG_DEST)) {
		u_char lbuf2[MAX_HSTLEN];

		mysyslog("TCP: %s connection attempt to %s from %s:%u",
			serv_lookup(tcp->th_dport, "tcp", sbuf, sizeof(sbuf)),
			host_lookup(&ip->ip_dst, tcp_res(), lbuf2, sizeof(lbuf2)),
			host_lookup(&ip->ip_src, tcp_res(), lbuf, sizeof(lbuf)),
			ntohs(tcp->th_sport));
	} else {
		mysyslog("TCP: %s connection attempt from %s:%u",
			serv_lookup(tcp->th_dport, "tcp", sbuf, sizeof(sbuf)),
			host_lookup(&ip->ip_src, tcp_res(), lbuf, sizeof(lbuf)),
			ntohs(tcp->th_sport));
	}

	free(data);
	close(sock);
	return (NULL);
}

/*
** Returns true if local port "port" is open and listening, false if it isn't.
*/

bool is_listening(in_port_t port) {
	FILE *fp;
	in_port_t lport;
	u_int mode;
	u_char buf[1024];

	port = htons(port);

	fp = fopen(TCP_DATA, "r");
	if (fp == NULL)
		return (false);

	while (get_line(fp, buf, sizeof(buf) - 1) != EOF) {
		if (sscanf(buf, TCP_FORMAT, &lport, &mode) != 2)
			continue;
		if (lport == port) {
			if (mode == TCP_LISTEN) {
				fclose(fp);
				return (true);
			}

			break;
		}
	}

	fclose(fp);
	return (false);
}
#endif /* __linux__ */

/* vim:ts=4:sw=8:tw=0 */
