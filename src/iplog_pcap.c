/*
** iplog_pcap.c - iplog pcap management routines.
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
** $Id: iplog_pcap.c,v 1.33 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pcap.h>

#ifdef HAVE_SYS_SOCKIO_H
#	include <sys/sockio.h>
#endif

#include <iplog.h>
#include <iplog_pcap.h>
#include <iplog_options.h>

static int get_iflist(struct pcap_data **int_list);
static int get_ifflags(const u_char *ifname, short *ifflags);
static int get_pcap_datalink(pcap_t *pd);
static int open_pcap_device(struct pcap_data *pdata);

u_char *pcap_network;

static int get_iflist(struct pcap_data **int_list) {
	int sock;
#ifdef HAVE_SOCKADDR_SA_LEN
	u_int i;
#endif
	struct ifreq buf[32], *ifr, *last, *next;
	struct ifconf ifc;
	struct pcap_data data;
	struct sockaddr_in *isin;
	u_char *p, *nlast = "\0";

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		IDEBUG(("[%s:%d] socket: %s", __FILE__, __LINE__, strerror(errno)));
		return (-1);
	}

	memset(&data, 0, sizeof(data));

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t) buf;

	if (ioctl(sock, SIOCGIFCONF, &ifc) != 0 ||
		(u_long) ifc.ifc_len < sizeof(struct ifreq))
	{
		IDEBUG(("[%s:%d] ioctl: %s", __FILE__, __LINE__, strerror(errno)));
		close(sock);
		return (-1);
	}

	ifr = buf;
	last = (struct ifreq *) ((u_char *) buf + ifc.ifc_len);
	for (; ifr < last ; ifr = next) {
#ifdef HAVE_SOCKADDR_SA_LEN
		i = ifr->ifr_addr.sa_len + sizeof(ifr->ifr_name);
		if (i < sizeof(struct ifreq))
			next = ifr + 1;
		else
			next = (struct ifreq *) ((u_char *) ifr + i);
#else
		next = ifr + 1;
#endif

		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;

		if (!ifflag_isset(ifr->ifr_name, IFF_UP))
			continue;

		p = strchr(ifr->ifr_name, ':');
		if (p != NULL)
			*p = '\0';

		if (strcmp(nlast, ifr->ifr_name)) {
			if (strcmp(nlast, "\0"))
				dlist_copy_append(&data, int_list, sizeof(data));
			nlast = ifr->ifr_name;
			memset(&data, 0, sizeof(data));
			xstrncpy(data.name, ifr->ifr_name, sizeof(data.name));
		}

		isin = (struct sockaddr_in *) &ifr->ifr_addr;
		data.addr = xrealloc(data.addr, sizeof(ipaddr_t) * (data.num_addr + 1));
		data.addr[data.num_addr++] = isin->sin_addr.s_addr;
	}

	if (data.num_addr != 0)
		dlist_copy_append(&data, int_list, sizeof(data));

	close(sock);
	return (0);
}

/*
** Store the flags set on interface "ifname" in "ifflags."
** Returns 0 on success, -1 on failure.
*/

static int get_ifflags(const u_char *ifname, short *ifflags) {
	struct ifreq ifr;
	int ret, sock;

	if (strlen(ifname) >= sizeof(ifr.ifr_name)) {
		IDEBUG(("[%s:%d] iff name too long: %s", __FILE__, __LINE__, ifname));
		return (-1);
	}

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		IDEBUG(("[%s:%d] socket: %s", __FILE__, __LINE__, strerror(errno)));
		return (-1);
	}

	xstrncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) {
		IDEBUG(("[%s:%d] %s: %s",
				__FILE__, __LINE__, ifr.ifr_name, strerror(errno)));
		ret = -1;
	} else {
		*(short *) ifflags = ifr.ifr_flags;
		ret = 0;
	}

	close(sock);
	return (ret);
}

/*
** Returns true if "test_flags" is set on interface "ifname,"
** false if it isn't.
*/

bool ifflag_isset(const u_char *ifname, short test_flag) {
	short ifflags;

	if (get_ifflags(ifname, &ifflags) == -1)
		return (false);

	return ((ifflags & test_flag) != 0);
}

/*
** Returns the datalink type of the interface specified in "pd."
** Returns -1 on failure.
*/

static int get_pcap_datalink(pcap_t *pd) {
	int datalink = pcap_datalink(pd), dlt;

	switch (datalink) {
		case DLT_RAW:
			dlt = 0;
			break;
		case DLT_ATM_RFC1483:
			dlt = 8;
			break;
		case DLT_EN10MB:
		case DLT_IEEE802:
			dlt = sizeof(struct ethhdr);
			break;
		case DLT_SLIP_BSDOS:
		case DLT_PPP_BSDOS:
			dlt = 24;
			break;
		case DLT_SLIP:
			dlt = 16;
			break;
		case DLT_PPP:
		case DLT_NULL:
#ifdef __OpenBSD__
		case DLT_LOOP:
#endif
			dlt = 4;
			break;
		default:
			dlt = -1;
			break;
	}

	return (dlt);
}

static int open_pcap_device(struct pcap_data *pdata) {
	u_char fstring[1024], *temp, errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filt;
	u_int i = 0;

	pdata->pd =
		pcap_open_live(pdata->name, SNAPLEN, opt_enabled(PROMISC), 0, errbuf);

	if (pdata->pd == NULL) {
		IDEBUG(("[%s:%d] pcap_open_live: %s (%s)",
			__FILE__, __LINE__, errbuf, strerror(errno)));
		return (-1);
	}

	pdata->dl = get_pcap_datalink(pdata->pd);

	if (pdata->dl == -1) {
		IDEBUG(("[%s:%d] Unknown datalink: %d",
			__FILE__, __LINE__, pcap_datalink(pdata->pd)));
		pcap_close(pdata->pd);
		return (-1);
	}

#ifdef __linux__
	/*
	** pcap filters don't work on Linux loopback devices.
	** I don't know why anybody would want to monitor loopback, anyway.
	*/
	if (ifflag_isset(pdata->name, IFF_LOOPBACK))
		return (0);
#endif

	xstrncpy(fstring, "ip and (", sizeof(fstring));
	if (opt_enabled(LOG_TCP)) {
		xstrncat(fstring, "tcp ", sizeof(fstring));
		++i;
	}

	if (opt_enabled(LOG_UDP)) {
		if (i++ == 0)
			temp = "udp ";
		else
			temp = "or udp ";
		xstrncat(fstring, temp, sizeof(fstring));
	}

	if (opt_enabled(LOG_ICMP)) {
		if (i == 0)
			temp = "icmp";
		else
			temp = "or icmp";
		xstrncat(fstring, temp, sizeof(fstring));
	}

	if (opt_enabled(PROMISC)) {
		u_char *p, *cur, *orig = xstrdup(pcap_network);

		cur = orig;
		xstrncat(fstring, ") and dst net (", sizeof(fstring));

		while (1) {
			p = strchr(cur, ',');
			if (p != NULL)
				*p++ = '\0';
			xstrncat(fstring, cur, sizeof(fstring));
			if (p == NULL)
				break;
			xstrncat(fstring, " or ", sizeof(fstring));
			cur = p;
		}

		free(orig);
	} else {
		struct sockaddr_in opd_sin;
		u_char nbuf[16];

		xstrncat(fstring, ") and dst host (", sizeof(fstring));

		for (i = 0 ; i < pdata->num_addr ; i++) {
			opd_sin.sin_addr.s_addr = pdata->addr[i];
			if (i > 0)
				xstrncat(fstring, " or ", sizeof(fstring));
			inet_ntoa_r(&opd_sin.sin_addr, nbuf, sizeof(nbuf));
			xstrncat(fstring, nbuf, sizeof(fstring));
		}
	}

	xstrncat(fstring, ")", sizeof(fstring));

	IDEBUG(("[%s:%d] Filter: %s", __FILE__, __LINE__, fstring));

	/*
	** There seems to be a memory leak in pcap_compile()..
	*/

	if (pcap_compile(pdata->pd, &filt, fstring, 1, 0) == -1)
		fatal("pcap_compile: %s", pcap_geterr(pdata->pd));

	if (pcap_setfilter(pdata->pd, &filt) == -1)
		fatal("pcap_setfilter: %s", pcap_geterr(pdata->pd));

	return (0);
}

int setup_pcap(struct pcap_data **plist, const u_char *ifstring) {
	struct pcap_data *cur;
	u_char **vif = NULL;
	size_t interfaces = 0;
	int ret;

	if (get_iflist(plist) == -1 || *plist == NULL)
		return (-1);

	cur = *plist;

	if (ifstring != NULL) {
		size_t i = 0, j;
		bool found;
		u_char *delim, *pos, *tstr;

		tstr = xstrdup(ifstring);

		for (pos = tstr ; (delim = strchr(pos, ',')) != NULL ; pos = delim) {
			*delim++ = '\0';
			vif = realloc(vif, sizeof(u_char *) * (i + 1));
			vif[i++] = pos;
		}

		vif = realloc(vif, sizeof(u_char *) * (i + 1));
		vif[i++] = pos;

		while (cur != NULL) {
			found = false;
			for (j = 0 ; j < i ; j++) {
				if (!strcmp(vif[j], cur->name)) {
					found = true;
					break;
				}
			}
			if (found == false) {
				free(cur->addr);
				cur = dlist_delete(cur, plist);
			} else
				cur = cur->next;
		}

		free(vif);
		free(tstr);
	} else {
		/*
		** Ignore loopback interfaces by default.
		*/
		while (cur != NULL) {
			if (ifflag_isset(cur->name, IFF_LOOPBACK)) {
				free(cur->addr);
				cur = dlist_delete(cur, plist);
			} else
				cur = cur->next;
		}
	}

	for (cur = *plist ; cur != NULL ;) {
		ret = open_pcap_device(cur);
		free(cur->addr);
		if (ret == -1) {
			mysyslog("Warning: unable to open %s", cur->name);
			cur = dlist_delete(cur, plist);
		} else {
			IDEBUG(("[%s:%d] got %s", __FILE__, __LINE__, cur->name));
			interfaces++;
			cur = cur->next;
		}
	}

	if (interfaces == 0)
		return (-1);

	return (0);
}

/* vim:ts=4:sw=8:tw=0 */
