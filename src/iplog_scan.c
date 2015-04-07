/*
** iplog_scan.c - iplog scan/flood detector.
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
** $Id: iplog_scan.c,v 1.35 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#include <iplog.h>
#include <iplog_scan.h>
#include <iplog_options.h>

#define ENDSCAN \
	"%s mode expired for %s - received a total of %lu packets (%lu bytes)."

#define ENDSCAN_P \
"%s mode to %s expired for %s - received a total of %lu packets (%lu bytes)."

static size_t st_size;
static struct scan_list *scan_table;

static void log_end_scan(const struct scan_data *cur, u_char type);
static void make_ports_str(u_short, u_char *, size_t, in_port_t *, u_short);
static void scan_cleanup(void *node);

static bool no_res(void) {
	return (false);
}

static const struct scan_info scan[] = {
	{ "TCP: port scan",			tcp_res,	PS_TIMEOUT,		PS_THOLD	},
	{ "TCP: null scan",			tcp_res,	NS_TIMEOUT,		NS_THOLD	},
	{ "TCP: FIN scan",			tcp_res,	FS_TIMEOUT,		FS_THOLD	},
	{ "TCP: SYN scan",			tcp_res,	SS_TIMEOUT,		SS_THOLD	},
	{ "TCP: Xmas scan",			tcp_res,	XS_TIMEOUT,		XS_THOLD	},
	{ "UDP: scan/flood",		udp_res,	UDP_TIMEOUT,	UDP_THOLD	},
	{ "ICMP/UDP: smurf attack",	no_res,		SMURF_TIMEOUT,	SMURF_THOLD	},
	{ "ICMP: ping flood",		icmp_res,	PING_TIMEOUT,	PING_THOLD	}
};

/*
** Log that a scan has expired/ended.
*/

static void log_end_scan(const struct scan_data *cur, u_char type) {
	u_char buf[MAX_HSTLEN];
	struct in_addr in;

	in.s_addr = cur->src_addr;
	host_lookup(&in, scan[type].resolv(), buf, sizeof(buf));

	if (opt_enabled(LOG_DEST)) {
		u_char dbuf[MAX_HSTLEN];

		in.s_addr = cur->dst_addr;
		host_lookup(&in, scan[type].resolv(), dbuf, sizeof(dbuf));

		mysyslog(ENDSCAN_P, scan[type].name, dbuf, buf,
				cur->type[type]->count, cur->type[type]->bytes);
	} else {
		mysyslog(ENDSCAN, scan[type].name, buf,
				cur->type[type]->count, cur->type[type]->bytes);
	}
}

/*
** Initialize the scan hash table.
*/

void init_scan_table(size_t tsize) {
	size_t i;

	st_size = tsize;
	scan_table = xcalloc(st_size, sizeof(struct scan_list));

	for (i = 0 ; i < st_size ; i++)
		pthread_mutex_init(&scan_table[i].lock, NULL);
}

/*
** Fills in "buf" with the ports numbers we have.
*/

static void make_ports_str(	u_short nports, u_char *buf, size_t buflen,
							in_port_t *ports, u_short maxports)
{
	if (nports) {
		if (nports == 1) {
			snprintf(buf, buflen, " [port %d]", ntohs(ports[0]));
		} else {
			u_short idx, slen;

			for (idx = 0 ; idx < nports ; idx++) {
				if (idx == 0)
					slen = snprintf(buf, buflen, " [ports %d", ntohs(ports[0]));
				else
					slen = snprintf(buf, buflen, ",%d", ntohs(ports[idx]));
				buf += slen;
				buflen -= slen;
			}

			if (nports >= maxports)
				xstrncpy(buf, ",...]", buflen);
			else
				xstrncpy(buf, "]", buflen);
		}
	} else
		buf[0] = '\0';
}

/*
** Check whether the host pointed to by "ip" appears to be scanning/flooding
** us.  Returns true if it is, false if it isn't.  If the host isn't found
** in the hash table, a new entry is created for it.
*/

bool check_scan(const struct ip *ip, u_char type, u_long len,
				int sport, int dport)
{
	u_long hash;
	ipaddr_t addr, daddr;
	struct scan_data *cur;
	bool ret = false, found = false, log_scan = false;
	/*
	** 6 chars for each port number "nnnnn," + 15 of
	** padding " [ports ", "...]", ...
	*/
	u_char bsports[SCAN_SRC_PORTS * 6 + 15];
	u_char bdports[SCAN_DST_PORTS * 6 + 15];

	daddr = ip->ip_dst.s_addr;
	addr = ip->ip_src.s_addr;

	if (type == SCAN_SMURF && opt_enabled(SMURF))
		addr &= 0xffffff;

	hash = SCAN_HASH(addr, daddr, st_size);

	pthread_mutex_lock(&scan_table[hash].lock);
	for (cur = scan_table[hash].head ; cur != NULL ; cur = cur->next) {
		if (cur->src_addr == addr && cur->dst_addr == daddr) {
			struct scan_t *data;
			time_t cur_time;

			found = true;

			if (cur->type[type] == NULL)
				cur->type[type] = xcalloc(1, sizeof(struct scan_t));

			data = cur->type[type];

			time(&cur_time);
			cur->last = cur_time;
			data->expire = cur_time + scan[type].timeout;
			data->bytes += len;

			if (sport != -1 && data->sports_count < SCAN_SRC_PORTS) {
				u_short idx;

				/* Search for this port in previous ports. */
				idx = 0;
				while (idx < data->sports_count && data->sports[idx] != sport)
					++idx;
				if (idx == data->sports_count)
					data->sports[data->sports_count++] = sport;
			}

			if (dport != -1 && data->dports_count < SCAN_DST_PORTS) {
				u_short idx;

				/* Search for this port in previous ports. */
				idx = 0;
				while (idx < data->dports_count && data->dports[idx] != dport)
					++idx;
				if (idx == data->dports_count)
					data->dports[data->dports_count++] = dport;
			}

			if (++data->count >= scan[type].threshold) {
				ret = true;
				if (data->logged == false) {
					data->logged = true;
					log_scan = true;
					make_ports_str(data->sports_count, bsports,
						sizeof(bsports), data->sports, SCAN_SRC_PORTS);
					make_ports_str(data->dports_count, bdports,
						sizeof(bdports), data->dports, SCAN_DST_PORTS);
				}
			}

			break;
		}
	}
	pthread_mutex_unlock(&scan_table[hash].lock);

	if (found == false) {
		struct scan_data *new_entry = xcalloc(1, sizeof(struct scan_data));
		struct scan_t *data;
		time_t cur_time;

		pthread_mutex_lock(&scan_table[hash].lock);
		if (scan_table[hash].cnt >= SCAN_MAXENT) {
			/*
			** This bucket is full.  Evict the oldest entry.
			*/
			size_t j;
			u_long oldest_time = ~0;
			struct scan_data *oldest = NULL, *tcur;

			for (tcur = scan_table[hash].head ; tcur ; tcur = tcur->next) {
				if ((u_long) tcur->last <= oldest_time) {
					oldest_time = tcur->last;
					oldest = tcur;
				}
			}

			for (j = 0 ; j < SCAN_TOTAL ; j++) {
				if (oldest->type[j] != NULL) {
					if (oldest->type[j]->count >= scan[j].threshold)
						log_end_scan(oldest, j);
					xfree(oldest->type[j]);
				}
			}

			cur = dlist_delete(oldest, &scan_table[hash].head);
			scan_table[hash].cnt--;
		}
		pthread_mutex_unlock(&scan_table[hash].lock);

		new_entry->src_addr = addr;
		new_entry->dst_addr = daddr;
		new_entry->type[type] = xcalloc(1, sizeof(struct scan_t));
		data = new_entry->type[type];
		data->bytes = len;
		++data->count; /* = 1  */

		if (sport != -1) {
			++data->sports_count; /* = 1 */
			data->sports[0] = sport;
		}

		if (dport != -1) {
			++data->dports_count; /* = 1 */
			data->dports[0] = dport;
		}

		time(&cur_time);
		data->expire = cur_time + scan[type].timeout;
		new_entry->last = cur_time;

		pthread_mutex_lock(&scan_table[hash].lock);
		dlist_prepend(new_entry, &scan_table[hash].head);
		++scan_table[hash].cnt;
		pthread_mutex_unlock(&scan_table[hash].lock);
	}

	if (log_scan == true) {
		u_char buf[MAX_HSTLEN];
		struct in_addr in;

		in.s_addr = addr;
		host_lookup(&in, scan[type].resolv(), buf, sizeof(buf));

		if (opt_enabled(LOG_DEST)) {
			u_char dbuf[MAX_HSTLEN];

			host_lookup(&ip->ip_dst, scan[type].resolv(), dbuf, sizeof(dbuf));
			mysyslog("%s detected to %s%s from %s%s", scan[type].name, dbuf,
				 bdports, buf, bsports);
		} else
			mysyslog("%s detected%s from %s%s", scan[type].name, bdports, buf,
				 bsports);
		ret = true;
	}

	return (ret);
}

/*
** Delete entries from the hash table that have expired.
*/

void expire_scans(void) {
	size_t i, j;
	struct scan_data *cur;
	bool remove_entry;

	for (i = 0 ; i < st_size ; i++) {
		pthread_mutex_lock(&scan_table[i].lock);
		cur = scan_table[i].head;

		for (remove_entry = true ; cur != NULL ;) {
			for (j = 0 ; j < SCAN_TOTAL ; j++) {
				if (cur->type[j] == NULL)
					continue;
				if (time(NULL) >= cur->type[j]->expire) {
					if (cur->type[j]->count >= scan[j].threshold)
						log_end_scan(cur, j);
					xfree(cur->type[j]);
				} else
					remove_entry = false;
			}

			if (remove_entry == true) {
				cur = dlist_delete(cur, &scan_table[i].head);
				--scan_table[i].cnt;
			} else
				cur = cur->next;
		}

		pthread_mutex_unlock(&scan_table[i].lock);
	}
}

#ifdef HAVE_PTHREAD_CANCEL

/*
** Destroys the scan hash table.
*/

void destroy_scan_table(void) {
	size_t i;

	for (i = 0 ; i < st_size ; i++) {
		if (scan_table[i].head != NULL)
			dlist_destroy(scan_table[i].head, scan_cleanup);
		memset(&scan_table[i], 0, sizeof(struct scan_list));
		pthread_mutex_init(&scan_table[i].lock, NULL);
	}
}

/*
** Cleanup function called when a scan table entry is deleted.
*/

static void scan_cleanup(void *node) {
	struct scan_data *cur = (struct scan_data *) node;
	size_t i;

	for (i = 0 ; i < SCAN_TOTAL ; i++) {
		if (cur->type[i] != NULL)
			xfree(cur->type[i]);
	}
}
#endif

/* vim:ts=4:sw=8:tw=0 */
