/*
** iplog_dns.c - iplog DNS cache routines.
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
** $Id: iplog_dns.c,v 1.21 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>

#include <iplog.h>
#include <iplog_dns.h>
#include <iplog_options.h>

static u_char *add_to_cache(ipaddr_t addr, u_long hash, u_char *, size_t);

static size_t dt_size;
static struct dns_entry *dns_table;

/*
** Initializes a hash table for the DNS cache with "tlen" buckets.
*/

void init_dns_table(size_t tlen) {
	size_t i;

	dt_size = tlen;
	dns_table = xcalloc(dt_size, sizeof(struct dns_entry));

	for (i = 0 ; i < dt_size ; i++)
		pthread_mutex_init(&dns_table[i].lock, NULL);
}

/*
** Scans the DNS hash table, removing any entries that have expired.
*/

void expire_dns(void) {
	size_t i;
	struct dns_data *cur;

	for (i = 0 ; i < dt_size ; i++) {
		pthread_mutex_lock(&dns_table[i].lock);
		cur = dns_table[i].head;

		while (cur != NULL) {
			if (time(NULL) >= cur->expire) {
				free(cur->host);
				cur = dlist_delete(cur, &dns_table[i].head);
				--dns_table[i].cnt;
			} else
				cur = cur->next;
		}

		pthread_mutex_unlock(&dns_table[i].lock);
	}
}

#ifdef HAVE_PTHREAD_CANCEL

/*
** Cleanup routine called when the DNS hash table is destroyed.
*/

static void dns_cleanup(void *data) {
	struct dns_data *cur = data;

	free(cur->host);
}

/*
** Destroys the DNS hash table.
*/

void destroy_dns_cache(void) {
	size_t i;

	/*
	** All the threads have been canceled, and the locks could be in any
	** state, just zero the whole table out
	*/
	for (i = 0 ; i < dt_size ; i++) {
		if (dns_table[i].head != NULL)
			dlist_destroy(dns_table[i].head, dns_cleanup);
		memset(&dns_table[i], 0, sizeof(struct dns_entry));
		pthread_mutex_init(&dns_table[i].lock, NULL);
	}
}
#endif

/*
** Search for the host specified by "addr" in the DNS hash table.
** If it's not found, resolve the hostname and add it to the cache.
** Copy the first len - 1 bytes of the result into "buf," nul-terminate buf.
*/

u_char *get_dns_cache(ipaddr_t addr, u_char *buf, size_t len) {
	u_long hash = DNS_HASH(addr, dt_size);
	bool found = false;
	struct dns_data *cur;

	pthread_mutex_lock(&dns_table[hash].lock);
	for (cur = dns_table[hash].head ; cur != NULL ; cur = cur->next) {
		if (cur->addr == addr) {
			xstrncpy(buf, cur->host, len);
			found = true;
			break;
		}
	}
	pthread_mutex_unlock(&dns_table[hash].lock);

	if (found == false)
		return (add_to_cache(addr, hash, buf, len));

	return (buf);
}

/*
** Add an entry for host "addr" to the DNS hash table.
*/

static u_char *add_to_cache(ipaddr_t addr, u_long hash, u_char *buf, size_t len)
{
	struct dns_data *new_entry = xmalloc(sizeof(struct dns_data));
	struct in_addr in;

	in.s_addr = addr;
	_host_lookup(&in, buf, len);

	new_entry->addr = addr;
	new_entry->expire = time(NULL) + DNS_TIMEOUT;

	if (opt_enabled(LOG_IP) && !isdigit(buf[strlen(buf) - 1])) {
		size_t mlen = strlen(buf) + MAX_IPLEN + 4;
		u_char ibuf[MAX_IPLEN];

		new_entry->host = xmalloc(mlen);
		inet_ntoa_r(&in, ibuf, sizeof(ibuf));
		snprintf(new_entry->host, mlen, "%s (%s)", buf, ibuf);

		if (mlen <= len)
			xstrncpy(buf, new_entry->host, len);
		else
			xstrncpy(buf, ibuf, len);
	} else
		new_entry->host = xstrdup(buf);

	pthread_mutex_lock(&dns_table[hash].lock);

	if (dns_table[hash].cnt >= DNS_MAX_ENT) {
		/*
		** This bucket is full.  Evict the oldest entry.
		*/
		u_long old_t = ~0;
		struct dns_data *cur, *oldest = NULL;

		for (cur = dns_table[hash].head ; cur != NULL ; cur = cur->next) {
			if ((u_long) cur->expire <= old_t) {
				old_t = cur->expire;
				oldest = cur;
			}
		}

		dlist_delete(oldest, &dns_table[hash].head);
		--dns_table[hash].cnt;
	}

	dlist_prepend(new_entry, &dns_table[hash].head);
	++dns_table[hash].cnt;
	pthread_mutex_unlock(&dns_table[hash].lock);

	return (buf);
}

/* vim:ts=4:sw=8:tw=0 */
