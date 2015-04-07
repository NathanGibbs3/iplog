/*
** iplog_input.c - IP input handling.
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
** $Id: iplog_input.c,v 1.19 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>

#include <iplog.h>
#include <iplog_options.h>
#include <iplog_input.h>

static struct ip *iplog_reassemble(const struct frag_data *fl);
static void deallocate_frags(struct frag_data *fl, u_long hash);
static void frag_cleanup(void *data);

static struct frag_list *frags;
static size_t frag_size;

/*
** Packet parser.
*/

void parse_packet(struct ip *ip) {
	u_char buf[MAX_HSTLEN];
	u_int h_len = __IP_HDR_LENGTH(ip);
	u_int len = ntohs(ip->ip_len);
	struct ip *temp_ip = NULL;

	/*
	** I think it's safe to assume most any TCP/IP implementation
	** will drop packets that fail either of the following two checks..
	*/

	if (h_len < sizeof(struct ip) || len < h_len) {
		if (opt_enabled(VERBOSE)) {
			if (opt_enabled(LOG_DEST)) {
				u_char buf2[MAX_HSTLEN];

				mysyslog("Short IP packet to %s from %s",
					host_lookup(&ip->ip_dst, any_res(), buf2, sizeof(buf2)),
					host_lookup(&ip->ip_src, any_res(),	buf, sizeof(buf)));
			} else {
				mysyslog("Short IP packet from %s",
					host_lookup(&ip->ip_src, any_res(),	buf, sizeof(buf)));
			}
		}

		return;
	}

	if (in_cksum((u_short *) ip, h_len) != 0) {
		if (opt_enabled(VERBOSE)) {
			if (opt_enabled(LOG_DEST)) {
				u_char buf2[MAX_HSTLEN];

				mysyslog("IP packet with invalid checksum to %s from %s",
					host_lookup(&ip->ip_dst, any_res(), buf2, sizeof(buf2)),
					host_lookup(&ip->ip_src, any_res(),	buf, sizeof(buf)));
			} else {
				mysyslog("IP packet with invalid checksum from %s",
					host_lookup(&ip->ip_src, any_res(),	buf, sizeof(buf)));
			}
		}

		return;
	}

	if (ntohs(ip->ip_off) & ~IP_DF) {
		bool done = false, found = false;
		u_int offset = ntohs(ip->ip_off);
		struct ip_fragment *tf, *temp;
		struct frag_data *cur;
		u_long hash;

		hash = FRAGHASH(ip->ip_src.s_addr, ip->ip_dst.s_addr,
						ip->ip_id, ip->ip_p);

		pthread_mutex_lock(&frags[hash].lock);
		for (cur = frags[hash].head ; cur != NULL ; cur = cur->next) {
			if (cur->id == ip->ip_id &&
				cur->saddr == ip->ip_src.s_addr &&
				cur->prot == ip->ip_p &&
				cur->daddr == ip->ip_dst.s_addr)
			{
				found = true;
				break;
			}
		}

		if (found == false)
			pthread_mutex_unlock(&frags[hash].lock);

		tf = xmalloc(sizeof(struct ip_fragment));

		tf->off = (offset & IP_OFFMASK) << 3;
		tf->len = len - __IP_HDR_LENGTH(ip);

		if (tf->off + tf->len > 0xffff) {
			if (opt_enabled(LOG_FRAG)) {
				if (opt_enabled(LOG_DEST)) {
					u_char buf2[MAX_HSTLEN];

					mysyslog("Oversized IP fragment to %s from %s",
						host_lookup(&ip->ip_dst, any_res(), buf2, sizeof(buf2)),
						host_lookup(&ip->ip_src, any_res(),	buf, sizeof(buf)));
				} else {
					mysyslog("Oversized IP fragment from %s",
						host_lookup(&ip->ip_src, any_res(),	buf, sizeof(buf)));
				}
			}

			if (found == true)
				deallocate_frags(cur, hash);

			free(tf);
			return;
		}

		if (found == false) {
			struct frag_data *tfl = xmalloc(sizeof(struct frag_data));

			tfl->prot = ip->ip_p;
			tfl->id = ip->ip_id;
			tfl->saddr = ip->ip_src.s_addr;
			tfl->daddr = ip->ip_dst.s_addr;
			tfl->expire = 0;
			tfl->frag = NULL;
			tfl->bytes = 0;
			tfl->t_len = 0;
			tfl->rf = 0;

			/*
			** If we've reached the limit, get rid of the oldest. In practice,
			** this will hardly, if ever, happen, unless we're being attacked.
			*/
			if (frags[hash].count >= FRAG_MAX) {
				u_long oldt = ~0;
				struct frag_data *q, *oldest = NULL;

				pthread_mutex_lock(&frags[hash].lock);
				for (q = frags[hash].head ; q != NULL ; q = q->next) {
					if ((u_long) q->expire <= oldt) {
						oldt = q->expire;
						oldest = q;
					}
				}
				deallocate_frags(oldest, hash);
			} else
				pthread_mutex_lock(&frags[hash].lock);

			cur = dlist_prepend(tfl, &frags[hash].head);
			++frags[hash].count;
		}

		if (tf->off == 0) {
			memcpy(&cur->header, ip, sizeof(struct ip));
			++cur->rf;
		}

		if (!(offset & IP_MF)) {
			cur->t_len = tf->off + tf->len;
			++cur->rf;
		}

		if (found == false) {
			tf->data = xmalloc(tf->len);
			memcpy(tf->data, (char *) ip + h_len, tf->len);
			temp = list_prepend(tf, &cur->frag);
		} else {
			struct ip_fragment *save;

			save = temp = cur->frag;

			while (temp != NULL) {
				if (tf->off < temp->off) {
					if ((temp->next && tf->off + tf->len > temp->next->off) ||
						(save != temp && tf->off < save->off + save->len))
					{
						if (opt_enabled(LOG_FRAG)) {
							if (opt_enabled(LOG_DEST)) {
								u_char buf2[MAX_HSTLEN];

								mysyslog("Overlapping IP frags to %s from %s",
									host_lookup(&ip->ip_dst, any_res(),
												buf2, sizeof(buf2)),
									host_lookup(&ip->ip_src, any_res(),
												buf, sizeof(buf)));
							} else {
								mysyslog("Overlapping IP fragments from %s",
									host_lookup(&ip->ip_src, any_res(),
												buf, sizeof(buf)));
							}
						}

						deallocate_frags(cur, hash);
						free(tf);
						return;
					} else {
						tf->data = xmalloc(tf->len);
						memcpy(tf->data, (char *) ip + h_len, tf->len);

						if (cur->frag == temp) {
							tf->next = temp;
							cur->frag = tf;
						} else {
							tf->next = temp;
							save->next = tf;
							tf->next = tf->next;
						}

						done = true;
					}

					break;
				} else {
					if (tf->off == temp->off) {
						if (opt_enabled(LOG_FRAG)) {
							if (opt_enabled(LOG_DEST)) {
								u_char buf2[MAX_HSTLEN];

								mysyslog("Duplicate IP fragments to %s from %s",
									host_lookup(&ip->ip_dst, any_res(),
												buf2, sizeof(buf2)),
									host_lookup(&ip->ip_src, any_res(),
												buf, sizeof(buf)));
							} else {
								mysyslog("Duplicate IP fragments from %s",
									host_lookup(&ip->ip_src, any_res(),
												buf, sizeof(buf)));
							}
						}

						deallocate_frags(cur, hash);
						free(tf);
						return;
					} else {
						save = temp;
						temp = temp->next;
					}
				}
			}

			if (done == false) {
				if (tf->off < save->len + save->off) {
					if (opt_enabled(LOG_FRAG)) {
						if (opt_enabled(LOG_DEST)) {
							u_char buf2[MAX_HSTLEN];

							mysyslog("Overlapping IP fragments to %s from %s",
									host_lookup(&ip->ip_dst, any_res(),
												buf2, sizeof(buf2)),
									host_lookup(&ip->ip_src, any_res(),
												buf, sizeof(buf)));
						} else {
							mysyslog("Overlapping IP fragments from %s",
								host_lookup(&ip->ip_src, any_res(),
											buf, sizeof(buf)));
						}
					}

					deallocate_frags(cur, hash);
					free(tf);
					return;
				}

				tf->data = xmalloc(tf->len);
				memcpy(tf->data, (char *) ip + sizeof(struct ip), tf->len);
				temp = list_append(tf, &cur->frag);
			}
		}

		cur->expire = time(NULL) + FRAG_TTL;
		cur->bytes += tf->len;

		if (cur->rf < 2) {
			pthread_mutex_unlock(&frags[hash].lock);
			return;
		}

		temp_ip = iplog_reassemble(cur);

		if (temp_ip == NULL) {
			pthread_mutex_unlock(&frags[hash].lock);
			return;
		}

		ip = temp_ip;
		deallocate_frags(cur, hash);
	}

	switch (ip->ip_p) {
		case IPPROTO_TCP:
			tcp_parser(ip);
			break;
		case IPPROTO_UDP:
			udp_parser(ip);
			break;
		case IPPROTO_ICMP:
			icmp_parser(ip);
			break;
	}

	if (temp_ip != NULL)
		free(temp_ip);
}

/*
** Reasseble the fragments in "frag_data" into a packet.  Return a pointer
** to the packet on success, NULL on failure.
*/

static struct ip *iplog_reassemble(const struct frag_data *fl) {
	u_long off = sizeof(struct ip);
	size_t plen = sizeof(struct ip) + fl->bytes;
	struct ip *ip;
	struct ip_fragment *cur;

	if (fl->bytes != fl->t_len)
		return (NULL);

	/*
	** If we got here, we have all the fragments contained in a sorted, linked
	** list.  Just glue together all the pieces.
	*/
	ip = xmalloc(plen);
	memcpy(ip, &fl->header, off);

	for (cur = fl->frag ; cur != NULL ; cur = cur->next)
		memcpy((char *) ip + (cur->off + off), cur->data, cur->len);

	ip->ip_len = htons(plen);
	/* We've ignored IP options, if any were present.. */
	ip->ip_hl = (sizeof(struct ip)) >> 2;

	/* Don't bother generating a new checksum, as we'll never use it */
	return (ip);
}

/*
** Destroy a fragment list.
** This must always be called with frags[hash].lock held.
*/

static void deallocate_frags(struct frag_data *fl, u_long hash) {
	list_destroy(fl->frag, frag_cleanup);
	dlist_delete(fl, &frags[hash].head);
	--frags[hash].count;
	pthread_mutex_unlock(&frags[hash].lock);
}

/*
** Fragment cleanup function.  This is called when an entry in the fragment
** hash table is deleted.
*/

static void frag_cleanup(void *data) {
	struct ip_fragment *frag = data;

	free(frag->data);
}

/*
** Removes expired entries from the fragment hash table.
*/

void expire_frags(void) {
	struct frag_data *cur;
	u_int i;

	for (i = 0 ; i < frag_size ; i++) {
		pthread_mutex_lock(&frags[i].lock);

		for (cur = frags[i].head ; cur != NULL ;) {
			if (cur->expire >= time(NULL)) {
				list_destroy(cur->frag, frag_cleanup);
				cur = dlist_delete(cur, &frags[i]);
				--frags[i].count;
			} else
				cur = cur->next;
		}

		pthread_mutex_unlock(&frags[i].lock);
	}
}

/*
** Initialize the fragment hash table.
*/

void init_frag_table(size_t f_size) {
	size_t i;

	frag_size = f_size;
	frags = xcalloc(frag_size, sizeof(struct frag_list));

	for (i = 0 ; i < frag_size ; i++)
		pthread_mutex_init(&frags[i].lock, NULL);
}

#ifdef HAVE_PTHREAD_CANCEL

/*
** Destroy the fragment hash table.
*/

void destroy_frag_table(void) {
	struct frag_data *cur;
	u_int i;

	/*
	** We've just canceled all the threads, and the locks could be in any
	** state, but it really doesn't matter now.  Just destroy the table and
	** reset everything.
	*/
	for (i = 0 ; i < frag_size ; i++) {
		for (cur = frags[i].head ; cur != NULL ; cur = cur->next)
			list_destroy(cur->frag, frag_cleanup);
		dlist_destroy(frags[i].head, NULL);
		frags[i].head = NULL;
		frags[i].count = 0;
		pthread_mutex_init(&frags[i].lock, NULL);
	}
}
#endif

/* vim:ts=4:sw=8:tw=0 */
