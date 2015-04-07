/*
** iplog.c - iplog main routine.
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
** $Id: iplog.c,v 1.31 2001/01/01 19:36:03 odin Exp $
*/

#define _GNU_SOURCE

#include <config.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <pcap.h>

#ifdef HAVE_PTHREAD_CANCEL
#	include <setjmp.h>
#endif

#ifndef __linux__
#	define THREADED_LIBPCAP_IS_BROKEN	1
#endif

#ifdef THREADED_LIBPCAP_IS_BROKEN
#	include <pcap-int.h>
#endif

#include <iplog.h>
#include <iplog_options.h>
#include <iplog_config.h>
#include <iplog_pcap.h>
#include <iplog_input.h>
#include <iplog_dns.h>
#include <iplog_scan.h>

#ifdef HAVE_PTHREAD_CANCEL
#	define setup_thread_cancelstate() \
		do { \
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL); \
			pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL); \
		} while (0)

	static void iplog_restart(int sig);
	static void pcap_cleanup(void *data);

	static sigjmp_buf jmpbuf;
#else
#	define	setup_thread_cancelstate() do { } while (0)
#endif

struct running {
	struct running *next;
	struct running *prev;
	pthread_t pt;
};

static struct running *running = NULL;
static struct pcap_data *plist = NULL;
static volatile bool cap_rawsock = false;
static u_int reading = 0;
static pthread_mutex_t running_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t plist_lock = PTHREAD_MUTEX_INITIALIZER;

static void *read_packets(void *data);
static void *expire_data(void *unused);
static void iplog_cleanup(int sig);
static void pq_add(struct ip *ip, size_t len);
static struct packet_list *pq_get(void);
static void *queue_manager(void *data);

u_char *ifstring, *logfile, *user, *group, *lockfile;

struct packet_queue {
	struct packet_list {
		struct packet_list *next;
		struct packet_list *prev;
		struct ip *ip;
		time_t received;
	} *head, *tail;
	pthread_mutex_t lock;
	pthread_cond_t cond;
};

static struct packet_queue packet_queue = {
	head:	NULL,
	tail:	NULL,
	lock:	PTHREAD_MUTEX_INITIALIZER,
	cond:	PTHREAD_COND_INITIALIZER
};

/*
** Add a node to the packet queue.
*/

static void pq_add(struct ip *ip, size_t len) {
	struct packet_list *new_node = xmalloc(sizeof(struct packet_list));

	new_node->received = time(NULL);

	/*
	** libpcap stores packet data in a static buffer.
	** Guess what happens without the copy if there's
	** more than one interface open.
	*/

	new_node->ip = xmalloc(len);
	memcpy(new_node->ip, ip, len);

	pthread_mutex_lock(&packet_queue.lock);

	dlist_prepend(new_node, &packet_queue.head);
	if (packet_queue.tail == NULL)
		packet_queue.tail = packet_queue.head;

	pthread_cond_signal(&packet_queue.cond);
	pthread_mutex_unlock(&packet_queue.lock);
}

/*
** Remove a node from the packet queue.
** This must be called with packet_queue.lock held.
**
** The caller is responsible for freeing any space associated with the
** removed node!
*/

static struct packet_list *pq_get(void) {
	struct packet_list *old_tail = packet_queue.tail;

	if (old_tail == NULL)
		return (NULL);

	packet_queue.tail = packet_queue.tail->prev;
	dlist_remove(old_tail, &packet_queue.head);

	pthread_mutex_unlock(&packet_queue.lock);

	return (old_tail);
}

int main(int argc, char **argv) {
	struct pcap_data *cur;
	struct running rtemp;
	volatile bool dropped = false;
	int test_socket;

	lockfile = xstrdup(LOCKFILE);
	parse_config(CONFFILE);

	/* Command-line options override the defaults set in the conf file. */
	get_options(argc, argv);
	check_options();

	myopenlog("iplog", LOG_PID | LOG_NDELAY);

	if (!opt_enabled(NO_FORK))
		fork_to_back();

	write_lockfile(lockfile);

	if (opt_enabled(DNS_CACHE))
		init_dns_table(opt_enabled(PROMISC) ? DNS_MAXSIZE_P : DNS_MAXSIZE_N);

	if (opt_enabled(ANY_SCAN))
		init_scan_table(opt_enabled(PROMISC) ? SCAN_TSIZE_P : SCAN_TSIZE_N);

	init_frag_table(FRAG_TSIZE);

#ifdef HAVE_PTHREAD_CANCEL
	sigsetjmp(jmpbuf, 1);
#endif

	if (plist == NULL && setup_pcap(&plist, ifstring) == -1)
		fatal("Couldn't initialize interfaces.");

	if (dropped == false) {
		dropped = true;
		drop_privs(user, group);
	}

	memset(&rtemp, 0, sizeof(rtemp));
	pthread_create(&rtemp.pt, NULL, queue_manager, NULL);

	/* This is not the best check, but it's better than checking {e,}uid */
	test_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (test_socket != -1) {
		cap_rawsock = true;
		close(test_socket);
	}

	if (opt_enabled(IGNORE_NS) && add_dns_ignore_rules() == -1)
		mysyslog("Unable to add dns ignore rules: %s", strerror(errno));

	pthread_mutex_lock(&running_lock);
	pthread_mutex_lock(&plist_lock);

	pthread_create(&rtemp.pt, NULL, expire_data, NULL);
	dlist_copy_prepend(&rtemp, &running, sizeof(rtemp));

	for (cur = plist ; cur != NULL ; cur = cur->next) {
		pthread_create(&rtemp.pt, NULL, read_packets, cur);
		dlist_copy_prepend(&rtemp, &running, sizeof(rtemp));
		reading++;
	}

	pthread_mutex_unlock(&plist_lock);
	pthread_mutex_unlock(&running_lock);

	if (opt_enabled(NO_FORK))
		signal(SIGINT, iplog_cleanup);
	signal(SIGTERM, iplog_cleanup);
	signal(SIGSEGV, iplog_cleanup);
#ifdef HAVE_PTHREAD_CANCEL
	signal(SIGHUP, iplog_restart);
#else
	signal(SIGHUP, SIG_IGN);
#endif

	select(0, NULL, NULL, NULL, NULL);
	exit(0);
}

/*
** Packet queue manager thread.
** This stays alive across restarts.
*/

static void *queue_manager(void *unused) {
	struct packet_list *packet;
	sigset_t expire_sigset;

	sigemptyset(&expire_sigset);

	if (opt_enabled(NO_FORK))
		sigaddset(&expire_sigset, SIGINT);
	sigaddset(&expire_sigset, SIGTERM);
	sigaddset(&expire_sigset, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &expire_sigset, NULL);

	pthread_mutex_lock(&packet_queue.lock);
	for (;;) {
		packet = pq_get();
		if (packet == NULL)
			pthread_cond_wait(&packet_queue.cond, &packet_queue.lock);
		else {
			parse_packet(packet->ip);
			free(packet->ip);
			free(packet);
			pthread_mutex_lock(&packet_queue.lock);
		}
	}

	return (unused);
}

/*
** Read in packets, send them off the appropriate function.
*/

static void *read_packets(void *data) {
	u_char *packet;
	struct pcap_pkthdr pkthdr;
	struct pcap_data *pdev = (struct pcap_data *) data;
	struct running *cur;
	sigset_t iplog_sigset;

#ifdef THREADED_LIBPCAP_IS_BROKEN
	/*
	** I'm not sure if this crap is actually needed on all
	** platforms that aren't Linux.  BSD seemed to need it, but
	** I don't know about any others (I don't have access to others
	** so I can't test) ..
	*/

	struct timeval tv;
	int fd = ((struct pcap *)pdev->pd)->fd;
	fd_set rfds;

	FD_ZERO(&rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 10000;
#endif

	setup_thread_cancelstate();

	sigemptyset(&iplog_sigset);
	if (opt_enabled(NO_FORK))
		sigaddset(&iplog_sigset, SIGINT);
	sigaddset(&iplog_sigset, SIGTERM);
	sigaddset(&iplog_sigset, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &iplog_sigset, NULL);

	for (;;) {
#ifdef THREADED_LIBPCAP_IS_BROKEN
		FD_SET(fd, &rfds);
		select(fd + 1, &rfds, NULL, NULL, &tv);
#endif
		packet = (u_char *) pcap_next(pdev->pd, &pkthdr);
		if (packet != NULL) {
			packet += pdev->dl;

			/* pq_add() handles locking. */
			pq_add((struct ip *) packet, pkthdr.caplen);

			if (pkthdr.caplen != pkthdr.len)
				IDEBUG(("caplen=%lu != len=%lu\n", pkthdr.caplen, pkthdr.len));
		} else if (errno == ENETDOWN) {
			mysyslog("Warning: interface %s went down.", pdev->name);
			pcap_close(pdev->pd);

			if (cap_rawsock == false) {
				mysyslog("Interface %s cannot be brought back up.", pdev->name);

				if (--reading == 0)
					fatal("No more interfaces open for reading.  Exiting.");

				pthread_mutex_lock(&running_lock);
				cur = running;

				/* Can't ever hit NULL */
				while (cur->pt != pthread_self())
					cur = cur->next;

				dlist_delete(cur, &running);
				pthread_mutex_unlock(&running_lock);

				pthread_mutex_lock(&plist_lock);
				dlist_delete(pdev, &plist);
				pthread_mutex_unlock(&plist_lock);

				pthread_exit(NULL);
			} else {
				struct pcap_data *dplist = NULL;

				for (;;) {
					if (setup_pcap(&dplist, pdev->name) != -1) {
						if (ifflag_isset(dplist->name, IFF_UP)) {
							mysyslog("Interface %s was reopened.",
								dplist->name);

							pthread_mutex_lock(&plist_lock);
							dlist_delete(pdev, &plist);
							pdev = dlist_prepend(dplist, &plist);
							pthread_mutex_unlock(&plist_lock);
							break;
						} else {
							pcap_close(dplist->pd);
							dlist_destroy(dplist, NULL);
						}
					}

					/* Try again in 30 seconds. */
					xsleep(30);
				}
			}
		}
	}

	return (NULL);
}

/*
** This function runs as a separate thread, expiring fragment data,
** scan hash table entries and dns hash table entries.
*/

static void *expire_data(void *unused) {
	sigset_t expire_sigset;

	setup_thread_cancelstate();
	sigemptyset(&expire_sigset);

	if (opt_enabled(NO_FORK))
		sigaddset(&expire_sigset, SIGINT);
	sigaddset(&expire_sigset, SIGTERM);
	sigaddset(&expire_sigset, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &expire_sigset, NULL);

	for (;;) {
		xsleep(EXPIRE_INTERVAL);

		expire_frags();
		if (opt_enabled(ANY_SCAN))
			expire_scans();

		if (opt_enabled(DNS_CACHE))
			expire_dns();
	}

	return (unused);
}

#ifdef HAVE_PTHREAD_CANCEL

/*
** Pcap cleanup function.
*/

static void pcap_cleanup(void *data) {
	struct pcap_data *cur = data;

	pcap_close(cur->pd);
}

/*
** Restart iplog.  Intended to be a signal handler.
*/

static void iplog_restart(int sig) {
	struct running *cur;
	extern pthread_mutex_t log_lock;

	pthread_mutex_lock(&packet_queue.lock);
	xusleep(2000);
	pthread_mutex_lock(&log_lock);

	for (cur = running ; cur != NULL ;) {
		pthread_cancel(cur->pt);
		pthread_join(cur->pt, NULL);
		cur = dlist_delete(cur, &running);
	}

	reading = 0;

	if (opt_enabled(ANY_SCAN))
		destroy_scan_table();

	if (opt_enabled(DNS_CACHE))
		destroy_dns_cache();

	destroy_frag_table();

	if (cap_rawsock == true) {
		dlist_destroy(plist, pcap_cleanup);
		plist = NULL;
	}

	destroy_filter_list(FIL_TCP);
	destroy_filter_list(FIL_UDP);
	destroy_filter_list(FIL_ICMP);

	pthread_mutex_unlock(&log_lock);
	pthread_mutex_unlock(&packet_queue.lock);

	mysyslog("Restarting iplog (pid %d).", getpid());
	mycloselog();

    parse_config(CONFFILE);
	check_options();
	myopenlog("iplog", LOG_PID | LOG_NDELAY);

	siglongjmp(jmpbuf, 1);

	/* Quiet gcc */
	(void) sig;
}
#endif

/*
** Iplog cleanup function.
*/

static void iplog_cleanup(int sig) {
	if (unlink(lockfile) == -1)
		mysyslog("Couldn't unlink \"%s\": %s", lockfile, strerror(errno));
	mysyslog("Caught signal %d, exiting.", sig);
	exit(0);
}

/* vim:ts=4:sw=8:tw=0 */
