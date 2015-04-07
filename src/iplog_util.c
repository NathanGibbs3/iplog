/*
** iplog_util.c - iplog utility functions.
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
** $Id: iplog_util.c,v 1.43 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <iplog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <pthread.h>

#include <iplog_options.h>
#include <iplog_dns.h>

typedef struct list {
	struct list *next;
} list_t;

typedef struct dlist {
	struct dlist *next;
	struct dlist *prev;
} dlist_t;

#ifndef HAVE_DPRINTF

/*
** dprintf(3) if the system's libc lacks it.
** Works line printf on a file descriptor.
*/

#	ifdef HAVE_VASPRINTF

int dprintf(int fd, const char *fmt, ...) {
	va_list ap;
	ssize_t ret;
	u_char *buf;

	va_start(ap, fmt);
	vasprintf((char **) &buf, fmt, ap);
	va_end(ap);

	ret = write(fd, buf, strlen(buf));
	free(buf);

	return (ret);
}

#	else /* !HAVE_VASPRINTF */ 

int dprintf(int fd, const char *fmt, ...) {
	va_list ap;
	ssize_t ret;
	u_char buf[2048];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	ret = write(fd, buf, strlen(buf));

	return (ret);
}

#	endif /* !HAVE_VASPRINTF */
#endif /* !HAVE_DPRINTF */

/*
** malloc(3) with error checking.  Returns a pointer to the allocated memory.
*/

void *xmalloc(size_t size) {
	void *ret = malloc(size);

	if (ret == NULL)
		fatal("Out of memory.");

	return (ret);
}

/*
** calloc(3) with error checking.  Returns a pointer to the allocated memory.
*/

void *xcalloc(size_t nmemb, size_t size) {
	void *p = calloc(nmemb, size);

	if (p == NULL)
		fatal("Out of memory.");

	return (p);
}

/*
** realloc(3) with error checking.  Returns a pointer to the allocated
** memory.
*/

void *xrealloc(void *ptr, size_t size) {
	void *ret = realloc(ptr, size);

	if (ret == NULL)
		fatal("Out of memory.");

	return (ret);
}

/*
** strdup(3) with error checking.  Returns a pointer to the new copy of the
** string.
*/

char *xstrdup(const char *s) {
	char *ret = strdup(s);

	if (ret == NULL)
		fatal("Out of memory.");

	return (ret);
}

/*
** Copy at most n-1 characters from src to dest and nul-terminate dest.
** Returns a pointer to the destination string.
*/

char *xstrncpy(char *dest, const char *src, size_t n) {
	u_char *ret = dest;

	if (n == 0)
		return (dest);

	while (--n > 0 && (*dest++ = *src++) != '\0')
		;
	*dest = '\0';

	return (ret);
}

/*
** Append at most n-1 characters from src to dest and nul-terminate dest.
** Returns a pointer to the destination string.
*/

char *xstrncat(char *dest, const char *src, size_t n) {
	u_char *ret = dest;

	if (n == 0)
		return (dest);

	for (; *dest != '\0' ; dest++, n--)
		;
	while (--n > 0 && (*dest++ = *src++) != '\0')
		;
	*dest = '\0';

	return (ret);
}

/*
** sleep(3) implemented with select.
*/

void xsleep(time_t seconds) {
	struct timeval tv;

	tv.tv_sec = seconds;
	tv.tv_usec = 0;

	select(0, NULL, NULL, NULL, &tv);
}

/*
** usleep(3) implemented with select.
*/

void xusleep(u_long usec) {
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = usec;

	select(0, NULL, NULL, NULL, &tv);
}

/*
** Resolves a port number to a service name (eg. 23 -> "telnet")
** returns "port %u" on failure.
*/

#ifndef HAVE_GETSERVBYPORT_R

u_char *serv_lookup(in_port_t port,
					const u_char *proto,
					u_char *buf,
					size_t len)
{
	static pthread_mutex_t serv_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct servent *se;

	port &= MAX_PORT;

	pthread_mutex_lock(&serv_mutex);

	se = getservbyport(port, proto);
	if (se != NULL)
		xstrncpy(buf, se->s_name, len);
	else
		snprintf(buf, len, "port %u", htons(port));

	pthread_mutex_unlock(&serv_mutex);

	return (buf);
}

#elif HAVE_GETSERVBYPORT_RSIX

u_char *serv_lookup(in_port_t port,
					const u_char *proto,
					u_char *buf,
					size_t len)
{
	int ret;
	struct servent *result, se;
	u_char rbuf[1024];

	port &= MAX_PORT;

	ret = getservbyport_r(port, proto, &se, rbuf, sizeof(rbuf), &result);

	if (ret != 0 || result == NULL)
		snprintf(buf, len, "port %u", htons(port));
	else
		xstrncpy(buf, se.s_name, len);

	return (buf);
}

#elif HAVE_GETSERVBYPORT_RFIVE

u_char *serv_lookup(in_port_t port,
					const u_char *proto,
					u_char *buf,
					size_t len)
{
	struct servent se;
	u_char rbuf[1024];

	port &= MAX_PORT;

	if (getservbyport_r(port, proto, &se, rbuf, sizeof(rbuf)) == NULL)
		snprintf(buf, len, "port %u", htons(port));
	else
		xstrncpy(buf, se.s_name, len);

	return (buf);
}

#elif HAVE_GETSERVBYPORT_RFOUR

u_char *serv_lookup(in_port_t port,
					const u_char *proto,
					u_char *buf,
					size_t len)
{
	struct servent se;
	struct servent_data sed;

	memset(&sed, 0, sizeof(sed));

	if (getservbyport_r(port, proto, &se, &sed) != 0)
		snprintf(buf, len, "port %u", htons(port));
	else
		xstrncpy(buf, se.s_name, len);

	return (buf);
}

#else
#	error "BUG - No serv_lookup()"
#endif


#ifndef HAVE_LOCALTIME_R

/*
** Wrapper to make localtime(3) thread-safe.
*/

struct tm *localtime_r(const time_t *cur_time, struct tm *result) {
	struct tm *tm;
	static pthread_mutex_t localtime_mutex = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&localtime_mutex);
	tm = localtime(cur_time);
	memcpy(result, tm, sizeof(struct tm));
	pthread_mutex_unlock(&localtime_mutex);

	return (result);
}

#endif

/*
** Thread-safe version of inet_ntoa(3).
*/

u_char *inet_ntoa_r(const struct in_addr *in, u_char *buf, size_t len) {
	ipaddr_t addr = ntohl(in->s_addr);

	snprintf(buf, len, "%u.%u.%u.%u",
			((addr >> 24) & 0xff), ((addr >> 16) & 0xff),
			((addr >> 8) & 0xff), (addr & 0xff));

	return (buf);
}

/*
** Resolve a protocol number to its name (eg. 6 -> "TCP")
** returns "proto %u" on failure.
*/

#ifndef HAVE_GETPROTOBYNUMBER_R

u_char *proto_lookup(int proto, u_char *buf, size_t len) {
	static pthread_mutex_t proto_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct protoent *pe;

	pthread_mutex_lock(&proto_mutex);
	pe = getprotobynumber(proto);
	if (pe != NULL) {
		xstrncpy(buf, pe->p_name, len);
		pthread_mutex_unlock(&proto_mutex);
	} else {
		pthread_mutex_unlock(&proto_mutex);
		snprintf(buf, len, "proto %u", proto);
	}

	return (buf);
}

#elif defined(HAVE_GETPROTOBYNUMBER_RFIVE)

u_char *proto_lookup(int proto, u_char *buf, size_t len) {
	int ret;
	struct protoent *result, pe;
	u_char tbuf[256];

	ret = getprotobynumber_r(proto, &pe, tbuf, sizeof(tbuf), &result);

	if (ret != 0 || result == NULL)
		snprintf(buf, len, "proto %u", proto);
	else
		xstrncpy(buf, pe.p_name, len);

	return (buf);
}

#elif defined(HAVE_GETPROTOBYNUMBER_RFOUR)

u_char *proto_lookup(int proto, u_char *buf, size_t len) {
	struct protoent pe;
	u_char tbuf[256];

	if (getprotobynumber_r(proto, &pe, tbuf, sizeof(tbuf)) == NULL)
		snprintf(buf, len, "proto %u", proto);
	else
		xstrncpy(buf, pe.p_name, len);

	return (buf);
}

#elif defined(HAVE_GETPROTOBYNUMBER_RTHREE)

u_char *proto_lookup(int proto, u_char *buf, size_t len) {
	struct protoent pe;
	struct protoent_data prd;

	memset(&prd, 0, sizeof(prd));

	if (getprotobynumber_r(proto, &pe, &prd) != 0)
		snprintf(buf, len, "proto %u", proto);
	else
		xstrncpy(buf, pe.p_name, len);

	return (buf);
}

#else
#	error "BUG - No proto_lookup()"
#endif

/*
** Returns the FQDN of the host specified by "in."  Returns its quad-dot
** notation IP address on failure (or if the resolver is disabled).
*/

u_char *host_lookup(const struct in_addr *in, bool resolv,
					u_char *buf, size_t len)
{
	if (resolv == false)
		return (inet_ntoa_r(in, buf, len));

	if (opt_enabled(DNS_CACHE))
		return (get_dns_cache(in->s_addr, buf, len));

	if (opt_enabled(LOG_IP)) {
		_host_lookup(in, buf, len);

		if (isdigit(buf[strlen(buf) - 1]))
			return (buf);

		if ((strlen(buf) + MAX_IPLEN + 4) < len) {
			u_char sbuf[MAX_IPLEN];
			u_char tbuf[len];

			xstrncpy(tbuf, buf, sizeof(tbuf));
			inet_ntoa_r(in, sbuf, sizeof(sbuf));
			snprintf(buf, len, "%s (%s)", tbuf, sbuf);
			return (buf);
		} else
			return (inet_ntoa_r(in, buf, len));
	}

	return (_host_lookup(in, buf, len));
}

/*
** The guts of host_lookup() (see above).
*/

#ifndef HAVE_GETHOSTBYADDR_R

u_char *_host_lookup(const struct in_addr *in, u_char *buf, size_t len) {
	static pthread_mutex_t host_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct hostent *he;

	pthread_mutex_lock(&host_mutex);
	he = gethostbyaddr((char *) in, sizeof(struct in_addr), AF_INET);

	if (he != NULL && strlen(he->h_name) < len) {
		xstrncpy(buf, he->h_name, len);
		pthread_mutex_unlock(&host_mutex);
	} else {
		pthread_mutex_unlock(&host_mutex);
		inet_ntoa_r(in, buf, len);
	}

	return (buf);
}

#elif defined(HAVE_GETHOSTBYADDR_REIGHT)

u_char *_host_lookup(const struct in_addr *in, u_char *buf, size_t len) {
	int herr, ret;
	struct hostent *result, he;
	u_char hbuf[1024];

	ret = gethostbyaddr_r((char *) in, sizeof(struct in_addr), AF_INET,
			&he, hbuf, sizeof(hbuf), &result, &herr);

#if defined __GLIBC__ && __GLIBC__ >= 2
	if (ret != 0 || result == NULL || strlen(he.h_name) >= len)
#else
	if (ret != 0 || strlen(he.h_name) >= len)
#endif
		inet_ntoa_r(in, buf, len);
	else
		xstrncpy(buf, he.h_name, len);

	return (buf);
}

#elif defined(HAVE_GETHOSTBYADDR_RSEVEN)

u_char *_host_lookup(const struct in_addr *in, u_char *buf, size_t len) {
	int herr;
	struct hostent *ret, he;
	u_char hbuf[1024];

	ret = gethostbyaddr_r((char *) in, sizeof(struct in_addr), AF_INET,
			&he, hbuf, sizeof(hbuf), &herr);

	if (ret == NULL || strlen(he.h_name) >= len)
		inet_ntoa_r(in, buf, len);
	else
		xstrncpy(buf, he.h_name, len);

	return (buf);
}

#elif defined(HAVE_GETHOSTBYADDR_RFIVE)

u_char *_host_lookup(const struct in_addr *in, u_char *buf, size_t len) {
	int ret;
	struct hostent he;
	struct hostent_data hed;

	memset(&hed, 0, sizeof(hed));

	ret = gethostbyaddr_r((char *) in, sizeof(struct in_addr), AF_INET,
			&he, &hed);

	if (ret != 0 || strlen(he.h_name) >= len)
		inet_ntoa_r(in, buf, len);
	else
		xstrncpy(buf, he.h_name, len);

	return (buf);
}

#else
#	error "BUG - No _host_lookup()"
#endif


/*
** Become a daemon.
*/

void fork_to_back(void) {
	int ret;

	ret = fork();
	if (ret > 0)
		_exit(0);
	else if (ret != 0)
		fatal("fork: %s", strerror(errno));

	if (setsid() == -1)
		fatal("setsid: %s", strerror(errno));

	if (chdir("/") == -1)
		fatal("chdir: %s", strerror(errno));

	umask(022);

	if (close(0) == -1)
		fatal("close(%d): %s", 0, strerror(errno));

	if (!opt_enabled(LOG_STDOUT)) {
		if (close(1) == -1)
			fatal("close(%d): %s", 1, strerror(errno));
	}

	if (close(2) == -1)
		fatal("close(%d): %s", 2, strerror(errno));

	ret = open("/dev/null", O_WRONLY);
	if (ret != 0)
		fatal("open: /dev/null: %s", strerror(errno));

	if (!opt_enabled(LOG_STDOUT)) {
		if (dup2(0, 1) == -1)
			fatal("dup2(%d, %d): %s", 0, 1, strerror(errno));
	}

	if (dup2(0, 2) == -1)
		fatal("dup2(%d, %d): %s", 0, 2, strerror(errno));
}

/*
** Switch to [e]uid of user and [e]gid of group, drop all supplementary groups.
*/

void drop_privs(const u_char *user, const u_char *group) {
	uid_t uid;
	gid_t gid;
	char *nptr;

	if (group != NULL) {
		struct group *gr = getgrnam(group);

		if (gr == NULL) {
			gid = strtoul(group, &nptr, 10);
			if (*nptr != '\0') 
				fatal("Unknown group: \"%s\"", group);
		} else
			gid = gr->gr_gid;

		if (setgid(gid) != 0)
			fatal("setgid(%d): %s", gid, strerror(errno));

		if (setgroups(0, NULL) != 0)
			fatal("setgroups(0, NULL): %s", strerror(errno));
	}

	if (user != NULL) {
		struct passwd *pw = getpwnam(user);

		if (pw == NULL) {
			uid = strtoul(user, &nptr, 10);
			if (*nptr != '\0')
				fatal("Unknown user: \"%s\"", user);
		} else
			uid = pw->pw_uid;

		if (setuid(uid) != 0)
			fatal("setuid(%d): %s", uid, strerror(errno));
	}
}

/*
** Logs a fatal error message and exits.
*/


#ifdef HAVE_VASPRINTF

void fatal(const u_char *fmt, ...) {
	va_list ap;
	u_char *message;

	va_start(ap, fmt);
	vasprintf((char **) &message, fmt, ap);
	va_end(ap);

	mysyslog("Fatal: %s", message);
	exit(-1);
}

#else

void fatal(const u_char *fmt, ...) {
	va_list ap;
	u_char message[2048];

	va_start(ap, fmt);
	vsnprintf(message, sizeof(message), fmt, ap);
	va_end(ap);

	mysyslog("Fatal: %s", message);
	exit(-1);
}

#endif

/*
** Read a line of up to len characters from fp into buf until
** a newline is encountered.  Nul-terminate buf.
*/

int get_line(FILE *fp, u_char *buf, size_t len) {
	int c;
	size_t i = 0;

	for (;;) {
		c = getc(fp);

		switch (c) {
			case EOF:
				if (i == 0)
					return EOF;
			case '\n':
				if (i >= len)
					i = 0;
				buf[i] = '\0';
				return (0);
			default:
				if (i == 0 && isspace(c))
					break;
				if (i < len)
					buf[i++] = c;
		}
	}

	return (0);
}

/*
** Write to a socket, deal with interrupted and incomplete writes.  Returns
** the number of characters written to the socket on success, -1 on failure.
*/

ssize_t sock_write(int sock, void *buf, size_t len) {
	ssize_t n, written = 0;

	while (len > 0) {
		n = write(sock, buf, len);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}

		written += n;
		len -= n;
		buf += n;
	}

	return (written);
}

/*
** Old, unoptimized implementation of the IP checksum..
*/

int in_cksum(u_short *addr, int len) {
	int nleft = len;
	u_short *w = addr;
	int sum = 0;
	u_short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

/*
** Returns true if the resolver is not disabled and false if it is disabled.
*/

bool any_res(void) {
	return (!opt_enabled(NO_RESOLV));
}

/*
** Add a node to the end of a doubly linked list.
*/

void *__dlist_append(void *data, void **head) {
	dlist_t **list_head = (dlist_t **) head;
	dlist_t *cur = *list_head;
	dlist_t *new_node = data;

	new_node->next = NULL;

	if (cur == NULL) {
		new_node->prev = NULL;
		*list_head = new_node;

		return (new_node);
	}

	while (cur->next != NULL)
		cur = cur->next;

	cur->next = new_node;
	new_node->prev = cur;

	return (new_node);
}

/*
** Allocate a new node, copy data there and add it to the end of a doubly
** linked list.
*/

void *__dlist_copy_append(const void *data, void **head, size_t len) {
	dlist_t *new_node = xmalloc(len);

	memcpy(new_node, data, len);

	return (dlist_append(new_node, head));
}

/*
** Add a node to the head of a doubly linked list.
*/

void *__dlist_prepend(void *data, void **head) {
	dlist_t *new_node = data;
	dlist_t **list_head = (dlist_t **) head;

	new_node->prev = NULL;
	new_node->next = *list_head;

	if (*list_head != NULL)
		(*list_head)->prev = new_node;

	*list_head = new_node;

	return (new_node);
}

/*
** Allocate a new node, copy data there and add it to the head of the linked
** list.
*/

void *__dlist_copy_prepend(const void *data, void **head, size_t len) {
	dlist_t *new_node = xmalloc(len);

	memcpy(new_node, data, len);

	return (dlist_prepend(new_node, head));
}

/*
** Remove a node from a doubly linked list.
*/

void *__dlist_remove(void *data, void **head) {
	dlist_t *dnode = data;
	dlist_t *next = dnode->next;
	dlist_t **list_head = (dlist_t **) head;

	if (dnode->prev == NULL) {
		*list_head = next;
		if (next != NULL)
			next->prev = NULL;
	} else {
		dnode->prev->next = next;
		if (next != NULL)
			next->prev = dnode->prev;
	}

	return (next);
}

/*
** Remove a node from a doubly linked list, free the memory it occupies.
*/

void *__dlist_delete(void *data, void **head) {
	void *ret = __dlist_remove(data, head);

	free(data);
	return (ret);
}

/*
** Add a node to the end of a linked list.
*/

void *__list_append(void *data, void **head) {
	list_t *cur, *new_node = data;

	new_node->next = NULL;

	if (*head == NULL)
		*head = new_node;
	else {
		cur = *head;
		while (cur->next != NULL)
			cur = cur->next;
		cur->next = new_node;
	}

	return (new_node);
}

/*
** Allocate a new node, copy data there and add it to the end of a linked
** list.
*/

void *__list_copy_append(const void *data, void **head, size_t len) {
	list_t *new_node = xmalloc(len);

	memcpy(new_node, data, len);

	return (list_append(new_node, head));
}

/*
** Add a node to the head of a linked list.
*/

void *__list_prepend(void *data, void **head) {
	list_t *old_head, *new_node = data;

	old_head = *head;
	*head = new_node;
	new_node->next = old_head;

	return (*head);
}

/*
** Allocate a new node, copy data there and add it to the head of the linked
** list.
*/

void *__list_copy_prepend(const void *data, void **head, size_t len) {
	list_t *new_node = xmalloc(len);

	memcpy(new_node, data, len);

	return (list_prepend(new_node, head));
}

/*
** Delete a node from a linked list.
*/

void *__list_delete(void *node, void **head) {
	list_t *ret = NULL, *cur = *head, *temp = NULL;

	while (cur != NULL) {
		if (cur == node) {
			ret = cur->next;

			if (temp == NULL)
				*head = ret;
			else
				temp->next = ret;

			free(cur);
			break;
		}

		temp = cur;
		cur = cur->next;
	}

	return (ret);
}

/*
** Destroy a linked list or a doubly linked list.
*/

void list_destroy(void *list_head, void (*cleanup)(void *)) {
	list_t *cur = list_head, *next;

	while (cur != NULL) {
		next = cur->next;
		if (cleanup != NULL)
			cleanup(cur);
		free(cur);
		cur = next;
	}
}

/* vim:ts=4:sw=8:tw=0 */
