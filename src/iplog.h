/*
** iplog.h - data used by all iplog modules.
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
** $Id: iplog.h,v 1.44 2001/01/01 16:02:14 odin Exp $
*/

#ifndef __IPLOG_H
#define __IPLOG_H

#ifndef HAVE_IPADDR_T
	typedef u_int32_t ipaddr_t;
#endif

#ifndef HAVE_IN_PORT_T
	typedef u_int16_t in_port_t;
#endif

#define __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/in.h>
#undef __FAVOR_BSD

#ifndef __SOLARIS_8__
#define  __IP_HDR_LENGTH(ip) (ip->ip_hl << 2)
#else
#include <inet/ip.h>
#define __IP_HDR_LENGTH IPH_HDR_LENGTH
#endif

#define FACILITY LOG_DAEMON
#define PRIORITY LOG_NOTICE

/*
** Path of the iplog configuration file.
*/

#define CONFFILE	"/etc/iplog.conf"

/*
** Making these smaller will probably do bad things.
*/
#define MAX_HSTLEN	256
#define MAX_SRVLEN	128
#define MAX_PRTLEN	32
#define MAX_IPLEN	16
#define MAX_PORT	0xffff
#define MIN_PORT	0

#ifdef DEBUG
#	define IDEBUG(x) do { mysyslog x; } while (0)
#else
#	define IDEBUG(x) do { } while (0)
#endif

#define xfree(x) do { free(x); (x) = NULL; } while (0)
#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))

#define DNS_HASH(x, y) ((((x) >> 24) + ((x) >> 16)) & ((y) - 1))
#define SCAN_HASH(x, y, z) (((x) ^ (y)) & ((z) - 1))

#define EXPIRE_INTERVAL 1

#ifndef HAVE___ATTRIBUTE__
#	define __attribute__(x)
#endif

#ifndef min
#	define min(x,y) ((x) < (y) ? (x) : (y))
#endif

typedef enum { false, true } bool;

#ifdef HAVE_PATHS_H
#	include <paths.h>
#endif

#ifndef _PATH_VARRUN
#	define LOCKFILE "/etc/iplog.pid"
#else
#	define LOCKFILE (_PATH_VARRUN "iplog.pid")
#endif

#if defined(__svr4__)
#	include <pthread.h>
#endif

#ifndef HAVE_DPRINTF
int dprintf(int fd, const char *fmt, ...);
#endif

#include <sys/time.h>

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *s);
char *xstrncpy(char *dest, const char *src, size_t n);
char *xstrncat(char *dest, const char *src, size_t n);
void xsleep(time_t seconds);
void xusleep(u_long usec);

void fork_to_back(void);
u_char *serv_lookup(in_port_t port, const u_char *proto, u_char *buf, size_t len);
u_char *proto_lookup(int proto, u_char *buf, size_t len);
void drop_privs(const u_char *user, const u_char *group);
void fatal(const u_char *fmt, ...);
int get_line(FILE *fp, u_char *buf, size_t len);
ssize_t sock_write(int sock, void *buf, size_t len);

void *__list_copy_append(const void *data, void **head_ptr, size_t len);
void *__list_append(void *data, void **head_ptr);
void *__list_copy_prepend(const void *data, void **head_ptr, size_t len);
void *__list_prepend(void *data, void **head_ptr);
void *__list_delete(void *node, void **head_ptr);

#define list_copy_append(x, y, z)	__list_copy_append((x), (void **) (y), (z))
#define list_append(x, y)			__list_append((x), (void **) (y))
#define list_copy_prepend(x, y, z)	__list_copy_prepend((x), (void **) (y), (z))
#define list_prepend(x, y)			__list_prepend((x), (void **) (y))
#define list_delete(x, y)			__list_delete((x), (void **) (y))

void *__dlist_copy_append(const void *data, void **head_ptr, size_t len);
void *__dlist_append(void *data, void **head_ptr);
void *__dlist_copy_prepend(const void *data, void **head_ptr, size_t len);
void *__dlist_prepend(void *data, void **head_ptr);
void *__dlist_delete(void *node, void **head_ptr);
void *__dlist_remove(void *data, void **head_ptr);

#define dlist_copy_append(x, y, z)	__dlist_copy_append((x), (void **) (y), (z))
#define dlist_append(x, y)			__dlist_append((x), (void **) (y))
#define dlist_copy_prepend(x, y, z)	__dlist_copy_prepend((x), (void **) (y), (z))
#define dlist_prepend(x, y)			__dlist_prepend((x), (void **) (y))
#define dlist_remove(x, y)			__dlist_remove((x), (void **) (y))
#define dlist_delete(x, y)			__dlist_delete((x), (void **) (y))

void list_destroy(void *list_head, void (*cleanup)(void *));

#define dlist_destroy	list_destroy

int in_cksum(u_short *addr, int len);

bool tcp_res(void);
bool udp_res(void);
bool icmp_res(void);
bool any_res(void);

void mysyslog(const char *fmt, ...);
void myopenlog(const char *name, int option);
void mycloselog(void);

void get_options(int argc, char * const argv[]);
void check_options(void);

void write_lockfile(const u_char *lockfile);
void kill_iplog(int sig, const u_char *lockfile);
bool get_raw_sock(void);
void expire_dns(void);

bool is_listening(in_port_t port);
void *get_ident_data(void *data);

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r(const time_t *cur_time, struct tm *result);
#endif

#include <iplog_inet_header.h>

int tcp_parser(const struct ip *ip);
int udp_parser(const struct ip *ip);
int icmp_parser(const struct ip *ip);

u_char *inet_ntoa_r(const struct in_addr *in, u_char *buf, size_t len);
u_char *host_lookup(const struct in_addr *in, bool resolv, u_char *buf, size_t len);
u_char *_host_lookup(const struct in_addr *in, u_char *buf, size_t len);

#if !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)
#	include <stdarg.h>
#endif

#ifndef HAVE_SNPRINTF
int snprintf(char *str, size_t n, char const *fmt, ...);
#endif

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *str, size_t n, char *fmt, va_list ap);
#endif

#endif /* __IPLOG_H */

/* vim:ts=4:sw=8:tw=0 */
