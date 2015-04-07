/*
** iplog_config.c - iplog configuration parser.
** Copyright (C) 2001 Ryan McCabe <odin@numb.org>
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
** $Id: iplog_config.c,v 1.26 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <iplog.h>
#include <arpa/inet.h>

#include <iplog_options.h>
#include <iplog_config.h>

static int get_icmp_type(const u_char *, struct port_range *);
static int get_addr(const u_char *, ipaddr_t *, ipaddr_t *, size_t);
static int get_addrrange(const u_char *, struct addr_entry *, ipaddr_t *, size_t);
static int get_port(const u_char *, int, const u_char *);
static int get_portrange(const u_char *, struct port_range *, u_int prot);

static bool port_match(const struct port_range *, in_port_t port);
static bool type_match(const struct port_range *, in_port_t port);
static bool addr_match(const struct addr_entry *, ipaddr_t addr);

static void enter_state(u_int new_state);
static void exit_state(void);

static const u_char *proto_list[] = { "tcp", "udp", "icmp" };
static u_char errbuf[512];
static struct filter_data *filters[3] = { NULL, NULL, NULL };

static u_int current_state = STATE_INITIAL;
static struct state_stack *state_stack = NULL;

/*
** Check whether the ICMP packet pointed to by "ip" matches any filters.
** Returns true if it matches, false if it doesn't.
*/

bool icmp_filter(u_int prot, const struct ip *ip, u_char type) {
	const struct filter_data *rule, *head = filters[prot];

	for (rule = head ; rule != NULL ; rule = rule->next) {
		if ((addr_match(&rule->src, ip->ip_src.s_addr) ^ rule->src.not) &&
			(addr_match(&rule->dst, ip->ip_dst.s_addr) ^ rule->dst.not) &&
			(type_match(&rule->dport, type) ^ rule->dport.not))

			return (false ^ rule->not);
	}

	return (false);
}

/*
** Check whether the packet pointed to by "ip" matches any filters.
** Returns true if it matches, false if it doesn't.
*/

bool tcp_filter(u_int p, const struct ip *ip, in_port_t sprt, in_port_t dprt) {
	const struct filter_data *rule, *head = filters[p];

	for (rule = head ; rule != NULL ; rule = rule->next) {
		if ((addr_match(&rule->src, ip->ip_src.s_addr) ^ rule->src.not) &&
			(addr_match(&rule->dst, ip->ip_dst.s_addr) ^ rule->dst.not) &&
			(port_match(&rule->dport, htons(dprt) ^ rule->dport.not)) &&
			(port_match(&rule->sport, htons(sprt) ^ rule->sport.not)))
		{
			return (false ^ rule->not);
		}
	}

	return (false);
}

/*
** Enter the state specified by "new_state."  Push the current state
** onto the state stack.
*/

static void enter_state(u_int new_state) {
	struct state_stack *ns = xmalloc(sizeof(struct state_stack));

	ns->state = current_state;
	ns->next = state_stack;
	state_stack = ns;

	current_state = new_state;
}

/*
** Exit the current state.  Pop the last state off the state stack.
*/

static void exit_state(void) {
	u_int new_state;
	struct state_stack *save;

#ifdef DEBUG
	if (state_stack == NULL)
		fatal("BUG: State stack is empty.");
#endif

	new_state = state_stack->state;
	save = state_stack;
	state_stack = state_stack->next;
	free(save);

	current_state = new_state;
}

/*
** Exit the current state, and enter the state specified by "x."
*/

#define xenter_state(x) \
	do {	\
		exit_state();	\
		enter_state((x)); \
	} while (0)

/*
** Checks whether the host in "test" matches "host."  Returns true if they
** match, false if they don't.
*/

static bool addr_match(const struct addr_entry *test, ipaddr_t host) {
	if (test->addr == 0 || host == 0 || test->addr == host)
		return (true);

	if (((host ^ test->addr) & test->mask) == 0)
		return (true);

	return (false);
}

/*
** Checks whether the ICMP types match.  Returns true if they match,
** false if they don't.
*/

static bool type_match(const struct port_range *test, in_port_t port) {
	if (test->min == TYPE_MATCH_ALL || test->min == port)
		return (true);

	return (false);
}

/*
** Checks whether "port" matches the specified port range.  Returns true
** if it matches, false if it doesn't.
*/

static bool port_match(const struct port_range *test, in_port_t port) {
	if (test->max == 0 && test->min == 0)
		return (true);

	if (test->max == test->min)
		return (test->max == port);

	if (!test->max)
		return (test->min <= port);
	else if (!test->min)
		return (test->max >= port);
	else
		return ((test->max >= port) && (test->min <= port));

	return (false);
}

/*
** Finds all the IP addresses for "hostname."  Writes the first IP address to
** "addr" and the others to "list."  On success, returns the number of IP
** addresses found, excluding the primary IP.  On failure, it returns -1.
*/

static int get_addr(const u_char *hostname, ipaddr_t *addr,
					ipaddr_t *list, size_t siz)
{
#ifdef HAVE_INET_ATON
	struct in_addr in;
#endif
	struct hostent *host;

	if (isdigit(hostname[strlen(hostname) - 1])) {
		u_char *p = (typeof(p)) hostname, i;

		for (i = 0 ; *p != '\0' ; p++) {
			if (*p == '.')
				++i;
		}

		if (i != 3) {
			u_char short_host[MAX_IPLEN];

			xstrncpy(short_host, hostname, sizeof(short_host));
			switch (i) {
				case 0:
					xstrncat(short_host, ".0", sizeof(short_host));
				case 1:
					xstrncat(short_host, ".0", sizeof(short_host));
				case 2:
					xstrncat(short_host, ".0", sizeof(short_host));
			}

#ifdef HAVE_INET_ATON
			inet_aton(short_host, &in);
			*addr = in.s_addr;
#else
			*addr = inet_addr(short_host);
#endif
			return (0);
		}
	}

	host = gethostbyname(hostname);
	if (host != NULL) {
		u_char **p;

		*addr = *((ipaddr_t *) host->h_addr);
		p = (typeof(p)) host->h_addr_list;

		if (list != NULL && *(p + 1) != NULL) {
			size_t i;

			for (i = 0 ; i < siz && *p != NULL ; p++, i++)
				list[i] = *(ipaddr_t *) *p;

			return (i);
		}

		return (0);
	} else {
#ifdef HAVE_INET_ATON
		if (inet_aton(hostname, &in) != 0)
			*addr = in.s_addr;
#else
		*addr = inet_addr(hostname);
#endif
		return (0);
	}

	return (-1);
}

/*
** Converts the string "str" to an ICMP code.  Returns the ICMP code on success.
** Returns -1 on failure.
*/

static int get_icmp_type(const u_char *str, struct port_range *dst) {
	char *nptr;
	int type;

	if (*str == '!') {
		dst->not = true;
		++str;
	}

	type = strtol(str, &nptr, 10);

	if (*nptr == '\0') {
		if (type < 0 || type > 18)
			return (-1);

		dst->min = type;
		return (0);
	}

	if (!strncasecmp(str, "ICMP_", 5))
		str += 5;

	if (!strncasecmp(str, "ECHOREPLY", 5))
		dst->min = ICMP_ECHO_REPLY;
	else if (!strncasecmp(str, "ECHO", 2))
		dst->min = ICMP_ECHO;
	else if (!strncasecmp(str, "UNREACH", 4))
		dst->min = ICMP_DEST_UNREACHABLE;
	else if (!strncasecmp(str, "REDIRECT", 3))
		dst->min = ICMP_REDIRECT;
	else if (!strncasecmp(str, "ROUTERADVERT", 9))
		dst->min = ICMP_ROUTER_ADVERT;
	else if (!strncasecmp(str, "ROUTERSOLICIT", 9))
		dst->min = ICMP_ROUTER_SOLICIT;
	else if (!strncasecmp(str, "TIMXCEED", 5))
		dst->min = ICMP_TIME_EXCEEDED;
	else if (!strncasecmp(str, "TIMESTAMP_REPLY", 10))
		dst->min = ICMP_TIMESTAMP_REPLY;
	else if (!strncasecmp(str, "TSTAMP", 6))
		dst->min = ICMP_TIMESTAMP;
	else if (!strncasecmp(str, "IREQREPLY", 5))
		dst->min = ICMP_INFO_REPLY;
	else if (!strncasecmp(str, "IREQ", 2))
		dst->min = ICMP_INFO_REQUEST;
	else if (!strncasecmp(str, "MASKREPLY", 5))
		dst->min = ICMP_ADDRESS_REPLY;
	else if (!strncasecmp(str, "MASKREQ", 2))
		dst->min = ICMP_ADDRESS;
	else if (!strncasecmp(str, "PARAMPROB", 4))
		dst->min = ICMP_PARAMETER_PROBLEM;
	else if (!strncasecmp(str, "SOURCEQUENCH", 3))
		dst->min = ICMP_SOURCE_QUENCH;
	else {
		snprintf(errbuf, sizeof(errbuf), "Unknown ICMP type: %s", str);
		return (-1);
	}

	return (0);
}

/*
** Extracts a port from string "s."  Returns the port number on success
** and -1 on failure.
*/

static int get_port(const u_char *s, int wildcard, const u_char *proto) {
	int port;

	if (!strcasecmp(s, EVERYTHING))
		port = wildcard;
	else {
		char *nptr;

		port = strtol(s, &nptr, 10);
		if (*nptr != '\0') {
			struct servent *se = getservbyname(s, proto);

			if (se == NULL) {
				snprintf(errbuf, sizeof(errbuf), "Invalid port: \"%s\"", s);
				return (-1);
			}

			port = htons(se->s_port);
		}
	}

	return (port);
}

/*
** Extracts an address range from the string "str."  Returns the number
** of IP addresses found on success and -1 on failure.
*/

static int get_addrrange(const u_char *str,
						struct addr_entry *addr,
						ipaddr_t *list,
						size_t siz)
{
	u_char *p, *q;
	int i = 0;

	if (*str == '!') {
		addr->not = true;
		++str;
	}

	p = strchr(str, '/');
	if (p != NULL) {
		*p++ = '\0';
		for (q = p ; *q != '\0' ; q++) {
			if (!isdigit(*q)) {
				i = 1;
				break;
			}
		}

		if (i == 1) {
			if (get_addr(p, &addr->mask, NULL, 0) == -1) {
				snprintf(errbuf, sizeof(errbuf), "Invalid mask: %s", str);
				return (-1);
			}
		} else {
			if (!strcasecmp(p, EVERYTHING))
				addr->mask = MASK_MATCH_ALL;
			else {
				char *nptr;

				i = strtoul(p, &nptr, 10);
				if (*nptr == '\0') {
					if (i >= 1 && i <= 32) {
						addr->mask = htonl(~((1 << (32 - i)) - 1));
					} else {
						snprintf(errbuf, sizeof(errbuf),
							"Invalid mask: must be in range 1 - 32");
						return (-1);
					}
				} else {
					snprintf(errbuf, sizeof(errbuf), "Invalid mask: %s", str);
					return (-1);
				}
			}
		}
	} else
		addr->mask = MASK_MATCH_ONE;

	if (!strcasecmp(str, EVERYTHING))
		addr->addr = 0;
	else {
		i = get_addr(str, &addr->addr, list, siz);
		if (i == -1)
			snprintf(errbuf, sizeof(errbuf), "Unknown host: %s", str);

		return (i);
	}

	return (0);
}

/*
** Extracts a port range from the string "str."  Returns 0 on success and
** -1 on failure.
*/

static int get_portrange(const u_char *str, struct port_range *port, u_int prot)
{
	const u_char *proto = proto_list[prot];
	u_char *p;
	int min_p, max_p;

	if (*str == '!') {
		port->not = true;
		++str;
	} else
		port->not = false;

	p = strchr(str, ':');
	if (p != NULL)
		*p++ = '\0';

	min_p = get_port(str, MIN_PORT, proto);

	if (min_p == -1)
		return (-1);

	if (p != NULL) {
		/* Allow for stuff like 6000: */
		if (*p == '\0')
			max_p = MAX_PORT;
		else {
			max_p = get_port(p, MAX_PORT, proto);
			if (max_p == -1)
				return (-1);
		}
	} else
		max_p = min_p;

	if ((min_p & MAX_PORT) != min_p ||
		(max_p & MAX_PORT) != max_p)
	{
		snprintf(errbuf, sizeof(errbuf),
			"Error: Ports must be between 1 and 65535");
		return (-1);
	}

	if (min_p > max_p) {
		snprintf(errbuf, sizeof(errbuf),
			"Error: Minimum port (%d) is greater than the maximum port (%d)",
			min_p, max_p);
		return (-1);
	}

	port->min = min_p;
	port->max = max_p;

	return (0);
}

/*
** Read in the configuration file, parse rules.  "filename" specifies the
** path of the config file.
**
** Who needs lex/yacc?
*/

void parse_config(const u_char *filename) {
	FILE *fp;
	u_char buf[8192], *token;
	u_int prot = 0, line_number = 0;
	struct filter_data *frule = NULL;
	extern u_char *user, *group, *ifstring, *logfile, *lockfile, *pcap_network;
	extern int facility, priority;
	ipaddr_t dadr[32], sadr[32];
	/* Avoid spurious gcc warnings.. */
	struct port_range *prange = NULL;
	struct addr_entry *adrent = NULL;
	ssize_t dcnt = 0, scnt = 0, res;
	bool src_set = 0, dst_set = 0, sport_set = 0, dport_set = 0, itype_set = 0;
	u_int32_t temp_flags = 0;

	fp = fopen(filename, "r");

	/*
	** Don't yell if the file doesn't exist.
	*/
	if (fp == NULL) {
		if (errno != ENOENT)
			 mysyslog("Unable to open %s: %s\n", filename, strerror(errno));
		return;
	}

	top:
	while (get_line(fp, buf, sizeof(buf) - 1) != EOF) {
		++line_number;

		if (current_state != STATE_COMMENT) {
			src_set = dst_set = sport_set = dport_set = itype_set = false;
			dcnt = scnt = res = 0;
			temp_flags = 0;

#ifdef DEBUG
			if (current_state != STATE_INITIAL) {
				fatal("BUG: [line %u] State should be 0 (is %u)",
					line_number, current_state);
			}
#endif
		}

		token = strtok(buf, " \t\n");
		if (token == NULL) {
			if (current_state != STATE_INITIAL &&
				current_state != STATE_COMMENT)
			{
				mysyslog("[line %u] Premature EOL", line_number);
			}
			continue;
		}

		do {
		top2:
			if (!strncmp(token, "/*", 2)) {
				enter_state(STATE_COMMENT);
				token += 2;
			} else if (current_state != STATE_COMMENT && *token == '#') {
				if (current_state != STATE_INITIAL)
					goto got_eol;

				if (frule != NULL)
					xfree(frule);

				goto top;
			}

			switch (current_state) {
				case STATE_INITIAL:
					if (!strcasecmp(token, "set"))
						enter_state(STATE_SET);
					else if (!strcasecmp(token, "log")) {
						frule = xmalloc(sizeof(struct filter_data));
						frule->not = false;
						enter_state(STATE_FILTER_PROT);
					} else if (!strcasecmp(token, "ignore")) {
						frule = xmalloc(sizeof(struct filter_data));
						frule->not = true;
						enter_state(STATE_FILTER_PROT);
					} else if (!strncasecmp(token, "interface", 9))
						enter_state(STATE_INTERFACE);
					else if (!strcasecmp(token, "logfile"))
						enter_state(STATE_LOGFILE);
					else if (!strcasecmp(token, "pid-file"))
						enter_state(STATE_LOCKFILE);
					else if (!strcasecmp(token, "user"))
						enter_state(STATE_USER);
					else if (!strcasecmp(token, "group"))
						enter_state(STATE_GROUP);
					else if (!strcasecmp(token, "facility"))
						enter_state(STATE_FACILITY);
					else if (!strcasecmp(token, "priority"))
						enter_state(STATE_PRIORITY);
					else if (!strcasecmp(token, "promisc"))
						enter_state(STATE_PROMISC);
					else {
						mysyslog("[line %d] Invalid rule: %s",
							line_number, token);
						goto top;
					}

					if (current_state == STATE_FILTER_PROT) {
						frule->sport.min = MIN_PORT;
						frule->sport.max = MAX_PORT;
						frule->sport.not = false;
						frule->dport.min = MIN_PORT;
						frule->dport.max = MAX_PORT;
						frule->dport.not = false;
						frule->src.addr = ADDR_MATCH_ALL;
						frule->src.mask = MASK_MATCH_ONE;
						frule->src.not = false;
						frule->dst.addr = ADDR_MATCH_ALL;
						frule->dst.mask = MASK_MATCH_ONE;
  						frule->dst.not = false;
					}
					break;

				case STATE_USER:
					if (user != NULL)
						free(user);
					user = xstrdup(token);
					exit_state();
					break;

				case STATE_GROUP:
					if (group != NULL)
						free(group);
					group = xstrdup(token);
					exit_state();
					break;

				case STATE_LOGFILE:
					if (logfile != NULL)
						free(logfile);
					logfile = xstrdup(token);
					exit_state();
					break;

				case STATE_LOCKFILE:
					if (lockfile != NULL)
						free(lockfile);
					lockfile = xstrdup(token);
					exit_state();
					break;

				case STATE_FACILITY:
					facility = get_facility(token);
					exit_state();
					break;

				case STATE_PRIORITY:
					priority = get_priority(token);
					exit_state();
					break;

				case STATE_INTERFACE:
					if (ifstring != NULL)
						free(ifstring);
					ifstring = xstrdup(token);
					exit_state();
					break;

				case STATE_PROMISC:
					flags |= (PROMISC | LOG_DEST);
					if (pcap_network != NULL)
						free(pcap_network);
					pcap_network = xstrdup(token);
					exit_state();
					break;

				case STATE_SET:
					if (!strcasecmp(token, "tcp"))
						temp_flags |= LOG_TCP;
					else if (!strcasecmp(token, "udp"))
						temp_flags |= LOG_UDP;
					else if (!strcasecmp(token, "icmp"))
						temp_flags |= LOG_ICMP;
					else if (!strcasecmp(token, "frag"))
						temp_flags |= LOG_FRAG;
					else if (!strcasecmp(token, "smurf"))
						temp_flags |= SMURF;
					else if (!strcasecmp(token, "bogus"))
						temp_flags |= BOGUS;
					else if (!strcasecmp(token, "log_ip"))
						temp_flags |= LOG_IP;
					else if (!strcasecmp(token, "log_dest"))
						temp_flags |= LOG_DEST;
					else if (!strcasecmp(token, "stdout"))
						temp_flags |= LOG_STDOUT;
					else if (!strcasecmp(token, "no_fork"))
						temp_flags |= NO_FORK;
					else if (!strcasecmp(token, "verbose"))
						temp_flags |= VERBOSE;
					else if (!strcasecmp(token, "fin_scan"))
						temp_flags |= FIN_SCAN;
					else if (!strcasecmp(token, "syn_scan"))
						temp_flags |= SYN_SCAN;
					else if (!strcasecmp(token, "udp_scan"))
						temp_flags |= UDP_SCAN;
					else if (!strcasecmp(token, "portscan"))
						temp_flags |= PORTSCAN;
					else if (!strcasecmp(token, "fool_nmap"))
						temp_flags |= FOOL_NMAP;
					else if (!strcasecmp(token, "xmas_scan"))
						temp_flags |= XMAS_SCAN;
					else if (!strcasecmp(token, "null_scan"))
						temp_flags |= NULL_SCAN;
					else if (!strcasecmp(token, "get_ident"))
						temp_flags |= GET_IDENT;
					else if (!strcasecmp(token, "dns_cache"))
						temp_flags |= DNS_CACHE;
					else if (!strcasecmp(token, "syn_flood"))
						temp_flags |= SYN_FLOOD;
					else if (!strcasecmp(token, "ignore_dns"))
						temp_flags |= IGNORE_NS;
					else if (!strcasecmp(token, "ping_flood"))
						temp_flags |= PING_FLOOD;
					else if (!strcasecmp(token, "scans_only"))
						temp_flags |= SCANS_ONLY;
					else if (!strcasecmp(token, "traceroute"))
						temp_flags |= TRACEROUTE;
					else if (!strcasecmp(token, "udp_resolve"))
						temp_flags |= UDP_RES;
					else if (!strcasecmp(token, "tcp_resolve"))
						temp_flags |= TCP_RES;
					else if (!strcasecmp(token, "icmp_resolve"))
						temp_flags |= ICMP_RES;
					else if (!strcasecmp(token, "disable_resolver"))
						temp_flags |= NO_RESOLV;
					else {
						mysyslog("[line %d] Invalid \"set\" target: %s",
							line_number, token);
					}
					xenter_state(STATE_NEED_BOOL);
					break;

				case STATE_NEED_BOOL:
					if (!strcasecmp(token, "true"))
						flags |= temp_flags;
					else if (!strcasecmp(token, "false"))
						flags &= ~temp_flags;
					else {
						mysyslog("[line %u] Invalid boolean token: %s",
							line_number, token);
					}
					exit_state();
					break;

				case STATE_FILTER_PROT:
					if (!strcasecmp(token, "tcp"))
						prot = FIL_TCP;
					else if (!strcasecmp(token, "udp"))
						prot = FIL_UDP;
					else if (!strcasecmp(token, "icmp")) {
						prot = FIL_ICMP;
						frule->dport.min = TYPE_MATCH_ALL;
					} else {
						mysyslog("[line %u] Invalid protocol: %s",
							line_number, token);
						xfree(frule);
						exit_state();
						goto top;
					}
					xenter_state(STATE_FILTER);
					break;

				case STATE_FILTER:
					if (!strcasecmp(token, "from")) {
						if (src_set != false) {
							mysyslog("[line %u] \"from\" already set.",
								line_number);
							xfree(frule);
							exit_state();
							goto top;
						}
						++src_set;
						adrent = &frule->src;
						enter_state(STATE_NEED_ARANGE);
					} else if (!strcasecmp(token, "to")) {
						if (dst_set != false) {
							mysyslog("[line %u] \"to\" already set.",
								line_number);
							xfree(frule);
							exit_state();
							goto top;
						}
						++dst_set;
						adrent = &frule->dst;
						enter_state(STATE_NEED_ARANGE);
					} else if (prot == FIL_TCP || prot == FIL_UDP) {
						if (!strcasecmp(token, "sport")) {
							if (sport_set != false) {
								mysyslog("[line %u] \"sport\" already set.",
									line_number);
								xfree(frule);
								exit_state();
								goto top;
							}
							++sport_set;
							prange = &frule->sport;
							enter_state(STATE_NEED_PRANGE);
						} else if (!strcasecmp(token, "dport")) {
							if (dport_set != false) {
								mysyslog("[line %u] \"dport\" already set.",
									line_number);
								xfree(frule);
								exit_state();
								goto top;
							}
							++dport_set;
							prange = &frule->dport;
							enter_state(STATE_NEED_PRANGE);
						} else {
							mysyslog("[line %u] Invalid filter keyword: %s",
								line_number, token);
							xfree(frule);
							exit_state();
							goto top;
						}
					} else if (prot == FIL_ICMP) {
						if (!strcasecmp(token, "type")) {
							if (itype_set != false) {
								mysyslog("[line %u] \"type\" already set.",
									line_number);
								xfree(frule);
								exit_state();
								goto top;
							}
							++itype_set;
							enter_state(STATE_NEED_ITYPE);
						} else {
							mysyslog("[line %u] Invalid filter keyword: %s",
								line_number, token);
							xfree(frule);
							exit_state();
							goto top;
						}
					} else {
						mysyslog("[line %u] Invalid filter keyword: %s",
							line_number, token);
						xfree(frule);
						exit_state();
						goto top;
					}
					/* Only EOL (or an error) takes us out of this state. */
					break;

				case STATE_NEED_ARANGE:
					if (adrent == &frule->src) {
						scnt = get_addrrange(token, adrent, sadr, sizeof(sadr));
						res = scnt;
					} else {
						dcnt = get_addrrange(token, adrent, dadr, sizeof(dadr));
						res = dcnt;
					}
					exit_state();

					if (res == -1) {
						mysyslog("[line %u] %s", line_number, errbuf);
						xfree(frule);
						exit_state();
						goto top;
					}
					break;

				case STATE_NEED_PRANGE:
					res = get_portrange(token, prange, prot);
					exit_state();

					if (res == -1) {
						mysyslog("[line %u] %s", line_number, errbuf);
						xfree(frule);
						exit_state();
						goto top;
					}
					break;

				case STATE_NEED_ITYPE:
					res = get_icmp_type(token, &frule->dport);
					exit_state();

					if (res == -1) {
						mysyslog("[line %u] %s", line_number, errbuf);
						xfree(frule);
						exit_state();
						goto top;
					}
					break;

				case STATE_COMMENT:
				{
					u_char *ret;

					ret = strstr(token, "*/");
					if (ret != NULL) {
						exit_state();
						token = ret + 2;
						while (*token == ' ' || *token == '\t')
							++token;
						if (*token != '\0')
							goto top2;
					}

					break;
				}
			}

			token = strtok(NULL, " \t\n");
			if (token == NULL) {
				u_char *errstr = NULL;

				got_eol:
				/* We've reached EOL. */
				switch (current_state) {
					case STATE_INITIAL:
					case STATE_COMMENT:
						break;

					case STATE_NEED_BOOL:
						/* True is implicit if no argument is provided. */
						flags |= temp_flags;
						exit_state();
						break;

					case STATE_FILTER:
						if (dport_set == false && sport_set == false &&
							dst_set == false && src_set == false &&
							itype_set == false)
						{
							switch (prot) {
								case FIL_TCP:
									temp_flags = LOG_TCP;
									break;
								case FIL_UDP:
									temp_flags = LOG_UDP;
									break;
								case FIL_ICMP:
									temp_flags = LOG_ICMP;
									break;
							}

							if (frule->not == true)
								flags &= ~temp_flags;
							else
								flags |= temp_flags;

							xfree(frule);
							exit_state();
							break;
						}

						if (scnt == 0 && dcnt == 0) {
							if (frule->not == false)
								list_prepend(frule, &filters[prot]);
							else
								list_append(frule, &filters[prot]);
							frule = NULL;
						} else {
							/* Don't even ask about the variable names.. */
							size_t bd, sd, id, j;
							ipaddr_t *bp, *sp, *bl, *sl;

							if (scnt > dcnt) {
								bd = scnt;
 								sd = dcnt;
								bp = &frule->src.addr;
								sp = &frule->dst.addr;
								bl = sadr;
								sl = dadr;
							} else {
								bd = dcnt;
								sd = scnt;
								bp = &frule->dst.addr;
								sp = &frule->src.addr;
								bl = dadr;
								sl = sadr;
							}

							for (id = 0 ; id < bd ; id++) {
								*bp = bl[id];
								for (j = 0 ; j < sd ; j++) {
									*sp = sl[j];
									if (frule->not == false) {
										list_copy_prepend(frule, &filters[prot],
											sizeof(struct filter_data));
									} else {
										list_copy_append(frule, &filters[prot],
											sizeof(struct filter_data));
									}
								}

								if (sd == 0) {
									if (frule->not == false) {
										list_copy_prepend(frule, &filters[prot],
											sizeof(struct filter_data));
									} else {
										list_copy_append(frule, &filters[prot],
											sizeof(struct filter_data));
									}
								}
							}

							xfree(frule);
						}

						exit_state();
						break;

					/*
					** Being in any of the following states is an indication
					** that something went wrong.
					*/

					case STATE_USER:
						errstr = "user parameter";
						break;
					case STATE_GROUP:
						errstr = "group parameter";
						break;
					case STATE_LOGFILE:
						errstr = "log file parameter";
						break;
					case STATE_PRIORITY:
						errstr = "syslog priority parameter";
						break;
					case STATE_FACILITY:
						errstr = "syslog facility parameter";
						break;
					case STATE_INTERFACE:
						errstr = "interface parameter";
						break;
					case STATE_PROMISC:
						errstr = "network parameter";
						break;
					case STATE_SET:
						errstr = "set target";
						break;
					case STATE_FILTER_PROT:
						errstr = "protocol parameter";
						break;
					case STATE_NEED_ITYPE:
						errstr = "ICMP type";
						exit_state();
						break;
					case STATE_NEED_ARANGE:
						errstr = "address parameter";
						exit_state();
						break;
					case STATE_NEED_PRANGE:
						errstr = "port parameter";
						exit_state();
						break;
				}

				if (errstr != NULL) {
					if (frule != NULL)
						xfree(frule);
					exit_state();
					mysyslog("[line %u] Missing %s", line_number, errstr);
				}

				/* Proceed to the next line. */
				break;
			}

			/* Proceed to the next token. */
		} while (1);
	}

	if (current_state != STATE_INITIAL) {
		if (current_state == STATE_COMMENT)
			mysyslog("%s: Parse Error: Unterminated comment.", filename);
		else {
#ifdef DEBUG
			fatal("BUG: [line %u] State should be 0 (is %u)",
				line_number, current_state);
#endif
		}
	}

	list_destroy(state_stack, NULL);
	fclose(fp);
}

/*
** Add filter rules to ignore DNS traffic from all the hosts listed as
** name servers in /etc/resolv.conf.
*/

int add_dns_ignore_rules(void) {
	struct filter_data fil_data;
	u_char buf[1024], *p;
	FILE *fp;
	ipaddr_t list[32];
	ssize_t num_addr;

	fp = fopen(NS_FILE, "r");
	if (fp == NULL)
		return (-1);

	fil_data.sport.min = 53;
	fil_data.sport.max = 53;
	fil_data.sport.not = false;
	fil_data.dport.min = MIN_PORT;
	fil_data.dport.max = MAX_PORT;
	fil_data.dport.not = false;
	fil_data.src.mask = MASK_MATCH_ONE;
	fil_data.src.not = false;
	fil_data.dst.addr = ADDR_MATCH_ALL;
	fil_data.dst.mask = MASK_MATCH_ONE;
	fil_data.dst.not = false;
	fil_data.not = true;

	while (get_line(fp, buf, sizeof(buf) - 1) != EOF) {
		p = strtok(buf, " \t");
		if (p == NULL)
			continue;

		if (strcmp(p, "nameserver"))
			continue;

		p = strtok(NULL, " \t");
		if (p == NULL)
			continue;

		num_addr = get_addr(p, &fil_data.src.addr, list, sizeof(list));
		if (num_addr == -1)
			continue;

		list_copy_prepend(&fil_data, &filters[FIL_UDP], sizeof(fil_data));
		if (num_addr > 0) {
			ssize_t i;

			for (i = 0 ; i < num_addr ; i++) {
				fil_data.src.addr = list[i];
				list_copy_prepend(&fil_data, &filters[FIL_UDP], sizeof(fil_data));
			}
		}
	}

	fclose(fp);
	return (0);
}

#ifdef HAVE_PTHREAD_CANCEL

/*
** Destroy the filter rules list for the protocol specified by "prot."
*/

void destroy_filter_list(u_int prot) {
	list_destroy(filters[prot], NULL);
	filters[prot] = NULL;
}
#endif

/* vim:ts=4:sw=8:tw=0 */
