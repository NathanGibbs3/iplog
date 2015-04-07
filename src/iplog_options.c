/*
** iplog_options.c - iplog command line argument handler.
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
** $Id: iplog_options.c,v 1.33 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>

#ifndef HAVE_GETOPT_LONG
#	include <gnu/getopt.h>
#else
#	include <getopt.h>
#endif

#include <iplog.h>
#include <iplog_options.h>
#include <iplog_config.h>

#define IS_DEFAULT(x) (opt_enabled((x)) ? '*' : ' ')

u_int32_t flags = ~0 &	~(	GET_IDENT | NO_RESOLV | FOOL_NMAP | NO_FORK |
							VERBOSE | LOG_STDOUT | IGNORE_NS | LOG_IP |
							PROMISC | LOG_DEST | SCANS_ONLY);

extern int facility;
extern int priority;
extern u_char *pcap_network;

static void enable(const u_char *arg, u_int32_t flag);
static void print_help(void);

/*
** Available: A,B,C,E,G,H,J,K,M,O,Q,W,X,Y,Z,j,r
*/

static const char opts[] = "DFILNPRSTUVa:bcdefg:hi:kl:mnopstu:vwxyz";

static const struct option longopts[] = {
	{"tcp",					optional_argument,	0, 10},
	{"udp",					optional_argument,	0, 11},
	{"icmp",				optional_argument,	0, 12},
	{"facility",			required_argument,	0, 13},
	{"priority",			required_argument,	0, 14},
	{"pid-file",			required_argument,	0, 15},
	{"kill",				no_argument,		0, 'k'},
	{"user",				required_argument,	0, 'u'},
	{"group",				required_argument,	0, 'g'},
	{"ignore",				no_argument,		0, 'd'},
	{"restart",				no_argument,		0, 'R'},
	{"no-fork",				no_argument,		0, 'o'},
	{"stdout",				no_argument,		0, 'L'},
	{"promisc",				required_argument,	0, 'a'},
	{"logfile",				required_argument,	0, 'l'},
	{"verbose",				optional_argument,	0, 'V'},
	{"log-ip",				optional_argument,	0, 'w'},
	{"log-dest",			optional_argument,	0, 'D'},
	{"fool-nmap",			optional_argument,	0, 'z'},
	{"dns-cache",			optional_argument,	0, 'c'},
	{"interface",			required_argument,	0, 'i'},
	{"get-ident",			optional_argument,	0, 'e'},
	{"scans-only",			optional_argument,	0, 'm'},
	{"tcp-resolve",			optional_argument,	0, 'T'},
	{"udp-resolve",			optional_argument,	0, 'U'},
	{"icmp-resolve",		optional_argument,	0, 'I'},
	{"disable-resolver",	no_argument,		0, 'N'},
	{"detect-syn-flood",	optional_argument,	0, 's'},
	{"detect-frag",			optional_argument,	0, 'y'},
	{"detect-smurf",		optional_argument,	0, 'S'},
	{"detect-bogus",		optional_argument,	0, 'b'},
	{"detect-portscan",		optional_argument,	0, 'p'},
	{"detect-udp-scan",		optional_argument,	0, 'F'},
	{"detect-ping-flood",	optional_argument,	0, 'P'},
	{"detect-fin-scan",		optional_argument,	0, 'f'},
	{"detect-syn-scan",		optional_argument,	0, 'q'},
	{"detect-xmas-scan",	optional_argument,	0, 'x'},
	{"detect-null-scan",	optional_argument,	0, 'n'},
	{"detect-traceroute",	optional_argument,	0, 't'},
	{"log-frag",			optional_argument,	0, 'y'},
	{"log-smurf",			optional_argument,	0, 'S'},
	{"log-bogus",			optional_argument,	0, 'b'},
	{"log-portscan",		optional_argument,	0, 'p'},
	{"log-udp-scan",		optional_argument,	0, 'F'},
	{"log-ping-flood",		optional_argument,	0, 'P'},
	{"log-fin-scan",		optional_argument,	0, 'f'},
	{"log-syn-scan",		optional_argument,	0, 'q'},
	{"log-xmas-scan",		optional_argument,	0, 'x'},
	{"log-null-scan",		optional_argument,	0, 'n'},
	{"log-traceroute",		optional_argument,	0, 't'},
	{"version",				no_argument,		0, 'v'},
	{"help",				no_argument,		0, 'h'},
	{NULL, 0, NULL, 0}
};

/*
** Parses command-line flags.
*/

void get_options(int argc, char *const argv[]) {
	extern u_char *logfile, *lockfile, *user, *group, *ifstring;
	int opt;

	while ((opt = getopt_long(argc, argv, opts, longopts, NULL)) != EOF) {
		switch (opt) {
			case 10:
				enable(optarg, LOG_TCP);
				break;
			case 11:
				enable(optarg, LOG_UDP);
				break;
			case 12:
				enable(optarg, LOG_ICMP);
				break;
			case 13:
				facility = get_facility(optarg);
				break;
			case 14:
				priority = get_priority(optarg);
				break;
			case 15:
				if (lockfile != NULL)
					free(lockfile);
				lockfile = xstrdup(optarg);
				break;
			case 'w':
				enable(optarg, LOG_IP);
				break;
			case 'd':
				flags |= IGNORE_NS;
				break;
			case 'u':
				if (user != NULL)
					free(user);
				user = xstrdup(optarg);
				break;
			case 'g':
				if (group != NULL)
					free(group);
				group = xstrdup(optarg);
				break;
			case 'k':
				kill_iplog(15, lockfile);
				break;
			case 'l':
				if (opt_enabled(LOG_STDOUT)) {
					mysyslog("Warning: Overriding --stdout");
					flags &= ~LOG_STDOUT;
				} else if (logfile != NULL)
					free(logfile);
				logfile = xstrdup(optarg);
				break;
			case 'L':
				if (logfile != NULL) {
					mysyslog("Warning: Overriding --logfile");
					xfree(logfile);
				}
				flags |= LOG_STDOUT;
				break;
			case 'm':
				enable(optarg, SCANS_ONLY);
				break;
			case 'o':
				flags |= NO_FORK;
				break;
			case 'c':
				enable(optarg, DNS_CACHE);
				break;
			case 'y':
				enable(optarg, LOG_FRAG);
				break;
			case 'a':
				flags |= (PROMISC | LOG_DEST);
				if (pcap_network != NULL)
					free(pcap_network);
				pcap_network = xstrdup(optarg);
				break;
			case 'D':
				enable(optarg, LOG_DEST);
				break;
			case 'e':
#ifdef __linux__
				enable(optarg, GET_IDENT);
#else
				mysyslog("Ident lookups are only supported on Linux.");
#endif
				break;
			case 'T':
				enable(optarg, TCP_RES);
				break;
			case 'U':
				enable(optarg, UDP_RES);
				break;
			case 'V':
				enable(optarg, VERBOSE);
				break;
			case 'I':
				enable(optarg, ICMP_RES);
				break;
			case 'S':
				enable(optarg, SMURF);
				break;
			case 'b':
				enable(optarg, BOGUS);
				break;
			case 'P':
				enable(optarg, PING_FLOOD);
				break;
			case 'p':
				enable(optarg, PORTSCAN);
				break;
			case 'x':
				enable(optarg, XMAS_SCAN);
				break;
			case 'f':
				enable(optarg, FIN_SCAN);
				break;
			case 'q':
				enable(optarg, SYN_SCAN);
				break;
			case 'F':
				enable(optarg, UDP_SCAN);
				break;
			case 'N':
				flags |= NO_RESOLV;
				break;
			case 'n':
				enable(optarg, NULL_SCAN);
				break;
			case 's':
				enable(optarg, SYN_FLOOD);
				break;
			case 't':
				enable(optarg, TRACEROUTE);
				break;
			case 'i':
				if (ifstring != NULL)
					free(ifstring);
				ifstring = xstrdup(optarg);
				break;
			case 'R':
				kill_iplog(1, lockfile);
				break;
			case 'z':
				enable(optarg, FOOL_NMAP);
				break;
			case 'v':
				mysyslog("iplog version %s\nby %s\n%s",
					VERSION, AUTHORS, WEBPAGE);
				exit(0);
			case 'h':
			default:
				print_help();
				break;
		}
	}
}

/*
** Checks whether a flag should be enabled or not.
*/

static void enable(const u_char *arg, u_int32_t flag) {
	if (arg == NULL || !strcasecmp(arg, "yes") || !strcasecmp(arg, "true"))
		flags |= flag;
	else if (!strcasecmp(arg, "no") || !strcasecmp(arg, "false"))
		flags &= ~flag;
	else if (!strcasecmp(arg, "toggle"))
		flags ^= flag;
	else {
		fatal("Arguments must be either \"yes\", \"true\", \"no\", "
			"\"false\" or \"toggle\".\nYou gave \"%s\"", optarg);
	}
}

/*
** Converts the string "new_facility" to a syslog(3) facility.  Returns
** the new facility on success and the default facility on failure.
*/

int get_facility(const u_char *new_facility) {
	int fac = FACILITY;

	if (!strncasecmp(new_facility, "log_", 4))
		new_facility += 4;

	if (!strcasecmp(new_facility, "auth"))
		fac = LOG_AUTH;
#ifdef LOG_AUTHPRIV
	else if (!strcasecmp(new_facility, "authpriv"))
		fac = LOG_AUTHPRIV;
#endif
	else if (!strcasecmp(new_facility, "cron"))
		fac = LOG_CRON;
	else if (!strcasecmp(new_facility, "daemon"))
		fac = LOG_DAEMON;
#ifdef LOG_FTP
	else if (!strcasecmp(new_facility, "ftp"))
		fac = LOG_FTP;
#endif
	else if (!strcasecmp(new_facility, "kern"))
		fac = LOG_KERN;
	else if (!strcasecmp(new_facility, "lpr"))
		fac = LOG_LPR;
	else if (!strcasecmp(new_facility, "mail"))
		fac = LOG_MAIL;
	else if (!strcasecmp(new_facility, "news"))
		fac = LOG_NEWS;
	else if (!strcasecmp(new_facility, "security"))
		fac = LOG_AUTH;
	else if (!strcasecmp(new_facility, "syslog"))
		fac = LOG_SYSLOG;
	else if (!strcasecmp(new_facility, "user"))
		fac = LOG_USER;
	else if (!strcasecmp(new_facility, "uucp"))
		fac = LOG_UUCP;
	else if (!strcasecmp(new_facility, "local0"))
		fac = LOG_LOCAL0;
	else if (!strcasecmp(new_facility, "local1"))
		fac = LOG_LOCAL1;
	else if (!strcasecmp(new_facility, "local2"))
		fac = LOG_LOCAL2;
	else if (!strcasecmp(new_facility, "local3"))
		fac = LOG_LOCAL3;
	else if (!strcasecmp(new_facility, "local4"))
		fac = LOG_LOCAL4;
	else if (!strcasecmp(new_facility, "local5"))
		fac = LOG_LOCAL5;
	else if (!strcasecmp(new_facility, "local6"))
		fac = LOG_LOCAL6;
	else if (!strcasecmp(new_facility, "local7"))
		fac = LOG_LOCAL7;
	else
		mysyslog("Invalid facility: \"%s\" - falling back to default.",
				new_facility);

	return (fac);
}

/*
** Converts the string "new_priority" to a syslog(3) priority.  Returns
** the new priority on success and the default priority on failure.
*/

int get_priority(const u_char *new_priority) {
	int pri = PRIORITY;

	if (!strncasecmp(new_priority, "log_", 4))
		new_priority += 4;

	if (!strcasecmp(new_priority, "alert"))
		pri = LOG_ALERT;
	else if (!strcasecmp(new_priority, "crit"))
		pri = LOG_CRIT;
	else if (!strcasecmp(new_priority, "debug"))
		pri = LOG_DEBUG;
	else if (!strcasecmp(new_priority, "emerg"))
		pri = LOG_EMERG;
	else if (!strcasecmp(new_priority, "err"))
		pri = LOG_ERR;
	else if (!strcasecmp(new_priority, "error"))
		pri = LOG_ERR;
	else if (!strcasecmp(new_priority, "info"))
		pri = LOG_INFO;
	else if (!strcasecmp(new_priority, "notice"))
		pri = LOG_NOTICE;
	else if (!strcasecmp(new_priority, "panic"))
		pri = LOG_EMERG;
	else if (!strcasecmp(new_priority, "warn"))
		pri = LOG_WARNING;
	else if (!strcasecmp(new_priority, "warning"))
		pri = LOG_WARNING;
	else
		mysyslog("Invalid priority: \"%s\" - falling back to default.",
				new_priority);

	return (pri);
}

/*
** Simplifies options, checks that no options conflict.
*/

void check_options(void) {
	if (!opt_enabled(LOG_TCP | LOG_UDP | LOG_ICMP))
		fatal("Told not to log anything.  Exiting.");

	if (opt_enabled(PROMISC) && opt_enabled(GET_IDENT))
		fatal("The promisc and get_ident flags are not compatible.");

	if (opt_enabled(NO_RESOLV))
		flags &= ~(TCP_RES | UDP_RES | ICMP_RES);
	else if (!(flags & (TCP_RES | UDP_RES | ICMP_RES)))
		flags |= NO_RESOLV;

	if (!opt_enabled(TCP_RES))
		flags &= ~SYN_FLOOD;

	if (opt_enabled(DNS_CACHE) && opt_enabled(NO_RESOLV))
		flags ^= DNS_CACHE;

	if (opt_enabled(SMURF) && !opt_enabled(LOG_ICMP | LOG_UDP))
		flags ^= SMURF;

	if (!opt_enabled(LOG_TCP))
		flags &= ~(PORTSCAN | NULL_SCAN | FIN_SCAN | XMAS_SCAN);

	if (!opt_enabled(LOG_ICMP))
		flags &= ~PING_FLOOD;

	if (!opt_enabled(LOG_UDP))
		flags &= ~(UDP_SCAN | IGNORE_NS);

	if (opt_enabled(FOOL_NMAP) && get_raw_sock() == false)
		flags ^= FOOL_NMAP;
}

/*
** Print all command-line options to the screen.
*/

static void print_help(void) {
	mysyslog(
"Usage: " PACKAGE " [options] (\"*\" Denotes enabled by default)\n"
"--user      or -u <user|UID>     Run as specified the user or UID.\n"
"--group     or -g <group|GID>    Run with specified the group or GID.\n"
"--logfile   or -l <file>         Log to <file>.\n"
"--pid-file  <file>               Use <file> as the pid file.\n"
"--ignore    or -d                Ignore DNS traffic from nameservers listed in\n"
"                                 /etc/resolv.conf.\n"
"--interface or -i <if0,...,ifN>  Listen on the specified interface(s).\n"
"--promisc   or -a <network>      Log traffic to all hosts on <network>.\n"
"--kill      or -k                Kill iplog, if it is running.\n"
"--restart   or -R                Restart iplog, if it is running.\n"
"--no-fork   or -o                Run in the foreground.\n"
"--stdout    or -L                Log to stdout.\n"
"--help      or -h                This help screen.\n"
"--version   or -v                Print version information and exit.\n"
"\n"
"--facility <facility>            Use the specified syslog facility.\n"
"--priority <priority>            Use the specified syslog priority.\n"
"\n"
"--tcp[=true|false|toggle]                      %cLog TCP traffic.\n"
"--udp[=true|false|toggle]                      %cLog UDP traffic.\n"
"--icmp[=true|false|toggle]                     %cLog ICMP traffic.\n"
"\n"
"--log-ip[=true|false|toggle]            or -w  %cLog IP along with hostname.\n"
"--log-dest[=true|false|toggle]          or -D  %cLog the destination of traffic.\n"
"--dns-cache[=true|false|toggle]         or -c  %cUse the built-in DNS cache.\n"
"--get-ident[=true|false|toggle]         or -e  %cGet ident info on connections\n"
"                                                to listening ports.\n"
"\n"
"--tcp-resolve[=true|false|toggle]       or -T  %cResolve IPs of TCP traffic.\n"
"--udp-resolve[=true|false|toggle]       or -U  %cResolve IPs of UDP traffic.\n"
"--icmp-resolve[=true|false|toggle]      or -I  %cResolve IPs of ICMP traffic.\n"
"--disable-resolver                      or -N  %cDo not resolve any IPs.\n"
"\n"
"--verbose[=true|false|toggle]           or -V  %cBe verbose.\n"
"--fool-nmap[=true|false|toggle]         or -z  %cFool nmap's OS detection.\n"
"--scans-only[=true|false|toggle]        or -m  %cOnly log scans.\n"
"--detect-syn-flood[=true|false|toggle]  or -s  %cStop resolving IPs if a\n"
"                                                SYN flood is detected.\n"
"\n"
"--log-frag[=true|false|toggle]          or -y  %cLog fragment attacks.\n"
"--log-traceroute[=true|false|toggle]    or -t  %cLog traceroutes.\n"
"--log-ping-flood[=true|false|toggle]    or -P  %cLog ICMP ping floods.\n"
"--log-smurf[=true|false|toggle]         or -S  %cLog smurf attacks.\n"
"--log-bogus[=true|false|toggle]         or -b  %cLog bogus TCP flags.\n"
"--log-portscan[=true|false|toggle]      or -p  %cLog port scans.\n"
"--log-udp-scan[=true|false|toggle]      or -F  %cLog UDP scans/floods.\n"
"--log-fin-scan[=true|false|toggle]      or -f  %cLog FIN scans.\n"
"--log-syn-scan[=true|false|toggle]      or -q  %cLog SYN scans.\n"
"--log-xmas-scan[=true|false|toggle]     or -x  %cLog Xmas scans.\n"
"--log-null-scan[=true|false|toggle]     or -n  %cLog null scans.",
IS_DEFAULT(LOG_TCP),	IS_DEFAULT(LOG_UDP),	IS_DEFAULT(LOG_ICMP),
IS_DEFAULT(LOG_IP),		IS_DEFAULT(LOG_DEST),	IS_DEFAULT(DNS_CACHE),
IS_DEFAULT(GET_IDENT),	IS_DEFAULT(TCP_RES),	IS_DEFAULT(UDP_RES),
IS_DEFAULT(ICMP_RES),	IS_DEFAULT(NO_RESOLV),	IS_DEFAULT(VERBOSE),
IS_DEFAULT(FOOL_NMAP),	IS_DEFAULT(SCANS_ONLY),	IS_DEFAULT(SYN_FLOOD),
IS_DEFAULT(LOG_FRAG),	IS_DEFAULT(TRACEROUTE),	IS_DEFAULT(PING_FLOOD),
IS_DEFAULT(SMURF),		IS_DEFAULT(BOGUS),		IS_DEFAULT(PORTSCAN),
IS_DEFAULT(UDP_SCAN),	IS_DEFAULT(FIN_SCAN),	IS_DEFAULT(SYN_SCAN),
IS_DEFAULT(XMAS_SCAN),	IS_DEFAULT(NULL_SCAN));
	exit(0);
}

/* vim:ts=4:sw=8:tw=0 */
