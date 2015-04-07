/*
** iplog_syslog.c - iplog logging mechanism.
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
** $Id: iplog_syslog.c,v 1.20 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <iplog.h>
#include <iplog_options.h>

#define LOG_SIZE 2048

extern u_char *logfile;

struct log_data {
	time_t expire;
	u_long times;
	int fd;
	u_char *last_message;
};

static struct log_data log = {
	expire:			0,
	times:			0,
	fd:				-1,
	last_message: 	NULL
};

int priority = PRIORITY;
int facility = FACILITY;

pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

/*
** Message logger.
*/

void mysyslog(const char *fmt, ...) {
	time_t now;
	va_list ap;
	u_char *p;

	va_start(ap, fmt);
#ifdef HAVE_VASPRINTF
	vasprintf((char **) &p, fmt, ap);
#else
	p = xmalloc(LOG_SIZE);
	vsnprintf(p, LOG_SIZE, fmt, ap);
#endif
	va_end(ap);

	if (log.fd == -1) {
		pthread_mutex_lock(&log_lock);
		printf("%s\n", p);
		pthread_mutex_unlock(&log_lock);
		free(p);
		return;
	}

	if (logfile == NULL && !opt_enabled(LOG_STDOUT)) {
		pthread_mutex_lock(&log_lock);
		syslog(priority, "%s", p);
		pthread_mutex_unlock(&log_lock);
		free(p);

		return;
	}

	pthread_mutex_lock(&log_lock);
	time(&now);

	if (!strcmp(p, log.last_message)) {
		free(p);
		if (now >= log.expire && log.times > 0) {
			dprintf(log.fd, "%.15s last message repeated %lu times\n",
				ctime(&now) + 4, log.times);
			free(log.last_message);
			log.last_message = xcalloc(1, 1);
			log.times = 0;
			log.expire = 0;
		}

		log.times++;
	} else {
		if (log.times > 0) {
			dprintf(log.fd, "%.15s last message repeated %lu times\n",
				ctime(&now) + 4, log.times);
			log.times = 0;
		}

		dprintf(log.fd, "%.15s %s\n", ctime(&now) + 4, p);
		log.expire = time(NULL) + 60;
		free(log.last_message);
		log.last_message = p;
	}
	pthread_mutex_unlock(&log_lock);
}

/*
** Initializer for the logger.
*/

void myopenlog(const char *name, int option) {

	if (logfile == NULL && !opt_enabled(LOG_STDOUT)) {
		log.fd = -2;
		openlog(name, option, facility);
	} else {
		int fd;

		log.expire = 0;
		log.times = 0;
		log.last_message = xcalloc(1, 1);

		if (opt_enabled(LOG_STDOUT))
			fd = fileno(stdout);
		else {
			fd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0644);

			if (fd == -1) {
				fatal("Unable to open \"%s\" for writing: %s.",
					logfile, strerror(errno));
			}
		}

		log.fd = fd;
	}

	mysyslog("iplog started.");
}

/*
** Analogous to closelog(3).
*/

void mycloselog(void) {
	if (logfile == NULL && !opt_enabled(LOG_STDOUT))
		closelog();
	else {
		time_t now;

		pthread_mutex_lock(&log_lock);

		time(&now);
		if (log.times > 0) {
			dprintf(log.fd, "%.15s last message repeated %lu times\n",
				ctime(&now) + 4, log.times);
		}
		if (!opt_enabled(LOG_STDOUT))
			close(log.fd);

		log.fd = -1;
		log.expire = 0;
		log.times = 0;

		free(log.last_message);
		log.last_message = xcalloc(1, 1);

		pthread_mutex_unlock(&log_lock);
	}
}

/* vim:ts=4:sw=8:tw=0 */
