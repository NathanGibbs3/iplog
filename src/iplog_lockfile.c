/*
** iplog_lockfile.c - iplog lockfile management.
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
** $Id: iplog_lockfile.c,v 1.15 2001/01/01 16:02:14 odin Exp $
*/

#include <config.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <iplog.h>

/*
** Write a lockfile for iplog.  Exits on failure.
*/

void write_lockfile(const u_char *lockfile) {
	int fd;
	struct flock fl;

	memset(&fl, 0, sizeof(fl));

	fd = open(lockfile, O_RDWR | O_CREAT | O_TRUNC | O_EXCL, 0644);

	if (fd == -1) {
		if (errno != EEXIST)
			fatal("Cannot open lockfile \"%s\": %s", lockfile, strerror(errno));

		fd = open(lockfile, O_RDONLY);
		if (fd == -1)
			fatal("Cannot open existing lockfile.");

		if (fcntl(fd, F_GETLK, &fl) == -1 || fl.l_type == F_UNLCK) {
			if (unlink(lockfile) != 0)
				fatal("Could not remove stale lockfile \"%s\"", lockfile);
		} else
			fatal("iplog is already running (pid: %d)", fl.l_pid);

		close(fd);

		fd = open(lockfile, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd == -1) {
			fatal("Cannot create lockfile \"%s\": %s",
				lockfile, strerror(errno));
		}
	}

	dprintf(fd, "%d\n", getpid());

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(fd, F_SETLK, &fl) == -1) {
		fatal("Lockfile \"%s\" could not be locked: %s", lockfile,
			strerror(errno));
	}
}

/*
** Kill iplog with signal "sig."  Exits on failure.
*/

void kill_iplog(int sig, const u_char *lockfile) {
	int fd;
	pid_t pid;
	ssize_t len;
	u_char buf[16];
	char *nptr;

	fd = open(lockfile, O_RDONLY);
	if (fd == -1) {
		if (errno == EEXIST)
			fatal("iplog is not running.");
		else
			fatal("Can't open pid file: %s", strerror(errno));
	}

	len = read(fd, buf, sizeof(buf));
	if (len < 1)
		fatal("Error reading pid.");

	buf[len] = '\0';
	nptr = strchr(buf, '\n');
	if (nptr != NULL)
		*nptr = '\0';
	pid = strtoul(buf, &nptr, 10);
	if (*nptr != '\0')
		fatal("Bad pid in %s: \"%s\"", lockfile, buf);

	if (kill(pid, sig) != 0)
		fatal("Can't send process signal %d: %s", sig, strerror(errno));

	exit(0);
}

/* vim:ts=4:sw=8:tw=0 */
