/*
 * Copyright 2011-2012 Con Kolivas
 * Copyright 2013 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <unistd.h>

#include "logging.h"
#include "miner.h"

bool opt_debug = false;
bool opt_log_output = true;

/* per default priorities higher than LOG_NOTICE are logged */
//int opt_log_level = LOG_NOTICE;

static void my_log_curses(int prio, const char *datetime, const char *str, bool force)
{
	if (opt_quiet && prio != LOG_ERR)
		return;

	/* Mutex could be locked by dead thread on shutdown so forcelog will
	 * invalidate any console lock status. */
	if (force) {
		mutex_trylock(&console_lock);
		mutex_unlock(&console_lock);
	}
	{
		mutex_lock(&console_lock);
		printf("%s%s%s", datetime, str, "                    \n");
		mutex_unlock(&console_lock);
	}
}

/* high-level logging function, based on global opt_log_level */

/*
 * log function
 */
void _applog(int prio, const char *str, bool force)
{
#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		syslog(LOG_LOCAL0 | prio, "%s", str);
	}
#else
	if (0) {}
#endif
	else {
		char datetime[64];
		struct timeval tv = {0, 0};
		struct tm *tm;

		cgtime(&tv);

		const time_t tmp_time = tv.tv_sec;
		int ms = (int)(tv.tv_usec / 1000);
		tm = localtime(&tmp_time);

		snprintf(datetime, sizeof(datetime), " [%d-%02d-%02d %02d:%02d:%02d.%03d] ",
			tm->tm_year + 1900,
			tm->tm_mon + 1,
			tm->tm_mday,
			tm->tm_hour,
			tm->tm_min,
			tm->tm_sec, ms);

		/* Only output to stderr if it's not going to the screen as well */
		if (!isatty(fileno((FILE *)stderr))) {
			fprintf(stderr, "%s%s\n", datetime, str);	/* atomic write to stderr */
			fflush(stderr);
		}

		my_log_curses(prio, datetime, str, force);
	}
}

void _simplelog(int prio, const char *str, bool force)
{
#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		syslog(LOG_LOCAL0 | prio, "%s", str);
	}
#else
	if (0) {}
#endif
	else {
		/* Only output to stderr if it's not going to the screen as well */
		if (!isatty(fileno((FILE *)stderr))) {
			fprintf(stderr, "%s\n", str);	/* atomic write to stderr */
			fflush(stderr);
		}

		my_log_curses(prio, "", str, force);
	}
}
