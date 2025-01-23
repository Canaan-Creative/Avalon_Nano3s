#ifndef __CG_LOG_H__
#define __CG_LOG_H__

#include "config.h"
#include <stdbool.h>
#include <stdarg.h>
#include "logging.h"

/* debug flags */
extern bool opt_debug;
extern bool opt_decode;
extern bool opt_log_output;
extern bool opt_realquiet;
extern bool want_per_device_stats;

/* global log_level, messages with lower or equal prio are logged */
//extern int opt_log_level;

#define LOGBUFSIZ 256
extern void _applog(int prio, const char *str, bool force);
extern void _simplelog(int prio, const char *str, bool force);

#define IN_FMT_FFL " in %s %s():%d"
#ifdef HAVE_SYSLOG_H
#define applog(prio, fmt, ...) do { \
	if (opt_debug || prio != LOG_DEBUG) { \
		if (use_syslog || opt_log_output || prio >= get_opt_log_level()) { \
			char tmp42[LOGBUFSIZ]; \
			snprintf(tmp42, sizeof(tmp42), fmt, ##__VA_ARGS__); \
			_applog(prio, tmp42, false); \
		} \
	} \
} while (0)
#endif

#define simplelog(prio, fmt, ...) do { \
	if (opt_debug || prio != LOG_DEBUG) { \
		if (/*use_syslog || */opt_log_output || prio >= get_opt_log_level()) { \
			char tmp42[LOGBUFSIZ]; \
			snprintf(tmp42, sizeof(tmp42), fmt, ##__VA_ARGS__); \
			_simplelog(prio, tmp42, false); \
		} \
	} \
} while (0)

#define applogsiz(prio, _SIZ, fmt, ...) do { \
	if (opt_debug || prio != LOG_DEBUG) { \
		if (/*use_syslog || */opt_log_output || prio >= get_opt_log_level()) { \
			char tmp42[_SIZ]; \
			snprintf(tmp42, sizeof(tmp42), fmt, ##__VA_ARGS__); \
			_applog(prio, tmp42, false); \
		} \
	} \
} while (0)

#define forcelog(prio, fmt, ...) do { \
	if (opt_debug || prio != LOG_DEBUG) { \
		if (/*use_syslog || */opt_log_output || prio >= get_opt_log_level()) { \
			char tmp42[LOGBUFSIZ]; \
			snprintf(tmp42, sizeof(tmp42), fmt, ##__VA_ARGS__); \
			_applog(prio, tmp42, true); \
		} \
	} \
} while (0)

#define quit(status, fmt, ...) do { \
	if (fmt) { \
		char tmp42[LOGBUFSIZ]; \
		snprintf(tmp42, sizeof(tmp42), fmt, ##__VA_ARGS__); \
		_applog(LOG_ERR, tmp42, true); \
	} \
	exit(status); \
} while (0)

#define early_quit(status, fmt, ...) do { \
	if (fmt) { \
		char tmp42[LOGBUFSIZ]; \
		snprintf(tmp42, sizeof(tmp42), fmt, ##__VA_ARGS__); \
		_applog(LOG_ERR, tmp42, true); \
	} \
	exit(status); \
} while (0)

#define quithere(status, fmt, ...) do { \
	if (fmt) { \
		char tmp42[LOGBUFSIZ]; \
		snprintf(tmp42, sizeof(tmp42), fmt IN_FMT_FFL, \
				##__VA_ARGS__, __FILE__, __func__, __LINE__); \
		_applog(LOG_ERR, tmp42, true); \
	} \
	exit(status); \
} while (0)

#define quitfrom(status, _file, _func, _line, fmt, ...) do { \
	if (fmt) { \
		char tmp42[LOGBUFSIZ]; \
		snprintf(tmp42, sizeof(tmp42), fmt IN_FMT_FFL, \
				##__VA_ARGS__, _file, _func, _line); \
		_applog(LOG_ERR, tmp42, true); \
	} \
	exit(status); \
} while (0)

#endif /* __LOGGING_H__ */
