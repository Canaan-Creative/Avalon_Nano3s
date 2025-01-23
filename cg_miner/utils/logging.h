#ifndef __LOGGING_H__
#define __LOGGING_H__

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
#include "zlog.h"
enum {
    LOG_NONE = 140,
    LOG_FATAL = 120,
	LOG_OP = 110,
	LOG_ERR = 100,
	LOG_WARNING = 80,
	LOG_NOTICE = 60,
	LOG_INFO = 40,
	LOG_DEBUG = 20,
};
#endif

void set_opt_log_level(int level);
void set_opt_log_level_with_name(char *level);
int get_opt_log_level();
char *get_opt_log_level_name();

#ifndef HAVE_SYSLOG_H
extern zlog_category_t *g_cat;

int log_init(char *path);
void log_exit();

#define applog(prio, fmt, ...) do { \
    if (prio >= get_opt_log_level()) { \
        zlog(g_cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        prio, fmt, ##__VA_ARGS__); \
	} \
} while (0)
#endif

#endif
