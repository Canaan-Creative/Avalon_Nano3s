#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "logging.h"

int opt_log_level = LOG_DEBUG;

#ifndef HAVE_SYSLOG_H
zlog_category_t *g_cat = NULL;

#define DEFAULT_ZLOGCONF	"\
[global]\n\
file perms = 644\n\
[levels]\n\
OP = 110,LOG_ERR\n\
[formats]\n\
simple = \"%d %ms %V %m%n\"\n\
op_format = \"%d %ms %m%n\"\n\
[rules]\n\
my_cat.NOTICE    \"/data/userdata/log/cg_sys.log\",1MB*1; simple\n\
my_cat.=OP      \"/data/userdata/log/cg_op.log\",512KB*1; op_format\n\
\n\
"

int log_init(char *path)
{
	int rc;
	int default_conf = 0;
	rc = zlog_init(path);
	if(rc)
	{
		printf("cg_miner: %s is not correct, use default logfile\n", path);
		default_conf = 1;
		rc = zlog_init(DEFAULT_ZLOGCONF);
	}
	g_cat = zlog_get_category("my_cat");
	if (default_conf)
		applog(LOG_NOTICE, "cg_miner: %s is not correct, use default logfile", path);
	return rc;
}

void log_exit()
{
	zlog_fini();
}

#endif

struct {
	char log_name[16];
	int log_level;
} log_name_to_level[] = {
	{"log_none", LOG_NONE},
	{"log_fatal", LOG_FATAL},
	{"log_error", LOG_ERR},
	{"log_op", LOG_OP},
	{"log_warning", LOG_WARNING},
	{"log_notice", LOG_NOTICE},
	{"log_info", LOG_INFO},
	{"log_debug", LOG_DEBUG},
};

void set_opt_log_level(int level)
{
    if(level > LOG_NONE){
        opt_log_level = LOG_NONE;
    } else if(level < LOG_DEBUG){
        opt_log_level = LOG_DEBUG;
    }

    opt_log_level = level; 
}

void set_opt_log_level_with_name(char *level)
{
	int i = 0;

	for(i = 0; i < sizeof(log_name_to_level)/sizeof(log_name_to_level[0]); i++){
		if(strncasecmp(level, log_name_to_level[i].log_name, sizeof(log_name_to_level[0].log_name)) == 0){
			set_opt_log_level(log_name_to_level[i].log_level);
			break;
		}
	}
}

int get_opt_log_level()
{
    return opt_log_level;
}

char *get_opt_log_level_name()
{
	int i = 0;

	for(i = 0; i < sizeof(log_name_to_level)/sizeof(log_name_to_level[0]); i++){
		if(opt_log_level == log_name_to_level[i].log_level){
			return log_name_to_level[i].log_name;
		}
	}
	return "none";
}

