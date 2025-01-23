/*
 * Copyright 2011-2018 Con Kolivas
 * Copyright 2011-2015 Andrew Smith
 * Copyright 2011-2012 Luke Dashjr
 * Copyright 2010 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <stdarg.h>
#include <assert.h>
#include <signal.h>
#include <limits.h>


#include <sys/stat.h>
#include <sys/types.h>

#include <sys/resource.h>
#include <ccan/opt/opt.h>
#include <jansson.h>
char *curly = ":D";
#include <libgen.h>
#include <sha2.h>
#include "compat.h"
#include "miner.h"
#include "http.h"
#include "cgminer.h"
#if defined(unix) || defined(__APPLE__)
	#include <errno.h>
	#include <fcntl.h>
	#include <sys/wait.h>
#endif


#ifdef USE_AVALON
#include "driver-avalon.h"
#endif
#include "poolcfg.h"

struct strategies strategies[] = {
	{ "Failover" },
	{ "Round Robin" },
	{ "Rotate" },
	{ "Load Balance" },
	{ "Balance" },
};

// static char packagename[256];

bool opt_work_update;
bool opt_protocol;

struct pool *opt_btcd;
static char *opt_benchfile;
static bool opt_benchmark;
bool have_longpoll;
bool want_per_device_stats;
bool use_syslog;
bool opt_quiet;
bool opt_realquiet;
bool opt_loginput;
bool opt_compact;
bool opt_decode;
const int opt_cutofftemp = 95;
int opt_log_interval = 5;
//static const int max_queue = 1;
const int max_scantime = 60;
const int max_expiry = 600;
uint64_t global_hashrate;
unsigned long global_quota_gcd = 1;
time_t last_getwork;
int opt_pool_fallback = 120;

bool opt_restart = true;
bool opt_nogpu;

struct list_head scan_devices;
int total_devices;
int zombie_devs;
static int most_devices;
struct cgpu_info **devices;
int mining_threads;
int num_processors;
bool use_curses;
static bool alt_status;
static bool switch_status;
static bool opt_submit_stale = true;
static int opt_shares;
static bool opt_fix_protocol;
bool opt_lowmem;
bool opt_autofan;
bool opt_autoengine;
bool opt_noadl;
// char *opt_api_allow = NULL;
char *opt_api_groups;
char *opt_api_description = PACKAGE_STRING;
int opt_api_port = 4028;
char *opt_api_host = API_LISTEN_ADDR;
bool opt_api_listen;
bool opt_api_mcast;
char *opt_api_mcast_addr = API_MCAST_ADDR;
char *opt_api_mcast_code = API_MCAST_CODE;
char *opt_api_mcast_des = "";
int opt_api_mcast_port = 4028;
bool opt_api_network;
bool opt_delaynet;
bool opt_disable_pool;
static bool no_work;
bool opt_worktime;

char *opt_bab_options = NULL;
static char *opt_set_null;



char *cgminer_path;
bool opt_gen_stratum_work;

#define QUIET	(opt_quiet || opt_realquiet)
#define TOTAL_CONTROL_THREADS	8

struct thr_info control_thr[TOTAL_CONTROL_THREADS];
struct thr_info **mining_thr;
static int api_thr_id;
static int http_thr_id;
static int watchpool_thr_id;
// static int watchdog_thr_id;
int gpur_thr_id;
bool hotplug_mode;
static int new_devices;
static int new_threads;
int hotplug_time = 5;

#if LOCK_TRACKING
pthread_mutex_t lockstat_lock;
#endif

pthread_mutex_t hash_lock;
static pthread_mutex_t *stgd_lock;
pthread_mutex_t console_lock;
cglock_t ch_lock;
static pthread_rwlock_t blk_lock;
static pthread_mutex_t sshare_lock;
#ifdef HAVE_LIBCURL
pthread_rwlock_t netacc_lock;
#endif
pthread_rwlock_t mining_thr_lock;
pthread_rwlock_t devices_lock;

static pthread_mutex_t lp_lock;
static pthread_cond_t lp_cond;

pthread_mutex_t restart_lock;
pthread_cond_t restart_cond;

pthread_cond_t gws_cond;

double rolling1, rolling5, rolling15;
double total_rolling;
double total_mhashes_done;


static struct timeval total_tv_start, total_tv_end;
static struct timeval restart_tv_start, update_tv_start;

cglock_t control_lock;
pthread_mutex_t stats_lock;

int hw_errors;
int64_t total_accepted, total_rejected, total_diff1;
int64_t total_getworks, total_stale, total_discarded;
double total_diff_accepted, total_diff_rejected, total_diff_stale;
static int staged_rollable;
unsigned int new_blocks;
static unsigned int work_block;
unsigned int found_blocks;

unsigned int local_work;
unsigned int total_go, total_ro;

struct pool **pools;
static struct pool *currentpool = NULL;

int total_pools, enabled_pools;
enum pool_strategy pool_strategy = POOL_FAILOVER;
int opt_rotate_period;
static int total_urls, total_users, total_passes, total_userpasses;

static
bool curses_active = true;

/* Protected by ch_lock */
char current_hash[68];
static char prev_block[12];
static char current_block[32];

static char datestamp[40];
static char blocktime[32];
struct timeval block_timeval;
static char best_share[8] = "0";
double current_diff = 0xFFFFFFFFFFFFFFFFULL;
static char block_diff[8];
uint64_t best_diff = 0;

struct block {
	char hash[68];
	UT_hash_handle hh;
	int block_no;
};

static struct block *blocks = NULL;


int swork_id;

/* For creating a hash database of stratum shares submitted that have not had
 * a response yet */
struct stratum_share {
	UT_hash_handle hh;
	bool block;
	struct work *work;
	int id;
	time_t sshare_time;
	time_t sshare_sent;
};

static struct stratum_share *stratum_shares = NULL;

char *opt_socks_proxy = NULL;
int opt_suggest_diff;
static const char def_conf[] = "cgminer.conf";
static char *default_config;
#define JSON_INCLUDE_CONF "include"
#define JSON_LOAD_ERROR "JSON decode of file '%s' failed\n %s"
#define JSON_LOAD_ERROR_LEN strlen(JSON_LOAD_ERROR)
#define JSON_MAX_DEPTH 10
#define JSON_MAX_DEPTH_ERR "Too many levels of JSON includes (limit 10) or a loop"
#define JSON_WEB_ERROR "WEB config err"

#if defined(unix) || defined(__APPLE__)
	static char *opt_stderr_cmd = NULL;
#endif // defined(unix)

//struct sigaction termhandler, inthandler, abrthandler;

struct thread_q *getq;

static uint32_t total_work;
struct work *staged_work = NULL;

struct schedtime {
	bool enable;
	struct tm tm;
};

struct schedtime schedstart;
struct schedtime schedstop;
bool sched_paused;

uint32_t pool_failcnt = 0;
uint32_t netfail_time[8] = {0, 0, 0, 0, 0, 0, 0, 0};

char * show_netfail(void)
{
	static char buf[16 * ARRAY_SIZE(netfail_time)];
	char tmp[16];

	memset(buf, 0, sizeof(buf));
	for (int i = 0; i < ARRAY_SIZE(netfail_time); i++) {
		sprintf(tmp, "%d ", netfail_time[i]);
		strcat(buf, tmp);
	}
	buf[strlen(buf) - 1] = '\0';

	return buf;
}

void get_datestamp(char *f, size_t fsiz, struct timeval *tv)
{
	struct tm *tm;

	const time_t tmp_time = tv->tv_sec;
	int ms = (int)(tv->tv_usec / 1000);
	tm = localtime(&tmp_time);
	snprintf(f, fsiz, "[%d-%02d-%02d %02d:%02d:%02d.%03d]",
		tm->tm_year + 1900,
		tm->tm_mon + 1,
		tm->tm_mday,
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec, ms);
}

static void get_timestamp(char *f, size_t fsiz, struct timeval *tv)
{
	struct tm *tm;

	const time_t tmp_time = tv->tv_sec;
	int ms = (int)(tv->tv_usec / 1000);
	tm = localtime(&tmp_time);
	snprintf(f, fsiz, "[%02d:%02d:%02d.%03d]",
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec, ms);
}

static char exit_buf[512];

static void opt_failed(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(exit_buf, sizeof(exit_buf), fmt, ap);
	va_end(ap);
	_applog(LOG_ERR, exit_buf, true);
	_applog(LOG_ERR, "opt parse failed, saveing default configuration ...", true);
}

static pthread_mutex_t sharelog_lock;
static FILE *sharelog_file = NULL;

static struct thr_info *__get_thread(int thr_id)
{
	return mining_thr[thr_id];
}

struct thr_info *get_thread(int thr_id)
{
	struct thr_info *thr;

	rd_lock(&mining_thr_lock);
	thr = __get_thread(thr_id);
	rd_unlock(&mining_thr_lock);

	return thr;
}

static struct cgpu_info *get_thr_cgpu(int thr_id)
{
	struct thr_info *thr = get_thread(thr_id);

	return thr->cgpu;
}

struct cgpu_info *get_devices(int id)
{
	struct cgpu_info *cgpu;

	rd_lock(&devices_lock);
	cgpu = devices?devices[id]:NULL;
	rd_unlock(&devices_lock);

	return cgpu;
}

static void sharelog(const char*disposition, const struct work*work)
{
	char *target, *hash, *data;
	struct cgpu_info *cgpu;
	unsigned long int t;
	struct pool *pool;
	int thr_id, rv;
	char s[1024];
	size_t ret;

	if (!sharelog_file)
		return;

	thr_id = work->thr_id;
	cgpu = get_thr_cgpu(thr_id);
	pool = work->pool;
	t = (unsigned long int)(work->tv_work_found.tv_sec);
	target = bin2hex(work->target, sizeof(work->target));
	hash = bin2hex(work->hash, sizeof(work->hash));
	data = bin2hex(work->data, sizeof(work->data));

	// timestamp,disposition,target,pool,dev,thr,sharehash,sharedata
	rv = snprintf(s, sizeof(s), "%lu,%s,%s,%s,%s%u,%u,%s,%s\n", t, disposition, target, pool->rpc_url, cgpu->drv->name, cgpu->device_id, thr_id, hash, data);
	free(target);
	free(hash);
	free(data);
	if (rv >= (int)(sizeof(s)))
		s[sizeof(s) - 1] = '\0';
	else if (rv < 0) {
		applog(LOG_ERR, "sharelog printf error");
		return;
	}

	mutex_lock(&sharelog_lock);
	ret = fwrite(s, rv, 1, sharelog_file);
	fflush(sharelog_file);
	mutex_unlock(&sharelog_lock);

	if (ret != 1)
		applog(LOG_ERR, "sharelog fwrite error");
}

static char *gbt_req = "{\"id\": 0, \"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": [\"coinbasetxn\", \"workid\", \"coinbase/append\"]}]}\n";

static char *gbt_solo_req = "{\"id\": 0, \"method\": \"getblocktemplate\", \"params\": [{\"rules\" : [\"segwit\"]}]}\n";

static const char *gbt_understood_rules[1] = { NULL };
static const char *gbt_solo_understood_rules[2] = {"segwit", NULL};

static bool gbt_check_required_rule(const char* rule, const char** understood_rules)
{
	const char *understood_rule;

	if (!understood_rules || !rule)
		return false;
	while ((understood_rule = *understood_rules++)) {
		if (strcmp(understood_rule, rule) == 0)
			return true;
	}
	return false;
}

static bool gbt_check_rules(json_t* rules_arr, const char** understood_rules)
{
	int i, rule_count;
	const char *rule;

	if (!rules_arr)
		return true;
	rule_count = json_array_size(rules_arr);
	for (i = 0; i < rule_count; i++) {
		rule = json_string_value(json_array_get(rules_arr, i));
		if (rule && *rule++ == '!' && !gbt_check_required_rule(rule, understood_rules))
			return false;
	}
	return true;
}

/* Adjust all the pools' quota to the greatest common denominator after a pool
 * has been added or the quotas changed. */
void adjust_quota_gcd(void)
{
	unsigned long gcd, lowest_quota = ~0UL, quota;
	struct pool *pool;
	int i;

	for (i = 0; i < total_pools; i++) {
		pool = pools[i];
		quota = pool->quota;
		if (!quota)
			continue;
		if (quota < lowest_quota)
			lowest_quota = quota;
	}

	if (likely(lowest_quota < ~0UL)) {
		gcd = lowest_quota;
		for (i = 0; i < total_pools; i++) {
			pool = pools[i];
			quota = pool->quota;
			if (!quota)
				continue;
			while (quota % gcd)
				gcd--;
		}
	} else
		gcd = 1;

	for (i = 0; i < total_pools; i++) {
		pool = pools[i];
		pool->quota_used *= global_quota_gcd;
		pool->quota_used /= gcd;
		pool->quota_gcd = pool->quota / gcd;
	}

	global_quota_gcd = gcd;
	applog(LOG_DEBUG, "Global quota greatest common denominator set to %lu", gcd);
}

/* Return value is ignored if not called from input_pool */
struct pool *add_pool(void)
{
	struct pool *pool;

	pool = cgcalloc(1,sizeof(struct pool));
	if(!pool)
		return NULL;
	pool->pool_no = pool->prio = total_pools;
	pools = cgrealloc(pools, sizeof(struct pool *) * (total_pools + 2));
	if(!pools)
		return NULL;
	pools[total_pools++] = pool;
	mutex_init(&pool->pool_lock);
	pthread_cond_init(&pool->cr_cond, NULL);

	cglock_init(&pool->data_lock);
	mutex_init(&pool->stratum_lock);
	cglock_init(&pool->gbt_lock);
	INIT_LIST_HEAD(&pool->curlring);

	/* Make sure the pool doesn't think we've been idle since time 0 */
	pool->tv_idle.tv_sec = ~0UL;

	pool->rpc_req = gbt_req;
	pool->rpc_proxy = NULL;
	pool->quota = 1;
	adjust_quota_gcd();

	return pool;
}

/* Pool variant of test and set */
static bool pool_tset(struct pool *pool, bool *var)
{
	bool ret;

	mutex_lock(&pool->pool_lock);
	ret = *var;
	*var = true;
	mutex_unlock(&pool->pool_lock);

	return ret;
}

bool pool_tclear(struct pool *pool, bool *var)
{
	bool ret;

	mutex_lock(&pool->pool_lock);
	ret = *var;
	*var = false;
	mutex_unlock(&pool->pool_lock);

	return ret;
}

struct pool *current_pool(void)
{
	struct pool *pool;

	cg_rlock(&control_lock);
	pool = currentpool;
	cg_runlock(&control_lock);

	return pool;
}

char *set_int_range(const char *arg, int *i, int min, int max)
{
	char *err = opt_set_intval(arg, i);

	if (err)
		return err;

	if (*i < min || *i > max)
		return "Value out of range";

	return NULL;
}

static char *set_int_1_to_65535(const char *arg, int *i)
{
	return set_int_range(arg, i, 1, 65535);
}

#ifdef USE_AVALON
static char *set_int_0_to_1(const char *arg, int *i)
{
	return set_int_range(arg, i, 0, 1);
}
#endif

static char *set_int_24_to_32(const char *arg, int *i)
{
	return set_int_range(arg, i, 24, 32);
}

static char __maybe_unused *set_int_0_to_2(const char *arg, int *i)
{
	return set_int_range(arg, i, 0, 2);
}

static char __maybe_unused *set_int_0_to_3(const char *arg, int *i)
{
	return set_int_range(arg, i, 0, 3);
}

static char __maybe_unused *set_int_0_to_4(const char *arg, int *i)
{
	return set_int_range(arg, i, 0, 4);
}

void get_intrange(char *arg, int *val1, int *val2)
{
	if (sscanf(arg, "%d-%d", val1, val2) == 1)
		*val2 = *val1;
}

static char *set_loadbalance(enum pool_strategy *strategy)
{
	*strategy = POOL_LOADBALANCE;
	return NULL;
}

static char *set_rotate(const char *arg, char __maybe_unused *i)
{
	pool_strategy = POOL_ROTATE;
	return set_int_range(arg, &opt_rotate_period, 0, 9999);
}

static char *set_rr(enum pool_strategy *strategy)
{
	*strategy = POOL_ROUNDROBIN;
	return NULL;
}

/* Detect that url is for a stratum protocol either via the presence of
 * stratum+tcp or by detecting a stratum server response */
bool detect_stratum(struct pool *pool, char *url)
{
	bool ret = false;

	check_extranonce_option(pool, url);

	if (!extract_sockaddr(url, &pool->sockaddr_url, &pool->stratum_port))
		goto out;

	if (!strncasecmp(url, "stratum+tcp://", 14)) {
		pool->rpc_url = strdup(url);
		pool->has_stratum = true;
		pool->stratum_url = pool->sockaddr_url;
		ret = true;
	}
	if (!strncasecmp(url, "stratum+tls://", 14) || !strncasecmp(url, "stratum+ssl://", 14) ){
		pool->rpc_url = strdup(url);
		pool->has_stratum = true;
		pool->stratum_url = pool->sockaddr_url;
		pool->is_tls = true;
		ret = true;
	}
out:
	if (!ret) {
		free(pool->sockaddr_url);
		free(pool->stratum_port);
		pool->stratum_port = pool->sockaddr_url = NULL;
	}
	return ret;
}

static struct pool *add_url(void)
{
	total_urls++;
	if (total_urls > total_pools)
	{
		if(add_pool() == NULL)
			return NULL;
	}
		
	return pools[total_urls - 1];
}

static char *setup_url(struct pool *pool, char *arg)
{
	arg = get_proxy(arg, pool);

	if (detect_stratum(pool, arg))
		goto out;

	opt_set_charp(arg, &pool->rpc_url);
	if (strncmp(arg, "http://", 7) &&
	    strncmp(arg, "https://", 8)) {
		char httpinput[256];

		strcpy(httpinput, "stratum+tcp://");
		strncat(httpinput, arg, 242);
		detect_stratum(pool, httpinput);
	}
out:
	return pool->rpc_url;
}

static char *set_url(char *arg)
{
	struct pool *pool = add_url();

	setup_url(pool, arg);
	return NULL;
}

static char *set_quota(char *arg)
{
	char *semicolon = strchr(arg, ';'), *url;
	int len, qlen, quota;
	struct pool *pool;

	if (!semicolon)
		return "No semicolon separated quota;URL pair found";
	len = strlen(arg);
	*semicolon = '\0';
	qlen = strlen(arg);
	if (!qlen)
		return "No parameter for quota found";
	len -= qlen + 1;
	if (len < 1)
		return "No parameter for URL found";
	quota = atoi(arg);
	if (quota < 0)
		return "Invalid negative parameter for quota set";
	url = arg + qlen + 1;
	pool = add_url();
	setup_url(pool, url);
	pool->quota = quota;
	applog(LOG_INFO, "Setting pool %d to quota %d", pool->pool_no, pool->quota);
	adjust_quota_gcd();

	return NULL;
}

static char *set_user(const char *arg)
{
	struct pool *pool;

	if (total_userpasses)
		return "Use only user + pass or userpass, but not both";
	
	total_users++;
	if (total_users > total_pools)
		add_pool();

	pool = pools[total_users - 1];
	opt_set_charp(arg, &pool->rpc_user);

	return NULL;
}

static char *set_pass(const char *arg)
{
	struct pool *pool;

	if (total_userpasses)
		return "Use only user + pass or userpass, but not both";

	total_passes++;
	if (total_passes > total_pools)
		add_pool();

	pool = pools[total_passes - 1];
	opt_set_charp(arg, &pool->rpc_pass);

	return NULL;
}

static char *set_userpass(const char *arg)
{
	struct pool *pool;
	char *updup;

	if (total_users || total_passes)
		return "Use only user + pass or userpass, but not both";
	if ((total_userpasses + 1) > total_pools) {
		pool = add_pool();
		if(!pool) {
			return "Failed to add pool: no mem";
		}
	}

	total_userpasses++;
	pool = pools[total_userpasses - 1];
	updup = strdup(arg);
	opt_set_charp(arg, &pool->rpc_userpass);
	pool->rpc_user = strtok(updup, ":");
	if (!pool->rpc_user)
		return "Failed to find : delimited user info";
	pool->rpc_pass = strtok(NULL, ":");
	if (!pool->rpc_pass)
		pool->rpc_pass = strdup("");

	return NULL;
}

static char *enable_debug(bool *flag)
{
	*flag = true;
	/* Turn on verbose output, too. */
	opt_log_output = true;
	return NULL;
}

static char *set_null(const char __maybe_unused *arg)
{
	return NULL;
}

/* These options are available from config file or commandline */
static struct opt_table opt_config_table[] = {
#ifdef USE_AVALON
	OPT_WITH_ARG("--avalon10-core-clk-sel",
		     opt_set_intval, opt_show_intval, &opt_avalon_core_clk_sel,
		     "Set Avalon10 core clk select, range 0-1. default: 0"),

	OPT_WITH_ARG("--avalon10-freq-sel",
		     set_int_0_to_4, opt_show_intval, &opt_avalon_freq_sel,
		     "Set Avalon10 default frequency select, range:[0, 4], step: 1, example: 3"),
	OPT_WITH_ARG("--avalon10-nonce-check",
		     set_int_0_to_1, opt_show_intval, &opt_avalon_nonce_check,
		     "Set A3210 nonce check, range 0-1."),
	OPT_WITH_ARG("--avalon10-nonce-mask",
		     set_int_24_to_32, opt_show_intval, &opt_avalon_nonce_mask,
		     "Set A3210 nonce mask, range 24-32."),
	OPT_WITH_ARG("--avalon10-polling-delay",
		     set_int_1_to_65535, opt_show_intval, &opt_avalon_polling_delay,
		     "Set Avalon10 polling delay value (ms)"),
	OPT_WITH_ARG("--avalon10-roll-enable",
		     set_int_0_to_1, opt_show_intval, &opt_avalon_roll_enable,
		     "Set A3210 roll enable, range 0-1."),
#endif
	OPT_WITHOUT_ARG("--debug|-D",
		     enable_debug, &opt_debug,
		     "Enable debug output"),
	OPT_WITHOUT_ARG("--disable-rejecting",
			opt_set_bool, &opt_disable_pool,
			"Automatically disable pools that continually reject shares"),
	OPT_WITH_ARG("--expiry|-E",
		     set_null, NULL, &opt_set_null,
		     opt_hidden),
	OPT_WITHOUT_ARG("--failover-only",
			set_null, &opt_set_null,
			opt_hidden),
	OPT_WITH_ARG("--fallback-time",
		     opt_set_intval, opt_show_intval, &opt_pool_fallback,
		     "Set time in seconds to fall back to a higher priority pool after period of instability"),
	OPT_WITHOUT_ARG("--fix-protocol",
			opt_set_bool, &opt_fix_protocol,
			"Do not redirect to stratum protocol from GBT"),
	OPT_WITHOUT_ARG("--load-balance",
		     set_loadbalance, &pool_strategy,
		     "Change multipool strategy from failover to quota based balance"),
	OPT_WITHOUT_ARG("--lowmem",
			opt_set_bool, &opt_lowmem,
			"Minimise caching of shares for low memory applications"),
#if defined(unix) || defined(__APPLE__)
	OPT_WITH_ARG("--monitor|-m",
		     opt_set_charp, NULL, &opt_stderr_cmd,
		     "Use custom pipe cmd for output messages"),
#endif // defined(unix)
	OPT_WITHOUT_ARG("--net-delay",
			opt_set_bool, &opt_delaynet,
			"Impose small delays in networking to not overload slow routers"),
	OPT_WITHOUT_ARG("--no-pool-disable",
			opt_set_invbool, &opt_disable_pool,
			opt_hidden),
	OPT_WITHOUT_ARG("--no-submit-stale",
			opt_set_invbool, &opt_submit_stale,
		        "Don't submit shares if they are detected as stale"),
	OPT_WITH_ARG("--pass|-p",
		     set_pass, NULL, &opt_set_null,
		     "Password for bitcoin JSON-RPC server"),
	//OPT_WITHOUT_ARG("--per-device-stats",
	//		opt_set_bool, &want_per_device_stats,
	//		"Force verbose mode and output per-device statistics"),
	OPT_WITH_ARG("--pools",
			opt_set_bool, NULL, &opt_set_null, opt_hidden),
	OPT_WITHOUT_ARG("--protocol-dump|-P",
			opt_set_bool, &opt_protocol,
			"Verbose dump of protocol-level activities"),
	OPT_WITH_ARG("--queue|-Q",
		     set_null, NULL, &opt_set_null,
		     opt_hidden),
	OPT_WITHOUT_ARG("--quiet|-q",
			opt_set_bool, &opt_quiet,
			"Disable logging output, display status and errors"),
	OPT_WITH_ARG("--quota|-U",
		     set_quota, NULL, &opt_set_null,
		     "quota;URL combination for server with load-balance strategy quotas"),
	OPT_WITHOUT_ARG("--real-quiet",
			opt_set_bool, &opt_realquiet,
			"Disable all output"),
	OPT_WITH_ARG("--retries",
		     set_null, NULL, &opt_set_null,
		     opt_hidden),
	OPT_WITH_ARG("--retry-pause",
		     set_null, NULL, &opt_set_null,
		     opt_hidden),
	OPT_WITH_ARG("--rotate",
		     set_rotate, NULL, &opt_set_null,
		     "Change multipool strategy from failover to regularly rotate at N minutes"),
	OPT_WITHOUT_ARG("--round-robin",
		     set_rr, &pool_strategy,
		     "Change multipool strategy from failover to round robin on failure"),
	OPT_WITH_ARG("--scan-time|-s",
		     set_null, NULL, &opt_set_null,
		     opt_hidden),
	OPT_WITH_ARG("--socks-proxy",
		     opt_set_charp, NULL, &opt_socks_proxy,
		     "Set socks4 proxy (host:port)"),
	OPT_WITH_ARG("--suggest-diff",
		     opt_set_intval, NULL, &opt_suggest_diff,
		     "Suggest miner difficulty for pool to user (default: none)"),
#ifdef HAVE_SYSLOG_H
	OPT_WITHOUT_ARG("--syslog",
			opt_set_bool, &use_syslog,
			"Use system log for output messages (default: standard error)"),
#endif
	OPT_WITHOUT_ARG("--text-only|-T",
			opt_set_invbool, &use_curses,
			opt_hidden
	),
	OPT_WITH_ARG("--url|-o",
		     set_url, NULL, &opt_set_null,
		     "URL for bitcoin JSON-RPC server"),
	OPT_WITH_ARG("--user|-u",
		     set_user, NULL, &opt_set_null,
		     "Username for bitcoin JSON-RPC server"),
	OPT_WITH_ARG("--userpass|-O",
		     set_userpass, NULL, &opt_set_null,
		     "Username:Password pair for bitcoin JSON-RPC server"),
	OPT_WITHOUT_ARG("--verbose",
			opt_set_bool, &opt_log_output,
			"Log verbose output to stderr as well as status output"),
	//OPT_WITHOUT_ARG("--widescreen",
	//		opt_set_bool, &opt_widescreen,
	//		"Use extra wide display without toggling"),
	OPT_WITHOUT_ARG("--worktime",
			opt_set_bool, &opt_worktime,
			"Display extra work time debug information"),
	OPT_ENDTABLE
};

static void calc_midstate(struct pool *pool, struct work *work)
{
	unsigned char data[64];
	uint32_t *data32 = (uint32_t *)data;
	sha256_ctx ctx;

	if (pool->vmask) {
		/* This would only be set if the driver requested a vmask and
		 * the pool has a valid version mask. */
		memcpy(work->data, &(pool->vmask_001[1]), 4);
		flip64(data32, work->data);
		sha256_init(&ctx);
		sha256_update(&ctx, data, 64);
		cg_memcpy(work->midstate1, ctx.h, 32);
		endian_flip32(work->midstate1, work->midstate1);

		memcpy(work->data, &(pool->vmask_001[2]), 4);
		flip64(data32, work->data);
		sha256_init(&ctx);
		sha256_update(&ctx, data, 64);
		cg_memcpy(work->midstate2, ctx.h, 32);
		endian_flip32(work->midstate2, work->midstate2);

		memcpy(work->data, &(pool->vmask_001[3]), 4);
		flip64(data32, work->data);
		sha256_init(&ctx);
		sha256_update(&ctx, data, 64);
		cg_memcpy(work->midstate3, ctx.h, 32);
		endian_flip32(work->midstate3, work->midstate3);

		memcpy(work->data, &(pool->vmask_001[4]), 4);
		flip64(data32, work->data);
		sha256_init(&ctx);
		sha256_update(&ctx, data, 64);
		cg_memcpy(work->midstate4, ctx.h, 32);
		endian_flip32(work->midstate4, work->midstate4);

		memcpy(work->data, &(pool->vmask_001[5]), 4);
		flip64(data32, work->data);
		sha256_init(&ctx);
		sha256_update(&ctx, data, 64);
		cg_memcpy(work->midstate5, ctx.h, 32);
		endian_flip32(work->midstate5, work->midstate5);

		memcpy(work->data, &(pool->vmask_001[6]), 4);
		flip64(data32, work->data);
		sha256_init(&ctx);
		sha256_update(&ctx, data, 64);
		cg_memcpy(work->midstate6, ctx.h, 32);
		endian_flip32(work->midstate6, work->midstate6);

		memcpy(work->data, &(pool->vmask_001[7]), 4);
		flip64(data32, work->data);
		sha256_init(&ctx);
		sha256_update(&ctx, data, 64);
		cg_memcpy(work->midstate7, ctx.h, 32);
		endian_flip32(work->midstate7, work->midstate7);

		memcpy(work->data, &(pool->vmask_001[0]), 4);
	}
	flip64(data32, work->data);
	sha256_init(&ctx);
	sha256_update(&ctx, data, 64);
	cg_memcpy(work->midstate, ctx.h, 32);
	endian_flip32(work->midstate, work->midstate);
}

/* Returns the current value of total_work and increments it */
static int total_work_inc(void)
{
	int ret;

	cg_wlock(&control_lock);
	ret = total_work++;
	cg_wunlock(&control_lock);

	return ret;
}

static struct work *make_work(void)
{
	struct work *work = cgcalloc(1, sizeof(struct work));
	if(!work)
		return NULL;
	work->id = total_work_inc();
	return work;
}

/* This is the central place all work that is about to be retired should be
 * cleaned to remove any dynamically allocated arrays within the struct */
void clean_work(struct work *work)
{
	free(work->job_id);
	free(work->ntime);
	free(work->coinbase);
	free(work->nonce1);
	memset(work, 0, sizeof(struct work));
}

/* All dynamically allocated work structs should be freed here to not leak any
 * ram from arrays allocated within the work struct. Null the actual pointer
 * used to call free_work. */
void _free_work(struct work **workptr, const char *file, const char *func, const int line)
{
	struct work *work = *workptr;

	if (unlikely(!work)) {
		applog(LOG_ERR, "Free work called with null work from %s %s:%d",
		       file, func, line);
		return;
	}

	clean_work(work);
	free(work);
	*workptr = NULL;
}

static void gen_hash(unsigned char *data, unsigned char *hash, int len);
static void calc_diff(struct work *work, double known);
char *workpadding = "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";

#define json_rpc_call(curl, url, userpass, rpc_req, probe, longpoll, rolltime, pool, share) (NULL)
#define work_decode(pool, work, val) (false)
#define gen_gbt_work(pool, work) {}

int dev_from_id(int thr_id)
{
	struct cgpu_info *cgpu = get_thr_cgpu(thr_id);

	return cgpu->device_id;
}

/* Create an exponentially decaying average over the opt_log_interval */
void decay_time(double *f, double fadd, double fsecs, double interval)
{
	double ftotal, fprop;

	if (fsecs <= 0)
		return;
	fprop = 1.0 - 1 / (exp(fsecs / interval));
	ftotal = 1.0 + fprop;
	*f += (fadd / fsecs * fprop);
	*f /= ftotal;
}

//static int __total_staged(void)
//{
//	return HASH_COUNT(staged_work);
//}

double total_secs = 1.0;
static char statusline[256];

/* Convert a uint64_t value into a truncated string for displaying with its
 * associated suitable for Mega, Giga etc. Buf array needs to be long enough */
static void suffix_string(uint64_t val, char *buf, size_t bufsiz, int sigdigits)
{
	const double  dkilo = 1000.0;
	const uint64_t kilo = 1000ull;
	const uint64_t mega = 1000000ull;
	const uint64_t giga = 1000000000ull;
	const uint64_t tera = 1000000000000ull;
	const uint64_t peta = 1000000000000000ull;
	const uint64_t exa  = 1000000000000000000ull;
	char suffix[2] = "";
	bool decimal = true;
	double dval;

	if (val >= exa) {
		val /= peta;
		dval = (double)val / dkilo;
		strcpy(suffix, "E");
	} else if (val >= peta) {
		val /= tera;
		dval = (double)val / dkilo;
		strcpy(suffix, "P");
	} else if (val >= tera) {
		val /= giga;
		dval = (double)val / dkilo;
		strcpy(suffix, "T");
	} else if (val >= giga) {
		val /= mega;
		dval = (double)val / dkilo;
		strcpy(suffix, "G");
	} else if (val >= mega) {
		val /= kilo;
		dval = (double)val / dkilo;
		strcpy(suffix, "M");
	} else if (val >= kilo) {
		dval = (double)val / dkilo;
		strcpy(suffix, "K");
	} else {
		dval = val;
		decimal = false;
	}

	if (!sigdigits) {
		if (decimal)
			snprintf(buf, bufsiz, "%.3g%s", dval, suffix);
		else
			snprintf(buf, bufsiz, "%d%s", (unsigned int)dval, suffix);
	} else {
		/* Always show sigdigits + 1, padded on right with zeroes
		 * followed by suffix */
		int ndigits = sigdigits - 1 - (dval > 0.0 ? floor(log10(dval)) : 0);

		snprintf(buf, bufsiz, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
	}
}

double cgpu_runtime(struct cgpu_info *cgpu)
{
	struct timeval now;
	double dev_runtime;

	if (cgpu->dev_start_tv.tv_sec == 0)
		dev_runtime = total_secs;
	else {
		cgtime(&now);
		dev_runtime = tdiff(&now, &(cgpu->dev_start_tv));
	}

	if (dev_runtime < 1.0)
		dev_runtime = 1.0;
	return dev_runtime;
}

double tsince_restart(void)
{
	struct timeval now;

	cgtime(&now);
	return tdiff(&now, &restart_tv_start);
}

double tsince_update(void)
{
	struct timeval now;

	cgtime(&now);
	return tdiff(&now, &update_tv_start);
}

static void get_statline(char *buf, size_t bufsiz, struct cgpu_info *cgpu)
{
	char displayed_hashes[16], displayed_rolling[16];
	double dev_runtime, wu;
	uint64_t dh64, dr64;

	dev_runtime = cgpu_runtime(cgpu);

	wu = cgpu->diff1 / dev_runtime * 60.0;

	dh64 = (double)cgpu->total_mhashes / dev_runtime * 1000000ull;
	dr64 = (double)cgpu->rolling * 1000000ull;
	suffix_string(dh64, displayed_hashes, sizeof(displayed_hashes), 4);
	suffix_string(dr64, displayed_rolling, sizeof(displayed_rolling), 4);

	snprintf(buf, bufsiz, "%s %d ", cgpu->drv->name, cgpu->device_id);
	cgpu->drv->get_statline_before(buf, bufsiz, cgpu);
	tailsprintf(buf, bufsiz, "(%ds):%s (avg):%sh/s | A:%.0f R:%.0f HW:%d WU:%.1f/m",
		opt_log_interval,
		displayed_rolling,
		displayed_hashes,
		cgpu->diff_accepted,
		cgpu->diff_rejected,
		cgpu->hw_errors,
		wu);
	cgpu->drv->get_statline(buf, bufsiz, cgpu);
}


static bool shared_strategy(void)
{
	return (pool_strategy == POOL_LOADBALANCE || pool_strategy == POOL_BALANCE);
}

static void enable_pool(struct pool *pool)
{
	if (pool->enabled != POOL_ENABLED) {
		enabled_pools++;
		pool->enabled = POOL_ENABLED;
	}
}


static void reject_pool(struct pool *pool)
{
	if (pool->enabled == POOL_ENABLED)
		enabled_pools--;
	pool->enabled = POOL_REJECTING;
}

static void restart_threads(void);

/* Theoretically threads could race when modifying accepted and
 * rejected values but the chance of two submits completing at the
 * same time is zero so there is no point adding extra locking */
static void
share_result(json_t *val, json_t *res, json_t *err, const struct work *work,
	     char *hashshow, bool resubmit, char *worktime)
{
	struct pool *pool = work->pool;
	struct cgpu_info *cgpu;

	cgpu = get_thr_cgpu(work->thr_id);

	if (json_is_true(res) || (work->gbt && json_is_null(res))) {
		mutex_lock(&stats_lock);
		cgpu->accepted++;
		total_accepted++;
		pool->accepted++;
		cgpu->diff_accepted += work->work_difficulty;
		total_diff_accepted += work->work_difficulty;
		pool->diff_accepted += work->work_difficulty;
		mutex_unlock(&stats_lock);

		pool->seq_rejects = 0;
		cgpu->last_share_pool = pool->pool_no;
		cgpu->last_share_pool_time = time(NULL);
		cgpu->last_share_diff = work->work_difficulty;
		pool->last_share_time = cgpu->last_share_pool_time;
		pool->last_share_diff = work->work_difficulty;
		applog(LOG_DEBUG, "PROOF OF WORK RESULT: true (yay!!!)");
		if (!QUIET) {
			if (total_pools > 1)
				applog(LOG_NOTICE, "Accepted %s %s %d pool %d %s%s",
				       hashshow, cgpu->drv->name, cgpu->device_id, work->pool->pool_no, resubmit ? "(resubmit)" : "", worktime);
			else
				applog(LOG_NOTICE, "Accepted %s %s %d %s%s",
				       hashshow, cgpu->drv->name, cgpu->device_id, resubmit ? "(resubmit)" : "", worktime);
		}
		sharelog("accept", work);
		if (opt_shares && total_diff_accepted >= opt_shares) {
			applog(LOG_WARNING, "Successfully mined %d accepted shares as requested and exiting.", opt_shares);
			kill_work();
			return;
		}

		/* Detect if a pool that has been temporarily disabled for
		 * continually rejecting shares has started accepting shares.
		 * This will only happen with the work returned from a
		 * longpoll */
		if (unlikely(pool->enabled == POOL_REJECTING)) {
			applog(LOG_WARNING, "Rejecting pool %d now accepting shares, re-enabling!", pool->pool_no);
			enable_pool(pool);
			switch_pools(NULL);
		}
		/* If we know we found the block we know better than anyone
		 * that new work is needed. */
		if (unlikely(work->block))
			restart_threads();
	} else {
		mutex_lock(&stats_lock);
		cgpu->rejected++;
		total_rejected++;
		pool->rejected++;
		cgpu->diff_rejected += work->work_difficulty;
		total_diff_rejected += work->work_difficulty;
		pool->diff_rejected += work->work_difficulty;
		pool->seq_rejects++;
		mutex_unlock(&stats_lock);

		applog(LOG_DEBUG, "PROOF OF WORK RESULT: false (booooo)");
		if (!QUIET) {
			char where[20];
			char disposition[36] = "reject";
			char reason[32];

			strcpy(reason, "");
			if (total_pools > 1)
				snprintf(where, sizeof(where), "pool %d", work->pool->pool_no);
			else
				strcpy(where, "");

			if (!work->gbt)
				res = json_object_get(val, "reject-reason");
			if (res) {
				const char *reasontmp = json_string_value(res);

				size_t reasonLen = strlen(reasontmp);
				if (reasonLen > 28)
					reasonLen = 28;
				reason[0] = ' '; reason[1] = '(';
				cg_memcpy(2 + reason, reasontmp, reasonLen);
				reason[reasonLen + 2] = ')'; reason[reasonLen + 3] = '\0';
				cg_memcpy(disposition + 7, reasontmp, reasonLen);
				disposition[6] = ':'; disposition[reasonLen + 7] = '\0';
			} else if (work->stratum && err) {
				if (json_is_array(err)) {
					json_t *reason_val = json_array_get(err, 1);
					char *reason_str;

					if (reason_val && json_is_string(reason_val)) {
						reason_str = (char *)json_string_value(reason_val);
						snprintf(reason, 31, " (%s)", reason_str);
					}
				} else if (json_is_string(err)) {
					const char *s = json_string_value(err);
					snprintf(reason, 31, " (%s)", s);
				}
			}

			applog(LOG_NOTICE, "Rejected %s %s %d %s%s %s%s",
			       hashshow, cgpu->drv->name, cgpu->device_id, where, reason, resubmit ? "(resubmit)" : "", worktime);
			sharelog(disposition, work);
		}

		/* Once we have more than a nominal amount of sequential rejects,
		 * at least 10 and more than 3 mins at the current utility,
		 * disable the pool because some pool error is likely to have
		 * ensued. Do not do this if we know the share just happened to
		 * be stale due to networking delays.
		 */
		if (pool->seq_rejects > 10 && !work->stale && opt_disable_pool && enabled_pools > 1) {
			double utility = total_accepted / total_secs * 60;

			if (pool->seq_rejects > utility * 3 && enabled_pools > 1) {
				applog(LOG_WARNING, "Pool %d rejected %d sequential shares, disabling!",
				       pool->pool_no, pool->seq_rejects);
				reject_pool(pool);
				if (pool == current_pool())
					switch_pools(NULL);
				pool->seq_rejects = 0;
			}
		}
	}
}

static void show_hash(struct work *work, char *hashshow)
{
	unsigned char rhash[32];
	char diffdisp[16];
	unsigned long h32;
	uint32_t *hash32;
	uint64_t uintdiff;
	int ofs;

	swab256(rhash, work->hash);
	for (ofs = 0; ofs <= 28; ofs ++) {
		if (rhash[ofs])
			break;
	}
	hash32 = (uint32_t *)(rhash + ofs);
	h32 = be32toh(*hash32);
	uintdiff = round(work->work_difficulty);
	suffix_string(work->share_diff, diffdisp, sizeof (diffdisp), 0);
	snprintf(hashshow, 64, "%08lx Diff %s/%"PRIu64"%s", h32, diffdisp, uintdiff,
		 work->block? " BLOCK!" : "");
}

/* Specifies whether we can use this pool for work or not. */
static bool pool_unusable(struct pool *pool)
{
	if (pool->idle)
		return true;
	if (pool->enabled != POOL_ENABLED)
		return true;
	if (pool->has_stratum && (!pool->stratum_active || !pool->stratum_notify))
		return true;
	return false;
}

/* In balanced mode, the amount of diff1 solutions per pool is monitored as a
 * rolling average per 10 minutes and if pools start getting more, it biases
 * away from them to distribute work evenly. The share count is reset to the
 * rolling average every 10 minutes to not send all work to one pool after it
 * has been disabled/out for an extended period. */
static struct pool *select_balanced(struct pool *cp)
{
	int i, lowest = cp->shares;
	struct pool *ret = cp;

	for (i = 0; i < total_pools; i++) {
		struct pool *pool = pools[i];

		if (pool_unusable(pool))
			continue;
		if (pool->shares < lowest) {
			lowest = pool->shares;
			ret = pool;
		}
	}

	ret->shares++;
	return ret;
}

static struct pool *priority_pool(int choice);

/* Select any active pool in a rotating fashion when loadbalance is chosen if
 * it has any quota left. */
static inline struct pool *select_pool(void)
{
	static int rotating_pool = 0;
	struct pool *pool, *cp;
	bool avail = false;
	int tested, i;

	cp = current_pool();

	if (pool_strategy == POOL_BALANCE) {
		pool = select_balanced(cp);
		goto out;
	}

	if (pool_strategy != POOL_LOADBALANCE) {
		pool = cp;
		goto out;
	} else
		pool = NULL;

	for (i = 0; i < total_pools; i++) {
		struct pool *tp = pools[i];

		if (tp->quota_used < tp->quota_gcd) {
			avail = true;
			break;
		}
	}

	/* There are no pools with quota, so reset them. */
	if (!avail) {
		for (i = 0; i < total_pools; i++)
			pools[i]->quota_used = 0;
		if (++rotating_pool >= total_pools)
			rotating_pool = 0;
	}

	/* Try to find the first pool in the rotation that is usable */
	tested = 0;
	while (!pool && tested++ < total_pools) {
		pool = pools[rotating_pool];
		if (pool->quota_used++ < pool->quota_gcd) {
			if (!pool_unusable(pool))
				break;
		}
		pool = NULL;
		if (++rotating_pool >= total_pools)
			rotating_pool = 0;
	}

	/* If there are no alive pools with quota, choose according to
	 * priority. */
	if (!pool) {
		for (i = 0; i < total_pools; i++) {
			struct pool *tp = priority_pool(i);

			if (!pool_unusable(tp)) {
				pool = tp;
				break;
			}
		}
	}

	/* If still nothing is usable, use the current pool */
	if (!pool)
		pool = cp;
out:
	applog(LOG_DEBUG, "Selecting pool %d for work", pool->pool_no);
	return pool;
}

/* truediffone == 0x00000000FFFF0000000000000000000000000000000000000000000000000000
 * Generate a 256 bit binary LE target by cutting up diff into 64 bit sized
 * portions or vice versa. */
static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
static const double bits192 = 6277101735386680763835789423207666416102355444464034512896.0;
static const double bits128 = 340282366920938463463374607431768211456.0;
static const double bits64 = 18446744073709551616.0;

/* Converts a little endian 256 bit value to a double */
static double le256todouble(const void *target)
{
	uint64_t *data64;
	double dcut64;

	data64 = (uint64_t *)(target + 24);
	dcut64 = le64toh(*data64) * bits192;

	data64 = (uint64_t *)(target + 16);
	dcut64 += le64toh(*data64) * bits128;

	data64 = (uint64_t *)(target + 8);
	dcut64 += le64toh(*data64) * bits64;

	data64 = (uint64_t *)(target);
	dcut64 += le64toh(*data64);

	return dcut64;
}

static double diff_from_target(void *target)
{
	double d64, dcut64;

	d64 = truediffone;
	dcut64 = le256todouble(target);
	if (unlikely(!dcut64))
		dcut64 = 1;
	return d64 / dcut64;
}

/*
 * Calculate the work->work_difficulty based on the work->target
 */
static void calc_diff(struct work *work, double known)
{
	struct cgminer_pool_stats *pool_stats = &(work->pool->cgminer_pool_stats);
	double difficulty;
	uint64_t uintdiff;

	if (known)
		work->work_difficulty = known;
	else
		work->work_difficulty = diff_from_target(work->target);

	difficulty = work->work_difficulty;

	pool_stats->last_diff = difficulty;
	uintdiff = round(difficulty);
	suffix_string(uintdiff, work->pool->diff, sizeof(work->pool->diff), 0);

	if (difficulty == pool_stats->min_diff)
		pool_stats->min_diff_count++;
	else if (difficulty < pool_stats->min_diff || pool_stats->min_diff == 0) {
		pool_stats->min_diff = difficulty;
		pool_stats->min_diff_count = 1;
	}

	if (difficulty == pool_stats->max_diff)
		pool_stats->max_diff_count++;
	else if (difficulty > pool_stats->max_diff) {
		pool_stats->max_diff = difficulty;
		pool_stats->max_diff_count = 1;
	}
}

static unsigned char bench_hidiff_bins[16][160];
static unsigned char bench_lodiff_bins[16][160];

static void kill_timeout(struct thr_info *thr)
{
	cg_completion_timeout(&thr_info_cancel, thr, 1000);
}

static void kill_mining(void)
{
	struct thr_info *thr;
	int i;

	forcelog(LOG_DEBUG, "Killing off mining threads");
	/* Kill the mining threads*/
	for (i = 0; i < mining_threads; i++) {
		pthread_t *pth = NULL;

		thr = get_thread(i);
		if (thr && PTH(thr) != 0L)
			pth = &thr->pth;
		thr_info_cancel(thr);
		if (pth && *pth)
			pthread_join(*pth, NULL);
	}
}

static void wait_mining(void)
{
	struct thr_info *thr;
	int i;

	forcelog(LOG_DEBUG, "Waiting on mining threads");
	/* Kill the mining threads*/
	for (i = 0; i < mining_threads; i++) {
		pthread_t *pth = NULL;

		thr = get_thread(i);
		if (thr && PTH(thr) != 0L)
			pth = &thr->pth;
		if (pth && *pth)
			pthread_join(*pth, NULL);
	}
}

static void __kill_work(void)
{
	struct thr_info *thr;
	int i;

	if (!successful_connect)
		return;
	// watchdog_disable();
	// watchdog_exit();
	forcelog(LOG_INFO, "Received kill message");


	forcelog(LOG_DEBUG, "Killing off watchpool thread");
	/* Kill the watchpool thread */
	thr = &control_thr[watchpool_thr_id];
	kill_timeout(thr);

	// forcelog(LOG_DEBUG, "Killing off watchdog thread");
	/* Kill the watchdog thread */
	// thr = &control_thr[watchdog_thr_id];
	// kill_timeout(thr);

	forcelog(LOG_DEBUG, "Shutting down mining threads");
	for (i = 0; i < mining_threads; i++) {
		struct cgpu_info *cgpu;

		thr = get_thread(i);
		if (!thr)
			continue;
		cgpu = thr->cgpu;
		if (!cgpu)
			continue;

		cgpu->shutdown = true;
	}

	/* Give the threads a chance to shut down gracefully */
	cg_completion_timeout(&wait_mining, NULL, 5000);
	/* Kill the threads and wait for them to return if not */
	cg_completion_timeout(&kill_mining, NULL, 5000);

	/* Stop the others */
	forcelog(LOG_DEBUG, "Killing off API thread");
	thr = &control_thr[api_thr_id];
	kill_timeout(thr);

	forcelog(LOG_DEBUG, "Killing off HTTP thread");
	thr = &control_thr[http_thr_id];
	kill_timeout(thr);
}

/* This should be the common exit path */
void kill_work(void)
{
	cg_completion_timeout(&__kill_work, NULL, 10000);
}

static void *raise_thread(void __maybe_unused *arg)
{
	raise(SIGTERM);
	return NULL;
}

/* This provides a mechanism for driver threads to initiate a shutdown without
 * the cyclical problem of the shutdown path being cancelled while the driver
 * thread shuts down.*/
void raise_cgminer(void)
{
	pthread_t pth;

	pthread_create(&pth, NULL, raise_thread, NULL);
}

static void _stage_work(struct work *work);

#define stage_work(WORK) do { \
	_stage_work(WORK); \
	WORK = NULL; \
} while (0)

/* Adjust an existing char ntime field with a relative noffset */
static void modify_ntime(char *ntime, int noffset)
{
	unsigned char bin[4];
	uint32_t h32, *be32 = (uint32_t *)bin;

	hex2bin(bin, ntime, 4);
	h32 = be32toh(*be32) + noffset;
	*be32 = htobe32(h32);
	__bin2hex(ntime, bin, 4);
}

void roll_work(struct work *work)
{
	uint32_t *work_ntime;
	uint32_t ntime;

	work_ntime = (uint32_t *)(work->data + 68);
	ntime = be32toh(*work_ntime);
	ntime++;
	*work_ntime = htobe32(ntime);
	local_work++;
	work->rolls++;
	work->nonce = 0;
	applog(LOG_DEBUG, "Successfully rolled work");
	/* Change the ntime field if this is stratum work */
	if (work->ntime)
		modify_ntime(work->ntime, 1);

	/* This is now a different work item so it needs a different ID for the
	 * hashtable */
	work->id = total_work_inc();
}

void roll_work_ntime(struct work *work, int noffset)
{
	uint32_t *work_ntime;
	uint32_t ntime;

	work_ntime = (uint32_t *)(work->data + 68);
	ntime = be32toh(*work_ntime);
	ntime += noffset;
	*work_ntime = htobe32(ntime);
	local_work++;
	work->rolls += noffset;
	work->nonce = 0;
	applog(LOG_DEBUG, "Successfully rolled work");

	/* Change the ntime field if this is stratum work */
	if (work->ntime)
		modify_ntime(work->ntime, noffset);

	/* This is now a different work item so it needs a different ID for the
	 * hashtable */
	work->id = total_work_inc();
}

struct work *make_clone(struct work *work)
{
	struct work *work_clone = copy_work(work);

	work_clone->clone = true;
	cgtime((struct timeval *)&(work_clone->tv_cloned));
	work_clone->longpoll = false;
	work_clone->mandatory = false;
	/* Make cloned work appear slightly older to bias towards keeping the
	 * master work item which can be further rolled */
	work_clone->tv_staged.tv_sec -= 1;

	return work_clone;
}

static void *submit_work_thread(void __maybe_unused *userdata)
{
	pthread_detach(pthread_self());
	return NULL;
}

/* Return an adjusted ntime if we're submitting work that a device has
 * internally offset the ntime. */
static char *offset_ntime(const char *ntime, int noffset)
{
	unsigned char bin[4];
	uint32_t h32, *be32 = (uint32_t *)bin;

	hex2bin(bin, ntime, 4);
	h32 = be32toh(*be32) + noffset;
	*be32 = htobe32(h32);

	return bin2hex(bin, 4);
}

/* Duplicates any dynamically allocated arrays within the work struct to
 * prevent a copied work struct from freeing ram belonging to another struct */
static void _copy_work(struct work *work, const struct work *base_work, int noffset)
{
	uint32_t id = work->id;

	clean_work(work);
	cg_memcpy(work, base_work, sizeof(struct work));
	/* Keep the unique new id assigned during make_work to prevent copied
	 * work from having the same id. */
	work->id = id;
	if (base_work->job_id)
		work->job_id = strdup(base_work->job_id);
	if (base_work->nonce1)
		work->nonce1 = strdup(base_work->nonce1);
	if (base_work->ntime) {
		/* If we are passed an noffset the binary work->data ntime and
		 * the work->ntime hex string need to be adjusted. */
		if (noffset) {
			uint32_t *work_ntime = (uint32_t *)(work->data + 68);
			uint32_t ntime = be32toh(*work_ntime);

			ntime += noffset;
			*work_ntime = htobe32(ntime);
			work->ntime = offset_ntime(base_work->ntime, noffset);
		} else
			work->ntime = strdup(base_work->ntime);
	} else if (noffset) {
		uint32_t *work_ntime = (uint32_t *)(work->data + 68);
		uint32_t ntime = be32toh(*work_ntime);

		ntime += noffset;
		*work_ntime = htobe32(ntime);
	}
	if (base_work->coinbase)
		work->coinbase = strdup(base_work->coinbase);
}

void set_work_ntime(struct work *work, int ntime)
{
	uint32_t *work_ntime = (uint32_t *)(work->data + 68);

	*work_ntime = htobe32(ntime);
	if (work->ntime) {
		free(work->ntime);
		work->ntime = bin2hex((unsigned char *)work_ntime, 4);
	}
}

/* Generates a copy of an existing work struct, creating fresh heap allocations
 * for all dynamically allocated arrays within the struct. noffset is used for
 * when a driver has internally rolled the ntime, noffset is a relative value.
 * The macro copy_work() calls this function with an noffset of 0. */
struct work *copy_work_noffset(struct work *base_work, int noffset)
{
	struct work *work = make_work();

	_copy_work(work, base_work, noffset);

	return work;
}

void pool_died(struct pool *pool)
{
	if (!pool_tset(pool, &pool->idle)) {
		cgtime(&pool->tv_idle);
		if (pool == current_pool()) {
			applog(LOG_WARNING, "Pool %d %s not responding!", pool->pool_no, pool->rpc_url);
			switch_pools(NULL);
		} else
			applog(LOG_INFO, "Pool %d %s failed to return work", pool->pool_no, pool->rpc_url);
	}
}

static bool stale_work(struct work *work, bool share)
{
	struct timeval now;
	time_t work_expiry;
	struct pool *pool;

	if (opt_benchmark || opt_benchfile)
		return false;

	if (work->work_block != work_block) {
		applog(LOG_DEBUG, "Work stale due to block mismatch");
		return true;
	}

	/* Technically the rolltime should be correct but some pools
	 * advertise a broken expire= that is lower than a meaningful
	 * scantime */
	if (work->rolltime > max_scantime)
		work_expiry = work->rolltime;
	else
		work_expiry = max_expiry;

	pool = work->pool;

	if (!share && pool->has_stratum) {
		bool same_job;

		if (!pool->stratum_active || !pool->stratum_notify) {
			applog(LOG_DEBUG, "Work stale due to stratum inactive");
			return true;
		}

		same_job = true;

		cg_rlock(&pool->data_lock);
		if (strcmp(work->job_id, pool->swork.job_id))
			same_job = false;
		cg_runlock(&pool->data_lock);

		if (!same_job) {
			applog(LOG_DEBUG, "Work stale due to stratum job_id mismatch");
			return true;
		}
	}

	if (unlikely(work_expiry < 5))
		work_expiry = 5;

	cgtime(&now);
	if ((now.tv_sec - work->tv_staged.tv_sec) >= work_expiry) {
		applog(LOG_DEBUG, "Work stale due to expiry");
		return true;
	}

	return false;
}

uint64_t share_diff(const struct work *work)
{
	bool new_best = false;
	double d64, s64;
	uint64_t ret;

	d64 = truediffone;
	s64 = le256todouble(work->hash);
	if (unlikely(!s64))
		s64 = 0;

	ret = round(d64 / s64);

	cg_wlock(&control_lock);
	if (unlikely(ret > best_diff)) {
		new_best = true;
		best_diff = ret;
		suffix_string(best_diff, best_share, sizeof(best_share), 0);
	}
	if (unlikely(ret > work->pool->best_diff))
		work->pool->best_diff = ret;
	cg_wunlock(&control_lock);

	if (unlikely(new_best))
		applog(LOG_DEBUG, "New best share: %s", best_share);

	return ret;
}

static void regen_hash(struct work *work)
{
	uint32_t *data32 = (uint32_t *)(work->data);
	unsigned char swap[80];
	uint32_t *swap32 = (uint32_t *)swap;
	unsigned char hash1[32];

	flip80(swap32, data32);
	sha256(swap, 80, hash1);
	sha256(hash1, 32, (unsigned char *)(work->hash));
}

static bool cnx_needed(struct pool *pool);

/* Find the pool that currently has the highest priority */
static struct pool *priority_pool(int choice)
{
	struct pool *ret = NULL;
	int i;

	for (i = 0; i < total_pools; i++) {
		struct pool *pool = pools[i];

		if (pool->prio == choice) {
			ret = pool;
			break;
		}
	}

	if (unlikely(!ret)) {
		applog(LOG_ERR, "WTF No pool %d found!", choice);
		return pools[choice];
	}
	return ret;
}

void switch_pools(struct pool *selected)
{
	struct pool *pool, *last_pool;
	int i, pool_no, next_pool;

	cg_wlock(&control_lock);
	last_pool = currentpool;
	pool_no = currentpool->pool_no;

	/* Switch selected to pool number 0 and move the rest down */
	if (selected) {
		if (selected->prio != 0) {
			for (i = 0; i < total_pools; i++) {
				pool = pools[i];
				if (pool->prio < selected->prio)
					pool->prio++;
			}
			selected->prio = 0;
		}
	}

	switch (pool_strategy) {
		/* All of these set to the master pool */
		case POOL_BALANCE:
		case POOL_FAILOVER:
		case POOL_LOADBALANCE:
			for (i = 0; i < total_pools; i++) {
				pool = priority_pool(i);
				if (pool_unusable(pool))
					continue;
				pool_no = pool->pool_no;
				break;
			}
			break;
		/* Both of these simply increment and cycle */
		case POOL_ROUNDROBIN:
		case POOL_ROTATE:
			if (selected && !selected->idle) {
				pool_no = selected->pool_no;
				break;
			}
			next_pool = pool_no;
			/* Select the next alive pool */
			for (i = 1; i < total_pools; i++) {
				next_pool++;
				if (next_pool >= total_pools)
					next_pool = 0;
				pool = pools[next_pool];
				if (pool_unusable(pool))
					continue;
				pool_no = next_pool;
				break;
			}
			break;
		default:
			break;
	}

	currentpool = pools[pool_no];
	pool = currentpool;
	cg_wunlock(&control_lock);

	if (pool != last_pool && pool_strategy != POOL_LOADBALANCE && pool_strategy != POOL_BALANCE) {
		applog(LOG_WARNING, "Switching to pool %d %s", pool->pool_no, pool->rpc_url);
		clear_pool_work(last_pool);
	}

	mutex_lock(&lp_lock);
	pthread_cond_broadcast(&lp_cond);
	mutex_unlock(&lp_lock);
}

void _discard_work(struct work **workptr, const char *file, const char *func, const int line)
{
	struct work *work = *workptr;

	if (unlikely(!work)) {
		applog(LOG_ERR, "Discard work called with null work from %s %s:%d",
		       file, func, line);
		return;
	}
	if (!work->clone && !work->rolls && !work->mined) {
		if (work->pool) {
			work->pool->discarded_work++;
			work->pool->quota_used--;
			work->pool->works--;
		}
		total_discarded++;
		applog(LOG_DEBUG, "Discarded work");
	} else
		applog(LOG_DEBUG, "Discarded cloned or rolled work");
	_free_work(workptr, file, func, line);
}

static void wake_gws(void)
{
	mutex_lock(stgd_lock);
	pthread_cond_signal(&gws_cond);
	mutex_unlock(stgd_lock);
}

static void discard_stale(void)
{
	struct work *work, *tmp;
	int stale = 0;

	mutex_lock(stgd_lock);
	HASH_ITER(hh, staged_work, work, tmp) {
		if (stale_work(work, false)) {
			HASH_DEL(staged_work, work);
			discard_work(work);
			stale++;
		}
	}
	pthread_cond_signal(&gws_cond);
	mutex_unlock(stgd_lock);

	if (stale)
		applog(LOG_DEBUG, "Discarded %d stales that didn't match current hash", stale);
}

/* A generic wait function for threads that poll that will wait a specified
 * time tdiff waiting on the pthread conditional that is broadcast when a
 * work restart is required. Returns the value of pthread_cond_timedwait
 * which is zero if the condition was met or ETIMEDOUT if not.
 */
int restart_wait(struct thr_info *thr, unsigned int mstime)
{
	struct timespec abstime, tdiff;
	int rc;

	cgcond_time(&abstime);
	ms_to_timespec(&tdiff, mstime);
	timeraddspec(&abstime, &tdiff);

	mutex_lock(&restart_lock);
	if (thr->work_restart)
		rc = 0;
	else
		rc = pthread_cond_timedwait(&restart_cond, &restart_lock, &abstime);
	mutex_unlock(&restart_lock);

	return rc;
}

static void *restart_thread(void __maybe_unused *arg)
{
	struct cgpu_info *cgpu;
	int i, mt;

	pthread_detach(pthread_self());

	/* Discard staged work that is now stale */
	discard_stale();

	rd_lock(&mining_thr_lock);
	mt = mining_threads;
	rd_unlock(&mining_thr_lock);

	for (i = 0; i < mt; i++) {
		cgpu = mining_thr[i]->cgpu;
		if (unlikely(!cgpu))
			continue;
		if (cgpu->deven != DEV_ENABLED)
			continue;
		// applog(LOG_INFO,"DO SET  info->work_restart  IS TRUE  1111");
		mining_thr[i]->work_restart = true;
		flush_queue(cgpu);
		cgpu->drv->flush_work(cgpu);
	}

	mutex_lock(&restart_lock);
	pthread_cond_broadcast(&restart_cond);
	mutex_unlock(&restart_lock);

	return NULL;
}

/* In order to prevent a deadlock via the various drv->flush_work
 * implementations we send the restart messages via a separate thread. */
static void restart_threads(void)
{
	pthread_t rthread;

	cgtime(&restart_tv_start);
	if (unlikely(pthread_create(&rthread, NULL, restart_thread, NULL)))
		quithere(ERR_CREATE_EXIT, "Failed to create restart thread errno=%d", errno);
}

static void signal_work_update(void)
{
	int i;

	// applog(LOG_INFO, "Work update message received");

	cgtime(&update_tv_start);
	rd_lock(&mining_thr_lock);
	for (i = 0; i < mining_threads; i++)
		mining_thr[i]->work_update = true;
	rd_unlock(&mining_thr_lock);
}

static void set_curblock(const char *hexstr, const unsigned char *bedata)
{
	int ofs;

	cg_wlock(&ch_lock);
	cgtime(&block_timeval);
	strcpy(current_hash, hexstr);
	cg_memcpy(current_block, bedata, 32);
	get_timestamp(blocktime, sizeof(blocktime), &block_timeval);
	cg_wunlock(&ch_lock);

	for (ofs = 0; ofs <= 56; ofs++) {
		if (memcmp(&current_hash[ofs], "0", 1))
			break;
	}
	strncpy(prev_block, &current_hash[ofs], 8);
	prev_block[8] = '\0';

	applog(LOG_INFO, "New block: %s... diff %s", current_hash, block_diff);
}

static int block_sort(struct block *blocka, struct block *blockb)
{
	return blocka->block_no - blockb->block_no;
}

/* Decode the current block difficulty which is in packed form */
static void set_blockdiff(const struct work *work)
{
	uint8_t pow = work->data[72];
	int powdiff = (8 * (0x1d - 3)) - (8 * (pow - 3));
	if (powdiff < 0)
		powdiff = 0;
	uint32_t diff32 = be32toh(*((uint32_t *)(work->data + 72))) & 0x00FFFFFF;
	double numerator = 0xFFFFULL << powdiff;
	double ddiff = numerator / (double)diff32;

	if (unlikely(current_diff != ddiff)) {
		suffix_string(ddiff, block_diff, sizeof(block_diff), 0);
		current_diff = ddiff;
		applog(LOG_NOTICE, "Network diff set to %s", block_diff);
	}
}

/* Search to see if this string is from a block that has been seen before */
static bool block_exists(const char *hexstr, const unsigned char *bedata, const struct work *work)
{
	int deleted_block = 0;
	struct block *s;
	bool ret = true;

	wr_lock(&blk_lock);
	HASH_FIND_STR(blocks, hexstr, s);
	if (!s) {
		s = cgcalloc(1, sizeof(struct block));
		if (unlikely(!s))
			return true;
		strcpy(s->hash, hexstr);
		s->block_no = new_blocks++;

		ret = false;
		/* Only keep the last hour's worth of blocks in memory since
		 * work from blocks before this is virtually impossible and we
		 * want to prevent memory usage from continually rising */
		if (HASH_COUNT(blocks) > 6) {
			struct block *oldblock;

			HASH_SORT(blocks, block_sort);
			oldblock = blocks;
			deleted_block = oldblock->block_no;
			HASH_DEL(blocks, oldblock);
			free(oldblock);
		}
		HASH_ADD_STR(blocks, hash, s);
		set_blockdiff(work);
		if (deleted_block)
			applog(LOG_DEBUG, "Deleted block %d from database", deleted_block);
	}
	wr_unlock(&blk_lock);

	if (!ret)
		set_curblock(hexstr, bedata);
	if (deleted_block)
		applog(LOG_DEBUG, "Deleted block %d from database", deleted_block);

	return ret;
}

static bool test_work_current(struct work *work)
{
	struct pool *pool = work->pool;
	unsigned char bedata[32];
	char hexstr[68];
	bool ret = true;
	unsigned char *bin_height = &pool->coinbase[43];
	uint8_t cb_height_sz = bin_height[-1];
	uint32_t height = 0;

	if (work->mandatory)
		return ret;

	swap256(bedata, work->data + 4);
	__bin2hex(hexstr, bedata, 32);

	/* Calculate block height */
	if (cb_height_sz <= 4) {
		memcpy(&height, bin_height, cb_height_sz);
		height = le32toh(height);
		height--;
	}

	cg_wlock(&pool->data_lock);
	if (pool->swork.clean) {
		pool->swork.clean = false;
		work->longpoll = true;
	}
	if (pool->current_height != height) {
		pool->current_height = height;
	}
	cg_wunlock(&pool->data_lock);

	/* Search to see if this block exists yet and if not, consider it a
	 * new block and set the current block details to this one */
	if (!block_exists(hexstr, bedata, work)) {
		/* Copy the information to this pool's prev_block since it
		 * knows the new block exists. */
		cg_memcpy(pool->prev_block, bedata, 32);
		if (unlikely(new_blocks == 1)) {
			ret = false;
			goto out;
		}

		work->work_block = ++work_block;

		if (work->longpoll) {
			if (work->stratum) {
				applog(LOG_NOTICE, "Stratum from pool %d detected new block at height %d",
				       pool->pool_no, height);
			} else {
				applog(LOG_NOTICE, "%sLONGPOLL from pool %d detected new block at height %d",
				       work->gbt ? "GBT " : "", pool->pool_no, height);
			}
		} else if (have_longpoll && !pool->gbt_solo)
			applog(LOG_NOTICE, "New block detected on network before pool notification from pool %d at height %d",
			       pool->pool_no, height);
		else if (!pool->gbt_solo)
			applog(LOG_NOTICE, "New block detected on network from pool %d at height %d",
			       pool->pool_no, height);
		restart_threads();
	} else {
		if (memcmp(pool->prev_block, bedata, 32)) {
			/* Work doesn't match what this pool has stored as
			 * prev_block. Let's see if the work is from an old
			 * block or the pool is just learning about a new
			 * block. */
			if (memcmp(bedata, current_block, 32)) {
				/* Doesn't match current block. It's stale */
				applog(LOG_DEBUG, "Stale data from pool %d at height %d", pool->pool_no, height);
				ret = false;
			} else {
				/* Work is from new block and pool is up now
				 * current. */
				applog(LOG_INFO, "Pool %d now up to date at height %d", pool->pool_no, height);
				cg_memcpy(pool->prev_block, bedata, 32);
			}
		}
		if (work->longpoll) {
			work->work_block = ++work_block;
			if (shared_strategy() || work->pool == current_pool()) {
				if (work->stratum) {
					applog(LOG_NOTICE, "Stratum from pool %d requested work restart",
					       pool->pool_no);
				} else {
					applog(LOG_NOTICE, "%sLONGPOLL from pool %d requested work restart",
					       work->gbt ? "GBT " : "", pool->pool_no);
				}
				restart_threads();
			}
		}
	}
out:
	work->longpoll = false;

	return ret;
}

static int tv_sort(struct work *worka, struct work *workb)
{
	return worka->tv_staged.tv_sec - workb->tv_staged.tv_sec;
}

static bool work_rollable(struct work *work)
{
	return (!work->clone && work->rolltime);
}

static bool hash_push(struct work *work)
{
	bool rc = true;

	mutex_lock(stgd_lock);
	if (work_rollable(work))
		staged_rollable++;
	if (likely(!getq->frozen)) {
		HASH_ADD_INT(staged_work, id, work);
		HASH_SORT(staged_work, tv_sort);
	} else
		rc = false;
	pthread_cond_broadcast(&getq->cond);
	mutex_unlock(stgd_lock);

	return rc;
}

static void _stage_work(struct work *work)
{
	applog(LOG_DEBUG, "Pushing work from pool %d to hash queue", work->pool->pool_no);
	work->work_block = work_block;
	test_work_current(work);
	work->pool->works++;
	hash_push(work);
}

void zero_bestshare(void)
{
	int i;

	best_diff = 0;
	memset(best_share, 0, 8);
	suffix_string(best_diff, best_share, sizeof(best_share), 0);

	for (i = 0; i < total_pools; i++) {
		struct pool *pool = pools[i];
		pool->best_diff = 0;
	}
}

static struct timeval tv_hashmeter;
static time_t hashdisplay_t;

void zero_stats(void)
{
	int i;
	cgtime(&total_tv_start);
	copy_time(&tv_hashmeter, &total_tv_start);
	total_rolling = 0;
	rolling1 = 0;
	rolling5 = 0;
	rolling15 = 0;
	total_mhashes_done = 0;
	total_getworks = 0;
	total_accepted = 0;
	total_rejected = 0;
	hw_errors = 0;
	total_stale = 0;
	total_discarded = 0;
	local_work = 0;
	total_go = 0;
	total_ro = 0;
	total_secs = 1.0;

	total_diff1 = 0;
	found_blocks = 0;
	total_diff_accepted = 0;
	total_diff_rejected = 0;
	total_diff_stale = 0;

	for (i = 0; i < total_pools; i++) {
		struct pool *pool = pools[i];

		pool->getwork_requested = 0;
		pool->accepted = 0;
		pool->rejected = 0;
		pool->stale_shares = 0;
		pool->discarded_work = 0;
		pool->getfail_occasions = 0;
		pool->remotefail_occasions = 0;
		pool->last_share_time = 0;
		pool->diff1 = 0;
		pool->diff_accepted = 0;
		pool->diff_rejected = 0;
		pool->diff_stale = 0;
		pool->last_share_diff = 0;
	}

	zero_bestshare();

	for (i = 0; i < total_devices; ++i) {
		struct cgpu_info *cgpu = get_devices(i);

		copy_time(&cgpu->dev_start_tv, &total_tv_start);

		mutex_lock(&hash_lock);
		cgpu->total_mhashes = 0;
		cgpu->accepted = 0;
		cgpu->rejected = 0;
		cgpu->hw_errors = 0;
		cgpu->utility = 0.0;
		cgpu->last_share_pool_time = 0;
		cgpu->diff1 = 0;
		cgpu->diff_accepted = 0;
		cgpu->diff_rejected = 0;
		cgpu->last_share_diff = 0;
		mutex_unlock(&hash_lock);

		/* Don't take any locks in the driver zero stats function, as
		 * it's called async from everything else and we don't want to
		 * deadlock. */
		cgpu->drv->zero_stats(cgpu);
	}
}

void default_save_file(char *filename)
{
	if (default_config && *default_config) {
		strcpy(filename, default_config);
		return;
	}

#if defined(unix) || defined(__APPLE__)
	if (getenv("HOME") && *getenv("HOME")) {
	        strcpy(filename, getenv("HOME"));
		strcat(filename, "/");
	}
	else
		strcpy(filename, "");
	strcat(filename, ".cgminer/");
	mkdir(filename, 0777);
#else
	strcpy(filename, "");
#endif
	strcat(filename, def_conf);
}

/* Sole work devices are serialised wrt calling get_work so they report in on
 * each pass through their scanhash function as well as in get_work whereas
 * queued work devices work asynchronously so get them to report in and out
 * only across get_work. */
static void thread_reportin(struct thr_info *thr)
{
	thr->getwork = false;
	cgtime(&thr->last);
	thr->cgpu->status = LIFE_WELL;
	thr->cgpu->device_last_well = time(NULL);
}

/* Tell the watchdog thread this thread is waiting on get work and should not
 * be restarted */
static void thread_reportout(struct thr_info *thr)
{
	thr->getwork = true;
	cgtime(&thr->last);
	thr->cgpu->status = LIFE_WELL;
	thr->cgpu->device_last_well = time(NULL);
}

static void hashmeter(int thr_id, uint64_t hashes_done)
{
	bool showlog = false;
	double tv_tdiff;
	time_t now_t;
	int diff_t;
	cgtime(&total_tv_end);
	tv_tdiff = tdiff(&total_tv_end, &tv_hashmeter);
	now_t = total_tv_end.tv_sec;
	diff_t = now_t - hashdisplay_t;
	if (diff_t >= opt_log_interval) {
		alt_status ^= switch_status;
		hashdisplay_t = now_t;
		showlog = true;
	} else if (thr_id < 0) {
		/* hashmeter is called by non-mining threads in case nothing
		 * has reported in to allow hashrate to converge to zero , but
		 * we only update if it has been more than opt_log_interval */
		return;
	}
	copy_time(&tv_hashmeter, &total_tv_end);

	if (thr_id >= 0) {
		struct thr_info *thr = get_thread(thr_id);
		struct cgpu_info *cgpu = thr->cgpu;
		double device_tdiff, thr_mhs;

		/* Update the last time this thread reported in */
		copy_time(&thr->last, &total_tv_end);
		cgpu->device_last_well = now_t;
		device_tdiff = tdiff(&total_tv_end, &cgpu->last_message_tv);
		copy_time(&cgpu->last_message_tv, &total_tv_end);
		thr_mhs = (double)hashes_done / device_tdiff / 1000000;
		applog(LOG_DEBUG, "[thread %d: %"PRIu64" hashes, %.1f mhash/sec]",
		       thr_id, hashes_done, thr_mhs);
		hashes_done /= 1000000;

		mutex_lock(&hash_lock);
		cgpu->total_mhashes += hashes_done;
		decay_time(&cgpu->rolling, hashes_done, device_tdiff, opt_log_interval);
		decay_time(&cgpu->rolling1, hashes_done, device_tdiff, 60.0);
		decay_time(&cgpu->rolling5, hashes_done, device_tdiff, 300.0);
		decay_time(&cgpu->rolling15, hashes_done, device_tdiff, 900.0);
		mutex_unlock(&hash_lock);

		if (want_per_device_stats && showlog) {
			char logline[256];

			get_statline(logline, sizeof(logline), cgpu);
			if (!curses_active) {
				printf("%s          \r", logline);
				fflush(stdout);
			} else
				applog(LOG_INFO, "%s", logline);
		}
	} else {
		/* No device has reported in, we have been called from the
		 * watchdog thread so decay all the hashrates */
		mutex_lock(&hash_lock);
		for (thr_id = 0; thr_id < mining_threads; thr_id++) {
			struct thr_info *thr = get_thread(thr_id);
			struct cgpu_info *cgpu = thr->cgpu;
			double device_tdiff  = tdiff(&total_tv_end, &cgpu->last_message_tv);

			copy_time(&cgpu->last_message_tv, &total_tv_end);
			decay_time(&cgpu->rolling, 0, device_tdiff, opt_log_interval);
			decay_time(&cgpu->rolling1, 0, device_tdiff, 60.0);
			decay_time(&cgpu->rolling5, 0, device_tdiff, 300.0);
			decay_time(&cgpu->rolling15, 0, device_tdiff, 900.0);
		}
		mutex_unlock(&hash_lock);
	}

	mutex_lock(&hash_lock);
	total_mhashes_done += hashes_done;
	decay_time(&total_rolling, hashes_done, tv_tdiff, opt_log_interval);
	decay_time(&rolling1, hashes_done, tv_tdiff, 60.0);
	decay_time(&rolling5, hashes_done, tv_tdiff, 300.0);
	decay_time(&rolling15, hashes_done, tv_tdiff, 900.0);
	global_hashrate = llround(total_rolling) * 1000000;

	total_secs = tdiff(&total_tv_end, &total_tv_start);

	if (showlog) {
		char displayed_hashes[16], displayed_rolling[16];
		char displayed_r1[16], displayed_r5[16], displayed_r15[16];
		uint64_t d64;

		d64 = (double)total_mhashes_done / total_secs * 1000000ull;
		suffix_string(d64, displayed_hashes, sizeof(displayed_hashes), 4);
		d64 = (double)total_rolling * 1000000ull;
		suffix_string(d64, displayed_rolling, sizeof(displayed_rolling), 4);
		d64 = (double)rolling1 * 1000000ull;
		suffix_string(d64, displayed_r1, sizeof(displayed_rolling), 4);
		d64 = (double)rolling5 * 1000000ull;
		suffix_string(d64, displayed_r5, sizeof(displayed_rolling), 4);
		d64 = (double)rolling15 * 1000000ull;
		suffix_string(d64, displayed_r15, sizeof(displayed_rolling), 4);

		snprintf(statusline, sizeof(statusline),
			"(%ds):%s (1m):%s (5m):%s (15m):%s (avg):%sh/s",
			opt_log_interval, displayed_rolling, displayed_r1, displayed_r5,
			displayed_r15, displayed_hashes);
	}
	mutex_unlock(&hash_lock);

#ifdef USE_LIBSYSTEMD
	sd_notifyf(false, "STATUS=%s", statusline);
#endif

	if (showlog) {
		if (!curses_active) {
			printf("%s          \r", statusline);
			fflush(stdout);
		}
		// else
		// 	applog(LOG_WARNING, "%s", statusline);
	}
}

static void stratum_share_result(json_t *val, json_t *res_val, json_t *err_val,
				 struct stratum_share *sshare)
{
	struct work *work = sshare->work;
	time_t now_t = time(NULL);
	char hashshow[64];
	int srdiff;

	srdiff = now_t - sshare->sshare_sent;
	if (opt_debug || srdiff > 0) {
		applog(LOG_INFO, "Pool %d stratum share result lag time %d seconds",
		       work->pool->pool_no, srdiff);
	}
	show_hash(work, hashshow);
	share_result(val, res_val, err_val, work, hashshow, false, "");
}

/* Parses stratum json responses and tries to find the id that the request
 * matched to and treat it accordingly. */
static bool parse_stratum_response(struct pool *pool, char *s)
{
	json_t *val = NULL, *err_val, *res_val, *id_val;
	struct stratum_share *sshare;
	json_error_t err;
	bool ret = false;
	int id;

	val = JSON_LOADS(s, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");

	if (json_is_null(id_val) || !id_val) {
		char *ss;

		if (err_val)
			ss = json_dumps(err_val, JSON_INDENT(3));
		else
			ss = strdup("(unknown reason)");

		applog(LOG_INFO, "JSON-RPC non method decode failed: %s", ss);

		free(ss);

		goto out;
	}

	id = json_integer_value(id_val);

	mutex_lock(&sshare_lock);
	HASH_FIND_INT(stratum_shares, &id, sshare);
	if (sshare) {
		HASH_DEL(stratum_shares, sshare);
		pool->sshares--;
	}
	mutex_unlock(&sshare_lock);

	if (!sshare) {
		double pool_diff;

		if (!res_val)
			goto out;
		/* Since the share is untracked, we can only guess at what the
		 * work difficulty is based on the current pool diff. */
		cg_rlock(&pool->data_lock);
		pool_diff = pool->sdiff;
		cg_runlock(&pool->data_lock);

		if (json_is_true(res_val)) {
			applog(LOG_NOTICE, "Accepted untracked stratum share from pool %d", pool->pool_no);

			/* We don't know what device this came from so we can't
			 * attribute the work to the relevant cgpu */
			mutex_lock(&stats_lock);
			total_accepted++;
			pool->accepted++;
			total_diff_accepted += pool_diff;
			pool->diff_accepted += pool_diff;
			mutex_unlock(&stats_lock);
		} else {
			applog(LOG_NOTICE, "Rejected untracked stratum share from pool %d", pool->pool_no);

			mutex_lock(&stats_lock);
			total_rejected++;
			pool->rejected++;
			total_diff_rejected += pool_diff;
			pool->diff_rejected += pool_diff;
			mutex_unlock(&stats_lock);
		}
		goto out;
	}
	stratum_share_result(val, res_val, err_val, sshare);
	free_work(sshare->work);
	free(sshare);

	ret = true;
out:
	if (val)
		json_decref(val);

	return ret;
}

void clear_stratum_shares(struct pool *pool)
{
	struct stratum_share *sshare, *tmpshare;
	double diff_cleared = 0;
	int cleared = 0;

	mutex_lock(&sshare_lock);
	HASH_ITER(hh, stratum_shares, sshare, tmpshare) {
		if (sshare->work->pool == pool) {
			HASH_DEL(stratum_shares, sshare);
			diff_cleared += sshare->work->work_difficulty;
			free_work(sshare->work);
			pool->sshares--;
			free(sshare);
			cleared++;
		}
	}
	mutex_unlock(&sshare_lock);

	if (cleared) {
		applog(LOG_WARNING, "Lost %d shares due to stratum disconnect on pool %d", cleared, pool->pool_no);
		pool->stale_shares += cleared;
		total_stale += cleared;
		pool->diff_stale += diff_cleared;
		total_diff_stale += diff_cleared;
	}
}

void clear_pool_work(struct pool *pool)
{
	struct work *work, *tmp;
	int cleared = 0;

	mutex_lock(stgd_lock);
	HASH_ITER(hh, staged_work, work, tmp) {
		if (work->pool == pool) {
			HASH_DEL(staged_work, work);
			free_work(work);
			cleared++;
		}
	}
	mutex_unlock(stgd_lock);

	if (cleared)
		applog(LOG_INFO, "Cleared %d work items due to stratum disconnect on pool %d", cleared, pool->pool_no);
}

static int cp_prio(void)
{
	int prio;

	cg_rlock(&control_lock);
	prio = currentpool->prio;
	cg_runlock(&control_lock);

	return prio;
}

/* We only need to maintain a secondary pool connection when we need the
 * capacity to get work from the backup pools while still on the primary */
static bool cnx_needed(struct pool *pool)
{
	struct pool *cp;

	if (pool->enabled != POOL_ENABLED)
		return false;

	/* Balance strategies need all pools online */
	if (pool_strategy == POOL_BALANCE)
		return true;
	if (pool_strategy == POOL_LOADBALANCE)
		return true;

	/* Idle stratum pool needs something to kick it alive again */
	if (pool->has_stratum && pool->idle)
		return true;

	cp = current_pool();
	if (cp == pool)
		return true;
	/* If we're waiting for a response from shares submitted, keep the
	 * connection open. */
	if (pool->sshares)
		return true;
	/* If the pool has only just come to life and is higher priority than
	 * the current pool keep the connection open so we can fail back to
	 * it. */
	if (pool_strategy == POOL_FAILOVER && pool->prio < cp_prio())
		return true;
	/* We've run out of work, bring anything back to life. */
	if (no_work)
		return true;
	return false;
}

static void wait_lpcurrent(struct pool *pool);
static void pool_resus(struct pool *pool);
static void gen_stratum_work(struct pool *pool, struct work *work);

void stratum_resumed(struct pool *pool)
{
	if (pool_tclear(pool, &pool->idle)) {
		applog(LOG_INFO, "Stratum connection to pool %d resumed", pool->pool_no);
		pool_resus(pool);
	}
}

static bool supports_resume(struct pool *pool)
{
	bool ret;

	cg_rlock(&pool->data_lock);
	ret = (pool->sessionid != NULL);
	cg_runlock(&pool->data_lock);

	return ret;
}
/* Generates stratum based work based on the most recent notify information
 * from the pool. This will keep generating work while a pool is down so we use
 * other means to detect when the pool has died in stratum_thread */
static void gen_stratum_work(struct pool *pool, struct work *work)
{
	unsigned char merkle_root[32], merkle_sha[64];
	uint32_t *data32, *swap32;
	uint64_t nonce2le;
	int i;

	cg_wlock(&pool->data_lock);

	/* Update coinbase. Always use an LE encoded nonce2 to fill in values
	 * from left to right and prevent overflow errors with small n2sizes */
	nonce2le = htole64(pool->nonce2);
	cg_memcpy(pool->coinbase + pool->nonce2_offset, &nonce2le, pool->n2size);
	work->nonce2 = pool->nonce2++;
	work->nonce2_len = pool->n2size;

	/* Downgrade to a read lock to read off the pool variables */
	cg_dwlock(&pool->data_lock);

	/* Generate merkle root */
	gen_hash(pool->coinbase, merkle_root, pool->coinbase_len);
	cg_memcpy(merkle_sha, merkle_root, 32);
	for (i = 0; i < pool->merkles; i++) {
		cg_memcpy(merkle_sha + 32, pool->swork.merkle_bin[i], 32);
		gen_hash(merkle_sha, merkle_root, 64);
		cg_memcpy(merkle_sha, merkle_root, 32);
	}
	data32 = (uint32_t *)merkle_sha;
	swap32 = (uint32_t *)merkle_root;
	flip32(swap32, data32);

	/* Copy the data template from header_bin */
	cg_memcpy(work->data, pool->header_bin, 112);
	cg_memcpy(work->data + 36, merkle_root, 32);

	/* Store the stratum work diff to check it still matches the pool's
	 * stratum diff when submitting shares */
	work->sdiff = pool->sdiff;

	/* Copy parameters required for share submission */
	work->job_id = strdup(pool->swork.job_id);
	work->nonce1 = strdup(pool->nonce1);
	work->ntime = strdup(pool->ntime);
	cg_runlock(&pool->data_lock);

	if (opt_debug) {
		char *header, *merkle_hash;

		header = bin2hex(work->data, 112);
		merkle_hash = bin2hex((const unsigned char *)merkle_root, 32);
		applog(LOG_INFO, "Generated stratum merkle %s", merkle_hash);
		applog(LOG_INFO, "Generated stratum header %s", header);
		applog(LOG_INFO, "Work job_id %s nonce2 %"PRIu64" ntime %s", work->job_id,
		       work->nonce2, work->ntime);
		free(header);
		free(merkle_hash);
	}

	calc_midstate(pool, work);
	set_target(work->target, work->sdiff);

	local_work++;
	work->pool = pool;
	work->stratum = true;
	work->nonce = 0;
	work->longpoll = false;
	work->getwork_level = GETWORK_MODE_STRATUM;
	work->work_block = work_block;
	/* Nominally allow a driver to ntime roll 60 seconds */
	work->drv_rolllimit = 60;
	calc_diff(work, work->sdiff);

	cgtime(&work->tv_staged);
}
/* One stratum receive thread per pool that has stratum waits on the socket
 * checking for new messages and for the integrity of the socket connection. We
 * reset the connection based on the integrity of the receive side only as the
 * send side will eventually expire data it fails to send. */
static bool ping_flag=false;
struct timeval ping_start, ping_end;
static void *stratum_rthread(void *userdata)
{
	struct pool *pool = (struct pool *)userdata;
	char threadname[16];

	pthread_detach(pthread_self());

	snprintf(threadname, sizeof(threadname), "%d/RStratum", pool->pool_no);
	rename_thread(threadname);

	while (42) {
		struct timeval timeout;
		int sel_ret;
		fd_set rd;
		char *s;

		if (unlikely(pool->removed)) {
			suspend_stratum(pool);
			break;
		}
		static int share_av_time[4];
		if(ping_flag == true){
			struct cgpu_info *cgpu = get_devices(0);
			int ping_diff = 0,count = 0;
			cgtime(&ping_end); //get share end time
			ping_diff = ms_tdiff(&ping_end, &pool->sshare_send);
			share_av_time[3] = 0;
			share_av_time[2] = share_av_time[1];
			share_av_time[1] = share_av_time[0];
			share_av_time[0] = ping_diff;
			for(int i = 0;i < 3;i++){
				if(share_av_time[i] > 0){
					share_av_time[3] += share_av_time[i];
					count++;
				}
				else{
					break;
				}
			}
			if(count != 0)
				cgpu->share_ping = share_av_time[3]/count; //get submission lag time
			ping_flag = false;
		}

		/* Check to see whether we need to maintain this connection
		 * indefinitely or just bring it up when we switch to this
		 * pool */
		if (!sock_full(pool) && !cnx_needed(pool)) {
			suspend_stratum(pool);
			clear_stratum_shares(pool);
			clear_pool_work(pool);

			wait_lpcurrent(pool);
			while (!restart_stratum(pool)) {
				pool_died(pool);
				if (pool->removed)
					goto out;
				cgsleep_ms(5000);
			}
		}

		FD_ZERO(&rd);
		FD_SET(pool->sock, &rd);
		timeout.tv_sec = 90;
		timeout.tv_usec = 0;

		/* The protocol specifies that notify messages should be sent
		 * every minute so if we fail to receive any for 90 seconds we
		 * assume the connection has been dropped and treat this pool
		 * as dead */
		if (!sock_full(pool) && (sel_ret = select(pool->sock + 1, &rd, NULL, NULL, &timeout)) < 1) {
			applog(LOG_DEBUG, "Stratum select failed on pool %d with value %d", pool->pool_no, sel_ret);
			s = NULL;
		} else
			s = recv_line(pool);
		if (!s) {
			applog(LOG_NOTICE, "Stratum connection to pool %d interrupted", pool->pool_no);
			pool->getfail_occasions++;
			total_go++;

			/* If the socket to our stratum pool disconnects, all
			 * tracked submitted shares are lost and we will leak
			 * the memory if we don't discard their records. */
			if (!supports_resume(pool) || opt_lowmem)
				clear_stratum_shares(pool);
			clear_pool_work(pool);
			if (pool == current_pool())
				restart_threads();

			while (!restart_stratum(pool)) {
				pool_died(pool);
				if (pool->removed)
					goto out;
				cgsleep_ms(5000);
			}
			continue;
		}

		/* Check this pool hasn't died while being a backup pool and
		 * has not had its idle flag cleared */
		stratum_resumed(pool);

		if (!parse_method(pool, s) && !parse_stratum_response(pool, s))
			applog(LOG_INFO, "Unknown stratum msg: %s", s);
		else if (pool->swork.clean) {
			struct work *work = make_work();
			if(work != NULL)
			{
				/* Generate a single work item to update the current
				* block database */
				gen_stratum_work(pool, work);
				/* Return value doesn't matter. We're just informing
				* that we may need to restart. */
				test_work_current(work);
				free_work(work);
			}
		}
		free(s);
	}

out:
	return NULL;
}

/* Each pool has one stratum send thread for sending shares to avoid many
 * threads being created for submission since all sends need to be serialised
 * anyway. */
static void *stratum_sthread(void *userdata)
{
	struct pool *pool = (struct pool *)userdata;
	uint64_t last_nonce2 = 0;
	uint32_t last_nonce = 0;
	char threadname[16];

	pthread_detach(pthread_self());

	snprintf(threadname, sizeof(threadname), "%d/SStratum", pool->pool_no);
	rename_thread(threadname);

	int trycnt = 0;
	do {
		pool->stratum_q = tq_new();
		trycnt++;
	} while((!pool->stratum_q) && (trycnt < 5));
	if (!pool->stratum_q)
		return NULL;

	while (42) {
		char noncehex[12], nonce2hex[20], s[1024];
		struct stratum_share *sshare;
		uint32_t *hash32, nonce;
		unsigned char nonce2[8];
		uint64_t *nonce2_64;
		struct work *work;
		bool submitted;

		if (unlikely(pool->removed))
			break;

		work = tq_pop(pool->stratum_q);
		if (unlikely(!work))
			continue;

		if (unlikely(work->nonce2_len > 8)) {
			applog(LOG_ERR, "Pool %d asking for inappropriately long nonce2 length %d",
			       pool->pool_no, (int)work->nonce2_len);
			applog(LOG_ERR, "Not attempting to submit shares");
			free_work(work);
			continue;
		}

		nonce = *((uint32_t *)(work->data + 76));
		nonce2_64 = (uint64_t *)nonce2;
		*nonce2_64 = htole64(work->nonce2);
		/* Filter out duplicate shares */
		if (unlikely(nonce == last_nonce && *nonce2_64 == last_nonce2)) {
			applog(LOG_INFO, "Filtering duplicate share to pool %d",
			       pool->pool_no);
			free_work(work);
			continue;
		}
		last_nonce = nonce;
		last_nonce2 = *nonce2_64;
		__bin2hex(noncehex, (const unsigned char *)&nonce, 4);
		__bin2hex(nonce2hex, nonce2, work->nonce2_len);

		sshare = cgcalloc(1, sizeof(struct stratum_share));
		hash32 = (uint32_t *)work->hash;
		submitted = false;

		sshare->sshare_time = time(NULL);
		
		/* This work item is freed in parse_stratum_response */
		sshare->work = work;
		memset(s, 0, 1024);

		mutex_lock(&sshare_lock);
		/* Give the stratum share a unique id */
		sshare->id = swork_id++;
		mutex_unlock(&sshare_lock);

		if (pool->vmask) {
			snprintf(s, sizeof(s),
				 "{\"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\": %d, \"method\": \"mining.submit\"}",
				pool->rpc_user, work->job_id, nonce2hex, work->ntime, noncehex, pool->vmask_002[work->micro_job_id], sshare->id);
		} else {
			snprintf(s, sizeof(s),
				"{\"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\": %d, \"method\": \"mining.submit\"}",
				pool->rpc_user, work->job_id, nonce2hex, work->ntime, noncehex, sshare->id);
		}

		applog(LOG_DEBUG, "Submitting share %08lx to pool %d",
					(long unsigned int)htole32(hash32[6]), pool->pool_no);

		/* Try resubmitting for up to 2 minutes if we fail to submit
		 * once and the stratum pool nonce1 still matches suggesting
		 * we may be able to resume. */
		while (time(NULL) < sshare->sshare_time + 120) {
			bool sessionid_match;

			if (likely(stratum_send(pool, s, strlen(s)))) {
				mutex_lock(&sshare_lock);
				HASH_ADD_INT(stratum_shares, id, sshare);
				pool->sshares++;
				mutex_unlock(&sshare_lock);

				if (pool_tclear(pool, &pool->submit_fail))
						applog(LOG_WARNING, "Pool %d communication resumed, submitting work", pool->pool_no);
				applog(LOG_DEBUG, "Successfully submitted, adding to stratum_shares db");
				submitted = true;
				break;
			}
			if (!pool_tset(pool, &pool->submit_fail) && cnx_needed(pool)) {
				applog(LOG_WARNING, "Pool %d stratum share submission failure", pool->pool_no);
				total_ro++;
				pool->remotefail_occasions++;
			}

			if (opt_lowmem) {
				applog(LOG_DEBUG, "Lowmem option prevents resubmitting stratum share");
				break;
			}

			cg_rlock(&pool->data_lock);
			sessionid_match = (pool->nonce1 && !strcmp(work->nonce1, pool->nonce1));
			cg_runlock(&pool->data_lock);

			if (!sessionid_match) {
				applog(LOG_DEBUG, "No matching session id for resubmitting stratum share");
				break;
			}
			/* Retry every 5 seconds */
			sleep(5);
		}

		if (unlikely(!submitted)) {
			applog(LOG_DEBUG, "Failed to submit stratum share, discarding");
			free_work(work);
			free(sshare);
			pool->stale_shares++;
			total_stale++;
		} else {
			int ssdiff;
			//ping start time
			if(ping_flag==false){
				cgtime(&pool->sshare_send);
				ping_flag=true;
			}
			sshare->sshare_sent = time(NULL);
			ssdiff = sshare->sshare_sent - sshare->sshare_time;
			if (opt_debug || ssdiff > 0) {
				applog(LOG_INFO, "Pool %d stratum share submission lag time %d seconds",
				       pool->pool_no, ssdiff);
			}
		}
	}

	/* Freeze the work queue but don't free up its memory in case there is
	 * work still trying to be submitted to the removed pool. */
	tq_freeze(pool->stratum_q);

	return NULL;
}

static void init_stratum_threads(struct pool *pool)
{
	have_longpoll = true;

	if (unlikely(pthread_create(&pool->stratum_sthread, NULL, stratum_sthread, (void *)pool)))
		applog(LOG_INFO, "Failed to create stratum sthread");
	if (unlikely(pthread_create(&pool->stratum_rthread, NULL, stratum_rthread, (void *)pool)))
		applog(LOG_INFO, "Failed to create stratum rthread");
}

static void *longpoll_thread(void *userdata);

static bool stratum_works(struct pool *pool)
{
	// applog(LOG_INFO, "Testing pool %d stratum %s", pool->pool_no, pool->stratum_url);
	check_extranonce_option(pool, pool->stratum_url);
	if (!extract_sockaddr(pool->stratum_url, &pool->sockaddr_url, &pool->stratum_port))
		return false;

	if (!initiate_stratum(pool))
		return false;

	return true;
}

static bool setup_gbt_solo(CURL __maybe_unused *curl, struct pool __maybe_unused *pool)
{
	return false;
}

static void pool_start_lp(struct pool *pool)
{
	if (!pool->lp_started) {
		pool->lp_started = true;
		if (unlikely(pthread_create(&pool->longpoll_thread, NULL, longpoll_thread, (void *)pool)))
			applog(LOG_INFO, "Failed to create pool longpoll thread");
	}
}

static bool pool_active(struct pool *pool, bool pinging)
{
	struct timeval tv_getwork, tv_getwork_reply;
	json_t *val = NULL;
	bool ret = false;
	CURL *curl;
	int uninitialised_var(rolltime);

	if (pool->has_gbt)
		applog(LOG_DEBUG, "Retrieving block template from pool %s", pool->rpc_url);
	// else
	// 	applog(LOG_INFO, "Testing pool %s", pool->rpc_url);

	/* This is the central point we activate stratum when we can */
retry_stratum:
	if (pool->has_stratum) {
		/* We create the stratum thread for each pool just after
		 * successful authorisation. Once the init flag has been set
		 * we never unset it and the stratum thread is responsible for
		 * setting/unsetting the active flag */
		bool init = pool_tset(pool, &pool->stratum_init);

		if (!init) {
			bool ret = initiate_stratum(pool) && auth_stratum(pool);
			extranonce_subscribe_stratum(pool);
			if (ret)
				init_stratum_threads(pool);
			else
				pool_tclear(pool, &pool->stratum_init);
			return ret;
		}
		return pool->stratum_active;
	}

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialisation failed");
		return false;
	}

	/* Probe for GBT support on first pass */
	if (!pool->probed) {
		applog(LOG_DEBUG, "Probing for GBT support");
		val = json_rpc_call(curl, pool->rpc_url, pool->rpc_userpass,
					gbt_req, true, false, &rolltime, pool, false);
		if (val) {
			json_t *rules_arr = json_object_get(val, "rules");

			if (!gbt_check_rules(rules_arr, gbt_understood_rules)) {
				applog(LOG_DEBUG, "Not all rules understood for GBT");
				json_decref(val);
				val = NULL;
			}
		}
		if (!val) {
			json_t *rules_arr;

			applog(LOG_DEBUG, "Probing for GBT solo support");
			val = json_rpc_call(curl, pool->rpc_url, pool->rpc_userpass,
					gbt_solo_req, true, false, &rolltime, pool, false);
			rules_arr = json_object_get(val, "rules");
			if (!gbt_check_rules(rules_arr, gbt_solo_understood_rules)) {
				applog(LOG_DEBUG, "Not all rules understood for GBT solo");
				json_decref(val);
				val = NULL;
			}
		}
		if (val) {
			bool append = false, submit = false, transactions = false;
			json_t *res_val, *mutables;
			int i, mutsize = 0;

			res_val = json_object_get(val, "result");
			if (res_val) {
				mutables = json_object_get(res_val, "mutable");
				mutsize = json_array_size(mutables);
			}

			for (i = 0; i < mutsize; i++) {
				json_t *arrval = json_array_get(mutables, i);

				if (json_is_string(arrval)) {
					const char *mutable = json_string_value(arrval);

					if (!strncasecmp(mutable, "coinbase/append", 15))
						append = true;
					else if (!strncasecmp(mutable, "submit/coinbase", 15))
						submit = true;
					else if (!strncasecmp(mutable, "transactions", 12))
						transactions = true;
				}
			}
			json_decref(val);

			/* Only use GBT if it supports coinbase append and
			 * submit coinbase */
			if (append && submit) {
				pool->has_gbt = true;
				pool->rpc_req = gbt_req;
			} else if (transactions) {
				pool->rpc_req = gbt_solo_req;
				/* Set up gbt_curl before setting gbt_solo
				 * flag to prevent longpoll thread from
				 * trying to use an un'inited gbt_curl */
				pool->gbt_curl = curl_easy_init();
				if (unlikely(!pool->gbt_curl))
					quit(ERR_POOL_EXIT, "GBT CURL initialisation failed");
				pool->gbt_solo = true;
				if (!opt_btcd)
					opt_btcd = pool;
			}
		}
		/* Reset this so we can probe fully just after this. It will be
		 * set to true that time.*/
		pool->probed = false;

		if (pool->has_gbt)
			applog(LOG_DEBUG, "GBT coinbase + append support found, switching to GBT protocol");
		else if (pool->gbt_solo)
			applog(LOG_DEBUG, "GBT coinbase without append found, switching to GBT solo protocol");
		else
			applog(LOG_DEBUG, "No GBT coinbase + append support found, pool unusable if it has no stratum");
	}

	cgtime(&tv_getwork);
	val = json_rpc_call(curl, pool->rpc_url, pool->rpc_userpass,
			    pool->rpc_req, true, false, &rolltime, pool, false);
	cgtime(&tv_getwork_reply);

	/* Detect if a http pool has an X-Stratum header at startup,
	 * and if so, switch to that in preference to gbt if it works */
	if (pool->stratum_url && !opt_fix_protocol && stratum_works(pool)) {
		applog(LOG_NOTICE, "Switching pool %d %s to %s", pool->pool_no, pool->rpc_url, pool->stratum_url);
		if (!pool->rpc_url)
			pool->rpc_url = strdup(pool->stratum_url);
		pool->has_stratum = true;
		curl_easy_cleanup(curl);

		goto retry_stratum;
	}

	if (!pool->has_stratum && !pool->gbt_solo && !pool->has_gbt) {
		applog(LOG_WARNING, "No Stratum, GBT or Solo support in pool %d %s unable to use", pool->pool_no, pool->rpc_url);
		return false;
	}
	if (val) {
		struct work *work = make_work();
		bool rc;

		rc = work_decode(pool, work, val);
		if (rc) {
			applog(LOG_DEBUG, "Successfully retrieved and deciphered work from pool %u %s",
			       pool->pool_no, pool->rpc_url);
			if (pool->gbt_solo) {
				ret = setup_gbt_solo(curl, pool);
				if (ret)
					pool_start_lp(pool);
				free_work(work);
				goto out;
			}
			work->pool = pool;
			work->rolltime = rolltime;
			copy_time(&work->tv_getwork, &tv_getwork);
			copy_time(&work->tv_getwork_reply, &tv_getwork_reply);
			work->getwork_level = GETWORK_MODE_TESTPOOL;
			calc_diff(work, 0);
			applog(LOG_DEBUG, "Pushing pooltest work to base pool");

			stage_work(work);
			total_getworks++;
			pool->getwork_requested++;
			ret = true;
		} else {
			applog(LOG_DEBUG, "Successfully retrieved but FAILED to decipher work from pool %u %s",
			       pool->pool_no, pool->rpc_url);
			free_work(work);
		}

		if (pool->lp_url)
			goto out;

		/* Decipher the longpoll URL, if any, and store it in ->lp_url */
		if (pool->hdr_path) {
			char *copy_start, *hdr_path;
			bool need_slash = false;
			size_t siz;

			hdr_path = pool->hdr_path;
			if (strstr(hdr_path, "://")) {
				pool->lp_url = hdr_path;
				hdr_path = NULL;
			} else {
				/* absolute path, on current server */
				copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
				if (pool->rpc_url[strlen(pool->rpc_url) - 1] != '/')
					need_slash = true;

				siz = strlen(pool->rpc_url) + strlen(copy_start) + 2;
				pool->lp_url = cgmalloc(siz);
				if(pool->lp_url)
					snprintf(pool->lp_url, siz, "%s%s%s", pool->rpc_url, need_slash ? "/" : "", copy_start);
			}
		} else
			pool->lp_url = NULL;

		pool_start_lp(pool);
	} else {
		applog(LOG_DEBUG, "FAILED to retrieve work from pool %u %s",
		       pool->pool_no, pool->rpc_url);
		if (!pinging && !pool->idle)
			applog(LOG_WARNING, "Pool %u slow/down or URL or credentials invalid", pool->pool_no);
	}
out:
	if (val)
		json_decref(val);
	curl_easy_cleanup(curl);
	return ret;
}

static void pool_resus(struct pool *pool)
{
	pool->seq_getfails = 0;
	if (pool_strategy == POOL_FAILOVER && pool->prio < cp_prio())
		applog(LOG_WARNING, "Pool %d %s alive, testing stability", pool->pool_no, pool->rpc_url);
	else
		applog(LOG_INFO, "Pool %d %s alive", pool->pool_no, pool->rpc_url);
}

static bool work_emptied;

/* If this is called non_blocking, it will return NULL for work so that must
 * be handled. */
static struct work *hash_pop(bool blocking)
{
	struct work *work = NULL, *tmp;
	int hc;

	mutex_lock(stgd_lock);
	if (!HASH_COUNT(staged_work)) {
		work_emptied = true;
		if (!blocking)
			goto out_unlock;
		do {
			struct timespec abstime, tdiff = {10, 0};
			int rc;

			cgcond_time(&abstime);
			timeraddspec(&abstime, &tdiff);
			pthread_cond_signal(&gws_cond);
			rc = pthread_cond_timedwait(&getq->cond, stgd_lock, &abstime);
			/* Check again for !no_work as multiple threads may be
				* waiting on this condition and another may set the
				* bool separately. */
			if (rc && !no_work) {
				no_work = true;
				applog(LOG_WARNING, "Waiting for work to be available from pools.");
			}
		} while (!HASH_COUNT(staged_work));
	}

	if (no_work) {
		applog(LOG_WARNING, "Work available from pools, resuming.");
		no_work = false;
	}

	hc = HASH_COUNT(staged_work);
	/* Find clone work if possible, to allow masters to be reused */
	if (hc > staged_rollable) {
		HASH_ITER(hh, staged_work, work, tmp) {
			if (!work_rollable(work))
				break;
		}
	} else
		work = staged_work;
	HASH_DEL(staged_work, work);
	if (work_rollable(work))
		staged_rollable--;

	/* Signal the getwork scheduler to look for more work */
	pthread_cond_signal(&gws_cond);

	/* Signal hash_pop again in case there are mutliple hash_pop waiters */
	pthread_cond_signal(&getq->cond);

	/* Keep track of last getwork grabbed */
	last_getwork = time(NULL);
out_unlock:
	mutex_unlock(stgd_lock);

	return work;
}

static void gen_hash(unsigned char *data, unsigned char *hash, int len)
{
	unsigned char hash1[32];

	sha256(data, len, hash1);
	sha256(hash1, 32, hash);
}

void set_target(unsigned char *dest_target, double diff)
{
	unsigned char target[32];
	uint64_t *data64, h64;
	double d64, dcut64;

	if (unlikely(diff == 0.0)) {
		/* This shouldn't happen but best we check to prevent a crash */
		applog(LOG_ERR, "Diff zero passed to set_target");
		diff = 1.0;
	}

	d64 = truediffone;
	d64 /= diff;

	dcut64 = d64 / bits192;
	h64 = dcut64;
	data64 = (uint64_t *)(target + 24);
	*data64 = htole64(h64);
	dcut64 = h64;
	dcut64 *= bits192;
	d64 -= dcut64;

	dcut64 = d64 / bits128;
	h64 = dcut64;
	data64 = (uint64_t *)(target + 16);
	*data64 = htole64(h64);
	dcut64 = h64;
	dcut64 *= bits128;
	d64 -= dcut64;

	dcut64 = d64 / bits64;
	h64 = dcut64;
	data64 = (uint64_t *)(target + 8);
	*data64 = htole64(h64);
	dcut64 = h64;
	dcut64 *= bits64;
	d64 -= dcut64;

	h64 = d64;
	data64 = (uint64_t *)(target);
	*data64 = htole64(h64);

	if (opt_debug) {
		char *htarget = bin2hex(target, 32);

		applog(LOG_DEBUG, "Generated target %s", htarget);
		free(htarget);
	}
	cg_memcpy(dest_target, target, 32);
}

#if defined (USE_AVALON)
int submit_nonce2_nonce(struct thr_info *thr, struct pool *pool, struct pool *real_pool,
			 uint32_t nonce2, uint32_t nonce,  uint32_t ntime, uint32_t micro_job_id)
{
	const int thr_id = thr->id;
	struct cgpu_info *cgpu = thr->cgpu;
	struct device_drv *drv = cgpu->drv;
	struct work *work = make_work();
	int ret;

	cg_wlock(&pool->data_lock);
	pool->nonce2 = nonce2;
	cg_wunlock(&pool->data_lock);

	gen_stratum_work(pool, work);
	roll_work_ntime(work, ntime);

	work->pool = real_pool;
	/* Inherit the sdiff from the original stratum */
	work->sdiff = pool->sdiff;

	work->thr_id = thr_id;
	work->work_block = work_block;
	work->pool->works++;

	// work->micro_job_id = micro_job_id ? (1 << micro_job_id) : 0;
	work->micro_job_id = micro_job_id;
	memcpy(work->data, &pool->vmask_001[work->micro_job_id], 4);

	work->mined = true;
	// applog(LOG_INFO,"work_difficulty=%lf,max=%lf,min=%lf",work->work_difficulty,drv->max_diff,drv->min_diff);
	work->device_diff = MIN(drv->max_diff, work->work_difficulty);
	work->device_diff = MAX(drv->min_diff, work->device_diff);
	ret = submit_nonce(thr, work, nonce);
	free_work(work);
	return ret;
}
#endif




/* The time difference in seconds between when this device last got work via
 * get_work() and generated a valid share. */
int share_work_tdiff(struct cgpu_info *cgpu)
{
	return last_getwork - cgpu->last_device_valid_work;
}

static void set_benchmark_work(struct cgpu_info *cgpu, struct work *work)
{
	cgpu->lodiff += cgpu->direction;
	if (cgpu->lodiff < 1)
		cgpu->direction = 1;
	if (cgpu->lodiff > 15) {
		cgpu->direction = -1;
		if (++cgpu->hidiff > 15)
			cgpu->hidiff = 0;
		cg_memcpy(work, &bench_hidiff_bins[cgpu->hidiff][0], 160);
	} else
		cg_memcpy(work, &bench_lodiff_bins[cgpu->lodiff][0], 160);
}

struct work *get_work(struct thr_info *thr, const int thr_id)
{
	struct cgpu_info *cgpu = thr->cgpu;
	struct work *work = NULL;
	time_t diff_t;

	thread_reportout(thr);
	applog(LOG_DEBUG, "Popping work from get queue to get work");
	diff_t = time(NULL);
	while (!work) {
		work = hash_pop(true);
		if (stale_work(work, false)) {
			discard_work(work);
			wake_gws();
		}
	}
	diff_t = time(NULL) - diff_t;
	/* Since this is a blocking function, we need to add grace time to
	 * the device's last valid work to not make outages appear to be
	 * device failures. */
	if (diff_t > 0) {
		applog(LOG_DEBUG, "Get work blocked for %d seconds", (int)diff_t);
		cgpu->last_device_valid_work += diff_t;
	}
	applog(LOG_DEBUG, "Got work from get queue to get work for thread %d", thr_id);

	work->thr_id = thr_id;
	if (opt_benchmark)
		set_benchmark_work(cgpu, work);

	thread_reportin(thr);
	work->mined = true;
	work->device_diff = MIN(cgpu->drv->max_diff, work->work_difficulty);
	work->device_diff = MAX(cgpu->drv->min_diff, work->device_diff);
	return work;
}

/* Submit a copy of the tested, statistic recorded work item asynchronously */
static void submit_work_async(struct work *work)
{
	struct pool *pool = work->pool;
	pthread_t submit_thread;

	cgtime(&work->tv_work_found);
	if (opt_benchmark) {
		struct cgpu_info *cgpu = get_thr_cgpu(work->thr_id);

		mutex_lock(&stats_lock);
		cgpu->accepted++;
		total_accepted++;
		pool->accepted++;
		cgpu->diff_accepted += work->work_difficulty;
		total_diff_accepted += work->work_difficulty;
		pool->diff_accepted += work->work_difficulty;
		mutex_unlock(&stats_lock);

		applog(LOG_NOTICE, "Accepted %s %d benchmark share nonce %08x",
		       cgpu->drv->name, cgpu->device_id, *(uint32_t *)(work->data + 64 + 12));
		return;
	}

	if (stale_work(work, true)) {
		if (opt_submit_stale)
			applog(LOG_NOTICE, "Pool %d stale share detected, submitting as user requested", pool->pool_no);
		else if (pool->submit_old)
			applog(LOG_NOTICE, "Pool %d stale share detected, submitting as pool requested", pool->pool_no);
		else {
			applog(LOG_NOTICE, "Pool %d stale share detected, discarding", pool->pool_no);
			sharelog("discard", work);

			mutex_lock(&stats_lock);
			total_stale++;
			pool->stale_shares++;
			total_diff_stale += work->work_difficulty;
			pool->diff_stale += work->work_difficulty;
			mutex_unlock(&stats_lock);

			free_work(work);
			return;
		}
		work->stale = true;
	}

	if (work->stratum) {
		applog(LOG_DEBUG, "Pushing pool %d work to stratum queue", pool->pool_no);
		if (unlikely(!pool->stratum_q || !tq_push(pool->stratum_q, work))) {
			applog(LOG_DEBUG, "Discarding work from removed pool");
			free_work(work);
		}
	} else {
		applog(LOG_DEBUG, "Pushing submit work to work thread");
		if (unlikely(pthread_create(&submit_thread, NULL, submit_work_thread, (void *)work)))
			applog(LOG_INFO, "Failed to create submit_work_thread");
	}
}

void inc_hw_errors(struct thr_info *thr)
{
	applog(LOG_INFO, "%s %d: invalid nonce - HW error", thr->cgpu->drv->name,
	       thr->cgpu->device_id);

	mutex_lock(&stats_lock);
	hw_errors++;
	thr->cgpu->hw_errors++;
	mutex_unlock(&stats_lock);

	thr->cgpu->drv->hw_error(thr);
}

/* Fills in the work nonce and builds the output data in work->hash */
static void rebuild_nonce(struct work *work, uint32_t nonce)
{
	uint32_t *work_nonce = (uint32_t *)(work->data + 64 + 12);

	*work_nonce = be32toh(nonce);

	regen_hash(work);
}

/* For testing a nonce against diff 1 */
bool test_nonce(struct work *work, uint32_t nonce)
{
	uint32_t *hash_32 = (uint32_t *)(work->hash + 28);

	rebuild_nonce(work, nonce);
	return (*hash_32 == 0);
}

/* For testing a nonce against an arbitrary diff */
bool test_nonce_diff(struct work *work, uint32_t nonce, double diff)
{
	uint64_t *hash64 = (uint64_t *)(work->hash + 24), diff64;

	rebuild_nonce(work, nonce);
	diff64 = 0x00000000ffff0000ULL;
	diff64 /= diff;

	return (le64toh(*hash64) <= diff64);
}

static void update_work_stats(struct thr_info *thr, struct work *work)
{
	double test_diff = current_diff;

	work->share_diff = share_diff(work);

	if (unlikely(work->share_diff >= test_diff)) {
		work->block = true;
		work->pool->solved++;
		found_blocks++;
		work->mandatory = true;
		applog(LOG_NOTICE, "Found block for pool %d!", work->pool->pool_no);
	}

	mutex_lock(&stats_lock);
	total_diff1 += work->device_diff;
	thr->cgpu->diff1 += work->device_diff;
	work->pool->diff1 += work->device_diff;
	thr->cgpu->last_device_valid_work = time(NULL);
	mutex_unlock(&stats_lock);
}

/* To be used once the work has been tested to be meet diff1 and has had its
 * nonce adjusted. Returns true if the work target is met. */
bool submit_tested_work(struct thr_info *thr, struct work *work)
{
	struct work *work_out;
	update_work_stats(thr, work);

	if (!fulltest(work->hash, work->target)) {
		applog(LOG_DEBUG, "%s %d: Share above target", thr->cgpu->drv->name,
		       thr->cgpu->device_id);
		return false;
	}
	work_out = copy_work(work);
	submit_work_async(work_out);
	return true;
}

void clear_new_nonce(struct thr_info *thr)
{
	struct cgpu_info *cgpu = thr->cgpu;
	cgpu->last_nonce = 0;
}

/* Rudimentary test to see if cgpu has returned the same nonce twice in a row which is
 * always going to be a duplicate which should be reported as a hw error. */
static bool new_nonce(struct thr_info *thr, uint32_t nonce)
{
	struct cgpu_info *cgpu = thr->cgpu;

	if (unlikely(cgpu->last_nonce == nonce)) {
		applog(LOG_INFO, "%s %d duplicate share detected as HW error",
		       cgpu->drv->name, cgpu->device_id);
		return false;
	}
	cgpu->last_nonce = nonce;
	return true;
}

/* Returns true if nonce for work was a valid share and not a dupe of the very last
 * nonce submitted by this device. */
int submit_nonce(struct thr_info *thr, struct work *work, uint32_t nonce)
{
	if(new_nonce(thr, nonce) == false)
	{
		return 0; // duplicate nonce, don't care
	}

	if (test_nonce(work, nonce))
		submit_tested_work(thr, work);
	else {
		return -1; // error
	}
	return 1; // succeed
}

static inline bool abandon_work(struct work *work, struct timeval *wdiff, uint64_t hashes)
{
	if (wdiff->tv_sec > max_scantime || hashes >= 0xfffffffe ||
	    stale_work(work, false))
		return true;
	return false;
}

static void mt_disable(struct thr_info *mythr, const int thr_id,
		       struct device_drv *drv)
{
	applog(LOG_WARNING, "Thread %d being disabled", thr_id);
	mythr->cgpu->rolling = 0;
	applog(LOG_DEBUG, "Waiting on sem in miner thread");
	cgsem_wait(&mythr->sem);
	applog(LOG_WARNING, "Thread %d being re-enabled", thr_id);
	drv->thread_enable(mythr);
}

/* The main hashing loop for devices that are slow enough to work on one work
 * item at a time, without a queue, aborting work before the entire nonce
 * range has been hashed if needed. */
static void hash_sole_work(struct thr_info *mythr)
{
	const int thr_id = mythr->id;
	struct cgpu_info *cgpu = mythr->cgpu;
	struct device_drv *drv = cgpu->drv;
	struct timeval getwork_start, tv_start, *tv_end, tv_workstart, tv_lastupdate;
	struct cgminer_stats *dev_stats = &(cgpu->cgminer_stats);
	struct cgminer_stats *pool_stats;
	/* Try to cycle approximately 5 times before each log update */
	const long cycle = opt_log_interval / 5 ? : 1;
	const bool primary = (!mythr->device_thread) || mythr->primary_thread;
	struct timeval diff, sdiff, wdiff = {0, 0};
	uint32_t max_nonce = drv->can_limit_work(mythr);
	int64_t hashes_done = 0;

	tv_end = &getwork_start;
	cgtime(&getwork_start);
	sdiff.tv_sec = sdiff.tv_usec = 0;
	cgtime(&tv_lastupdate);

	while (likely(!cgpu->shutdown)) {
		struct work *work = get_work(mythr, thr_id);
		int64_t hashes;

		mythr->work_restart = false;
		cgpu->new_work = true;

		cgtime(&tv_workstart);
		work->nonce = 0;
		cgpu->max_hashes = 0;
		if (!drv->prepare_work(mythr, work)) {
			applog(LOG_ERR, "work prepare failed, exiting "
				"mining thread %d", thr_id);
			break;
		}
		work->device_diff = MIN(drv->max_diff, work->work_difficulty);
		work->device_diff = MAX(drv->min_diff, work->device_diff);

		do {
			cgtime(&tv_start);

			subtime(&tv_start, &getwork_start);

			addtime(&getwork_start, &dev_stats->getwork_wait);
			if (time_more(&getwork_start, &dev_stats->getwork_wait_max))
				copy_time(&dev_stats->getwork_wait_max, &getwork_start);
			if (time_less(&getwork_start, &dev_stats->getwork_wait_min))
				copy_time(&dev_stats->getwork_wait_min, &getwork_start);
			dev_stats->getwork_calls++;

			pool_stats = &(work->pool->cgminer_stats);

			addtime(&getwork_start, &pool_stats->getwork_wait);
			if (time_more(&getwork_start, &pool_stats->getwork_wait_max))
				copy_time(&pool_stats->getwork_wait_max, &getwork_start);
			if (time_less(&getwork_start, &pool_stats->getwork_wait_min))
				copy_time(&pool_stats->getwork_wait_min, &getwork_start);
			pool_stats->getwork_calls++;

			cgtime(&(work->tv_work_start));

			/* Only allow the mining thread to be cancelled when
			 * it is not in the driver code. */
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

			thread_reportin(mythr);
			hashes = drv->scanhash(mythr, work, work->nonce + max_nonce);
			thread_reportout(mythr);

			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
			pthread_testcancel();

			/* tv_end is == &getwork_start */
			cgtime(&getwork_start);

			if (unlikely(hashes == -1)) {
				applog(LOG_ERR, "%s %d failure, disabling!", drv->name, cgpu->device_id);
				cgpu->deven = DEV_DISABLED;
				dev_error(cgpu, REASON_THREAD_ZERO_HASH);
				cgpu->shutdown = true;
				break;
			}

			hashes_done += hashes;
			if (hashes > cgpu->max_hashes)
				cgpu->max_hashes = hashes;

			timersub(tv_end, &tv_start, &diff);
			sdiff.tv_sec += diff.tv_sec;
			sdiff.tv_usec += diff.tv_usec;
			if (sdiff.tv_usec > 1000000) {
				++sdiff.tv_sec;
				sdiff.tv_usec -= 1000000;
			}

			timersub(tv_end, &tv_workstart, &wdiff);

			if (unlikely((long)sdiff.tv_sec < cycle)) {
				int mult;

				if (likely(max_nonce == 0xffffffff))
					continue;

				mult = 1000000 / ((sdiff.tv_usec + 0x400) / 0x400) + 0x10;
				mult *= cycle;
				if (max_nonce > (0xffffffff * 0x400) / mult)
					max_nonce = 0xffffffff;
				else
					max_nonce = (max_nonce * mult) / 0x400;
			} else if (unlikely(sdiff.tv_sec > cycle))
				max_nonce = max_nonce * cycle / sdiff.tv_sec;
			else if (unlikely(sdiff.tv_usec > 100000))
				max_nonce = max_nonce * 0x400 / (((cycle * 1000000) + sdiff.tv_usec) / (cycle * 1000000 / 0x400));

			timersub(tv_end, &tv_lastupdate, &diff);
			/* Update the hashmeter at most 5 times per second */
			if ((hashes_done && (diff.tv_sec > 0 || diff.tv_usec > 200000)) ||
			    diff.tv_sec >= opt_log_interval) {
				hashmeter(thr_id, hashes_done);
				hashes_done = 0;
				copy_time(&tv_lastupdate, tv_end);
			}

			if (unlikely(mythr->work_restart)) {
				/* Apart from device_thread 0, we stagger the
				 * starting of every next thread to try and get
				 * all devices busy before worrying about
				 * getting work for their extra threads */
				if (!primary) {
					struct timespec rgtp;

					rgtp.tv_sec = 0;
					rgtp.tv_nsec = 250 * mythr->device_thread * 1000000;
					nanosleep(&rgtp, NULL);
				}
				break;
			}

			if (unlikely(mythr->pause || cgpu->deven != DEV_ENABLED))
				mt_disable(mythr, thr_id, drv);

			sdiff.tv_sec = sdiff.tv_usec = 0;
		} while (!abandon_work(work, &wdiff, cgpu->max_hashes));
		free_work(work);
	}
	cgpu->deven = DEV_DISABLED;
}

/* Put a new unqueued work item in cgpu->unqueued_work under cgpu->qlock till
 * the driver tells us it's full so that it may extract the work item using
 * the get_queued() function which adds it to the hashtable on
 * cgpu->queued_work. */
static void fill_queue(struct thr_info *mythr, struct cgpu_info *cgpu, struct device_drv *drv, const int thr_id)
{
	do {
		bool need_work;

		/* Do this lockless just to know if we need more unqueued work. */
		need_work = (!cgpu->unqueued_work);

		/* get_work is a blocking function so do it outside of lock
		 * to prevent deadlocks with other locks. */
		if (need_work) {
			struct work *work = get_work(mythr, thr_id);

			wr_lock(&cgpu->qlock);
			/* Check we haven't grabbed work somehow between
			 * checking and picking up the lock. */
			if (likely(!cgpu->unqueued_work))
				cgpu->unqueued_work = work;
			else
				need_work = false;
			wr_unlock(&cgpu->qlock);

			if (unlikely(!need_work))
				discard_work(work);
		}
		/* The queue_full function should be used by the driver to
		 * actually place work items on the physical device if it
		 * does have a queue. */
	} while (!drv->queue_full(cgpu));
}

/* Add a work item to a cgpu's queued hashlist */
void __add_queued(struct cgpu_info *cgpu, struct work *work)
{
	cgpu->queued_count++;
	HASH_ADD_INT(cgpu->queued_work, id, work);
}

struct work *__get_queued(struct cgpu_info *cgpu)
{
	struct work *work = NULL;

	if (cgpu->unqueued_work) {
		work = cgpu->unqueued_work;
		if (unlikely(stale_work(work, false))) {
			discard_work(work);
		} else
			__add_queued(cgpu, work);
		cgpu->unqueued_work = NULL;
		wake_gws();
	}

	return work;
}

/* This function is for retrieving one work item from the unqueued pointer and
 * adding it to the hashtable of queued work. Code using this function must be
 * able to handle NULL as a return which implies there is no work available. */
struct work *get_queued(struct cgpu_info *cgpu)
{
	struct work *work;

	wr_lock(&cgpu->qlock);
	work = __get_queued(cgpu);
	wr_unlock(&cgpu->qlock);

	return work;
}

void add_queued(struct cgpu_info *cgpu, struct work *work)
{
	wr_lock(&cgpu->qlock);
	__add_queued(cgpu, work);
	wr_unlock(&cgpu->qlock);
}

/* Get fresh work and add it to cgpu's queued hashlist */
struct work *get_queue_work(struct thr_info *thr, struct cgpu_info *cgpu, int thr_id)
{
	struct work *work = get_work(thr, thr_id);

	add_queued(cgpu, work);
	return work;
}

/* This function is for finding an already queued work item in the
 * given que hashtable. Code using this function must be able
 * to handle NULL as a return which implies there is no matching work.
 * The calling function must lock access to the que if it is required.
 * The common values for midstatelen, offset, datalen are 32, 64, 12 */
struct work *__find_work_bymidstate(struct work *que, char *midstate, size_t midstatelen, char *data, int offset, size_t datalen)
{
	struct work *work, *tmp, *ret = NULL;

	HASH_ITER(hh, que, work, tmp) {
		if (memcmp(work->midstate, midstate, midstatelen) == 0 &&
		    memcmp(work->data + offset, data, datalen) == 0) {
			ret = work;
			break;
		}
	}

	return ret;
}

/* This function is for finding an already queued work item in the
 * device's queued_work hashtable. Code using this function must be able
 * to handle NULL as a return which implies there is no matching work.
 * The common values for midstatelen, offset, datalen are 32, 64, 12 */
struct work *find_queued_work_bymidstate(struct cgpu_info *cgpu, char *midstate, size_t midstatelen, char *data, int offset, size_t datalen)
{
	struct work *ret;

	rd_lock(&cgpu->qlock);
	ret = __find_work_bymidstate(cgpu->queued_work, midstate, midstatelen, data, offset, datalen);
	rd_unlock(&cgpu->qlock);

	return ret;
}

struct work *clone_queued_work_bymidstate(struct cgpu_info *cgpu, char *midstate, size_t midstatelen, char *data, int offset, size_t datalen)
{
	struct work *work, *ret = NULL;

	rd_lock(&cgpu->qlock);
	work = __find_work_bymidstate(cgpu->queued_work, midstate, midstatelen, data, offset, datalen);
	if (work)
		ret = copy_work(work);
	rd_unlock(&cgpu->qlock);

	return ret;
}

/* This function is for finding an already queued work item in the
 * given que hashtable. Code using this function must be able
 * to handle NULL as a return which implies there is no matching work.
 * The calling function must lock access to the que if it is required. */
struct work *__find_work_byid(struct work *queue, uint32_t id)
{
	struct work *ret = NULL;
	HASH_FIND_INT(queue, &id, ret);
	return ret;
}

struct work *find_queued_work_byid(struct cgpu_info *cgpu, uint32_t id)
{
	struct work *ret;

	rd_lock(&cgpu->qlock);
	ret = __find_work_byid(cgpu->queued_work, id);
	rd_unlock(&cgpu->qlock);

	return ret;
}

struct work *clone_queued_work_byid(struct cgpu_info *cgpu, uint32_t id)
{
	struct work *work, *ret = NULL;

	rd_lock(&cgpu->qlock);
	work = __find_work_byid(cgpu->queued_work, id);
	if (work)
		ret = copy_work(work);
	rd_unlock(&cgpu->qlock);

	return ret;
}

void __work_completed(struct cgpu_info *cgpu, struct work *work)
{
	cgpu->queued_count--;
	HASH_DEL(cgpu->queued_work, work);
}

/* This iterates over a queued hashlist finding work started more than secs
 * seconds ago and discards the work as completed. The driver must set the
 * work->tv_work_start value appropriately. Returns the number of items aged. */
int age_queued_work(struct cgpu_info *cgpu, double secs)
{
	struct work *work, *tmp;
	struct timeval tv_now;
	int aged = 0;

	cgtime(&tv_now);

	wr_lock(&cgpu->qlock);
	HASH_ITER(hh, cgpu->queued_work, work, tmp) {
		if (tdiff(&tv_now, &work->tv_work_start) > secs) {
			__work_completed(cgpu, work);
			free_work(work);
			aged++;
		}
	}
	wr_unlock(&cgpu->qlock);

	return aged;
}

/* This function should be used by queued device drivers when they're sure
 * the work struct is no longer in use. */
void work_completed(struct cgpu_info *cgpu, struct work *work)
{
	wr_lock(&cgpu->qlock);
	__work_completed(cgpu, work);
	wr_unlock(&cgpu->qlock);

	free_work(work);
}

/* Combines find_queued_work_bymidstate and work_completed in one function
 * withOUT destroying the work so the driver must free it. */
struct work *take_queued_work_bymidstate(struct cgpu_info *cgpu, char *midstate, size_t midstatelen, char *data, int offset, size_t datalen)
{
	struct work *work;

	wr_lock(&cgpu->qlock);
	work = __find_work_bymidstate(cgpu->queued_work, midstate, midstatelen, data, offset, datalen);
	if (work)
		__work_completed(cgpu, work);
	wr_unlock(&cgpu->qlock);

	return work;
}

void flush_queue(struct cgpu_info *cgpu)
{
	struct work *work = NULL;

	if (unlikely(!cgpu))
		return;

	/* Use only a trylock in case we get into a deadlock with a queueing
	 * function holding the read lock when we're called. */
	if (wr_trylock(&cgpu->qlock))
		return;
	work = cgpu->unqueued_work;
	cgpu->unqueued_work = NULL;
	wr_unlock(&cgpu->qlock);

	if (work) {
		free_work(work);
		applog(LOG_DEBUG, "Discarded queued work item");
	}
}

/* This version of hash work is for devices that are fast enough to always
 * perform a full nonce range and need a queue to maintain the device busy.
 * Work creation and destruction is not done from within this function
 * directly. */
void hash_queued_work(struct thr_info *mythr)
{
	struct timeval tv_start = {0, 0}, tv_end;
	struct cgpu_info *cgpu = mythr->cgpu;
	struct device_drv *drv = cgpu->drv;
	const int thr_id = mythr->id;
	int64_t hashes_done = 0;

	while (likely(!cgpu->shutdown)) {
		struct timeval diff;
		int64_t hashes;

		fill_queue(mythr, cgpu, drv, thr_id);

		hashes = drv->scanwork(mythr);

		/* Reset the bool here in case the driver looks for it
		 * synchronously in the scanwork loop. */
		mythr->work_restart = false;

		if (unlikely(hashes == -1 )) {
			applog(LOG_ERR, "%s %d failure, disabling!", drv->name, cgpu->device_id);
			cgpu->deven = DEV_DISABLED;
			dev_error(cgpu, REASON_THREAD_ZERO_HASH);
			break;
		}

		hashes_done += hashes;
		cgtime(&tv_end);
		timersub(&tv_end, &tv_start, &diff);
		/* Update the hashmeter at most 5 times per second */
		if ((hashes_done && (diff.tv_sec > 0 || diff.tv_usec > 200000)) ||
		    diff.tv_sec >= opt_log_interval) {
			hashmeter(thr_id, hashes_done);
			hashes_done = 0;
			copy_time(&tv_start, &tv_end);
		}

		if (unlikely(mythr->pause || cgpu->deven != DEV_ENABLED))
			mt_disable(mythr, thr_id, drv);

		if (mythr->work_update) {
			drv->update_work(cgpu);
			mythr->work_update = false;
		}
	}
	cgpu->deven = DEV_DISABLED;
}

/* This version of hash_work is for devices drivers that want to do their own
 * work management entirely, usually by using get_work(). Note that get_work
 * is a blocking function and will wait indefinitely if no work is available
 * so this must be taken into consideration in the driver. */
void hash_driver_work(struct thr_info *mythr)
{
	struct timeval tv_start = {0, 0}, tv_end;
	struct cgpu_info *cgpu = mythr->cgpu;
	struct device_drv *drv = cgpu->drv;
	const int thr_id = mythr->id;
	int64_t hashes_done = 0;

	while (likely(!cgpu->shutdown)) 
	{
		struct timeval diff;
		int64_t hashes;

		hashes = drv->scanwork(mythr);

		/* Reset the bool here in case the driver looks for it
		 * synchronously in the scanwork loop. */
		mythr->work_restart = false;

		if (unlikely(hashes == -1 )) {
			applog(LOG_ERR, "%s %d failure, disabling!", drv->name, cgpu->device_id);
			cgpu->deven = DEV_DISABLED;
			dev_error(cgpu, REASON_THREAD_ZERO_HASH);
			break;
		}

		hashes_done += hashes;
		cgtime(&tv_end);
		timersub(&tv_end, &tv_start, &diff);
		/* Update the hashmeter at most 5 times per second */
		if ((hashes_done && (diff.tv_sec > 0 || diff.tv_usec > 200000)) ||
		    diff.tv_sec >= opt_log_interval) {
			hashmeter(thr_id, hashes_done);
			hashes_done = 0;
			copy_time(&tv_start, &tv_end);
		}

		if (unlikely(mythr->pause || cgpu->deven != DEV_ENABLED))
			mt_disable(mythr, thr_id, drv);

		if (mythr->work_update) 
		{
			drv->update_work(cgpu);
			mythr->work_update = false;
		}
	}
	applog(LOG_ERR,"hash_driver_work exit");
	cgpu->deven = DEV_DISABLED;
}

void *miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	const int thr_id = mythr->id;
	struct cgpu_info *cgpu = mythr->cgpu;
	struct device_drv *drv = cgpu->drv;
	char threadname[16];

	snprintf(threadname, sizeof(threadname), "%d/Miner", thr_id);
	applog(LOG_NOTICE,"miner_thread create success");

	thread_reportout(mythr);
	if (!drv->thread_init(mythr)) {
		dev_error(cgpu, REASON_THREAD_FAIL_INIT);
		goto out;
	}

	applog(LOG_INFO, "Waiting on sem in miner thread");
	cgsem_wait(&mythr->sem);

	cgpu->last_device_valid_work = time(NULL);
	drv->hash_work(mythr);
	drv->thread_shutdown(mythr);
out:
	return NULL;
}

enum {
	STAT_SLEEP_INTERVAL		= 1,
	STAT_CTR_INTERVAL		= 10000000,
	FAILURE_INTERVAL		= 30,
};


/* This will make the longpoll thread wait till it's the current pool, or it
 * has been flagged as rejecting, before attempting to open any connections.
 */
static void wait_lpcurrent(struct pool *pool)
{
	while (!cnx_needed(pool) && (pool->enabled == POOL_DISABLED ||
	       (pool != current_pool() && pool_strategy != POOL_LOADBALANCE &&
	       pool_strategy != POOL_BALANCE))) {
		mutex_lock(&lp_lock);
		pthread_cond_wait(&lp_cond, &lp_lock);
		pool->idle = true;
		mutex_unlock(&lp_lock);
	}
}

static void *longpoll_thread(void __maybe_unused *userdata)
{
	pthread_detach(pthread_self());
	return NULL;
}

void reinit_device(struct cgpu_info *cgpu)
{
	if (cgpu->deven == DEV_DISABLED)
		return;
	cgpu->drv->reinit_device(cgpu);
}

static struct timeval rotate_tv;

/* We reap curls if they are unused for over a minute */
static void reap_curl(struct pool *pool)
{
	struct curl_ent *ent, *iter;
	struct timeval now;
	int reaped = 0;

	cgtime(&now);

	mutex_lock(&pool->pool_lock);
	list_for_each_entry_safe(ent, iter, &pool->curlring, node) {
		if (pool->curls < 2)
			break;
		if (now.tv_sec - ent->tv.tv_sec > 300) {
			reaped++;
			pool->curls--;
			list_del(&ent->node);
			curl_easy_cleanup(ent->curl);
			free(ent);
		}
	}
	mutex_unlock(&pool->pool_lock);

	if (reaped)
		applog(LOG_DEBUG, "Reaped %d curl%s from pool %d", reaped, reaped > 1 ? "s" : "", pool->pool_no);
}

/* Prune old shares we haven't had a response about for over 2 minutes in case
 * the pool never plans to respond and we're just leaking memory. If we get a
 * response beyond that time they will be seen as untracked shares. */
static void prune_stratum_shares(struct pool *pool)
{
	struct stratum_share *sshare, *tmpshare;
	time_t current_time = time(NULL);
	int cleared = 0;

	mutex_lock(&sshare_lock);
	HASH_ITER(hh, stratum_shares, sshare, tmpshare) {
		if (sshare->work->pool == pool && current_time > sshare->sshare_time + 120) {
			HASH_DEL(stratum_shares, sshare);
			free_work(sshare->work);
			free(sshare);
			cleared++;
		}
	}
	mutex_unlock(&sshare_lock);

	if (cleared) {
		applog(LOG_WARNING, "Lost %d shares due to no stratum share response from pool %d",
		       cleared, pool->pool_no);
		pool->stale_shares += cleared;
		total_stale += cleared;
	}
}

static void *watchpool_thread(void __maybe_unused *userdata)
{
	int intervals = 0;
	cgtimer_t cgt;

	pthread_detach(pthread_self());
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	applog(LOG_NOTICE,"watchpool_thread create success");

	set_lowprio();
	cgtimer_time(&cgt);

	while (42) {
		struct timeval now;
		int i;

		if (++intervals > 120)
			intervals = 0;
		cgtime(&now);

		for (i = 0; i < total_pools; i++) {
			struct pool *pool = pools[i];

			if (!opt_benchmark && !opt_benchfile) {
				reap_curl(pool);
				prune_stratum_shares(pool);
			}

			/* Get a rolling utility per pool over 10 mins */
			if (intervals > 119) {
				double shares = pool->diff1 - pool->last_shares;

				pool->last_shares = pool->diff1;
				pool->utility = (pool->utility + shares * 0.63) / 1.63;
				pool->shares = pool->utility;
			}

			if (pool->enabled == POOL_DISABLED)
				continue;

			/* Don't start testing a pool if its test thread
			 * from startup is still doing its first attempt. */
			if (unlikely(pool->testing))
				continue;

			if (pool_active(pool, true)) {
				if (pool_tclear(pool, &pool->idle))
					pool_resus(pool);
			} else
				cgtime(&pool->tv_idle);

			/* Only switch pools if the failback pool has been
			 * alive for more than 5 minutes to prevent
			 * intermittently failing pools from being used. */
			if (!pool->idle && pool_strategy == POOL_FAILOVER && pool->prio < cp_prio() &&
			    now.tv_sec - pool->tv_idle.tv_sec > opt_pool_fallback) {
				applog(LOG_WARNING, "Pool %d %s stable for >%d seconds",
				       pool->pool_no, pool->rpc_url, opt_pool_fallback);
				switch_pools(NULL);
			}
		}

		if (current_pool()->idle)
			switch_pools(NULL);

		if (pool_strategy == POOL_ROTATE && now.tv_sec - rotate_tv.tv_sec > 60 * opt_rotate_period) {
			cgtime(&rotate_tv);
			switch_pools(NULL);
		}

		cgsleep_ms_r(&cgt, 5000);
		cgtimer_time(&cgt);
	}
	return NULL;
}

/* Makes sure the hashmeter keeps going even if mining threads stall, updates
 * the screen at regular intervals, and restarts threads if they appear to have
 * died. */
#define WATCHDOG_INTERVAL		2
#define WATCHDOG_SICK_TIME		120
#define WATCHDOG_DEAD_TIME		600
#define WATCHDOG_SICK_COUNT		(WATCHDOG_SICK_TIME/WATCHDOG_INTERVAL)
#define WATCHDOG_DEAD_COUNT		(WATCHDOG_DEAD_TIME/WATCHDOG_INTERVAL)

static void log_print_status(struct cgpu_info *cgpu)
{
	char logline[255];

	get_statline(logline, sizeof(logline), cgpu);
	applog(LOG_WARNING, "%s", logline);
}

static void noop_get_statline(char __maybe_unused *buf, size_t __maybe_unused bufsiz, struct cgpu_info __maybe_unused *cgpu);
void blank_get_statline_before(char *buf, size_t bufsiz, struct cgpu_info __maybe_unused *cgpu);

void print_summary(void)
{
	struct timeval diff;
	int hours, mins, secs, i;
	double utility, displayed_hashes, work_util;

	timersub(&total_tv_end, &total_tv_start, &diff);
	hours = diff.tv_sec / 3600;
	mins = (diff.tv_sec % 3600) / 60;
	secs = diff.tv_sec % 60;

	utility = total_accepted / total_secs * 60;
	work_util = total_diff1 / total_secs * 60;

	applog(LOG_WARNING, "\nSummary of runtime statistics:\n");
	applog(LOG_WARNING, "Started at %s", datestamp);
	if (total_pools == 1)
		applog(LOG_WARNING, "Pool: %s", pools[0]->rpc_url);
	applog(LOG_WARNING, "Runtime: %d hrs : %d mins : %d secs", hours, mins, secs);
	displayed_hashes = total_mhashes_done / total_secs;

	applog(LOG_WARNING, "Average hashrate: %.1f Mhash/s", displayed_hashes);
	applog(LOG_WARNING, "Solved blocks: %d", found_blocks);
	applog(LOG_WARNING, "Best share difficulty: %s", best_share);
	applog(LOG_WARNING, "Share submissions: %"PRId64, total_accepted + total_rejected);
	applog(LOG_WARNING, "Accepted shares: %"PRId64, total_accepted);
	applog(LOG_WARNING, "Rejected shares: %"PRId64, total_rejected);
	applog(LOG_WARNING, "Accepted difficulty shares: %1.f", total_diff_accepted);
	applog(LOG_WARNING, "Rejected difficulty shares: %1.f", total_diff_rejected);
	if (total_accepted || total_rejected)
		applog(LOG_WARNING, "Reject ratio: %.1f%%", (double)(total_rejected * 100) / (double)(total_accepted + total_rejected));
	applog(LOG_WARNING, "Hardware errors: %d", hw_errors);
	applog(LOG_WARNING, "Utility (accepted shares / min): %.2f/min", utility);
	applog(LOG_WARNING, "Work Utility (diff1 shares solved / min): %.2f/min\n", work_util);

	applog(LOG_WARNING, "Stale submissions discarded due to new blocks: %"PRId64, total_stale);
	applog(LOG_WARNING, "Unable to get work from server occasions: %d", total_go);
	applog(LOG_WARNING, "Work items generated locally: %d", local_work);
	applog(LOG_WARNING, "Submitting work remotely delay occasions: %d", total_ro);
	applog(LOG_WARNING, "New blocks detected on network: %d\n", new_blocks);

	if (total_pools > 1) {
		for (i = 0; i < total_pools; i++) {
			struct pool *pool = pools[i];

			applog(LOG_WARNING, "Pool: %s", pool->rpc_url);
			if (pool->solved)
				applog(LOG_WARNING, "SOLVED %d BLOCK%s!", pool->solved, pool->solved > 1 ? "S" : "");
			applog(LOG_WARNING, " Share submissions: %"PRId64, pool->accepted + pool->rejected);
			applog(LOG_WARNING, " Accepted shares: %"PRId64, pool->accepted);
			applog(LOG_WARNING, " Rejected shares: %"PRId64, pool->rejected);
			applog(LOG_WARNING, " Accepted difficulty shares: %1.f", pool->diff_accepted);
			applog(LOG_WARNING, " Rejected difficulty shares: %1.f", pool->diff_rejected);
			if (pool->accepted || pool->rejected)
				applog(LOG_WARNING, " Reject ratio: %.1f%%", (double)(pool->rejected * 100) / (double)(pool->accepted + pool->rejected));

			applog(LOG_WARNING, " Items worked on: %d", pool->works);
			applog(LOG_WARNING, " Stale submissions discarded due to new blocks: %d", pool->stale_shares);
			applog(LOG_WARNING, " Unable to get work from server occasions: %d", pool->getfail_occasions);
			applog(LOG_WARNING, " Submitting work remotely delay occasions: %d\n", pool->remotefail_occasions);
		}
	}

	applog(LOG_WARNING, "Summary of per device statistics:\n");
	for (i = 0; i < total_devices; ++i) {
		struct cgpu_info *cgpu = get_devices(i);

		cgpu->drv->get_statline_before = &blank_get_statline_before;
		cgpu->drv->get_statline = &noop_get_statline;
		log_print_status(cgpu);
	}

	if (opt_shares) {
		applog(LOG_WARNING, "Mined %.0f accepted shares of %d requested\n", total_diff_accepted, opt_shares);
		if (opt_shares > total_diff_accepted)
			applog(LOG_WARNING, "WARNING - Mined only %.0f shares of %d requested.", total_diff_accepted, opt_shares);
	}
	applog(LOG_WARNING, " ");

	fflush(stderr);
	fflush(stdout);
}

static bool pools_active = false;

static void *test_pool_thread(void *arg)
{
	struct pool *pool = (struct pool *)arg;
	applog(LOG_NOTICE,"test_pool_thread create success");
	if (!pool->blocking)
		pthread_detach(pthread_self());
retry:
	if (pool->removed)
		goto out;
	if (pool_active(pool, false)) {
		pool_tclear(pool, &pool->idle);
		bool first_pool = false;

		cg_wlock(&control_lock);
		if (!pools_active) {
			currentpool = pool;
			if (pool->pool_no != 0)
				first_pool = true;
			pools_active = true;
		}
		cg_wunlock(&control_lock);

		if (unlikely(first_pool))
			applog(LOG_NOTICE, "Switching to pool %d %s - first alive pool", pool->pool_no, pool->rpc_url);

		pool_resus(pool);
		switch_pools(NULL);
	} else {
		pool_died(pool);
		if (!pool->blocking) {
			sleep(5);
			goto retry;
		}
	}

	pool->testing = false;
out:
	return NULL;
}

/* Various noop functions for drivers that don't support or need their
 * variants. */
static void noop_reinit_device(struct cgpu_info __maybe_unused *cgpu)
{
}

void blank_get_statline_before(char __maybe_unused *buf,size_t __maybe_unused bufsiz, struct cgpu_info __maybe_unused *cgpu)
{
}

static void noop_get_statline(char __maybe_unused *buf, size_t __maybe_unused bufsiz, struct cgpu_info __maybe_unused *cgpu)
{
}

static bool noop_get_stats(struct cgpu_info __maybe_unused *cgpu)
{
	return true;
}

static bool noop_thread_prepare(struct thr_info __maybe_unused *thr)
{
	return true;
}

static uint64_t noop_can_limit_work(struct thr_info __maybe_unused *thr)
{
	return 0xffffffff;
}

static bool noop_thread_init(struct thr_info __maybe_unused *thr)
{
	return true;
}

static bool noop_prepare_work(struct thr_info __maybe_unused *thr, struct work __maybe_unused *work)
{
	return true;
}

static void noop_hw_error(struct thr_info __maybe_unused *thr)
{
}

static void noop_thread_shutdown(struct thr_info __maybe_unused *thr)
{
}

static void noop_thread_enable(struct thr_info __maybe_unused *thr)
{
}

static void noop_detect(bool __maybe_unused hotplug)
{
}

static void generic_zero_stats(struct cgpu_info *cgpu)
{
	cgpu->diff_accepted =
	cgpu->diff_rejected =
	cgpu->hw_errors = 0;
}

#define noop_flush_work noop_reinit_device
#define noop_update_work noop_reinit_device
#define noop_queue_full noop_get_stats
#define noop_identify_device noop_reinit_device

/* Fill missing driver drv functions with noops */
void fill_device_drv(struct device_drv *drv)
{
	if (!drv->drv_detect)
		drv->drv_detect = &noop_detect;
	if (!drv->reinit_device)
		drv->reinit_device = &noop_reinit_device;
	if (!drv->get_statline_before)
		drv->get_statline_before = &blank_get_statline_before;
	if (!drv->get_statline)
		drv->get_statline = &noop_get_statline;
	if (!drv->get_stats)
		drv->get_stats = &noop_get_stats;
	if (!drv->thread_prepare)
		drv->thread_prepare = &noop_thread_prepare;
	if (!drv->can_limit_work)
		drv->can_limit_work = &noop_can_limit_work;
	if (!drv->thread_init)
		drv->thread_init = &noop_thread_init;
	if (!drv->prepare_work)
		drv->prepare_work = &noop_prepare_work;
	if (!drv->hw_error)
		drv->hw_error = &noop_hw_error;
	if (!drv->thread_shutdown)
		drv->thread_shutdown = &noop_thread_shutdown;
	if (!drv->thread_enable)
		drv->thread_enable = &noop_thread_enable;
	if (!drv->hash_work)
		drv->hash_work = &hash_sole_work;
	if (!drv->flush_work)
		drv->flush_work = &noop_flush_work;
	if (!drv->update_work)
		drv->update_work = &noop_update_work;
	if (!drv->queue_full)
		drv->queue_full = &noop_queue_full;
	if (!drv->zero_stats)
		drv->zero_stats = &generic_zero_stats;
	/* If drivers support internal diff they should set a max_diff or
	 * we will assume they don't and set max to 1. */
	if (!drv->max_diff)
		drv->max_diff = 1;
	if (!drv->genwork)
		opt_gen_stratum_work = true;
}

static int cgminer_id_count = 0;
void enable_device(struct cgpu_info *cgpu)
{
	cgpu->deven = DEV_ENABLED;

	wr_lock(&devices_lock);
	devices[cgpu->cgminer_id = cgminer_id_count++] = cgpu;
	wr_unlock(&devices_lock);

	if (hotplug_mode)
		new_threads += cgpu->threads;
	else
		mining_threads += cgpu->threads;

	rwlock_init(&cgpu->qlock);
	cgpu->queued_work = NULL;
}

struct _cgpu_devid_counter {
	char name[4];
	int lastid;
	UT_hash_handle hh;
};

static void adjust_mostdevs(void)
{
	if (total_devices - zombie_devs > most_devices)
		most_devices = total_devices - zombie_devs;
}

bool add_cgpu(struct cgpu_info *cgpu)
{
	static struct _cgpu_devid_counter *devids = NULL;
	struct _cgpu_devid_counter *d;

	HASH_FIND_STR(devids, cgpu->drv->name, d);
	if (d)
		cgpu->device_id = ++d->lastid;
	else {
		int retry_cnt = 5;
		do {
			d = cgmalloc(sizeof(*d));
			if(d)
				break;
		} while(retry_cnt-- > 0);
		if(retry_cnt <= 0){
			applog(LOG_ERR, "add cgpu failed");
			return false;
		}
		cg_memcpy(d->name, cgpu->drv->name, sizeof(d->name));
		cgpu->device_id = d->lastid = 0;
		HASH_ADD_STR(devids, name, d);
	}

	wr_lock(&devices_lock);
	devices = cgrealloc(devices, sizeof(struct cgpu_info *) * (total_devices + new_devices + 2));
	wr_unlock(&devices_lock);
	if (unlikely(!devices))
	{
		applog(LOG_ERR, "mem not enough when add cpu");
		total_devices = 0;
		if (hotplug_mode)
			new_devices = 0;
		return false;
	}

	mutex_lock(&stats_lock);
	cgpu->last_device_valid_work = time(NULL);
	mutex_unlock(&stats_lock);

	if (hotplug_mode)
		devices[total_devices + new_devices++] = cgpu;
	else
		devices[total_devices++] = cgpu;

	adjust_mostdevs();

	return true;
}

struct device_drv *copy_drv(struct device_drv *drv)
{
	struct device_drv *copy;

	copy = cgmalloc(sizeof(*copy));
	if(!copy)
		return NULL;
	cg_memcpy(copy, drv, sizeof(*copy));
	copy->copy = true;
	return copy;
}

static void probe_pools(void)
{
	int i;

	for (i = 0; i < total_pools; i++) {
		struct pool *pool = pools[i];

		pool->testing = true;
		pthread_create(&pool->test_thread, NULL, test_pool_thread, (void *)pool);
	}
}

#define DRIVER_FILL_DEVICE_DRV(X) fill_device_drv(&X##_drv);
#define DRIVER_DRV_DETECT_ALL(X) X##_drv.drv_detect(false);

static void init_global_lock_cond()
{
	mutex_init(&hash_lock);
	mutex_init(&console_lock);
	cglock_init(&control_lock);
	mutex_init(&stats_lock);
	mutex_init(&sharelog_lock);
	cglock_init(&ch_lock);
	mutex_init(&sshare_lock);
	rwlock_init(&blk_lock);
	#ifdef HAVE_LIBCURL
	rwlock_init(&netacc_lock);
	#endif
	rwlock_init(&mining_thr_lock);
	//rwlock_init(&devices_lock);

	mutex_init(&lp_lock);
	if (unlikely(pthread_cond_init(&lp_cond, NULL)))
		early_quit(ERR_CREATE_EXIT, "Failed to pthread_cond_init lp_cond");

	mutex_init(&restart_lock);
	if (unlikely(pthread_cond_init(&restart_cond, NULL)))
		early_quit(ERR_CREATE_EXIT, "Failed to pthread_cond_init restart_cond");

	if (unlikely(pthread_cond_init(&gws_cond, NULL)))
		early_quit(ERR_CREATE_EXIT, "Failed to pthread_cond_init gws_cond");

}

void mmu_net_status(bool cnn_status)
{
	static bool last_status = false;
	static int netfail_index = 0;

	if (cnn_status == last_status)
		return;

	if (cnn_status && netfail_time[0] == 0) { // first connection
		// led_set(LED_DAY_NORMAL, LED_LIGHT_GREEN);
		applog(LOG_OP, "Pool connect first");
	} else if (cnn_status && netfail_time[0] != 0) { // disconnected -> connected
		netfail_time[netfail_index + 1] = (uint32_t)time(NULL);
		netfail_index = (netfail_index + 2) % ARRAY_SIZE(netfail_time);
		applog(LOG_OP, "Pool reconnect");
	} else if (!cnn_status) { // connected -> disconnected
		netfail_time[netfail_index] = (uint32_t)time(NULL);
		netfail_time[netfail_index + 1] = 0;
		pool_failcnt++;
		applog(LOG_OP, "Pool disconnect");
	}

	last_status = cnn_status;
}

void *cgminer_thread(void* param)
{
	bool pool_msg = false;
	struct thr_info *thr;
	struct block *block;
	int i,j,k,slept = 0;
	applog(LOG_INFO,"cgminer_thread create success!");
#ifdef __linux
	/* If we're on a small lowspec platform with only one CPU, we should
	 * yield after dropping a lock to allow a thread waiting for it to be
	 * able to get CPU time to grab the lock. */
	if (sysconf(_SC_NPROCESSORS_ONLN) == 1)
		selective_yield = &sched_yield;
#endif
	int argc = ((struct cgminer_param_t*)param)->argc;
	char ** argv = ((struct cgminer_param_t*)param)->argv;
	pthread_detach(pthread_self());
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	init_global_lock_cond();

	/* Create a unique get work queue */
	getq = tq_new();
	if (!getq)
		early_quit(ERR_CREATE_EXIT, "Failed to create getq");
	else
		/* We use the getq mutex as the staged lock */
		stgd_lock = &getq->mutex;

	// snprintf(packagename, sizeof(packagename), "%s %s", PACKAGE, VERSION);

	block = cgcalloc(ERR_CREATE_EXIT, sizeof(struct block));
	for (i = 0; i < 36; i++)
		strcat(block->hash, "0");
	HASH_ADD_STR(blocks, hash, block);
	strcpy(current_hash, block->hash);

	INIT_LIST_HEAD(&scan_devices);
	/* parse command line */
	opt_register_table(opt_config_table,
			   "Options for both config file and command line");

	// TODO: maybe should in idle when opt_parse failed
	opt_parse(&argc, argv, opt_failed);

	if (want_per_device_stats)
		opt_log_output = true;

	if (!total_pools)
		applog(LOG_WARNING, "Need to specify at least one pool server,total_pools=%d",total_pools);

	for (i = 0; i < total_pools; i++) {
		struct pool *pool = pools[i];
		size_t siz;

		pool->cgminer_stats.getwork_wait_min.tv_sec = MIN_SEC_UNSET;
		pool->cgminer_pool_stats.getwork_wait_min.tv_sec = MIN_SEC_UNSET;

		if (!pool->rpc_userpass) {
			if (!pool->rpc_pass)
				pool->rpc_pass = strdup("");
			if (!pool->rpc_user)
			{
				pool->removed = true;
				// early_quit(ERR_POOL_EXIT, "No login credentials supplied for pool %u %s", i, pool->rpc_url); //retry
			}
			else {
				siz = strlen(pool->rpc_user) + strlen(pool->rpc_pass) + 2;
				pool->rpc_userpass = cgmalloc(siz);
				if(pool->rpc_userpass)
					snprintf(pool->rpc_userpass, siz, "%s:%s", pool->rpc_user, pool->rpc_pass);
			}
		}
	}
	/* Set the currentpool to pool 0 */
	if (total_pools > 0)
		currentpool = pools[0];

	for (i = 0; i < total_pools; i++) {
		struct pool *pool  = pools[i];
		enable_pool(pool);
		pool->idle = true;
	}

	applog(LOG_NOTICE,"start detect mm_miner and building a virtual avalon");

	// Start threads
	/* Use the DRIVER_PARSE_COMMANDS macro to detect all devices */
	DRIVER_PARSE_COMMANDS(DRIVER_FILL_DEVICE_DRV)
	DRIVER_PARSE_COMMANDS(DRIVER_DRV_DETECT_ALL)
	
	/* Use the DRIVER_PARSE_COMMANDS macro to fill all the device_drvs */
	for (i = 0; i < total_devices; ++i)
		enable_device(devices[i]);

	mining_thr = cgcalloc(mining_threads, sizeof(thr));
    for (i = 0; i < mining_threads; i++)
        mining_thr[i] = cgcalloc(1, sizeof(*thr));

    if (unlikely(total_devices == 0))
	{
        applog(LOG_ERR, "total_devices is zero, maybe somewhere be wrong");
	}

	k = 0;
	for (i = 0; i < total_devices; ++i) {
		struct cgpu_info *cgpu = devices[i];
		int retry_cnt = 5;
		do{
			cgpu->thr = cgmalloc(sizeof(*cgpu->thr) * (cgpu->threads+1));
			if(cgpu->thr)
				break;
		}while((retry_cnt-- > 0));
		if(retry_cnt <= 0){
			early_quit(ERR_CREATE_EXIT, "miner_threads malloc failed");
			return NULL;
		}
		cgpu->thr[cgpu->threads] = NULL;
		cgpu->status = LIFE_INIT;

		for (j = 0; j < cgpu->threads; ++j, ++k) {
			thr = get_thread(k);
			thr->id = k;
			thr->cgpu = cgpu;
			thr->device_thread = j;
			if (!cgpu->drv->thread_prepare(thr))
				continue;
			if (unlikely(thr_info_create(thr, NULL, miner_thread, thr))) {
				early_quit(ERR_CREATE_EXIT, "miner thread %d create failed", thr->id);
				return NULL;
			}
			cgpu->thr[j] = thr;
			/* Enable threads for devices set not to mine but disable
			 * their queue in case we wish to enable them later */
			if (cgpu->deven != DEV_DISABLED) {
				applog(LOG_DEBUG, "Pushing sem post to thread %d", thr->id);
				cgsem_post(&thr->sem);
			}
		}
	}

	total_mhashes_done = 0;
	for (i = 0; i < total_devices; ++i)
	{
		devices[i]->cgminer_stats.getwork_wait_min.tv_sec = MIN_SEC_UNSET;
		devices[i]->rolling = 0;
		devices[i]->total_mhashes = 0;
	}

	sleep(1);//Ensure that miner_thread running
	/* Create API socket thread */
	api_thr_id = 0;
	thr = &control_thr[api_thr_id];
	if (thr_info_create(thr, NULL, api_thread, thr))
		early_quit(ERR_CREATE_EXIT, "API thread create failed");

	/* Create http server thread */
	http_thr_id = 1;
	thr = &control_thr[http_thr_id];
	if (thr_info_create(thr, NULL, http_thread, thr))
		early_quit(ERR_CREATE_EXIT, "HTTP thread create failed");


	/* Look for at least one active pool before starting */
	applog(LOG_NOTICE, "Probing for an alive pool");
	probe_pools();

	do {
		sleep(1);
		slept++;
	} while (!pools_active && slept < 20);

	if(slept >= 20)
		applog(LOG_WARNING,"Failed to find a suitable pool when attempting to connect to the pool 20s");

	while (!pools_active) {
		if (!pool_msg) {
			applog(LOG_ERR, "No servers were found that could be used to get work from.");
			applog(LOG_ERR, "Please check the details from the list below of the servers you have input");
			applog(LOG_ERR, "Most likely you have input the wrong URL, forgotten to add a port, or have not set up workers");
			for (i = 0; i < total_pools; i++) {
				struct pool *pool = pools[i];
				applog(LOG_WARNING, "Pool: %d  URL: %s  User: %s  Password: %s",
				i, pool->rpc_url, pool->rpc_user, pool->rpc_pass);
			}
			pool_msg = true;
		}
		sleep(1);
	};

	cgtime(&total_tv_start);
	cgtime(&total_tv_end);
	cgtime(&tv_hashmeter);
	get_datestamp(datestamp, sizeof(datestamp), &total_tv_start);

	watchpool_thr_id = 2;
	thr = &control_thr[watchpool_thr_id];
	/* start watchpool thread */
	if (thr_info_create(thr, NULL, watchpool_thread, NULL))
		early_quit(ERR_CREATE_EXIT, "watchpool thread create failed");

	// watchdog_thr_id = 3;
	// thr = &control_thr[watchdog_thr_id];
	/* start watchdog thread */
	// if (thr_info_create(thr, NULL, watchdog_thread, NULL))
	// 	early_quit(ERR_CREATE_EXIT, "watchdog thread create failed");

	set_highprio();

	/* Once everything is set up, main() becomes the getwork scheduler */
	while (42) {
		struct pool *pool;

		/* Check connection status of current pool */
		if (current_pool()->has_stratum && current_pool()->stratum_active)
			mmu_net_status(true);
		else
			mmu_net_status(false);

		if (opt_work_update)
			signal_work_update();
		opt_work_update = false;

		while (42) {
			pool = select_pool();
			if (!pool_unusable(pool))
				break;
			switch_pools(NULL);
			pool = select_pool();
			if (pool_unusable(pool))
				cgsleep_ms(5);
		};
		
		cgsleep_ms(100);
	}
	
	return NULL;
}


int get_pools_stats(cgminer_pools *cgi_pool_info)
{
	int i,ret = -1;
	for (i = 0; i < total_pools; i++) {
		struct pool *pool = pools[i];
		if (pool->removed)
			continue;

		if(pool->rpc_url == NULL)
			sprintf(cgi_pool_info[i].url, "%s", "");
		else
			sprintf(cgi_pool_info[i].url, "%s", pool->rpc_url);
		
		if(pool->rpc_user == NULL)
			sprintf(cgi_pool_info[i].worker, "%s", "");
		else
			sprintf(cgi_pool_info[i].worker, "%s", pool->rpc_user);

		if(pool->rpc_pass == NULL)
			sprintf(cgi_pool_info[i].passwd, "%s", "");
		else
			sprintf(cgi_pool_info[i].passwd, "%s", pool->rpc_pass);

	}
	if(currentpool)
	{
		if(currentpool->stratum_active)
			ret = currentpool->pool_no;
		else
			ret =  -1;
	}
	return ret;
}