#include <stdint.h>
#include <signal.h>
#include <execinfo.h>
#include <sys/sysinfo.h>
#include <unistd.h> 
#include "boardconf.h"
#include "logging.h"
#include "poolcfg.h"
#include "cgminer.h"
#include "miner.h"

#define log_conf "../confiles/zlog_cg.conf"

struct cgminer_param_t cgparam;

// do with all necessary things before exit
void process_before_exit(void)
{
	log_exit();
}

void sighandler(int sig)
{
#define BACKTRACE_MAX_FRAMES 100

	static bool in_handler = false;
	applog(LOG_ERR, "capture a signal: %d", sig);

	switch(sig){
	case SIGSEGV:
		if (!in_handler){
			int j, nptrs;
			void* buffer[BACKTRACE_MAX_FRAMES];
			char** symbols;

			in_handler = true;

			nptrs = backtrace(buffer, BACKTRACE_MAX_FRAMES);
			applog(LOG_ERR, "SIGSEGV captured, stack trace(%d):", nptrs);
			symbols = backtrace_symbols(buffer, nptrs);
			if (symbols != NULL){
				for (j = 0; j < nptrs; j++)
					applog(LOG_ERR, "%s", symbols[j]);
				free(symbols);
			}

			in_handler = false;
		}
		break;
	default:
		break;
	}

	process_before_exit();
	exit(ABORT_EXIT);
}

void init_signal_handlers(void)
{
	struct sigaction handler;

	handler.sa_handler = &sighandler;
	handler.sa_flags = 0;
	sigemptyset(&handler.sa_mask);
	sigaction(SIGSEGV, &handler, NULL);
	sigaction(SIGTERM, &handler, NULL);
	sigaction(SIGINT, &handler, NULL);
	sigaction(SIGABRT, &handler, NULL);
	sigaction(SIGILL, &handler, NULL);
	sigaction(SIGFPE, &handler, NULL);
	sigaction(SIGUSR2, &handler, NULL);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
}
void cgminer_creat(void)
{
	struct cgicfg cgi_info;
	char *str, *token, *saveptr;
	char conf[MAX_LEN_CONF_STR]={'\0'};
	int param_num, i;
	pthread_t tid;
	/* convert conf into argc & argv */
	char *param[256]={NULL};
	/* get pools info */
	memset(&cgi_info,0,sizeof(struct cgicfg));
	cgminer_pools_get(&cgi_info);
    /* cgminer */
    snprintf(conf, MAX_LEN_CONF_STR, "%s ", PACKAGE_NAME);
    /* standard */
    strncat(conf, cgi_info.standard, MAX_LEN_CONF_STR-strlen(conf)-1);
    /* pools */
    for (i = 0; i < POOL_VALID_NUM; i ++) 
	{
        if (strlen(cgi_info.pools[i].url) != 0) {
            strncat(conf, " -o ", MAX_LEN_CONF_STR-strlen(conf)-1);
            strncat(conf, cgi_info.pools[i].url, MAX_LEN_CONF_STR-strlen(conf)-1);
			applog(LOG_INFO, "url[%d]     %s", i, cgi_info.pools[i].url);
        }
        if (strlen(cgi_info.pools[i].user) != 0) 
		{
            strncat(conf, " -u ", MAX_LEN_CONF_STR-strlen(conf)-1);
            strncat(conf, cgi_info.pools[i].user, MAX_LEN_CONF_STR-strlen(conf)-1);
			applog(LOG_INFO, "worker[%d]  %s", i, cgi_info.pools[i].user);
        }
        if (strlen(cgi_info.pools[i].pass) != 0) 
		{
            strncat(conf, " -p ", MAX_LEN_CONF_STR-strlen(conf)-1);
            strncat(conf, cgi_info.pools[i].pass, MAX_LEN_CONF_STR-strlen(conf)-1);
			applog(LOG_INFO, "pass[%d]    %s", i, cgi_info.pools[i].pass);
        }
    }
	for(param_num = 0, str = conf; ;param_num ++, str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (token == NULL)
			break;
		param[param_num] = token;
	}
	cgparam.argc = param_num;
	cgparam.argv = param;
	pthread_create(&tid,NULL,cgminer_thread,(void *)&cgparam);

}

int main(int argc, char *argv[])
{
	atexit(process_before_exit);
	init_signal_handlers();
	log_init(log_conf);
#if (RELEASE_LVL == 0)
	char *releaselvl = "Debug";
#elif (RELEASE_LVL == 2)
	char *releaselvl = "Customized";
#else
	char *releaselvl = "Release";
#endif
	applog(LOG_INFO, "cgminer start up,Version:%s (%s)", FWVERSION, releaselvl);
	pools_cfg_init();
	cgminer_creat();
	while (1)
	{
		sleep(5);
	}

	return 0;
}
