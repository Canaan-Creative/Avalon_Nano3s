#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sysutils.h"
#include "logging.h"

int exec_cmd(const char *cmd, char *res, int res_size)
{
	FILE *fp = NULL;
	char buf[256] = {0};
	int left_size = 0;

	if(NULL == cmd || NULL == res || res_size <= 0){
		return -1;
	}

	memset(res, 0, sizeof(res_size));
	res_size -= 1; // make sure res[res_size - 1] = 0;

	fp= popen(cmd, "r");
	if(NULL == fp){
		return -1;
	}

	while(fgets(buf, sizeof(buf), fp)) {
		if((left_size = (res_size - strlen(res))) <= 0)
			break;
		strncat(res, buf, left_size);
	}

	pclose(fp);
	return 0;
}

void rename_thread(const char* name)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "cg@%s", name);
#if defined(PR_SET_NAME)
	// Only the first 15 characters are used (16 - NUL terminator)
	prctl(PR_SET_NAME, buf, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__))
	pthread_set_name_np(pthread_self(), buf);
#elif defined(MAC_OSX)
	pthread_setname_np(buf);
#else
	// Prevent warnings
	(void)buf;
#endif
}

void rename_thread_normal(const char* name)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%s", name);
#if defined(PR_SET_NAME)
	// Only the first 15 characters are used (16 - NUL terminator)
	prctl(PR_SET_NAME, buf, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__))
	pthread_set_name_np(pthread_self(), buf);
#elif defined(MAC_OSX)
	pthread_setname_np(buf);
#else
	// Prevent warnings
	(void)buf;
#endif
}

void set_lowprio(void)
{
	int ret = nice(10);

	if (!ret)
		applog(LOG_INFO, "Unable to set thread to low priority");
}

void set_highprio(void)
{
	int ret = nice(-10);

	if (!ret)
		applog(LOG_DEBUG, "Unable to set thread to high priority");
}
