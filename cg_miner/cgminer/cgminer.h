
#ifndef _CGMINER_H_
#define _CGMINER_H_

struct cgminer_param_t{
	int argc;
	char **argv;
};

void *cgminer_thread(void* param);

#endif