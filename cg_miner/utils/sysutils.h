#ifndef __SYSUTILS_H__
#define __SYSUTILS_H__

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pthread.h>

#ifndef bswap_32
#define	bswap_16(value)  ((((value) & 0xff) << 8) | ((value) >> 8))
//#define	bswap_32(value)	(value)
#define	bswap_32(value)	\
	(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
	(uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define	swap_32(value)	 ((value >> 24) | (value << 24) | ((value >> 8) & 0xff00) | ((value << 8) & 0xff0000))
#endif

int exec_cmd(const char *cmd, char *res, int res_size);
void rename_thread(const char* name);
void rename_thread_normal(const char* name);
void set_lowprio(void);
void set_highprio(void);

#endif

