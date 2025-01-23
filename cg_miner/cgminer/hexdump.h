#ifndef __HEXDUMP_H
#define __HEXDUMP_H
#include "config.h"
#define hex_print(p) applog(LOG_DEBUG, "%s", p)

#define BYTES_PER_LINE 0x10

void hexdump(const uint8_t *p, unsigned int len);
#endif
