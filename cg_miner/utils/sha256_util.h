#ifndef SHA256_UTIL_H__

#define SHA256_UTIL_H__

#include <stdint.h>
void sha256_midstate(const uint8_t *input, uint8_t *state);
void gen_hash(unsigned char *data, unsigned char *hash, int len);


#endif