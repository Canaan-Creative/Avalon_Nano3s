#include <stdint.h>

#include "sha2.h"

#ifndef PACK32
#define PACK32(str, x)					\
{							\
	*(x) = ((uint32_t)*((str) + 3))			\
		| ((uint32_t)*((str) + 2) << 8)		\
		| ((uint32_t)*((str) + 1) << 16)	\
		| ((uint32_t)*((str) + 0) << 24);	\
}
#endif

void ssha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}

void sha256_midstate(const uint8_t *input, uint8_t *state)
{
	sha256_ctx ctx;
	sha256_init(&ctx);

	unsigned int mid[16];
	for (int i = 0; i < 16; i++) {
		PACK32(&input[i * 4], &mid[i])
	}
	sha256_update(&ctx, (unsigned char *)mid, 64);

	//ssha256_update(&ctx, input, 64);

	unsigned char *p = (unsigned char *)ctx.h;
	for (int i = 0; i < 32; i++) {
		state[i] = p[31 - i];
	}
}

void gen_hash(unsigned char *data, unsigned char *hash, int len)
{
	unsigned char hash1[32];

	ssha256(data, len, hash1);
	ssha256(hash1, 32, hash);
}
