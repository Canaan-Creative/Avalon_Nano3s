
#ifndef _SYSCFG_H_
#define _SYSCFG_H_
#include <stdint.h>
#include <stdbool.h>

#define FILENAME "/data/userconfig/cgminer.conf"

#define TMP_BUF_LEN         10
#define POOL_VALID_NUM      3
#define MAX_LEN_URL         384
#define MAX_LEN_USER_PASS   128
#define MAX_LEN_STAND       256
#define MAX_LEN_CONF_STR    ((MAX_LEN_URL + MAX_LEN_USER_PASS + MAX_LEN_USER_PASS) * POOL_VALID_NUM + MAX_LEN_STAND + 128)

#define MAX_LEN_TZ           64
#define MAX_LEN_HW_INFO      128

struct poolcfg {
    char url[MAX_LEN_URL + 1];
    char user[MAX_LEN_USER_PASS + 1];
    char pass[MAX_LEN_USER_PASS + 1];
};

struct cgicfg{
    char standard[MAX_LEN_STAND]; /* standard configuration string */
    struct poolcfg pools[POOL_VALID_NUM];
};

struct hwcfg {
    /* Full name showed for users, such as "AvalonMiner 1041" */
    char prod[MAX_LEN_HW_INFO/2 + MAX_LEN_HW_INFO/4];
    /* Brief name showed for users, such as "1041" */
    char model[MAX_LEN_HW_INFO/4];
};

typedef struct{
    uint8_t runeffect;
    uint8_t effect;
    uint8_t bright;
    uint32_t temper;
    uint32_t rgb;
} ledinfo;

void pools_cfg_init(void);
int pools_cfg_assemble(void);
void file_content_get(char *buf);
void cgminer_pools_get(struct cgicfg *cgi_info);
void cjson_parse(struct cgicfg *cgi_info);
void cgminer_pools_set(uint8_t *pdata,uint8_t poolnum);
#endif
