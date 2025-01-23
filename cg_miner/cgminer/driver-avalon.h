/* Copyright (c) 2025, Canaan Creative Co., Ltd.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _AVALON_H_
#define _AVALON_H_

#include "util.h"
#include "mm_miner.h"
#include "boardconf.h"
#include "web/cgi/cgi.h"


#ifdef USE_AVALON

#define WEB_LEN_URL 							384
#define WEB_LEN_USER_PASS 						128
#define WEB_LEN_TIMEZONE						128
#define AVA_VOLT_ADJ_SWITCH_OFF					0
#define AVA_VOLT_ADJ_SWITCH_ON					1
#define AVALON_DEFAULT_FAN_MIN					5 /* % */
#define AVALON_DEFAULT_FAN_MAX					100
#define AVALON_DEFAULT_FAN_SPD					-1

#define AVALON_DEFAULT_TEMP_OVERHEAT			113

#define AVALON_DEFAULT_VOLTAGE_MIN				300
#define AVALON_DEFAULT_VOLTAGE_MAX				350 
#define AVALON_INVALID_VOLTAGE_LEVEL			-1

#define AVALON_INVALID_ASIC_OTP					-1
#define AVALON_DEFAULT_CORE_CLK_SEL				1

#define AVALON_DEFAULT_FACTORY_INFO_0_MIN		-15
#define AVALON_DEFAULT_FACTORY_INFO_0			0
#define AVALON_DEFAULT_FACTORY_INFO_0_MAX		15
#define AVALON_DEFAULT_FACTORY_INFO_0_CNT		1
#define AVALON_DEFAULT_FACTORY_INFO_0_IGNORE	16

#define AVALON_DEFAULT_FACTORY_INFO_1_CNT		3

#define AVALON_DEFAULT_TEMP_TARGET			75

#define AVALON_DEFAULT_FREQUENCY_0M			0
#define AVALON_DEFAULT_FREQUENCY_525M		525
#define AVALON_DEFAULT_FREQUENCY_575M		575
#define AVALON_DEFAULT_HIGH_PERFORMANCE_FREQUENCY_625M		625
#define AVALON_DEFAULT_HIGH_PERFORMANCE_FREQUENCY_675M		675
#define AVALON_DEFAULT_FREQUENCY_650M	    650
#define AVALON_DEFAULT_FREQUENCY_725M	    725
#define AVALON_DEFAULT_FREQUENCY_775M	    775
#define AVALON_DEFAULT_FREQUENCY_850M	    850
#define AVALON_DEFAULT_FREQUENCY_MAX	    1195
#define AVALON_DEFAULT_FREQUENCY		(AVALON_DEFAULT_FREQUENCY_MAX)
#define DEFAULT_FREQUENCY_SEL       	(3)
#define AVALON_DEFAULT_FREQUENCY_SEL	DEFAULT_FREQUENCY_SEL

#define AVALON_DEFAULT_MODULARS			1	/* Only support 6 modules maximum with one AUC */
#define AVALON_DEFAULT_MINER_CNT	  	HBOARD_COUNT
#define AVALON_DEFAULT_PLL_CNT			4
#define AVALON_DEFAULT_ASIC_EFUSE_INDEX	16

#define AVALON_DEFAULT_CORE_VOLT_CNT	8

#define AVALON_DEFAULT_ROLLTIME_RATIO  	83

#define AVALON_DEFAULT_POLLING_DELAY	100 /* ms */
#define AVALON_DEFAULT_NONCE_MASK       25
#define AVALON_DEFAULT_NONCE_CHECK	    1

#define AVALON_DEFAULT_ROLL_ENABLE	    1

#define AVALON_DEFAULT_SMART_SPEED		1
#define AVALON_DEFAULT_SSDN_PRO			0
#define AVALON_DEFAULT_TH_PASS			170
#define AVALON_DEFAULT_TH_FAIL			10000
#define AVALON_DEFAULT_TH_INIT			32767
#define AVALON_DEFAULT_TH_MSSEL			0
#define AVALON_DEFAULT_TH_TIMEOUT		1300000
#define AVALON_DEFAULT_LV1_TH_MSADD		0
#define AVALON_DEFAULT_LV1_TH_MS		8
#define AVALON_DEFAULT_LV2_TH_MSADD		0
#define AVALON_DEFAULT_LV2_TH_MS		0
#define AVALON_DEFAULT_LV3_TH_MSADD		0
#define AVALON_DEFAULT_LV3_TH_MS		0
#define AVALON_DEFAULT_LV4_TH_MSADD		0
#define AVALON_DEFAULT_LV4_TH_MS		0
#define AVALON_DEFAULT_MUX_L2H			0
#define AVALON_DEFAULT_MUX_H2L			1
#define AVALON_DEFAULT_H2LTIME0_SPD		3
#define AVALON_DEFAULT_SPDLOW			1
#define AVALON_DEFAULT_SPDHIGH			4

#define AVALON_POWER_LEVEL_DEFAULT   	1
#define AVALON_DEFAULT_VOLTAGE_LEVEL	50

#define AVALON_DRV_DIFFMAX				4096 //2700
#define AVALON_ASIC_TIMEOUT_CONST		419430400 /* (2^32 * 1000) / (256 * 40) */

#define AVALON_MODULE_DETECT_INTERVAL	30 /* 30 s */

#define AVALON_CONNECTER_UART			1

#define AVALON_OTP_LEN	        		32

#define AVALON_MODULE_BROADCAST	    	0
#define AVALON_ASIC_ID_BROADCAST		0x3ff
/* End of avalon protocol package type */

#define AVALON_FREQ_INIT_MODE			0x0
#define AVALON_FREQ_PLLADJ_MODE			0x1

#define AVALON_DEFAULT_FACTORY_INFO_CNT	(AVALON_DEFAULT_FACTORY_INFO_0_CNT + AVALON_DEFAULT_FACTORY_INFO_1_CNT)
#define AVALON_POWER_ASIC_POUT			4
#define AVALON_POWER_ASIC_VOL			5
#define AVALON_POWER_WALL_POUT			6
#define AVALON_DEFAULT_POWER_INFO_CNT	7

#define AVALON_MODULE_INDEX	    		0
#define avalon_pkg  mm_pkg
#define avalon_ret avalon_pkg

#define WEBPASS_SIGN_LEN 				8
#define WEBPASS_SIGN_MINI3_STR 			"ff0000ee"
#define WEBPASS_SHA256_LEN 				64
#define WEBPASS_LEN 					64
#define WEB_PASSWD_LEN 					24

#define MAX_LEN_FAC_CONF     			256
typedef struct{
	uint16_t pll[AVALON_DEFAULT_PLL_CNT]; //4 pll points for each chip.
}core_pll;

typedef struct{
	uint32_t efuse[AVALON_DEFAULT_ASIC_EFUSE_INDEX];
}efuse_index;
typedef struct{
	core_pll **asics_freq;
	uint32_t **spdlog_pass;
	uint32_t **spdlog_fail;
	core_pll **asic_pllcnt;
	uint16_t **asics_volt;
	int16_t **asics_temp;
	uint64_t **chip_matching_work;
}ava_asics_info;
typedef struct{
	char asic_chipid[7];
	uint8_t core_bin;
	uint8_t noncemask;
	core_pll set_freq[4];
	uint32_t local_works;
	uint32_t errcode_crc[4];
	uint32_t com_crc[4];
	uint32_t mhsmm;
	uint32_t mhsspd;
	double dh;
	double spd_dh;
	double realtime_dh;
	double m_temp_sumavg;
	double m_temp_summax;	
	float freq;
}ava_miner_info;

typedef struct{
	uint8_t ip[4];
	uint8_t mac[6];
	uint8_t mask[4];
	uint8_t gateway[4];
	uint8_t dns[4];
	uint8_t dns_bak[4];
	char ssid_name[128];
	uint8_t protocal;
	int rssi;
	uint8_t devtype;
}ava_net_info;

struct avalon_info {
	/* Public data */
	int64_t last_diff1;
	int64_t pending_diff1;
	double last_rej;

	int mm_count;
	int xfer_err_cnt;
	int pool_no;

	struct timeval firsthash;
	struct timeval last_fan_adj;
	struct timeval last_stratum;
	struct timeval last_detect;

	cglock_t update_lock;

	struct pool pool0;
	struct pool pool1;
	struct pool pool2;
	uint32_t max_ntime; /* Maximum: 7200 */
	int share_time;
	bool conn_overloaded;
	bool work_restart;
	uint32_t last_jobid;

	uint8_t connecter; /* AUC or IIC */

	/* For modulars */

	/*For sys curing info*/
	uint8_t maxmode[AVALON_DEFAULT_MODULARS];
	uint8_t fan_count[AVALON_DEFAULT_MODULARS];
	uint8_t miner_count[AVALON_DEFAULT_MODULARS];
	char little_ver[AVALON_DEFAULT_MODULARS][MAX_VER_LEN+1];
	char big_ver[AVALON_DEFAULT_MODULARS][MAX_VER_LEN+1];
	char dna[AVALON_DEFAULT_MODULARS][MAX_DNA_LEN+1];
	long memfree[AVALON_DEFAULT_MODULARS];
	char mm_hw[AVALON_DEFAULT_MODULARS][AVALON_MM_MODULE_LEN];
	char mm_sw[AVALON_DEFAULT_MODULARS][AVALON_MM_MODULE_LEN];
	char sn[AVALON_DEFAULT_MODULARS][AVALON_DEFAULT_MINER_CNT][SN_LEN + 1];
	/*For sys dynamic info*/
	bool enable[AVALON_DEFAULT_MODULARS];
	uint8_t workmode[AVALON_DEFAULT_MODULARS];
	int32_t worklvl[AVALON_DEFAULT_MODULARS];
	int32_t lvlinfo[AVALON_DEFAULT_MODULARS][WORK_MODE_MAX];
	uint8_t reboot_record[AVALON_DEFAULT_MODULARS];
	uint32_t reboot_record_sub[AVALON_DEFAULT_MODULARS];
	uint8_t mm_status[AVALON_DEFAULT_MODULARS];
	uint64_t diff1[AVALON_DEFAULT_MODULARS][AVALON_DEFAULT_MINER_CNT];
	uint32_t error_code[AVALON_DEFAULT_MODULARS][AVALON_DEFAULT_MINER_CNT + 1]; 
	int temp_overheat[AVALON_DEFAULT_MODULARS];
	char timezone [AVALON_DEFAULT_MODULARS][MAX_LEN_TZ];
	char webuser[AVALON_DEFAULT_MODULARS][WEBPASS_LEN+1];
	char webpass[AVALON_DEFAULT_MODULARS][WEBPASS_LEN+1];
	uint8_t bar[AVALON_DEFAULT_MODULARS];
	uint32_t asic_count[AVALON_DEFAULT_MODULARS];
	uint32_t max_asic_count[AVALON_DEFAULT_MODULARS];
	uint8_t state[AVALON_DEFAULT_MODULARS];
	uint8_t cali_all[AVALON_DEFAULT_MODULARS];
	miner_cali_info cali_info[AVALON_DEFAULT_MODULARS];
	struct hwcfg hw_info[AVALON_DEFAULT_MODULARS];
	struct timeval elapsed[AVALON_DEFAULT_MODULARS];
	long int sys_elapsed[AVALON_DEFAULT_MODULARS];
	uint64_t dhw_works[AVALON_DEFAULT_MODULARS];
	uint64_t hw_works[AVALON_DEFAULT_MODULARS];
	uint64_t hw_works_i[AVALON_DEFAULT_MODULARS][AVALON_DEFAULT_MINER_CNT];
	uint32_t filtermesh_time[AVALON_DEFAULT_MODULARS];
	uint32_t hu_errcode[AVALON_DEFAULT_MODULARS][AVALON_DEFAULT_MINER_CNT];
	uint32_t mm_errcode[AVALON_DEFAULT_MODULARS];
	uint8_t softoff_rsn[AVALON_DEFAULT_MODULARS];
	/*For periph info*/
	int fan_pct[AVALON_DEFAULT_MODULARS];
	int fan_cpm[AVALON_DEFAULT_MODULARS][4];
	int inlet_temp[AVALON_DEFAULT_MODULARS];
	int outlet_temp[AVALON_DEFAULT_MODULARS];
	uint32_t lcd_show[AVALON_DEFAULT_MODULARS];
	uint32_t lcd_bright[AVALON_DEFAULT_MODULARS];
	uint32_t lcd_onoff[AVALON_DEFAULT_MODULARS];
	uint16_t power_info[AVALON_DEFAULT_MODULARS][10];
	ava_net_info net_info;
	uint8_t ledmode;
	ledinfo led;

	/*For miner and asic info*/
	ava_miner_info miner[AVALON_DEFAULT_MODULARS];
	ava_asics_info asics[AVALON_DEFAULT_MODULARS];
};
struct avalonano_dev_desc {
	uint8_t dev_id_str[8];
	uint8_t miner_count; /* it should not greater than AVALON_DEFAULT_MINER_CNT */
	uint8_t asic_count; /* asic count each miner, it should not great than AVALON_DEFAULT_MINER_CNT */
	int set_voltage_level;
	int tmp_target;
	uint16_t set_freq[AVALON_DEFAULT_PLL_CNT];
};
typedef enum polling_status
{
    NORMAL = 0,
    ERROR  = -1,
    NORES   = -2,
} polling_status_t;


enum{
	WEB_GET_MISC_STATS = 0,
	WEB_GET_NET_STATS,
	WEB_SET_POOLS,
	WEB_GET_PASSWD,
	WEB_SET_AUTH,
	WEB_GET_QR_LOGIN,
	WEB_SET_REBOOT,
};

typedef struct {
	uint8_t protocal;
	uint8_t ip[4];
	uint8_t mac[6];
	uint8_t netmask[4];
	uint8_t gatway[4];
	uint8_t dns[4];
	uint8_t dns_bak[4];
	char ssid_name[128];
}web_stats_net;
typedef struct {
	char url[WEB_LEN_URL + 1];
	char worker[WEB_LEN_USER_PASS + 1];
	char passwd[WEB_LEN_USER_PASS + 1];
}cgminer_pools;

typedef struct{
	char webuser[WEBPASS_LEN+1];
	char webpass[WEBPASS_LEN+1];
}web_login;

typedef struct{
	char random[64];
	char sha_dna[64];
}qr_auth;

typedef struct{
	char timezone[WEB_LEN_TIMEZONE];
	uint8_t 	work_mode;
	uint8_t		work_mode_cnt;
	uint8_t 	power_status;
	int32_t		work_lvl;
	uint32_t 	miner_count;
    uint32_t    fanr;   
   	uint32_t    temp;
	uint32_t    tempf;
    uint32_t    fan1;
    uint32_t    GHSspd;
    uint32_t    GHSmm;
    uint32_t    DHspd;
    uint32_t    SoftOFF;
    uint32_t    HashStatus;
    uint32_t    GHSavg;
    uint32_t    MTavg1;
	uint32_t    MTavg1f;
	uint32_t 	wallpower;
	uint32_t 	asic_cnt;
}web_stats_misc;

#define AVALON_SEND_OK 0
#define AVALON_SEND_ERROR -1
#define AVALON_RECV_OK 0
#define AVALON_RECV_ERROR -1

extern char *set_avalon_fan(char *arg);
extern char *set_avalon_asic_otp(char *arg);
extern void avalon_set_finish(struct cgpu_info *avalon, int addr);

extern float get_miner_temp_avg(int module);
extern char* set_device_time(char *set, char *replybuf);
extern void avalon_reset_k210(struct cgpu_info *avalon);

extern int opt_avalon_polling_delay;
extern int opt_avalon_freq_sel;
extern uint32_t opt_avalon_nonce_mask;
extern uint32_t opt_avalon_nonce_check;

extern uint32_t opt_avalon_roll_enable;
extern uint32_t opt_avalon_core_clk_sel;

extern int get_pools_stats(cgminer_pools *cgi_info);

#endif /* USE_avalon */
#endif /* _avalon_H_ */
