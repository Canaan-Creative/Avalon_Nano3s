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
#ifndef __MM_MINER_H__
#define __MM_MINER_H__

#include "poolcfg.h"

#define HBOARD_COUNT					1

#define NETWORK_TYPE_DHCP               0
#define NETWORK_TYPE_STATIC             1

#define MAX_DNA_LEN                     16
#define MAX_VER_LEN                     32
#define SN_LEN							40
#define WEBPASS_LEN						64
#define TOAST_NONCE_COUNT			    64
#define TOAST_PLL_COUNT                 4  

#define AVALON_MM_MODULE_LEN            16

#define MSG_KEY_PATH 	                "/dev/null"
#define AVALON_MM_MTYPE                 0x1
#define MM_AVALON_MTYPE                 0x2


struct mm_header {
	uint16_t type;
    uint16_t idx; // combine packages’ idx
    uint16_t num;// combine packages’ total number
    uint32_t len; // bytes length, valid data length(ranged)
};
#define MSG_PKG_DATA_LEN                256
#define HEAD_LEN                        (sizeof(struct mm_header))
#define MAX_PKG_LEN                     (MSG_PKG_DATA_LEN + HEAD_LEN)
#define DATA_LEN(len)                   (len-HEAD_LEN)

typedef struct
{
    struct mm_header hdr;
    char mtext[MSG_PKG_DATA_LEN];
}mm_pkg;

typedef struct{
    long mtype;
    mm_pkg pkg;
}Msg;

/*********** ↓↓↓ data packet type between driver-avalon and mmu  service comm  ↓↓↓ ***********/
/*********************************** primary type ********************************************/
#define AVA_P_DETECT                    0x10  /* 0x10-0x1f: handshake recognition type*/ 
#define AVA_P_ACKDETECT                 0x11
 
#define AVA_P_POLLING                   0x20  /* 0x20-0x2f: pivotal type */

/* The following types some contain subtypes, be careful when using or adding them */
#define AVA_P_SET_JOB                   0x30  /* 0x30-0x4f: set upper to lower */
#define AVA_P_SET_PERIPH                0x31
#define AVA_P_SET_SYS                	0x32
#define AVA_P_SET_ASIC					0x33

#define AVA_P_STATUS_NONCE              0x50  /* 0x50-0x5f: status polling */
#define AVA_P_STATUS_PERIPH             0x51
#define AVA_P_STATUS_SYS               	0x52
#define AVA_P_STATUS_MINER              0x53
#define AVA_P_STATUS_ASIC               0x54

#define AVA_P_SET_POOLS                 0x60
#define AVA_P_WEB_REBOOT				0x61


/*********************************** minor type *******************************************/
/*********** set for subtype ***********/
												/* set for job subtype */
#define AVA_P_SET_PERIPH_VOLT    		 0x01	/* set for periph subtype: start with 0x01 */
#define AVA_P_SET_PERIPH_FAN      		 0x02
#define AVA_P_SET_PERIPH_AUDIO    		 0x04
#define AVA_P_SET_PERIPH_LCD      		 0x05
#define AVA_P_SET_PERIPH_NET_STATIC      0x06
#define AVA_P_SET_PERIPH_NET_DHCP      	 0x07
#define AVA_P_SET_PERIPH_NET_DNS	     0x08
#define AVA_P_SET_PERIPH_LIGHT_SENSE	 0x09
#define AVA_P_SET_PERIPH_LEDMODE         0x10
#define AVA_P_SET_PERIPH_LEDDAY		 	 0x11
#define AVA_P_SET_PERIPH_NIGHTLAMP       0x12
#define AVA_P_SET_PERIPH_HASHSN   	 	 0x13

#define AVA_P_SET_SYS_TARGET_TEMP 		 0x01	/* set for sys subtype: start with 0x01 */
#define AVA_P_SET_SYS_VOLT_TUNING 		 0x02
#define AVA_P_SET_SYS_LEVEL 		 	 0x03
#define AVA_P_SET_SYS_MODE 				 0x04
#define AVA_P_SET_SYS_REBOOT 			 0x05
#define AVA_P_SET_SYS_SOFTON 			 0x06
#define AVA_P_SET_SYS_SOFTOFF 			 0x07
#define AVA_P_SET_SYS_AGING_PARAMETER    0x08
#define AVA_P_SET_SYS_FILTER_CLEAN	     0x09
#define AVA_P_SET_SYS_TIME_ZONE			 0x10
#define AVA_P_SET_SYS_TIMESTAMP			 0x11
#define AVA_P_SET_SYS_WEB_PASS		 	 0x12
#define AVA_P_SET_SYS_ENVTEMP		 	 0x13
#define AVA_P_SET_SYS_MODE_LEVEL		 0x14
#define AVA_P_SET_SYS_HWINFO			 0x15

#define AVA_P_SET_ASIC_PLL        		 0x01	/* set for asic subtype: start with 0x01 */
#define AVA_P_SET_ASIC_SS	      		 0x02
#define AVA_P_SET_ASIC_SSDN_PRO	  		 0x03
#define AVA_P_SET_ASIC_PLL_SEL	  		 0x04

/*********** status for subtype ***********/
                                                /* status for nonce subtype */
                                                /* status for periph subtype */
                                                /* status for sys subtype */
                                                /* status for miner subtype */
#define	AVA_STATUS_ASIC_PLLCNT  		 0x00	/* status for asic subtype: start with 0x00 */
#define	AVA_STATUS_ASIC_PLL				 0x01
#define	AVA_STATUS_ASIC_PASSCORE		 0x02
#define	AVA_STATUS_ASIC_FAILCORE		 0x03
#define	AVA_STATUS_ASIC_TEMP			 0x04
#define	AVA_STATUS_ASIC_VOLT			 0x05
#define	AVA_STATUS_ASIC_EFUSE			 0x06
#define	AVA_STATUS_ASIC_MAX				 0x07

/************ ↑↑↑ data packet type between driver-avalon and mmu  service comm  ↑↑↑ ************/

typedef enum {
    LED_MODE_DAY,
    LED_MODE_DARK,
    LED_MODE_MAX,
} LED_MODE;

struct lcd_api{
	uint16_t key;
	uint16_t val;
};

struct sn_api{
	uint8_t hash;
	uint8_t sn[SN_LEN+1];
};

typedef struct{
	uint8_t mode;
	uint16_t duration;
}night_lamp;

typedef enum {
    LED_DARK = 0,      	// dark
    LED_LIGHTCONTINUE, 	// single color, e.g. red/green/yellow
    LED_BLINK,         	// blink
    LED_BREATH,        	// breath light
    LED_COLORCYCLE,    	// color cycle light
    LED_SHRINK,       	// shrink
    LED_EXTEND,       	// extend
    LED_EFFECT_MAX,
} LED_EFFECT;

typedef enum{
	DEV_VERTICAL = 0,
	DEV_INCLINED
}Horizontal;

typedef enum{
	IN_INIT = 0,
	IN_WORK,
	IN_STANDBY,
	IN_IDLE,
	IN_FAULT,
}workstate_sys;

enum {
    WORK_MODE_LOW = 0,
    WORK_MODE_MID,
    WORK_MODE_HIGH,
    WORK_MODE_MAX
};

typedef struct cali_param_t{
	uint16_t max_pout;
	uint16_t temp;
	uint16_t volt;
	uint16_t pll_start;
	uint16_t pll_interval;
}cali_param;
typedef struct {
   uint8_t aging_finished;
   cali_param param;
}miner_cali_info;

typedef struct{
	uint8_t vaild;
	time_t timestamp;
}soft_onoff;

typedef struct{
	char chipid[7];
	uint8_t nonce_mask;
	uint32_t local_work[HBOARD_COUNT];
	uint32_t errcode[HBOARD_COUNT+1];
	uint32_t err_crc[HBOARD_COUNT];
	uint32_t com_crc[HBOARD_COUNT];
	uint32_t mhsmm;
	uint32_t mhsspd;
	double dh;
	double spd_dh;
	double realtime_dh;
	double m_temp_sumavg;
	double m_temp_summax;
	float freq;
}miner_info;

struct miner_nonce {
	volatile uint32_t job_id : 32;
	volatile uint32_t nonce2 : 32;
	volatile uint32_t nonce : 32;
	volatile uint32_t asic_id : 10;
	volatile uint32_t miner_id : 6;
	volatile uint32_t ntime : 8;
	volatile uint32_t mid_id : 4;
	volatile uint32_t valid : 4;
	volatile uint32_t last_job_nonce2: 32;
};

typedef struct{
	uint8_t ip[4];
	uint8_t mac[6];
	uint8_t mask[4];
	uint8_t gateway[4];
	uint8_t dns[4];
	uint8_t dns_bak[4];
	char ssid_name[128];
	uint8_t protocal;
	uint8_t exist;
	int rssi;
	uint8_t devtype;
}netinfo;

typedef struct{
	uint8_t workmode;
	int32_t worklvl;
	int32_t lvlinfo[WORK_MODE_MAX];
	uint8_t bar;
	int maxmode;
	uint32_t asic_cnt;
	uint32_t max_asic_cnt;
	uint8_t state;
	uint8_t cali_all;
	miner_cali_info cali_info;
	struct hwcfg hw_info;
	char timezone[MAX_LEN_TZ];
	char webuser[WEBPASS_LEN+1];
	char webpass[WEBPASS_LEN+1];
	uint32_t filtermesh_time;
	uint32_t hu_errcode[HBOARD_COUNT];
	uint32_t mm_errcode;
	uint8_t core_bin;
	long int elapsed;
	long memfree;
	uint8_t softoff_rsn; 
}sys_info;

typedef struct{
	uint8_t miner_cnt;
    uint8_t fan_cnt;
    uint8_t maxmode;
	uint8_t reboot_record;
	uint32_t reboot_record_sub;
    char hwtype[AVALON_MM_MODULE_LEN];
    char swtype[AVALON_MM_MODULE_LEN];
	char little_ver[MAX_VER_LEN+1];
	char big_ver[MAX_VER_LEN+1];
	char dna[MAX_DNA_LEN+1];
	char sn[HBOARD_COUNT][SN_LEN+1];
}curing_sys_info;

typedef struct{
	int inlet_temp;
	int outlet_temp;
	int hash_temp;
	uint8_t upright;
	uint16_t fan[5];
	uint16_t power[10];
	netinfo net;
	uint16_t lcd_onoff;
	uint16_t lcd_show;		// msg id:off\summary\time\wallpaper
	uint16_t lcd_bright;	//auto/manu:high 8bit ;light value:litte 8bit
	uint8_t ledmode;
	int led_bright;
	ledinfo led;
	int power_actual_maxmode;
	uint16_t light_mode;
	uint16_t hash_copper;
	uint16_t mcu_err_code;
	float hash_ldo_in;
	float hash_pv;
	float hash_pv_3_4;
	float hash_pv_1_2;
	float hash_pv_1_4;
}periph_info;


#define AVALON_P_COINBASE_SIZE	        (6 * 1024 + 64)
#define AVALON_P_MERKLES_COUNT	        30
#define AVALON_P_TARTGET_LEN            32

typedef struct{
	uint32_t job_id;
	size_t coinbase_len;
	uint8_t coinbase[AVALON_P_COINBASE_SIZE];
	uint32_t nonce2;
	int nonce2_offset;
	int nonce2_size; /* only 4 is support atm. */
	int merkle_offset;
	int nmerkles;
	uint8_t merkles[AVALON_P_MERKLES_COUNT][32];
	uint8_t header[128];
	uint8_t	target[32];
	uint32_t vmask[8];
	uint32_t start;
	uint32_t range;
	uint8_t work_restart;
}mm_work;

typedef struct{
	uint8_t miner_id;
	uint16_t asic_id;
	uint32_t freq[TOAST_PLL_COUNT];
}asic_pll_setting;

#endif