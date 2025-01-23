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
#include <math.h>
#include <unistd.h> 
#include <dirent.h>
#include "miner.h"
#include "driver-avalon.h"
#include "crc.h"
#include "sha2.h"
#include "mm_miner.h"
#include "logging.h"

#define ERR_STEP_NULL						0
#define ERR_STEP_NONCE2						1
#define ERR_STEP_NONCE2_ERROR				2
#define ERR_STEP_JOBID_ERROR				3
#define ERR_STEP_JOBID_AND_NONCE2			4
#define ERR_STEP_JOBID_AND_NONCE2_ERROR		5

#define ENUM_NONCE_OK						0		// nonce true
#define ENUM_NONCE_DUP						1		// nonce duplicate
#define ENUM_NONCE_ERR						2		// nonce error

#define	FACTCFG_OTHERS_SET_PROD				101
#define	FACTCFG_OTHERS_SET_MODEL			105
#define	FACTCFG_QUERY						255

#define LED_COLOR_MAX   					(0xFF)
#define LED_OFST_R      					(8 * 2)
#define LED_OFST_G      					(8 * 1)
#define LED_OFST_B      					(8 * 0)

pthread_mutex_t mutex_msg;
qr_auth *g_ava_qr_auth;
static mm_work g_mm_work;
static uint8_t msg_data[10*1024];
bool fac_cfg_locked =true;
bool work_update = false; 
uint8_t g_ava_qr_login = 0;
int g_msgId = -1;
int opt_avalon_freq_sel = AVALON_DEFAULT_FREQUENCY_SEL;
int opt_avalon_polling_delay = AVALON_DEFAULT_POLLING_DELAY;
uint32_t opt_avalon_nonce_mask = AVALON_DEFAULT_NONCE_MASK;
uint32_t opt_avalon_nonce_check = AVALON_DEFAULT_NONCE_CHECK;
uint32_t opt_avalon_roll_enable = AVALON_DEFAULT_ROLL_ENABLE;
uint32_t opt_avalon_core_clk_sel = AVALON_DEFAULT_CORE_CLK_SEL;

char sysstatus[4][16]={
	"In Init",
	"In Work",
	"In Idle",
	"In Fault",
};

static int service_comm_init()
{
	if(g_msgId <0)
	{
		pthread_mutex_init(&mutex_msg, NULL);
		key_t key = ftok(MSG_KEY_PATH,'A');
		g_msgId = msgget(key, IPC_CREAT | 0777);
		if(g_msgId < 0)
		{
			applog(LOG_ERR,"IPC_CREAT fail\n");
			return -1;
		}
		applog(LOG_WARNING,"DO DRIVER VREAT MSG ID=%d",g_msgId);
	}
	return 0;
}
void service_msg_data_send(uint16_t type,uint8_t *p_data,uint16_t data_len)
{
	uint16_t item_num, send_len;
	Msg msg;
	struct mm_header *hdr = &msg.pkg.hdr;
	pthread_mutex_lock(&mutex_msg);
    item_num = (data_len / MSG_PKG_DATA_LEN) + ((data_len % MSG_PKG_DATA_LEN) ? 1:0);
	msg.mtype = AVALON_MM_MTYPE;
	hdr->type = type;
	hdr->len = data_len;
	hdr->num = item_num;
	send_len = MSG_PKG_DATA_LEN;

    for(int i = 0; i < item_num; i++) 
	{
        memset(msg.pkg.mtext,0,MSG_PKG_DATA_LEN);
		hdr->idx = i;
		if(i == (item_num-1))
            send_len = (data_len % MSG_PKG_DATA_LEN)?(data_len % MSG_PKG_DATA_LEN):MSG_PKG_DATA_LEN;
        if(p_data)
		    memcpy(msg.pkg.mtext,p_data + (i * MSG_PKG_DATA_LEN), send_len);
		msgsnd(g_msgId,&msg,sizeof(msg.pkg),0);
	}
    pthread_mutex_unlock(&mutex_msg);
}

static uint16_t service_msg_recv(uint8_t *pdata,uint16_t *type)
{
	#define MAX_TRY  3
	bool recv_ok = false;
	int res;
	uint8_t try = 0;
	uint32_t offset = 0;
	Msg msg_recv;
	struct mm_header *hdr = &msg_recv.pkg.hdr;
	do{
		res = msgrcv(g_msgId, &msg_recv, sizeof(msg_recv.pkg), MM_AVALON_MTYPE, 0);
		if(res > 0)
		{
			memcpy(pdata+offset,msg_recv.pkg.mtext,MSG_PKG_DATA_LEN);
			offset += MSG_PKG_DATA_LEN;
			if(hdr->idx == (hdr->num-1))
			{
				*type = hdr->type;
				recv_ok = true;
				return hdr->len;
			}
		}
		else
		{
			try ++;
		}
	}while(!recv_ok || (try>MAX_TRY));
	return 0;
}



static void asics_info_creat(struct cgpu_info *avalon, int module,uint8_t miner_count,uint16_t asiccnt)
{
	int i,j,k;
	struct avalon_info *info = avalon->device_data;

	//init for asic frequency
	if(info->asics[module].asics_freq == NULL)
	{
		info->asics[module].asics_freq = cgcalloc(miner_count, sizeof(core_pll*));
		for(i = 0; i < miner_count; i++)
		{
			info->asics[module].asics_freq[i] = cgcalloc(asiccnt, sizeof(core_pll));
			for(j = 0; j < asiccnt; j++)
			{
				for(k = 0; k < AVALON_DEFAULT_PLL_CNT; k++)
				{
					info->asics[module].asics_freq[i][j].pll[k] = 0;
				}
			}
		}
	}

	//init for spdlog_pass
	if(info->asics[module].spdlog_pass == NULL)
	{
		info->asics[module].spdlog_pass = cgcalloc(miner_count, sizeof(uint32_t*));
		for(i = 0; i < miner_count; i++)
		{
			info->asics[module].spdlog_pass[i] = cgcalloc(asiccnt,sizeof(uint32_t));
			for(j = 0; j < asiccnt; j++)
			{
				info->asics[module].spdlog_pass[i][j] = 0;
			}
		}
	}

	//init for spdlog_fail
	if(info->asics[module].spdlog_fail == NULL)
	{
		info->asics[module].spdlog_fail = cgcalloc(miner_count, sizeof(uint32_t*));
		for(i = 0; i < miner_count; i++)
		{
			info->asics[module].spdlog_fail[i] = cgcalloc(asiccnt,sizeof(uint32_t));
			for(j = 0; j < asiccnt; j++)
			{
				info->asics[module].spdlog_fail[i][j] = 0;
			}
		}
	}

	//init for asic_pllcnt
	if(info->asics[module].asic_pllcnt == NULL)
	{
		info->asics[module].asic_pllcnt = cgcalloc(miner_count, sizeof(core_pll*));
		for(i = 0; i < miner_count; i++)
		{
			info->asics[module].asic_pllcnt[i] = cgcalloc(asiccnt, sizeof(core_pll));
			for(j = 0; j < asiccnt; j++)
			{
				for(k = 0; k < AVALON_DEFAULT_PLL_CNT; k ++)
				{
					info->asics[module].asic_pllcnt[i][j].pll[k] = 0;
				}
			}
		}
	}

	//init for asic volt
	if(info->asics[module].asics_volt == NULL)
	{
		info->asics[module].asics_volt = cgcalloc(miner_count, sizeof(uint16_t*));
		for(i = 0; i < miner_count; i++)
		{
			info->asics[module].asics_volt[i] = cgcalloc(asiccnt,sizeof(uint16_t));
			for(j = 0; j < asiccnt; j++)
			{
				info->asics[module].asics_volt[i][j] = 0;
			}
		}
	}


	//init for asic temp
	if(info->asics[module].asics_temp == NULL)
	{
		info->asics[module].asics_temp = cgcalloc(miner_count, sizeof(int16_t*));
		for(i = 0; i < miner_count; i++)
		{
			info->asics[module].asics_temp[i] = cgcalloc(asiccnt,sizeof(int16_t));
			for(j = 0; j < asiccnt; j++)
			{
				info->asics[module].asics_temp[i][j] = -273;
			}
		}
	}

	//init for asic MW
	if(info->asics[module].chip_matching_work == NULL)
	{
		info->asics[module].chip_matching_work = cgcalloc(miner_count, sizeof(uint64_t*));
		for(i = 0; i < miner_count; i++)
		{
			info->asics[module].chip_matching_work[i] = cgcalloc(asiccnt,sizeof(int64_t));
			for(j = 0; j < asiccnt; j++)
			{
				info->asics[module].chip_matching_work[i][j] = 0;
			}
		}
	}

}

static int job_idcmp(uint8_t *job_id, char *pool_job_id)
{
	int job_id_len;
	unsigned short crc, crc_expect;
	if (!pool_job_id)
		return 1;

	job_id_len = strlen(pool_job_id);
	crc_expect = crc16((unsigned char *)pool_job_id, job_id_len);
	crc = job_id[0] << 8 | job_id[1];

	if (crc_expect == crc)
		return 0;

	applog(LOG_DEBUG, "avalon: job_id doesn't match! [%04x:%04x (%s)]",crc, crc_expect, pool_job_id);

	return 1;
}

static inline int get_temp_max(struct avalon_info *info, int addr)
{
	int i, j;
	int max = -273;
	for (i = 0; i < info->miner_count[addr]; i++)
	{ 
		for (j = 0; j < info->asic_count[addr]; j++) 
		{
			if (info->asics[addr].asics_temp[i][j] > max)
			{
				max = info->asics[addr].asics_temp[i][j];
			}
		}
	}

	if (max < info->inlet_temp[addr])
		max = info->inlet_temp[addr];

	return max;
}

static inline int get_miner_temp_max(struct avalon_info *info, int addr, int miner)
{
	int i;
	int max = -273;

	for (i = 0; i < info->asic_count[addr]; i++) 
	{
		if (info->asics[addr].asics_temp[miner][i] > max)
		{
			max = info->asics[addr].asics_temp[miner][i];
		}
	}

	return max;
}

static uint8_t decode_nonce_mask(uint8_t val)
{
	uint8_t nonce_mask = 24;
	if((val < 0) || (val > 8)) 
	{
		applog(LOG_ERR,"E: Invalid nonce mask");
		return 0xff;
	}

	nonce_mask += val;
	return nonce_mask;
}

static void asics_info_polling(struct cgpu_info *avalon,uint8_t modular_id, uint8_t type)
{
	int i;
	struct avalon_info *info = avalon->device_data;	

	switch (type)
	{
	case AVA_STATUS_ASIC_PLLCNT:
		if(info->asics[modular_id].asic_pllcnt)
		{
			for(i = 0; i < info->miner_count[modular_id];i++)
			{
				memcpy(info->asics[modular_id].asic_pllcnt[i], msg_data + i * sizeof(core_pll) * info->asic_count[modular_id], sizeof(core_pll) * info->asic_count[modular_id]);
			}
		}
		break;
	case AVA_STATUS_ASIC_PLL:
		if(info->asics[modular_id].asics_freq)
		{
			for(i = 0; i < info->miner_count[modular_id];i++)
			{
				memcpy(info->asics[modular_id].asics_freq[i], msg_data + i * sizeof(core_pll) * info->asic_count[modular_id], sizeof(core_pll) * info->asic_count[modular_id]);
			}
		}
		break;
	case AVA_STATUS_ASIC_PASSCORE:
		if(info->asics[modular_id].spdlog_pass)
		{
			for(i = 0; i < info->miner_count[modular_id];i++)
			{
				memcpy(info->asics[modular_id].spdlog_pass[i], msg_data + i * sizeof(uint32_t) * info->asic_count[modular_id], sizeof(uint32_t) * info->asic_count[modular_id]);
			}
		}
		break;
	case AVA_STATUS_ASIC_FAILCORE:
		if(info->asics[modular_id].spdlog_fail)
		{
			for(i = 0; i < info->miner_count[modular_id];i++)
			{
				memcpy(info->asics[modular_id].spdlog_fail[i], msg_data + i * sizeof(uint32_t) * info->asic_count[modular_id], sizeof(uint32_t) * info->asic_count[modular_id]);
			}
		}
		break;
	case AVA_STATUS_ASIC_TEMP:	
		if(info->asics[modular_id].asics_temp)
		{
			for(i = 0; i < info->miner_count[modular_id];i++)
			{
				memcpy(info->asics[modular_id].asics_temp[i], msg_data + i * sizeof(uint16_t) * info->asic_count[modular_id], sizeof(uint16_t) * info->asic_count[modular_id]);
			}
		}
		break;
	case AVA_STATUS_ASIC_VOLT:
		if(info->asics[modular_id].asics_volt)
		{
			for(i = 0; i < info->miner_count[modular_id];i++)
			{
				memcpy(info->asics[modular_id].asics_volt[i], msg_data + i * sizeof(uint16_t) * info->asic_count[modular_id], sizeof(uint16_t) * info->asic_count[modular_id]);
			}
		}
		break;
	default:
		break;
	}
}

static void check_nonce(struct cgpu_info *avalon, struct thr_info *thr, int modular_id,uint16_t data_len)
{
	struct avalon_info *info = avalon->device_data;
	struct pool *pool, *real_pool, *last_pool;
	struct pool *pool_stratum0 = &info->pool0;
	struct pool *pool_stratum1 = &info->pool1;
	struct pool *pool_stratum2 = &info->pool2;
	uint8_t job_id[2];
	uint32_t nonce, nonce2, ntime, miner_id, asic_id;
	uint32_t micro_job_id,step_nonce2,last_job_nonce2;
	int i,pool_no,brecord,total,ret_val;
	int64_t last_diff1;
	static int nonce_cnt = 0;
	struct miner_nonce *m_nonce = NULL;

	if (unlikely(!info->asic_count[0]))
		return;
	uint32_t total_asic_cnt = info->miner_count[0] * info->asic_count[0];
	total = data_len / sizeof(struct miner_nonce);
	m_nonce = (struct miner_nonce *)msg_data;
	if(work_update)
	{
		applog(LOG_NOTICE,"recv %d nonce from mm_miner job_id = 0x%x",nonce_cnt,info->last_jobid);
		nonce_cnt = 0;
		work_update =false;
	}
	nonce_cnt = total + nonce_cnt;
	for (i = 0; i < total; i++) 
	{
		if(!m_nonce->valid)
		{	
			applog(LOG_WARNING, "nonce invalid i = %d",i);
			continue;
		}
		last_job_nonce2 = m_nonce->last_job_nonce2;
		micro_job_id = m_nonce->mid_id;
		ntime = m_nonce->ntime;
		miner_id = m_nonce->miner_id;
		asic_id = m_nonce->asic_id;
		nonce = m_nonce->nonce;
		nonce2 = m_nonce->nonce2;
		job_id[0] = (m_nonce->job_id >> 24) & 0xff;
		job_id[1] = (m_nonce->job_id >> 16) & 0xff;
		pool_no = (m_nonce->job_id) & 0xffff;
		/* Can happen during init sequence before add_cgpu */
		if (unlikely(!thr))
			break;
		if ((miner_id >= info->mm_count) || (asic_id >= info->asic_count[0])) 
		{
			applog(LOG_ERR, "%s-%d-%d: Wrong miner_id:%d or asic_id:%d",avalon->drv->name, avalon->device_id, modular_id, miner_id, asic_id);
			continue;
		}
		if (pool_no >= total_pools || pool_no < 0)
			continue;
		
		if (ntime > info->max_ntime)
			info->max_ntime = ntime;
		real_pool = pool = pools[pool_no];
		last_pool = pool_stratum0;
		if (!job_idcmp(job_id, pool_stratum0->swork.job_id)) 
		{
			pool = pool_stratum0;
			last_pool = pool_stratum1;
		}
		else if (!job_idcmp(job_id, pool_stratum1->swork.job_id)) 
		{
			pool = pool_stratum1;
			last_pool = pool_stratum2;
		} 
		else if (!job_idcmp(job_id, pool_stratum2->swork.job_id)) 
		{
			pool = pool_stratum2;
			last_pool = NULL;
		} 
		else 
		{
			if (likely(thr))
				inc_hw_errors(thr);
			info->hw_works_i[modular_id][miner_id]++;
			applog(LOG_ERR,"job_id compare error");
			continue;
		}
		last_diff1 = avalon->diff1;
		brecord = ENUM_NONCE_OK;
		step_nonce2 = ERR_STEP_NULL;
		ret_val = submit_nonce2_nonce(thr, pool, real_pool, nonce2, nonce, ntime, micro_job_id);
		if (ret_val == 0) // duplicate nonce
		{
			brecord = ENUM_NONCE_DUP;
		}
		else if(ret_val < 0) // error, correct the nonce2 and check it again
		{
			if(nonce2 < total_asic_cnt)
			{
				if(!last_pool || !last_pool->swork.job_id)
				{
					step_nonce2 = ERR_STEP_JOBID_ERROR;
					brecord = ENUM_NONCE_ERR;
				} 
				else 
				{
					// last circle's end nonce2 is n, this asci's nonce2 is x in this circle,
					// so the real changing of nonce2 is ...->n->0->...->x->...
					// then this asci's last nonce2 is (n+1+x-total_asic_cnt)
					step_nonce2 = ERR_STEP_JOBID_AND_NONCE2;
					nonce2 = last_job_nonce2 + 1 + nonce2 - total_asic_cnt;
					pool = last_pool;
					brecord = ENUM_NONCE_OK;
				}
			}
			else
			{
				step_nonce2 = ERR_STEP_NONCE2;
				nonce2 -= total_asic_cnt;
				brecord = ENUM_NONCE_OK;
			}
			if((step_nonce2 == ERR_STEP_NONCE2) || (step_nonce2 == ERR_STEP_JOBID_AND_NONCE2))
			{
				clear_new_nonce(thr);
				if (submit_nonce2_nonce(thr, pool, real_pool, nonce2, nonce, ntime, micro_job_id) <= 0)
				{
					if (step_nonce2 == ERR_STEP_NONCE2)
						step_nonce2 = ERR_STEP_NONCE2_ERROR;
					else
						step_nonce2 = ERR_STEP_JOBID_AND_NONCE2_ERROR;
					brecord = ENUM_NONCE_ERR;
				}
			}
		}
		switch(brecord)
		{
		case ENUM_NONCE_OK:
			info->diff1[modular_id][miner_id] += (avalon->diff1 - last_diff1);
			info->asics[modular_id].chip_matching_work[miner_id][asic_id]++;
			break;
		case ENUM_NONCE_DUP:
			info->dhw_works[modular_id]++;
			break;
		case ENUM_NONCE_ERR:
			if (likely(thr))
				inc_hw_errors(thr);
			info->hw_works_i[modular_id][miner_id]++;
			break;
		default:
			break;
		}
		m_nonce ++;
	}
}

static int polling_get_info(struct cgpu_info *avalon,int modular_id,int msgId)
{
	Msg msg;
	uint16_t recv_type;
	uint16_t recv_len = 0;
	periph_info periph_info;
 	sys_info sys_info;
	miner_info mm_info;
	memset(&msg,0,sizeof(Msg));
	service_msg_data_send(AVA_P_POLLING,NULL,1); 
	recv_len = service_msg_recv(msg_data,&recv_type);
	if(recv_len == 0)
	{
		applog(LOG_ERR,"polling recv failed");
		return -1;
	}
	struct avalon_info *info = avalon->device_data;
	struct thr_info *thr = NULL;
	uint8_t primary_type = 0,minor_type = 0;
	int i,j;
	if (likely(avalon->thr))
		thr = avalon->thr[0];
	primary_type = recv_type & 0xff;
	minor_type = (recv_type >> 8) & 0xff;
	switch (primary_type)
	{
	case AVA_P_STATUS_NONCE:
		check_nonce(avalon, thr, modular_id,recv_len);
		break;
	case AVA_P_STATUS_SYS:
		memset(&sys_info,0,sizeof(sys_info));
		memcpy(&sys_info,msg_data,sizeof(sys_info));
		info->asic_count[modular_id] = sys_info.asic_cnt;
		info->max_asic_count[modular_id] = sys_info.max_asic_cnt;
		info->workmode[modular_id] = sys_info.workmode;
		info->worklvl[modular_id] = sys_info.worklvl;
		info->memfree[modular_id] = sys_info.memfree;
		memcpy(&info->lvlinfo[modular_id],&sys_info.lvlinfo,sizeof(info->lvlinfo[modular_id]));
		info->maxmode[modular_id] = sys_info.maxmode;
		info->bar[modular_id] = sys_info.bar;
		info->filtermesh_time[modular_id] = sys_info.filtermesh_time;
		strncpy(info->timezone[modular_id],sys_info.timezone,MAX_LEN_TZ);
		strncpy(info->webpass[modular_id],sys_info.webpass,WEBPASS_LEN+1);
		strncpy(info->webuser[modular_id],sys_info.webuser,WEBPASS_LEN+1);
		memcpy(&info->hw_info[modular_id],&sys_info.hw_info,sizeof(struct hwcfg));
		info->state[modular_id] = sys_info.state;
		memcpy(&info->cali_info[modular_id],&sys_info.cali_info,sizeof(miner_cali_info));
		if(info->asic_count[modular_id])
		{
			asics_info_creat(avalon,modular_id,info->miner_count[modular_id],info->max_asic_count[modular_id]);
		}
		for(i = 0; i< info->miner_count[modular_id]; i++)
			info->hu_errcode[modular_id][i] = sys_info.hu_errcode[i];
		info->mm_errcode[modular_id] = sys_info.mm_errcode;
		info->miner[modular_id].core_bin = sys_info.core_bin;
		info->sys_elapsed[modular_id] = sys_info.elapsed;
		info->softoff_rsn[modular_id] = sys_info.softoff_rsn;
		info->cali_all[modular_id] = sys_info.cali_all;
		break;
	case AVA_P_STATUS_PERIPH:
		memset(&periph_info,0,sizeof(periph_info));
		memcpy(&periph_info, msg_data, sizeof(periph_info));
		info->inlet_temp[modular_id] = periph_info.inlet_temp;
		info->outlet_temp[modular_id] = periph_info.outlet_temp;
		for(i= 0; i<info->fan_count[modular_id];i++)
		{
			info->fan_cpm[modular_id][i] = periph_info.fan[i];
		}
		info->fan_pct[modular_id] = periph_info.fan[i];
		// power[0]:err     power[1]:0          power[2]:vout      power[3]:iout      power[4]:0
		// power[5]:voutcmd power[6]:poutwall   power[7]:min_vol   power[8]:max_vol   power[9]:0
		memcpy(info->power_info[modular_id], periph_info.power, sizeof(periph_info.power));
		memcpy(info->net_info.ip, periph_info.net.ip, sizeof(periph_info.net.ip));
		memcpy(info->net_info.mac, periph_info.net.mac, sizeof(periph_info.net.mac));
		memcpy(info->net_info.mask, periph_info.net.mask, sizeof(periph_info.net.mask));
		memcpy(info->net_info.gateway, periph_info.net.gateway, sizeof(periph_info.net.gateway));
		memcpy(info->net_info.dns, periph_info.net.dns, sizeof(periph_info.net.dns));
		memcpy(info->net_info.dns_bak, periph_info.net.dns_bak, sizeof(periph_info.net.dns_bak));
		memcpy(info->net_info.ssid_name, periph_info.net.ssid_name, sizeof(periph_info.net.ssid_name));
		memcpy(info->net_info.mac, periph_info.net.mac, sizeof(periph_info.net.mac));
		info->net_info.protocal = periph_info.net.protocal;
		info->net_info.rssi = periph_info.net.rssi;
		info->net_info.devtype = periph_info.net.devtype;
		info->lcd_onoff[modular_id] = periph_info.lcd_onoff;
		info->lcd_show[modular_id] = periph_info.lcd_show;
		info->lcd_bright[modular_id] = periph_info.lcd_bright;
		info->ledmode = periph_info.ledmode;
		memcpy(&info->led, &periph_info.led, sizeof(periph_info.led));
		break;
	case AVA_P_STATUS_MINER:
		memset(&mm_info, 0, sizeof(miner_info));
		memcpy(&mm_info, msg_data, sizeof(miner_info));
		memcpy(info->miner[modular_id].asic_chipid, mm_info.chipid, 7);
		info->miner[modular_id].noncemask 		= decode_nonce_mask(mm_info.nonce_mask);
		if(info->asics[modular_id].asics_freq) 
		{
			for(i = 0; i < info->miner_count[modular_id]; i++)
			{
				for(j = 0 ; j < AVALON_DEFAULT_PLL_CNT; j++)
				{
					info->miner[modular_id].set_freq[i].pll[j] 	=  info->asics[modular_id].asics_freq[i][0].pll[j];			
				}
			}
		}
		info->miner[modular_id].local_works = 0;
		for(i = 0; i < info->miner_count[modular_id]; i++)
			info->miner[modular_id].local_works 	+= mm_info.local_work[i];
		memcpy(info->miner[modular_id].errcode_crc, mm_info.err_crc, sizeof(mm_info.err_crc));
		memcpy(info->miner[modular_id].com_crc, mm_info.com_crc, sizeof(mm_info.com_crc));
		info->miner[modular_id].mhsmm 			= mm_info.mhsmm;
		info->miner[modular_id].mhsspd 			= mm_info.mhsspd;
		info->miner[modular_id].dh 				= mm_info.dh;
		info->miner[modular_id].spd_dh 			= mm_info.spd_dh;
		info->miner[modular_id].realtime_dh 	= mm_info.realtime_dh;
		info->miner[modular_id].m_temp_sumavg 	= mm_info.m_temp_sumavg;
		info->miner[modular_id].m_temp_summax	= mm_info.m_temp_summax;
		info->miner[modular_id].freq			= mm_info.freq;
		break;
	case AVA_P_STATUS_ASIC:
		asics_info_polling(avalon,modular_id,minor_type);
		break;
	default:
		break;
	}
	return 0;
}


static void update_pool_work(struct cgpu_info *avalon, struct pool *pool)
{
	struct avalon_info *info = avalon->device_data;
	const int merkle_offset = 36;
	uint32_t tmp;
	unsigned char target[32];
	int job_id_len, n2size;
	unsigned short crc;
	uint32_t range, start;

	g_mm_work.coinbase_len = pool->coinbase_len;
	g_mm_work.nonce2_offset = pool->nonce2_offset;
	n2size = pool->n2size >= 4 ? 4 : pool->n2size;
	g_mm_work.nonce2_size = n2size;
	g_mm_work.merkle_offset = merkle_offset;
	g_mm_work.nmerkles = pool->merkles;

	if (pool->n2size == 3)
		range = 0xffffff / (total_devices ? total_devices : 1);
	else
		range = 0xffffffff / (total_devices ? total_devices : 1);

	start = range * avalon->device_id;
	g_mm_work.start = start;
	g_mm_work.range = range;

	if (info->work_restart) 
	{
		// applog(LOG_INFO,"HERE  info->work_restart  IS TRUE");
		info->work_restart = false;
		g_mm_work.work_restart = 0x1;
	}

	g_mm_work.vmask[0] = pool->vmask_001[0];
	g_mm_work.vmask[1] = pool->vmask_001[1];
	g_mm_work.vmask[2] = pool->vmask_001[2];
	g_mm_work.vmask[3] = pool->vmask_001[3];
	g_mm_work.vmask[4] = pool->vmask_001[4];
	g_mm_work.vmask[5] = pool->vmask_001[5];
	g_mm_work.vmask[6] = pool->vmask_001[6];
	g_mm_work.vmask[7] = pool->vmask_001[7];

	if (pool->sdiff <= AVALON_DRV_DIFFMAX)
		set_target(target, pool->sdiff);
	else
		set_target(target, AVALON_DRV_DIFFMAX);

	memcpy(&g_mm_work.target,&target,sizeof(target));

	if (opt_debug) 
	{
		char *target_str;
		target_str = bin2hex(target, AVALON_P_TARTGET_LEN);
		applog(LOG_DEBUG, "%s-%d: Pool stratum target: %s", avalon->drv->name, avalon->device_id, target_str);
		free(target_str);
	}

	job_id_len = strlen(pool->swork.job_id);
	crc = crc16((unsigned char *)pool->swork.job_id, job_id_len);
	tmp = ((crc << 16) | pool->pool_no);

	if (info->last_jobid != tmp) 
	{
		info->last_jobid = tmp;
		g_mm_work.job_id = tmp;
	}
	memcpy(g_mm_work.coinbase, pool->coinbase, pool->coinbase_len);
	memcpy(g_mm_work.header,pool->header_bin,sizeof(g_mm_work.header));

	for(int i = 0; i < pool->merkles; i++)
		memcpy(g_mm_work.merkles[i],pool->swork.merkle_bin[i],32);

	applog(LOG_NOTICE,"send work to mm_miner,job_id = 0x%x",tmp);
	work_update = true;
	service_msg_data_send(AVA_P_SET_JOB,(uint8_t*)&g_mm_work,sizeof(mm_work));   
}

struct cgpu_info *virtual_alloc_cgpu(struct device_drv *drv, int threads)
{
	struct cgpu_info *cgpu = cgcalloc(1, sizeof(*cgpu));
	cgpu->drv = drv;
	cgpu->deven = DEV_ENABLED;
	cgpu->threads = threads;
	return cgpu;
}
struct cgpu_info *virtual_free_cgpu(struct cgpu_info *cgpu)
{
	if (cgpu->drv->copy)
		free(cgpu->drv);
	free(cgpu->device_path);
	free(cgpu);
	return NULL;
}

static bool avalon_prepare(struct thr_info *thr)
{
	struct cgpu_info *avalon = thr->cgpu;
	struct avalon_info *info = avalon->device_data;

	info->last_diff1 = 0;
	info->pending_diff1 = 0;
	info->last_rej = 0;
	info->xfer_err_cnt = 0;
	info->pool_no = 0;

	memset(&(info->firsthash), 0, sizeof(info->firsthash));
	cgtime(&(info->last_fan_adj));
	cgtime(&info->last_stratum);
	cgtime(&info->last_detect);

	cglock_init(&info->update_lock);
	cglock_init(&info->pool0.data_lock);
	cglock_init(&info->pool1.data_lock);
	cglock_init(&info->pool2.data_lock);

	return true;
}

static void avalon_sswork_flush(struct cgpu_info *avalon)
{
	struct avalon_info *info = avalon->device_data;
	struct thr_info *thr = avalon->thr[0];
	if (thr->work_restart)
	{
		info->work_restart = true;
		// applog(LOG_INFO,"DO SET  info->work_restart  IS TRUE  0000");
	}
		
}

static int avalon_set_freq(struct cgpu_info *avalon, int addr, int miner_id, int asic_id, unsigned short freq[])
{
	u_int16_t type = 0;
	asic_pll_setting pll_setting;
	memcpy(pll_setting.freq,freq,sizeof(pll_setting.freq));
	pll_setting.miner_id = miner_id;
	pll_setting.asic_id = asic_id;
	applog(LOG_OP, "%d-%d: nano3s set freq miner %d-%d, freq:%d",
			avalon->device_id, addr, miner_id, asic_id, freq[3]);
	type = (AVA_P_SET_ASIC << 8) | AVA_P_SET_ASIC_PLL;
	service_msg_data_send(type,(uint8_t *)&pll_setting,sizeof(pll_setting));
	return 0;
}

static void little_detect_modules(struct cgpu_info *avalon)
{
	#define MAX_ATTEMPT  10
	struct avalon_info *info = avalon->device_data;
	int i, j;
	uint8_t attempt = 0;
	Msg msg_send;
	uint16_t recv_type;
	uint16_t data_offset = 0;
	uint8_t recvdata[512];
	if(service_comm_init())
		return;
	for (i = 0; i < AVALON_DEFAULT_MODULARS; i++) 
	{
		if (info->enable[i])
			continue;
		applog(LOG_WARNING,"DO driver_avalon detect");
		memset(&msg_send,0,sizeof(Msg));
		service_msg_data_send(AVA_P_DETECT,NULL,1);
		do{
			if(service_msg_recv(recvdata,&recv_type))
			{
				applog(LOG_WARNING,"DO driver_avalon recev recv_type=%d",recv_type);
				if(recv_type == AVA_P_ACKDETECT)
				{
					info->miner_count[i] = *(recvdata+data_offset);
					data_offset += sizeof(uint8_t);
					info->fan_count[i] = *(recvdata+data_offset);
					data_offset += sizeof(uint8_t);
					info->maxmode[i] = *(recvdata+data_offset);
					data_offset += sizeof(uint8_t);
					info->reboot_record[i] = *(recvdata+data_offset);
					data_offset += sizeof(uint8_t);
					info->reboot_record_sub[i] = *(recvdata+data_offset);
					data_offset += sizeof(uint32_t );
					memcpy(info->little_ver[i],(char*)&recvdata+data_offset,MAX_VER_LEN);
					data_offset += MAX_VER_LEN;
					memcpy(info->big_ver[i],(char*)&recvdata+data_offset,MAX_VER_LEN);
					data_offset += MAX_VER_LEN;
					memcpy(info->dna[i],(char*)&recvdata+data_offset,MAX_DNA_LEN);
					data_offset += MAX_DNA_LEN;
					memcpy(info->mm_hw[i],(char*)&recvdata+data_offset,AVALON_MM_MODULE_LEN);
					data_offset += AVALON_MM_MODULE_LEN;
					memcpy(info->mm_sw[i],(char*)&recvdata+data_offset,AVALON_MM_MODULE_LEN);
					data_offset += AVALON_MM_MODULE_LEN;
					for (int j=0;j<AVALON_DEFAULT_MINER_CNT;j++)
					{
						memcpy(info->sn[i][j],(char*)&recvdata+data_offset,SN_LEN+1);
						data_offset += SN_LEN+1;
					}
					applog(LOG_WARNING,"DO driver_avalon recev detect ack,little version:%s,big version:%s ,miner count is %d fan count is %d dna is %s sw is %s hw is %s maxmode is %d",info->little_ver[i],info->big_ver[i],info->miner_count[i],info->fan_count[i],info->dna[i],info->mm_sw[i],info->mm_hw[i],info->maxmode[i]);
					break;
				}
			}
			else
			{
				attempt++;
			}
		}while(attempt < MAX_ATTEMPT);
		/* Check count of modulars */
		if (i == AVALON_DEFAULT_MODULARS) 
		{
			applog(LOG_NOTICE, "You have connected more than %d machines. This is discouraged.", (AVALON_DEFAULT_MODULARS - 1));
			info->conn_overloaded = true;
			break;
		} 
		else
		{
			info->conn_overloaded = false;
		}

		info->enable[i] = 1;
		cgtime(&info->elapsed[i]);

		info->temp_overheat[i] = AVALON_DEFAULT_TEMP_OVERHEAT;
		info->fan_pct[i] = 100;
		info->cali_info[i].param.temp = AVALON_DEFAULT_TEMP_TARGET;
		memset(info->fan_cpm[i], 0, sizeof(info->fan_cpm[i]));

		info->inlet_temp[i] = -273;
		info->hw_works[i] = 0;
		info->dhw_works[i] = 0;

		for (j = 0; j < info->miner_count[i]; j++) 
		{
			info->hw_works_i[i][j] = 0;
			info->error_code[i][j] = 0;
			info->diff1[i][j] = 0;
		}
		info->error_code[i][j] = 0;

		applog(LOG_NOTICE, "%s-%d: New module detected! ID[%d-%x]", avalon->drv->name, avalon->device_id, i, info->dna[i][MAX_DNA_LEN - 1]);
	}

}

static struct cgpu_info *avalon_device_detect(void)
{
	#define DETECT_TMS	3
	int tms = 0;
	int i, modules = 0;
	struct avalon_info *info;
	struct cgpu_info *avalon = virtual_alloc_cgpu(&avalon_drv, 1);
	
	applog(LOG_WARNING,"avalon_device_detect~~~");
	
	applog(LOG_WARNING, "%s-%d: Found at %s", avalon->drv->name, avalon->device_id,
	       avalon->device_path);

	avalon->device_data = cgcalloc(1, sizeof(struct avalon_info));
	memset(avalon->device_data, 0, sizeof(struct avalon_info));
	info = avalon->device_data;

	for (i = 0; i < AVALON_DEFAULT_MODULARS; i++)
		info->enable[i] = 0;

	info->connecter = AVALON_CONNECTER_UART;

	do {
		little_detect_modules(avalon);
		tms++;
		modules = 0;
		for (i = 0; i < AVALON_DEFAULT_MODULARS; i++)
			modules += info->enable[i];
		if (modules == 0)
			sleep(2);
	} while ((modules == 0) && (tms < DETECT_TMS));

	if (!modules) 
	{
		applog(LOG_WARNING, "avalon found but no modules initialised");
		free(info);
		avalon = virtual_free_cgpu(avalon);
		return NULL;
	}

	info->mm_count = modules;//wendy add 
	/* We have an avalon uart connected */
	avalon->threads = 1;
	bool retb = add_cgpu(avalon);
	if(!retb)
	{
		applog(LOG_WARNING, "avalon found but add cgpu failed");
		free(info);
		avalon = virtual_free_cgpu(avalon);
		return NULL;
	}

	return avalon;
}

static inline void avalon_detect(bool __maybe_unused hotplug)
{
	avalon_device_detect();
}

static polling_status_t polling(struct cgpu_info *avalon,int msgId)
{
	struct avalon_info *info = avalon->device_data;
	int i;

	for (i = 0; i < AVALON_DEFAULT_MODULARS; i++) 
	{
		cgsleep_ms(opt_avalon_polling_delay);
		if((!info->enable[i]))
			return ERROR;
		polling_get_info(avalon,i,msgId);
	}
	return NORMAL;
}

static void copy_pool_stratum(struct pool *pool_stratum, struct pool *pool)
{
	int i;
	int merkles = pool->merkles, job_id_len;
	size_t coinbase_len = pool->coinbase_len;
	unsigned short crc;

	if (!pool->swork.job_id)
		return;

	if (pool_stratum->swork.job_id) 
	{
		job_id_len = strlen(pool->swork.job_id);
		crc = crc16((unsigned char *)pool->swork.job_id, job_id_len);
		job_id_len = strlen(pool_stratum->swork.job_id);

		if (crc16((unsigned char *)pool_stratum->swork.job_id, job_id_len) == crc)
			return;
	}

	cg_wlock(&pool_stratum->data_lock);
	free(pool_stratum->swork.job_id);
	free(pool_stratum->nonce1);
	free(pool_stratum->coinbase);

	pool_stratum->coinbase = cgcalloc(1, coinbase_len);
	memcpy(pool_stratum->coinbase, pool->coinbase, coinbase_len);

	for (i = 0; i < pool_stratum->merkles; i++)
		free(pool_stratum->swork.merkle_bin[i]);

	if (merkles) 
	{
		pool_stratum->swork.merkle_bin = cgrealloc(pool_stratum->swork.merkle_bin,sizeof(char *) * merkles + 1);
		if(pool_stratum->swork.merkle_bin)
		{
			for (i = 0; i < merkles; i++) 
			{
				pool_stratum->swork.merkle_bin[i] = cgmalloc(32);
				if(pool_stratum->swork.merkle_bin[i])
				{
					memcpy(pool_stratum->swork.merkle_bin[i], pool->swork.merkle_bin[i], 32);
				}
			}
		}
	}

	pool_stratum->sdiff = pool->sdiff;
	pool_stratum->coinbase_len = pool->coinbase_len;
	pool_stratum->nonce2_offset = pool->nonce2_offset;
	pool_stratum->n2size = pool->n2size;
	pool_stratum->merkles = pool->merkles;
	pool_stratum->swork.job_id = strdup(pool->swork.job_id);
	pool_stratum->nonce1 = strdup(pool->nonce1);

	memcpy(pool_stratum->ntime, pool->ntime, sizeof(pool_stratum->ntime));
	memcpy(pool_stratum->header_bin, pool->header_bin, sizeof(pool_stratum->header_bin));

	memcpy(pool_stratum->vmask_001, pool->vmask_001, sizeof(pool_stratum->vmask_001));
	memcpy(pool_stratum->vmask_002, pool->vmask_002, sizeof(pool_stratum->vmask_002));
	memcpy(pool_stratum->vmask_003, pool->vmask_003, sizeof(pool_stratum->vmask_003));

	cg_wunlock(&pool_stratum->data_lock);
}

static void avalon_sswork_update(struct cgpu_info *avalon)
{
	struct avalon_info *info = avalon->device_data;
	struct pool *pool;
	int coinbase_len_posthash, coinbase_len_prehash;

	cgtime(&info->last_stratum);
	/* Step 1: MM protocol check */
	pool = current_pool();
	if (!pool->has_stratum) 
	{
		applog(LOG_ERR, "%s-%d: MM has to use stratum pools", avalon->drv->name, avalon->device_id);
		return;
	}

	coinbase_len_prehash = pool->nonce2_offset - (pool->nonce2_offset % SHA256_BLOCK_SIZE);
	coinbase_len_posthash = pool->coinbase_len - coinbase_len_prehash;

	if (coinbase_len_posthash + SHA256_BLOCK_SIZE > AVALON_P_COINBASE_SIZE) 
	{
		applog(LOG_ERR, "%s-%d: MM pool modified coinbase length(%d) is more than %d",
		       avalon->drv->name, avalon->device_id,
		       coinbase_len_posthash + SHA256_BLOCK_SIZE, AVALON_P_COINBASE_SIZE);
		return;
	}
	if (pool->merkles > AVALON_P_MERKLES_COUNT) 
	{
		applog(LOG_ERR, "%s-%d: MM merkles has to be less then %d", avalon->drv->name, avalon->device_id, AVALON_P_MERKLES_COUNT);
		return;
	}
	if (pool->n2size < 3) 
	{
		applog(LOG_ERR, "%s-%d: MM nonce2 size has to be >= 3 (%d)", avalon->drv->name, avalon->device_id, pool->n2size);
		return;
	}
	cg_wlock(&info->update_lock);

	/* Step 2: Send out stratum pkgs */
	cg_rlock(&pool->data_lock);
	info->pool_no = pool->pool_no;
	copy_pool_stratum(&info->pool2, &info->pool1);
	copy_pool_stratum(&info->pool1, &info->pool0);
	copy_pool_stratum(&info->pool0, pool);

	update_pool_work(avalon,pool);
	cg_runlock(&pool->data_lock);
	/* Step 3: Send out finish pkg */
	// avalon_s	tratum_finish(avalon);
	cg_wunlock(&info->update_lock);
}

static int64_t avalon_scanhash(struct thr_info *thr)
{
	struct cgpu_info *avalon = thr->cgpu;
	struct avalon_info *info = avalon->device_data;
	struct timeval current;
	int i, count = 0;
	int64_t ret;
	if(thr->work_restart)
		return 0;
	cgtime(&current);

    count = 0;
	for (i = 0; i < AVALON_DEFAULT_MODULARS; i++)
	{
		if (!info->enable[i])
		{
			count ++;
		}
	}

	if(count == AVALON_DEFAULT_MODULARS)
		info->mm_count = 0;

	/* Step 2: Try to detect new modules */
	if ((tdiff(&current, &(info->last_detect)) > AVALON_MODULE_DETECT_INTERVAL) && !info->mm_count) 
	{
		little_detect_modules(avalon);
		cgtime(&info->last_detect);
		count = 0;
		for (i = 0; i < AVALON_DEFAULT_MODULARS; i++) 
		{
			if (info->enable[i])
			{
				count++;
			}
		}
		info->mm_count = count;
	}
	/* Step 4: Polling  */
	cg_rlock(&info->update_lock);
	ret = polling(avalon,g_msgId);
	cg_runlock(&info->update_lock);
	if(!ret)
		cgtime(&info->last_detect);
	/* Step 6: Calculate hashes. Use the diff1 value which is scaled by
	 * device diff and is usually lower than pool diff which will give a
	 * more stable result, but remove diff rejected shares to more closely
	 * approximate diff accepted values. */
	info->pending_diff1 += avalon->diff1 - info->last_diff1;
	info->last_diff1 = avalon->diff1;
	info->pending_diff1 -= avalon->diff_rejected - info->last_rej;
	info->last_rej = avalon->diff_rejected;
	if (info->pending_diff1 && !info->firsthash.tv_sec) 
	{
		cgtime(&info->firsthash);
		copy_time(&(avalon->dev_start_tv), &(info->firsthash));
	}

	if (info->pending_diff1 <= 0)
	{
		ret = 0;
	}
	else 
	{
		ret = info->pending_diff1;
		info->pending_diff1 = 0;
	}
	return ret * 0x100000000ull;
}

#define STATBUFLEN_WITH_DBG			(64 * 1024)
/* Once statbuf for debug is allocated, NEVER free to avoid fragmentation */
static char *get_statbuf(void)
{
	static char *buf = NULL;
	if (buf == NULL)
		buf = cgcalloc(1, STATBUFLEN_WITH_DBG);

	memset(buf, '\0', STATBUFLEN_WITH_DBG);
	return buf;
}

extern uint32_t pool_failcnt;
extern char *show_netfail(void);

static void avalon_web_stats(struct cgpu_info *avalon,void * data,uint8_t type)
{
	struct avalon_info *info = avalon->device_data;
	web_stats_misc *stats_misc = NULL;
	web_stats_net *stats_net = NULL;
	web_login *login = NULL;
	uint8_t *qr_login = NULL;

	struct timeval current;
	double diff1 = 0;
	int i,j;
	cgtime(&current);
	switch(type)
	{
	case WEB_GET_MISC_STATS:
		for (i = 0; i < AVALON_DEFAULT_MODULARS; i++) 
		{
			if (!info->enable[i])
				continue;
			stats_misc = (web_stats_misc *)data;
			stats_misc->miner_count = info->miner_count[i];
			stats_misc->fanr = info->fan_pct[i];
			stats_misc->temp = info->inlet_temp[i];
			stats_misc->tempf = info->inlet_temp[i] * 9 / 5 + 32;
			stats_misc->fan1 = info->fan_cpm[i][0];
			stats_misc->GHSspd = info->miner[i].mhsspd / 1000;
			stats_misc->GHSmm = (float)info->miner[i].mhsmm / 1000;
			stats_misc->DHspd = info->miner[i].spd_dh;
			stats_misc->SoftOFF = info->state[i];
			stats_misc->HashStatus = info->mm_status[i];
			for (j = 0; j < info->miner_count[i]; j++)
				diff1 += info->diff1[i][j];
			stats_misc->GHSavg = diff1 / tdiff(&current, &(info->elapsed[i])) * 4.294967296;
			stats_misc->MTavg1 = (int)round(info->miner[i].m_temp_sumavg);
			stats_misc->MTavg1f = (int)round(info->miner[i].m_temp_sumavg) * 9 / 5 + 32;
			stats_misc->work_lvl = info->worklvl[i];
			stats_misc->wallpower = info->power_info[i][6];
			stats_misc->power_status = info->power_info[i][0];
			stats_misc->work_mode = info->workmode[i];
			stats_misc->work_mode_cnt = info->maxmode[i];
			stats_misc->asic_cnt = info->asic_count[i];
			memcpy(stats_misc->timezone,info->timezone[i],sizeof(info->timezone[i]));
		}
		break;
	case WEB_GET_NET_STATS:
		for (i = 0; i < AVALON_DEFAULT_MODULARS; i++) 
		{
			if (!info->enable[i])
				continue;
			stats_net = (web_stats_net *)data;
			stats_net->protocal = info->net_info.protocal;
			memcpy(stats_net->ip, info->net_info.ip, sizeof(stats_net->ip));
			memcpy(stats_net->mac, info->net_info.mac, sizeof(stats_net->mac));
			memcpy(stats_net->netmask, info->net_info.mask, sizeof(stats_net->netmask));
			memcpy(stats_net->gatway, info->net_info.gateway, sizeof(stats_net->gatway));
			memcpy(stats_net->dns, info->net_info.dns, sizeof(stats_net->dns));
			memcpy(stats_net->dns_bak, info->net_info.dns_bak, sizeof(stats_net->dns_bak));
			memcpy(stats_net->ssid_name, info->net_info.ssid_name, sizeof(stats_net->ssid_name));
		}
		break;

	case WEB_SET_POOLS:
		cgminer_pools_set(data,POOL_VALID_NUM);
		break;
	case WEB_GET_PASSWD:
		login = (web_login *)data;
		strncpy(login->webuser, info->webuser[0],WEBPASS_LEN + 1);
		strncpy(login->webpass, info->webpass[0],WEBPASS_LEN + 1);
		break;
	case WEB_SET_AUTH:
		g_ava_qr_auth = (qr_auth *)data;
		break;
	case WEB_GET_QR_LOGIN:
		qr_login = (uint8_t *)data;
		memcpy(qr_login,&g_ava_qr_login,sizeof(g_ava_qr_login));
		if(g_ava_qr_login)
			g_ava_qr_login = false;
		break;
	case WEB_SET_REBOOT:
		service_msg_data_send(AVA_P_WEB_REBOOT,data,1); 
		break;
	default:
		break;
	}
	
}

static void avalon_get_login(struct cgpu_info *avalon,char* user,char* pass)
{
	struct avalon_info *info = avalon->device_data;
	memcpy(user,info->webuser[0],WEBPASS_LEN+1);
	memcpy(pass,info->webpass[0],WEBPASS_LEN+1);
}

static struct api_data *avalon_api_stats(struct cgpu_info *avalon)
{
	struct api_data *root = NULL;
	struct avalon_info *info = avalon->device_data;
	struct cgpu_info *cgpu;
	int share_ping;
	int i, j, k,m;
	char buf[256];
	char *statbuf = NULL;
	struct timeval current;
	float mhsmm; //auc_temp = 0.0;
	double diff1;
	int tmp = 0;
	cgtime(&current);
	statbuf = get_statbuf();
#if (RELEASE_LVL == 0)
	char *releaselvl = "Debug";
#elif (RELEASE_LVL == 2)
	char *releaselvl = "Customized";
#else
	char *releaselvl = "Release";
#endif

	for (i = 0; i < AVALON_DEFAULT_MODULARS; i++) 
	{
		if (!info->enable[i])
			continue;
		if(!avalon->show_litestats)
		{
			sprintf(buf, "Ver[%s-%s]", info->hw_info[i].model, FWVERSION);
			strcat(statbuf, buf);
			sprintf(buf, " LVer[%s]", info->little_ver[i]);
			strcat(statbuf, buf);
			sprintf(buf, " BVer[%s]", info->big_ver[i]);
			strcat(statbuf, buf);
			sprintf(buf, " FW[%s]", releaselvl);
			strcat(statbuf, buf);

			uint8_t r = info->led.rgb >> LED_OFST_R;
			uint8_t g = info->led.rgb >> LED_OFST_G;
			uint8_t b = info->led.rgb >> LED_OFST_B;
			sprintf(buf, " LED[%d-%d] LEDUser[%d-%d-%d-%d-%d-%d]",
				info->ledmode, info->led.runeffect, info->led.effect, info->led.bright, info->led.temper, r, g, b);
			strcat(statbuf, buf);

			sprintf(buf, " LcdOnoff[%d] LcdSwitch[%d]", info->lcd_onoff[i], info->lcd_show[i]);
			strcat(statbuf, buf);

			sprintf(buf, " DNA[%s]",info->dna[i]);
			strcat(statbuf, buf);

			sprintf(buf, " MEMFREE[%ld]",info->memfree[i]);
 			strcat(statbuf, buf);

			sprintf(buf, " PFCnt[%d]", pool_failcnt);
			strcat(statbuf, buf);

			strcat(statbuf, " NETFAIL[");
			strcat(statbuf, show_netfail());
			statbuf[strlen(statbuf)] = ']';

			strcat(statbuf, " SYSTEMSTATU[");
			sprintf(buf, "Work: %s, Hash Board: %d", sysstatus[info->state[i]],info->miner_count[i]);
			strcat(statbuf, buf);
			statbuf[strlen(statbuf)] = ']';

			sprintf(buf, " Elapsed[%ld]", info->sys_elapsed[i]);
			strcat(statbuf, buf);

			sprintf(buf, " BOOTBY[0x%02X.%08X]", info->reboot_record[i], info->reboot_record_sub[i]);
			strcat(statbuf, buf);


			sprintf(buf, " LW[%"PRIu32"]", info->miner[i].local_works);
			strcat(statbuf, buf);

			strcat(statbuf, " MH[");
			info->hw_works[i]  = 0;
			for (j = 0; j < info->miner_count[i]; j++) 
			{
				info->hw_works[i] += info->hw_works_i[i][j];
				sprintf(buf, "%"PRIu64" ", info->hw_works_i[i][j]);
				strcat(statbuf, buf);
			}
			statbuf[strlen(statbuf) - 1] = ']';

			sprintf(buf, " DHW[%"PRIu64"] HW[%"PRIu64"]", info->dhw_works[i], info->hw_works[i]);
			strcat(statbuf, buf);

			sprintf(buf, " DH[%.3f%%]", info->miner[i].dh);
			strcat(statbuf, buf);

			sprintf(buf, " ITemp[%d]", info->inlet_temp[i]);
			strcat(statbuf, buf);

			sprintf(buf, " OTemp[%d]", info->outlet_temp[i]);
			strcat(statbuf, buf);

			sprintf(buf, " TMax[%d]", (int)info->miner[i].m_temp_summax);
			strcat(statbuf, buf);

			sprintf(buf, " TAvg[%d]", (int)(info->miner[i].m_temp_sumavg));
			strcat(statbuf, buf);

			sprintf(buf, " TarT[%d]", info->cali_info[i].param.temp);
			strcat(statbuf, buf);

			for (k = 0; k < info->fan_count[i]; ++k)
			{
				sprintf(buf, " Fan%d[%d]", (k+1),info->fan_cpm[i][k]);
				strcat(statbuf, buf);
			}
			sprintf(buf, " FanR[%d%%]", info->fan_pct[i]);
			strcat(statbuf, buf);

			sprintf(buf, " PS[");
			strcat(statbuf, buf);

			sprintf(buf, "%d %d %d %d %d %d %d",info->power_info[i][0], info->power_info[i][1], info->power_info[i][2], info->power_info[i][3], info->power_info[i][4], info->power_info[i][5], info->power_info[i][6]);
			strcat(statbuf, buf);
			statbuf[strlen(statbuf)] = ']';

			sprintf(buf, " GHSspd[%.2f] DHspd[%.3f%%]", (float)info->miner[i].mhsspd / 1000.0, info->miner[i].spd_dh);
			strcat(statbuf, buf);

			diff1 = 0;
			for (j = 0; j < info->miner_count[i]; j++)
				diff1 += info->diff1[i][j];

			mhsmm = (float)info->miner[i].mhsmm;

			sprintf(buf, " GHSmm[%.2f] GHSavg[%.2f] WU[%.2f] Freq[%.2f]", (float)mhsmm / 1000,
						diff1 / tdiff(&current, &(info->elapsed[i])) * 4.294967296,
						diff1 / tdiff(&current, &(info->elapsed[i])) * 60.0,
						info->miner[i].freq);
			strcat(statbuf, buf);

			strcat(statbuf, " MGHS[");
			for (j = 0; j < info->miner_count[i]; j++) 
			{
				sprintf(buf, "%.2f ", info->diff1[i][j] / tdiff(&current, &(info->elapsed[i])) * 4.294967296);
				strcat(statbuf, buf);
			}
			statbuf[strlen(statbuf) - 1] = ']';

			strcat(statbuf, " MTmax[");

			for (j = 0; j < info->miner_count[i]; j++) 
			{
				sprintf(buf, "%d ", get_miner_temp_max(info, i, j));
				strcat(statbuf, buf);
			}
			statbuf[strlen(statbuf) - 1] = ']';

			sprintf(buf, " MTavg[%d]", (int)round(info->miner[i].m_temp_sumavg));
			strcat(statbuf, buf);

			sprintf(buf, " TA[%d]", info->miner_count[0] * info->asic_count[0]);
			strcat(statbuf, buf);

			sprintf(buf, " Core[%s]", info->miner[i].asic_chipid);
			strcat(statbuf, buf);
			sprintf(buf, " BIN[%d]", info->miner[i].core_bin);
			strcat(statbuf, buf);
			cgpu = get_devices(0);
			share_ping = cgpu?cgpu->share_ping:0;
			sprintf(buf, " PING[%d]", share_ping);
			strcat(statbuf, buf);

			sprintf(buf, " SoftOFF[%d]", info->softoff_rsn[i]);
			strcat(statbuf, buf);

			strcat(statbuf, " ECHU[");
			for (j = 0; j < info->miner_count[i]; j++) 
			{
				sprintf(buf, "%d ", info->hu_errcode[i][j]);
				strcat(statbuf, buf);
			}
			statbuf[strlen(statbuf) - 1] = ']';
			sprintf(buf, " ECMM[%d]", info->mm_errcode[i]);
			strcat(statbuf, buf);

			for (m = 0; m < info->miner_count[i]; m++) 
			{
				sprintf(buf, " PLL%d[", m);
				strcat(statbuf, buf);
				tmp = 0;
				for (k = 0; k < AVALON_DEFAULT_PLL_CNT; k++) 
				{
					for (j = 0; j < info->asic_count[i]; j++)
					{
						tmp += info->asics[i].asic_pllcnt[m][j].pll[k];
					}
					sprintf(buf, "%d ", tmp);
					strcat(statbuf, buf);
					tmp = 0;
				}
				statbuf[strlen(statbuf) - 1] = ']';
			}

			if (true /*opt_debug*/)
			{
				for (j = 0; j < info->miner_count[i]; j++) 
				{
					sprintf(buf, " SF%d[", j);
					strcat(statbuf, buf);
					for (k = 0; k < AVALON_DEFAULT_PLL_CNT; k++) 
					{
						sprintf(buf, "%d ", info->miner[i].set_freq[j].pll[k]);
						strcat(statbuf, buf);
					}

					statbuf[strlen(statbuf) - 1] = ']';
				}
				for (j = 0; j < info->miner_count[i]; j++) 
				{
					sprintf(buf, " PVT_T%d[", j);
					strcat(statbuf, buf);
					if(info->asic_count[i] == 0)
						statbuf[strlen(statbuf)] = ' ';
					for (k = 0; k < info->asic_count[i]; k++) 
					{
						sprintf(buf, "%3d ", (int)info->asics[i].asics_temp[j][k]);
						strcat(statbuf, buf);
					}

					statbuf[strlen(statbuf) - 1] = ']';
					statbuf[strlen(statbuf)] = '\0';
				}

				for (j = 0; j < info->miner_count[i]; j++) 
				{
					sprintf(buf, " PVT_V%d[", j);
					strcat(statbuf, buf);
					if(info->asic_count[i] == 0)
						statbuf[strlen(statbuf)] = ' ';
					for (k = 0; k < info->asic_count[i]; k++) 
					{
						sprintf(buf, "%d ", info->asics[i].asics_volt[j][k]);
						strcat(statbuf, buf);
					}

					statbuf[strlen(statbuf) - 1] = ']';
					statbuf[strlen(statbuf)] = '\0';
				}

				for (j = 0; j < info->miner_count[i]; j++)
				{
					sprintf(buf, " MW%d[", j);
					strcat(statbuf, buf);
					if(info->asic_count[i] == 0)
						statbuf[strlen(statbuf)] = ' ';
					for (k = 0; k < info->asic_count[i]; k++) 
					{
						sprintf(buf, "%"PRIu64" ", info->asics[i].chip_matching_work[j][k]);
						strcat(statbuf, buf);
					}

					statbuf[strlen(statbuf) - 1] = ']';
				}
				strcat(statbuf, " CRC[");
				for (j = 0; j < info->miner_count[i]; j++) 
				{
					if(info->miner[i].errcode_crc)
						sprintf(buf, "%u ", info->miner[i].errcode_crc[j]);
					else
						sprintf(buf, "%u ", 0);
					strcat(statbuf, buf);
				}
				statbuf[strlen(statbuf) - 1] = ']';

				strcat(statbuf, " COMCRC[");
				for (j = 0; j < info->miner_count[i]; j++) 
				{
					if(info->miner[i].com_crc)
						sprintf(buf, "%u ", info->miner[i].com_crc[j]);
					else
						sprintf(buf, "%u ", 0);
					strcat(statbuf, buf);
				}
				statbuf[strlen(statbuf) - 1] = ']';

				sprintf(buf, " ATA%d[", info->workmode[i]);
				strcat(statbuf, buf);
				if(info->cali_info[i].aging_finished)
				{
					sprintf(buf, "%d-%d-%d-%d-%d ",info->cali_info[i].param.max_pout,info->cali_info[i].param.temp,
					info->cali_info[i].param.volt,info->cali_info[i].param.pll_start,info->cali_info[i].param.pll_interval);
					strcat(statbuf, buf);
				}
				else
				{
					statbuf[strlen(statbuf)] = ' ';
				}
				statbuf[strlen(statbuf) - 1] = ']';
				statbuf[strlen(statbuf)] = '\0';

				int l;
				if(avalon->show_all_estats)
				{

					/* i: modular, j: miner, k: asic, l: value */
					for (j = 0; j < info->miner_count[i]; j++) 
					{
						for (l = 0; l < AVALON_DEFAULT_PLL_CNT; l++) 
						{
							sprintf(buf, " CF%d_%d[", j, l);
							strcat(statbuf, buf);
							if(info->asic_count[i] == 0)
								statbuf[strlen(statbuf)] = ' ';
							for (k = 0; k < info->asic_count[i]; k++) 
							{
								sprintf(buf, "%3d ", info->asics[i].asics_freq[j][k].pll[l]);
								strcat(statbuf, buf);
							}

							statbuf[strlen(statbuf) - 1] = ']';
							statbuf[strlen(statbuf)] = '\0';
						}
					}
					for (j = 0; j < info->miner_count[i]; j++) {
						for (l = 0; l < AVALON_DEFAULT_PLL_CNT; l++) 
						{
							sprintf(buf, " PLLCNT%d_%d[", j, l);
							strcat(statbuf, buf);
							if(info->asic_count[i] == 0)
								statbuf[strlen(statbuf)] = ' ';
							for (k = 0; k < info->asic_count[i]; k++) 
							{
								sprintf(buf, "%3d ", info->asics[i].asic_pllcnt[j][k].pll[l]);
								strcat(statbuf, buf);
							}

							statbuf[strlen(statbuf) - 1] = ']';
							statbuf[strlen(statbuf)] = '\0';
						}
					}
					for (j = 0; j < info->miner_count[i]; j++) 
					{
						sprintf(buf, " ERATIO%d[", j);
						strcat(statbuf, buf);
						if(info->asic_count[i] == 0)
							statbuf[strlen(statbuf)] = ' ';
	
						for (k = 0; k < info->asic_count[i]; k++) 
						{
							if (info->asics[i].spdlog_pass[j][k])
								sprintf(buf, "%6.2f%% ", (double)(info->asics[i].spdlog_fail[j][k]  * 100.0 / (info->asics[i].spdlog_pass[j][k] + info->asics[i].spdlog_fail[j][k])));
							else
								sprintf(buf, "%6.2f%% ", 0.0);
							strcat(statbuf, buf);
						}
						statbuf[strlen(statbuf) - 1] = ']';
					}
					for (l = 0; l < 2; l++) {
						for (j = 0; j < info->miner_count[i]; j++) 
						{
							sprintf(buf, " C_%02d_%02d[", j, l);
							strcat(statbuf, buf);
							if(info->asic_count[i] == 0)
								statbuf[strlen(statbuf)] = ' ';
							for (k = 0; k < info->asic_count[i]; k++) 
							{
								if(l == 0)
								{
									sprintf(buf, "%7d ", info->asics[i].spdlog_pass[j][k]);
									strcat(statbuf, buf);
								}
								else
								{
									sprintf(buf, "%7d ", info->asics[i].spdlog_fail[j][k]);
									strcat(statbuf, buf);
								}
							}

							statbuf[strlen(statbuf) - 1] = ']';
						}
					}

					for (j = 0; j < info->miner_count[i]; j++) 
					{
						sprintf(buf, " GHSmm%02d[", j);
						strcat(statbuf, buf);
						if(info->asic_count[i] == 0)
						{
							statbuf[strlen(statbuf)] = ' ';
						}
						for (k = 0; k < info->asic_count[i]; k++) 
						{
							mhsmm = 0;
							for (l = 0; l < TOAST_PLL_COUNT; l++) 
							{
								if (!strncmp((char *)&(info->little_ver[i]), "851", 3))
									mhsmm += (info->asics[i].asic_pllcnt[j][k].pll[l]  * info->asics[i].asics_freq[j][k].pll[l]);
								else
									mhsmm += (info->asics[i].asic_pllcnt[j][k].pll[l]  * info->miner[i].set_freq[j].pll[l]);
							}
							sprintf(buf, "%7.2f ", mhsmm / 1000);
							strcat(statbuf, buf);
						}
						statbuf[strlen(statbuf) - 1] = ']';
					}
				}
			}

			sprintf(&statbuf[strlen(statbuf)], " WORKMODE[%d]", info->workmode[i]);
			sprintf(&statbuf[strlen(statbuf)], " WORKLEVEL[%d]", (int8_t)(info->worklvl[i] & 0xff));
			sprintf(&statbuf[strlen(statbuf)], " MPO[%d]", info->cali_info[i].param.max_pout);
			sprintf(&statbuf[strlen(statbuf)], " CALIALL[%d]", info->cali_all[i]);
			sprintf(&statbuf[strlen(statbuf)], " ADJ[%d]", info->cali_info[i].aging_finished);
			if(info->cali_info[i].aging_finished != 1)
				sprintf(&statbuf[strlen(statbuf)], " BAR[%d]", info->bar[i]);
		}
		else
		{
			sprintf(buf, "LVer[%s] ", info->little_ver[i]);
			strcpy(statbuf, buf);

			sprintf(buf, "BVer[%s] ", info->big_ver[i]);
			strcat(statbuf, buf);

			strcat(statbuf, "MVer[");
			for (j = 0; j < info->miner_count[i]; j++) 
			{
				sprintf(buf, "%s ", "0");
				strcat(statbuf, buf);
			}
			statbuf[strlen(statbuf) - 1] = ']';
			sprintf(buf, " FW[%s] ", releaselvl);
			strcat(statbuf, buf);

			sprintf(buf, "STATE[%d] ", info->state[i]);
			strcat(statbuf, buf);

			sprintf(buf, "MODE[%d] ", info->workmode[i]);
			strcat(statbuf, buf);

			sprintf(buf, "LEVEL[%d] ", (int8_t)(info->worklvl[i] & 0xff));
			strcat(statbuf, buf);

			sprintf(buf, "GHSspd[%f] ", (float)info->miner[i].mhsspd / 1000.0);
			strcat(statbuf, buf);

			sprintf(buf, "ITemp[%d] ", info->inlet_temp[i]);
			strcat(statbuf, buf);

			sprintf(buf, "OTemp[%d] ", info->outlet_temp[i]);
			strcat(statbuf, buf);

			sprintf(buf, "Limitemp[%d] ", 0);
			strcat(statbuf, buf);

			sprintf(buf, "FanR[%d%%] ", info->fan_pct[i]);
			strcat(statbuf, buf);

			sprintf(buf, "Filter[%d] ", info->filtermesh_time[i]);
			strcat(statbuf, buf);

			uint8_t r = info->led.rgb >> LED_OFST_R;
			uint8_t g = info->led.rgb >> LED_OFST_G;
			uint8_t b = info->led.rgb >> LED_OFST_B;
			sprintf(buf, "LED[%d-%d] LEDUser[%d-%d-%d-%d-%d-%d] ",
				info->ledmode, info->led.runeffect, info->led.effect, info->led.bright, info->led.temper, r, g, b);
			strcat(statbuf, buf);

			sprintf(buf, "LcdOnoff[%d] ", info->lcd_onoff[i]);
			strcat(statbuf, buf);

			sprintf(buf, "LcdSwitch[%d] ", info->lcd_show[i]);
			strcat(statbuf, buf);

			sprintf(buf, "LcdBright[%d] ", info->lcd_bright[i]);
			strcat(statbuf, buf);

			strcat(statbuf, "ECHU[");

			for (j = 0; j < info->miner_count[i]; j++) 
			{
				sprintf(buf, "%d ", info->hu_errcode[i][j]);
				strcat(statbuf, buf);
			}
			statbuf[strlen(statbuf) - 1] = ']';

			sprintf(buf, " ECMM[%d]", info->mm_errcode[i]);
			strcat(statbuf, buf);

			sprintf(buf, " SSID[%s]", info->net_info.ssid_name);
			strcat(statbuf, buf);

			sprintf(buf, " RSSI[%d]", info->net_info.rssi);
			strcat(statbuf, buf);

			sprintf(buf, " NetDevType[%d]", info->net_info.devtype);
			strcat(statbuf, buf);

		}
		sprintf(buf, "MM ID%d", i);
		root = api_add_string(root, buf, statbuf, false);
	}
	root = api_add_int(root, "MM Count", &(info->mm_count), true);
	root = api_add_uint8(root, "Nonce Mask", &info->miner[0].noncemask, true);
	return root;
}

/*	`
 * format: freq[-addr[-miner]]
 * addr[0, AVALON_DEFAULT_MODULARS - 1], 0 means all modulars
 * miner[0, miner_count], 0 means all miners
 */
char *set_avalon_device_freq(struct cgpu_info *avalon, char *arg, char *replybuf)
{
	struct avalon_info *info = avalon->device_data;
	unsigned int val[AVALON_DEFAULT_PLL_CNT],addr = 0, i, j, k;
	uint32_t miner_id = 0;
	uint32_t asic_id = 0;
	if (!(*arg))
		return "invalid parameter";

	sscanf(arg, "%d:%d:%d:%d-%d-%d-%d", &val[0], &val[1], &val[2], &val[3], &addr, &miner_id, &asic_id);
	
	if (val[AVALON_DEFAULT_PLL_CNT - 1]  > AVALON_DEFAULT_FREQUENCY_MAX)
		return "Invalid value passed to set_avalon_device_freq";

	if (addr >= AVALON_DEFAULT_MODULARS) 
	{
		applog(LOG_ERR, "invalid modular index: %d, valid range 0-%d", addr, (AVALON_DEFAULT_MODULARS - 1));
		return "Invalid modular index to set_avalon_device_freq";
	}

	if (miner_id > AVALON_DEFAULT_MINER_CNT)
		return "Invalid miner id passed to set_avalon_device_freq";

	if (asic_id > info->asic_count[addr])
		return "Invalid asic id passed to set_avalon_device_freq";

	if (!addr) 
	{
		for (i = 0; i < AVALON_DEFAULT_MODULARS; i++) 
		{
			if (!info->enable[i])
				continue;

			if (miner_id > info->miner_count[i]) 
			{
				applog(LOG_ERR, "invalid miner index: %d, valid range 0-%d", miner_id, info->miner_count[i]);
				return "Invalid miner index to set_avalon_device_freq";
			}

			if (miner_id) 
			{
				for (k = 0; k < AVALON_DEFAULT_PLL_CNT; k++)
					info->miner[i].set_freq[miner_id - 1].pll[k] = val[k];
				if (!asic_id)
					avalon_set_freq(avalon, i, miner_id - 1, AVALON_ASIC_ID_BROADCAST, info->miner[i].set_freq[miner_id - 1].pll);
				else
					avalon_set_freq(avalon, i, miner_id - 1, asic_id - 1, info->miner[i].set_freq[miner_id - 1].pll);

			} 
			else 
			{
				for (j = 0; j < info->miner_count[i]; j++) 
				{
					for (k = 0; k < AVALON_DEFAULT_PLL_CNT; k++)
						info->miner[i].set_freq[j].pll[k] = val[k];

					if (!asic_id)
						avalon_set_freq(avalon, i, j, AVALON_ASIC_ID_BROADCAST, info->miner[i].set_freq[j].pll);
					else
						avalon_set_freq(avalon, i, j, asic_id - 1, info->miner[i].set_freq[j].pll);

				}
			}
		}
	} 
	else 
	{
		if (!info->enable[addr]) 
		{
			applog(LOG_ERR, "Disabled modular:%d", addr);
			return "Disabled modular to set_avalon_device_freq";
		}

		if (miner_id > info->miner_count[addr]) 
		{
			applog(LOG_ERR, "invalid miner index: %d, valid range 0-%d", miner_id, info->miner_count[addr]);
			return "Invalid miner index to set_avalon_device_freq";
		}

		if (miner_id)
		{
			for (k = 0; k < AVALON_DEFAULT_PLL_CNT; k++)
				info->miner[addr].set_freq[miner_id - 1].pll[k] = val[k];

			if (!asic_id)
				avalon_set_freq(avalon, addr, miner_id - 1, AVALON_ASIC_ID_BROADCAST, info->miner[addr].set_freq[miner_id - 1].pll);
			else
				avalon_set_freq(avalon, addr, miner_id - 1, asic_id - 1, info->miner[addr].set_freq[miner_id - 1].pll);
		} 
		else 
		{
			for (j = 0; j < info->miner_count[addr]; j++) 
			{
				for (k = 0; k < AVALON_DEFAULT_PLL_CNT; k++)
					info->miner[addr].set_freq[j].pll[k] = val[k];

				if (!asic_id)
					avalon_set_freq(avalon, addr, j, AVALON_ASIC_ID_BROADCAST, info->miner[addr].set_freq[j].pll);
				else
					avalon_set_freq(avalon, addr, j, asic_id - 1, info->miner[addr].set_freq[j].pll);
			}
		}
	}
	applog(LOG_NOTICE, "%s-%d,m_id:%d,a_id:%d :%d:%d:%d: Update frequency to %d",
		avalon->drv->name, avalon->device_id, miner_id, asic_id, val[0], val[1], val[2], val[3]);

	return NULL;
}

typedef char *(*process_cmd_fn)(struct cgpu_info *info, char *request, char *reply);


static char *set_avalon_device_voltage(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int ret, val, i;
	struct avalon_info *info = avalon->device_data;
    if (!request || !*request)
	{
		applog(LOG_WARNING, "%s:request=%s, parm is NULL",__FUNCTION__,request);
		for (i = 0; i < AVALON_DEFAULT_MODULARS; i++)
		{
			sprintf(replybuf, "PS[%d %d %d %d %d %d %d]", info->power_info[i][0],
			info->power_info[i][1], info->power_info[i][2], info->power_info[i][3],
			info->power_info[i][4], info->power_info[i][5], info->power_info[i][6]);
		}
        return NULL;
    }

	ret = sscanf(request, "%d", &val);
	for (i = 0; i < AVALON_DEFAULT_MODULARS; i++)
	{
		if (ret == 1 && (val >= info->power_info[i][7]) && (val <= info->power_info[i][8]))
		{
			applog(LOG_OP, "Setting voltage: ret=%d,val=%d",ret, val);
			service_msg_data_send(((AVA_P_SET_PERIPH << 8) | AVA_P_SET_PERIPH_VOLT),(uint8_t*)&val,sizeof(int));
		}
		else
		{
			sprintf(replybuf, "Setting invalid: voltage range %d~%d", info->power_info[i][7],info->power_info[i][8]);
			return replybuf;
		}
	}
    return NULL;
}

char *set_avalon_device_fan_spd(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int val, ret;
	uint16_t type = 0;

	ret = sscanf(request, "%d", &val);
	if (ret < 1)
		return "No value passed to avalon-fan";

	if (val != -1 && (val < 15 || val > 100))
		return "invalid fan value, valid range 15-100 for stable pwm,-1 for auto adjust";

	type = (AVA_P_SET_PERIPH << 8) | AVA_P_SET_PERIPH_FAN;
	applog(LOG_OP, "Set fan spd %s:type=0x%x,val=%d,sizeof(int)=%ld",__FUNCTION__,type,val,sizeof(int));
	service_msg_data_send(type,(uint8_t*)&val,sizeof(int));

	return NULL;
}

char *set_avalon_ledmode(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int ret;
	uint8_t ledmode = 0;
	uint16_t type = 0;
	struct avalon_info *info = avalon->device_data;

	ret = sscanf(request, "%hhu", &ledmode);
	if ( (ret == 1) && ((ledmode == LED_MODE_DAY) || (ledmode == LED_MODE_DARK)) )
	{
		type = (AVA_P_SET_PERIPH << 8)|AVA_P_SET_PERIPH_LEDMODE;
		service_msg_data_send(type,&ledmode,sizeof(ledmode));
		info->ledmode = ledmode;
		sprintf(replybuf, "success set:%d", info->ledmode);
	}
	else
	{
		sprintf(replybuf, "Input param error.");
		return replybuf;
	}

	return NULL;
}

char *set_avalon_device_ledday(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int ret;
	uint16_t type = 0;
	uint32_t data[16] = {0};
	ledinfo led = {0};
	struct avalon_info *info = avalon->device_data;

	if (info->ledmode != LED_MODE_DAY)
	{
		sprintf(replybuf, "not in (day)mode now");
		return NULL;
	}

	ret = sscanf(request, "%d-%d-%d-%d-%d-%d", &data[0], &data[1], &data[2], &data[3], &data[4], &data[5]);
	if ((ret == 6) && (data[0] <= LED_COLORCYCLE))
	{
			led.effect = data[0];
			led.bright = data[1];
			led.temper = data[2];
			led.rgb = (data[3] & LED_COLOR_MAX) << LED_OFST_R;
			led.rgb |= (data[4] & LED_COLOR_MAX) << LED_OFST_G;
			led.rgb |= (data[5] & LED_COLOR_MAX) << LED_OFST_B;
	}
	else
	{
		sprintf(replybuf, "led parameter wrong");
		return replybuf;
	}
	type = (AVA_P_SET_PERIPH << 8) | AVA_P_SET_PERIPH_LEDDAY;
	service_msg_data_send(type, (uint8_t*)&led, sizeof(ledinfo));
	sprintf(replybuf, "led set ok");

	return NULL;
}

char *set_avalon_device_lcd(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int ret;
	uint16_t type = 0;
	uint16_t data[2] = {0};
	ret = sscanf(request, "%hd:%hd",&data[0], &data[1]);
	if (ret != 2)
		return "No value passed to lcd";

	type = (AVA_P_SET_PERIPH << 8) | AVA_P_SET_PERIPH_LCD;
	service_msg_data_send(type,(uint8_t*)&data,sizeof(data));
	sprintf(replybuf, "success lcd:id[%d] val[%d] len=%ld",data[0],data[1],sizeof(data));

	return NULL;
}

char *set_avalon_nightlamp(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int ret;
	uint16_t type = 0;
	night_lamp nightlamp = {0};
	struct avalon_info *info = avalon->device_data;

	if (info->ledmode != LED_MODE_DARK)
	{
		sprintf(replybuf, "not in (dark)mode now");
		return replybuf;
	}

	ret = sscanf(request, "%hhu-%hu", &nightlamp.mode, &nightlamp.duration);
	if ( (ret == 2) && ((nightlamp.mode == 0) || (nightlamp.mode == 1)) )
	{
		type = (AVA_P_SET_PERIPH << 8)|AVA_P_SET_PERIPH_NIGHTLAMP;
		service_msg_data_send(type,(uint8_t*)&nightlamp,sizeof(nightlamp));
		sprintf(replybuf, "success set:%d %hu", nightlamp.mode, nightlamp.duration);
	}
	else
	{
		sprintf(replybuf, "Input param error.");
		return replybuf;
	}

	return NULL;
}

char *set_avalon_device_loop(struct cgpu_info *avalon, char *request, char *replybuf)
{
	char buf[32];
	int i, module_id = 0;
	struct avalon_info *info = avalon->device_data;

	sprintf(replybuf, "LOOP[");
	for(i = 0; i < info->miner_count[module_id]; i++)
	{
		sprintf(buf,"%d ", info->asic_count[module_id]);
		strcat(replybuf,buf);
	}
	strcat(replybuf,"]");
	return NULL;
}

char *set_avalon_device_reboot(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int ret;
	uint16_t reboot_delay = 0;
	#define MAX_DELEY_TIME  300
	if (!request || !*request)
	{
		sprintf(replybuf, "missing reboot value");
		return replybuf;
	}
	ret = sscanf(request, "%hd", &reboot_delay);
	if(ret)
	{
		if(reboot_delay <= MAX_DELEY_TIME)
		{
			applog(LOG_OP,"API set reboot delay:%d", reboot_delay);
			service_msg_data_send(((AVA_P_SET_SYS << 8) | AVA_P_SET_SYS_REBOOT),(uint8_t*)&reboot_delay,sizeof(uint16_t));
		}
		else
		{
			sprintf(replybuf, "reboot value should be 0~300 seconds");
			return replybuf;
		}
	}
	else
	{
		sprintf(replybuf, "reboot value not number");
		return replybuf;	
	}
	return NULL;
}


char* set_device_time(char *set, char *replybuf)
{
	uint16_t type = 0;
	int ret = 0, flag_unknown = 0;
	struct cgpu_info *cgpu = NULL;
	struct avalon_info *info = NULL;
	cgpu = get_devices(0);
	char cmd[16] = {'\0'};
	char buf[64] = {'\0'};
	time_t timestamp = 0;
	if(cgpu)
	{
		info = cgpu->device_data;
		ret = sscanf(set, "%[^,],t:%ld,%s", cmd, &timestamp, buf);
		if(ret == 1) 
		{
			if(!strcmp(cmd, "get"))
				sprintf(replybuf, "time t:%s",info->timezone[0]);
			else
				flag_unknown = 1;
		}
		else if(ret == 3) 
		{
			if(!strcmp(cmd, "set")) 
			{
				type = (AVA_P_SET_SYS << 8)|AVA_P_SET_SYS_TIME_ZONE;
				service_msg_data_send(type,(uint8_t*)&buf,sizeof(buf));
				type = (AVA_P_SET_SYS << 8)|AVA_P_SET_SYS_TIMESTAMP;
				service_msg_data_send(type,(uint8_t*)&timestamp,sizeof(timestamp));
				sprintf(replybuf, "time t:%ld %s",timestamp,buf);
			}
			else
			{
				flag_unknown = 1;
			}
		}
		else
		{
			flag_unknown = 1;
		}

		if (flag_unknown)
			sprintf(replybuf, "time unknown argument");
	}
	return NULL;
}

enum wp_result {
	WP_OK,
	WP_ERR_HEADER,
	WP_ERR_MAGIC,
	WP_ERR_VERSION,
	WP_ERR_SIZE,
	WP_ERR_OFFSET,
	WP_ERR_PAYLOAD,
	WP_ERR_FILE,
	WP_ERR_SHALEN,
	WP_ERR_SHA,
	WP_ERR_VERIFY,
	WP_ERR_UNKNOWN = 0xFF,
};

static void rm_file(char *path)
{
	DIR *dp = NULL;
	struct dirent *entry;
	char tmp_path[512] = {'\0'};

	dp = opendir(path);
	if(dp)
	{
		while((entry = readdir(dp)))
		{
			if(entry->d_type == DT_REG)
			{
				snprintf(tmp_path,sizeof(tmp_path),"%s/%s",path,entry->d_name);
				remove(tmp_path);
			}
		}
		closedir(dp);
	}
}

int verify_msg(uint8_t *data, int len, uint8_t *sha, int sha_len, const char *public_pem)
{
	int ret = 0;
	mbedtls_pk_context pubkey;
	mbedtls_rsa_context *rsa_ctx;
	mbedtls_pk_init(&pubkey);
	mbedtls_pk_parse_public_key(&pubkey, (const unsigned char *)public_pem, strlen(public_pem) + 1);
	rsa_ctx = mbedtls_pk_rsa(pubkey);
	ret = mbedtls_rsa_rsassa_pss_verify(rsa_ctx, MBEDTLS_MD_SHA256, sha_len, sha, data);
	if(ret != 0) 
	{
		mbedtls_pk_free(&pubkey);
		applog(LOG_ERR, "rsa verify error -0x%x", -ret);
		return ret;
	}
	mbedtls_pk_free(&pubkey);
	return 0;
}

const char *pic_public_pem =
"-----BEGIN PUBLIC KEY-----\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBZai9zzwffT+uK/4W9lu7e+6g"
"3yzC8LJfoDfcWFz7Uf/IfQ/eoRS1lW94KCMhfW34nuoguwEjFcrZHlK1wmt9Dtzi"
"qPY2taEtFaftl2h+7nwx1ca2vNfJyqv0SmjIeGmKQgfB/Qsh5HAaEWHUeMgIkTnS"
"N4u3VEbLoPq75L6lAQIDAQAB\n"
"-----END PUBLIC KEY-----\n";

// content idx != 0: hex_str(hdr+data)
// content idx = 0: hex_str(hdr+ sha(32bytes) + sign(128bytes))
static int wallpaper_update(char *content, char *format)
{
	#define WALLPAPER_DIRTMP "/data/userconfig/wallpapertmp"
	#define WP_MAGIC	"nano"
	#define WP_VER		1
	struct __attribute__ ((packed)) pic_header {
		uint8_t	magic[8];   // check mini nano
		uint32_t format_ver;
		uint8_t header_len;
		uint8_t reserved1[1];
		uint16_t payload_len;
		uint16_t uid;
		uint16_t idx;
		uint32_t file_size;
		uint32_t offset;
	} hdr;

	static uint32_t uid_cur = 0;
	static uint32_t offset_cur = 0;
	static unsigned char data_sha[32] = {0};
	int ret = 0, result = WP_OK;
	int count = 0;
	unsigned char data_sha2[32] = {0};
	unsigned char sign[128] = {0};
	char sha_hex[68] = {'\0'}, sha_hex2[68] = {'\0'};
	uint8_t buf[4096] = {0};
	sha256_ctx ctx;
	FILE* fp = NULL;
	uint16_t type = 0;
	uint16_t data[2] = {4, 0};
	char filename[512] = {'\0'};

	// first check format
	if(strcmp(format, "none") == 0) 
	{
		rm_file(WALLPAPER_DIRTMP);
		data[1] = 1;
		type = (AVA_P_SET_PERIPH << 8) | AVA_P_SET_PERIPH_LCD;
		service_msg_data_send(type,(uint8_t*)data,sizeof(data));
		return WP_OK;
	}

	if(strlen(content) <= (sizeof(hdr)*2)) 
	{
		result = WP_ERR_HEADER;
		goto WP_ERR;
	}

	hex2bin((unsigned char *)&hdr, content, sizeof(hdr));

	applog(LOG_INFO, "wallpaper update offset:%d, len:%d, size:%d, idx:%d, rlen:%ld",
		hdr.offset, hdr.payload_len, hdr.file_size, hdr.idx, strlen(content));

	if(strncmp((char*)hdr.magic, WP_MAGIC, strlen(WP_MAGIC))) 
	{
		result = WP_ERR_MAGIC;
		goto WP_ERR;
	}

	if(hdr.format_ver != WP_VER) 
	{
		result = WP_ERR_VERSION;
		goto WP_ERR;
	}

	if((hdr.file_size > 307200) || (hdr.file_size < 1024)) // size: 1k ~ 300k
	{ 
		result = WP_ERR_SIZE;
		goto WP_ERR;
	}

	if ((hdr.payload_len + sizeof(hdr))*2 != strlen(content)) 
	{
		result = WP_ERR_PAYLOAD;
		goto WP_ERR;
	}

	if ((hdr.offset + hdr.payload_len) > hdr.file_size) 
	{
		result = WP_ERR_OFFSET;
		goto WP_ERR;
	}

	if ((uid_cur != hdr.uid) || (hdr.idx == 0)) 
	{
		uid_cur = hdr.uid;
		offset_cur = 0;
	}

	if (hdr.offset > offset_cur) 
	{
		result = WP_ERR_OFFSET;
		goto WP_ERR;
	}
	offset_cur = hdr.offset;

	hex2bin(buf, content + (sizeof(hdr) * 2), hdr.payload_len);
	if(hdr.idx == 0)
	{
		if(hdr.payload_len == (sizeof(data_sha) + sizeof(sign)))
		{
			memcpy(data_sha, buf, sizeof(data_sha));
			memcpy(sign, buf+sizeof(data_sha), sizeof(sign));

			//verify sha
			mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data_sha, sizeof(data_sha), data_sha2);
			ret = verify_msg(sign, sizeof(sign), data_sha2, sizeof(data_sha2), pic_public_pem);
			if(ret != 0) 
			{
				result = WP_ERR_VERIFY;
				goto WP_ERR;
			}
		} 
		else 
		{
			return WP_ERR_SHALEN;
		}

		rm_file(WALLPAPER_DIRTMP);
		sprintf(filename, "%s/wallpaper_%d.%s.tmp", WALLPAPER_DIRTMP,uid_cur,format);
		fp = fopen(filename, "w+");
		if(fp == NULL)
		{
			applog(LOG_ERR, "open %s error:%s", filename, strerror(errno));
			result = WP_ERR_FILE;
			goto WP_ERR;
		}

		fsync(fileno(fp));
		fclose(fp);
		return WP_OK;
	} 
	else 
	{
		sprintf(filename, "%s/wallpaper_%d.%s.tmp", WALLPAPER_DIRTMP,uid_cur,format);
		fp = fopen(filename, "r+");
		if(fp == NULL) 
		{
			applog(LOG_ERR, "open %s error:%s", filename, strerror(errno));
			result = WP_ERR_FILE;
			goto WP_ERR;
		}

		fseek(fp, hdr.offset, SEEK_SET);
		fwrite(buf, 1, hdr.payload_len, fp);
		fsync(fileno(fp));

		if (hdr.file_size != (hdr.offset + hdr.payload_len)) 
		{
			offset_cur = hdr.offset + hdr.payload_len;
			fclose(fp);
			return WP_OK;
		}

		// file finished
		rewind(fp);
		sha256_init(&ctx);
		while((count = fread(buf, 1, sizeof(buf), fp)) > 0)
			sha256_update(&ctx, buf, count);
		sha256_final(&ctx, data_sha2);
		if(memcmp(data_sha2, data_sha, sizeof(data_sha)) == 0)
		{
			fclose(fp);
			data[1] = 1;
			type = (AVA_P_SET_PERIPH << 8) | AVA_P_SET_PERIPH_LCD;
			service_msg_data_send(type,(uint8_t*)data,sizeof(data));
			return WP_OK;
		}

		fclose(fp);
		__bin2hex(sha_hex, data_sha, 32);
		__bin2hex(sha_hex2, data_sha2, 32);
		applog(LOG_ERR, "wallpaper sha(%s) error, expect %s", sha_hex2, sha_hex);
		result = WP_ERR_SHA;
		goto WP_ERR;
	}
	result = WP_ERR_UNKNOWN;

WP_ERR:
	applog(LOG_ERR, "wallpaper recv failed %d (%.*s)", result, (int)sizeof(hdr), content);

	return result;
}

// ascset|0,wallpaper,format,hex_str(header+data)
// format: png/gif/none
// data max: 100k, min: 1024
char *set_avalon_device_wallpaper(struct cgpu_info *avalon, char *request, char *replybuf)
{
	#define LCDCMDJOIN ','
	#define WP_PKG_LEN  2104
	int ret = 0;
	char mode[8] = {0};
	struct avalon_info *info = avalon->device_data;

	if(info->lcd_onoff == 0)
		return "lcd is off and the settings do not take effect";

	char *pdata = strchr(request, LCDCMDJOIN);
	if (pdata == NULL)
		return "input param error";

	*(pdata++) = '\0';
	strncpy(mode, request, sizeof(mode)-1);
	if(strlen(pdata) > WP_PKG_LEN)
	{
		sprintf(replybuf, "input param len greater than %d",WP_PKG_LEN);
		return replybuf;
	}

	if((strcmp(mode,"png")== 0) || (strcmp(mode,"gif") == 0) || (strcmp(mode,"none") == 0))
	{
		ret = wallpaper_update(pdata, mode);
		if(ret == 0)
		{
			applog(LOG_OP, "wallpaper update ok");
			sprintf(replybuf, "wallpaper recv ok %ld", strlen(pdata));
		}
		else
		{
			sprintf(replybuf, "wallpaper recv failed %d", ret);
			return replybuf;
		}
	}
	else
	{
		sprintf(replybuf, "Input param cmd error.");
		return replybuf;
	}
	return NULL;
}

static char* set_avalon_device_worklevel(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int8_t level = 0;
	uint16_t type = 0;
	char cmd[16] = { 0 };
	struct avalon_info *info = avalon->device_data;
	int ret = sscanf(request, "%[^,],%hhd", cmd, &level);
	level &= 0xFF;
	if ((ret == 1) && (!strcmp(cmd, "get")))
	{
		sprintf(replybuf, "worklevel %hhd", info->worklvl[0] & 0xff);
	}
	else if ((ret == 2) && (!strcmp(cmd, "set")) && (level <= (int8_t)((info->worklvl[0] & 0xff000000) >> 24)) && (level >= (int8_t)((info->worklvl[0] & 0x00ff0000) >> 16)))
	{		
		if(!info->cali_info[0].aging_finished)
		{
			sprintf(replybuf, "current level %d is caling,Don't permit switch level",info->worklvl[0] & 0xff);
			return replybuf;
		}
		else
		{
			if(level != (info->worklvl[0] & 0xff))
			{
				type = (AVA_P_SET_SYS << 8)|AVA_P_SET_SYS_LEVEL;
				service_msg_data_send(type,(uint8_t*)&level,sizeof(uint8_t));
			}
			applog(LOG_OP,"current_level = %d,previous_level = %d",level,(int8_t)(info->worklvl[0] & 0xff));
		}
	}
	else
	{
		sprintf(replybuf, "worklevel unknown argument");
		return replybuf;
	}
	return NULL;
}

static char* set_avalon_device_workmode(struct cgpu_info *avalon, char *request, char *replybuf)
{
	uint8_t mode = 0;
	uint16_t type = 0;
	char cmd[16] = { 0 };

	struct avalon_info *info = avalon->device_data;
	int ret = sscanf(request, "%[^,],%hhd", cmd, &mode);
	mode &= 0xFF;
	if ((ret == 1) && (!strcmp(cmd, "get")))
	{
		sprintf(replybuf, "workmode %hhd", info->workmode[0]);
	}
	else if ((ret == 2) && (!strcmp(cmd, "set")) )
	{	
		if(mode <= info->maxmode[0])	
		{
			if(!info->cali_info[0].aging_finished)
			{
				sprintf(replybuf, "current mode %d is caling Don't permit switch mode",info->workmode[0]);
				return replybuf;
			}
			else
			{
				if(mode != info->workmode[0])
				{
					type = (AVA_P_SET_SYS << 8)|AVA_P_SET_SYS_MODE;
					service_msg_data_send(type,(uint8_t*)&mode,sizeof(uint8_t));
				}
				applog(LOG_OP,"current_mode = %d  previous_mode = %d",mode,info->workmode[0]);
			}
		}
		else
		{
			sprintf(replybuf, "error:1 not support set workmode max_mode[%d]",info->maxmode[0]);
			return replybuf;
		}
	}
	else
	{
		sprintf(replybuf, "error:2 parameter error");
		return replybuf;
	}
	return NULL;
}

static char* set_avalon_work_mode_lvl(struct cgpu_info *avalon, char *request, char *replybuf)
{
	uint8_t mode = 0;
	int8_t level = 0;
	uint16_t type = 0;
	int16_t workinfo = 0;
	char cmd[16] = { 0 };
	struct avalon_info *info = avalon->device_data;
	int ret = sscanf(request, "%[^,],%hhd,%hhd", cmd, &mode,&level);
	if ((ret == 1) && (!strcmp(cmd, "get")))
	{
		sprintf(replybuf, "workmode %hhd worklevel %hhd", info->workmode[0],info->worklvl[0] & 0xff);
	}
	else if(ret == 3 && (!strcmp(cmd, "set")))
	{
		if(!info->cali_info[0].aging_finished)
		{
			sprintf(replybuf, "current mode %d is caling. Don't permit switch mode",info->workmode[0]);
			return replybuf;
		}
		else
		{
			if(mode < info->maxmode[0])
			{
				if((level <= (int8_t)((info->lvlinfo[0][mode] & 0xff000000) >> 24)) && (level >= (int8_t)((info->lvlinfo[0][mode] & 0x00ff0000) >> 16)))
				{
					if(mode != info->workmode[0] || level != (info->worklvl[0] & 0xff))
					{
						type = (AVA_P_SET_SYS << 8)|AVA_P_SET_SYS_MODE_LEVEL;
						workinfo = ((mode << 8) & 0xff00) | (level & 0xff);
						service_msg_data_send(type,(uint8_t*)&workinfo,sizeof(int16_t));
					}
					applog(LOG_OP,"current_mode = %d current_level = %d, previous_mode = %d previous_level = %d",mode,level,info->workmode[0],(int8_t)(info->worklvl[0] & 0xff));
				}
				else
				{
					applog(LOG_INFO,"worklevel unknown argument set level = %d level rang:%d ~ %d",
					level,(int8_t)((info->lvlinfo[0][mode] & 0x00ff0000) >> 16),(int8_t)((info->lvlinfo[0][mode] & 0xff000000) >> 24));
					sprintf(replybuf, "worklevel unknown argument level range:%d ~ %d",
					(int8_t)((info->lvlinfo[0][mode] & 0x00ff0000) >> 16),(int8_t)((info->lvlinfo[0][mode] & 0xff000000) >> 24));
					return replybuf;
				}
			}
			else
			{
				applog(LOG_INFO,"workmode unknown argument max mode:%d",info->maxmode[0]);
				sprintf(replybuf, "error:1 not support set workmode max_mode[%d]",info->maxmode[0]);
				return replybuf;
			}
		}
	}
	else
	{
		sprintf(replybuf, "error:2 parameter error");
		return replybuf;
	}
	return NULL;
}

static char *set_avalon_qr_auth(struct cgpu_info *avalon, char *arg,char *replybuf)
{
	struct avalon_info *info = avalon->device_data;
	int ret = 0;
	char random_buf[MAX_LEN_USER_PASS] = {'\0'};
	char verify_buf[MAX_LEN_USER_PASS] = {'\0'};
	char bulk_buf[MAX_LEN_USER_PASS] = {'\0'};
	char tmp_bulk_buf[MAX_LEN_USER_PASS + 1] = {'\0'};
	char tmp_verify_buf[MAX_LEN_USER_PASS] = {'\0'};
	char str_sha_verify[MAX_LEN_USER_PASS] = {'\0'};
	unsigned char sha_verfity[MAX_LEN_USER_PASS] = {0};

	if(strlen(arg) == 0)
	{
		sprintf(replybuf, "param invalid!");
		return replybuf;
	}

	ret = sscanf(arg, "%[^,],%[^,]", random_buf, verify_buf);
	sprintf(tmp_bulk_buf,"%s",g_ava_qr_auth->sha_dna);
	strcat(bulk_buf,tmp_bulk_buf);
	memset(tmp_bulk_buf,0,MAX_LEN_USER_PASS);
	memcpy(tmp_bulk_buf,info->webpass[0],WEB_PASSWD_LEN);
	strcat(bulk_buf,tmp_bulk_buf);
	sha256((unsigned char*)&bulk_buf, strlen(bulk_buf), sha_verfity);

	//the first 24 character hex16 to str
	memcpy(str_sha_verify,bin2hex(sha_verfity, WEB_PASSWD_LEN),WEB_PASSWD_LEN);

	memcpy(tmp_verify_buf,WEBPASS_SIGN_MINI3_STR,WEBPASS_SIGN_LEN);
	strcat(tmp_verify_buf, str_sha_verify);

	applog(LOG_WARNING,"input random = %s  verify_buf   = %s",random_buf,verify_buf);
	applog(LOG_WARNING,"real  random = %s  real_verify  = %s",g_ava_qr_auth->random,tmp_verify_buf);
	if(ret == 2)
	{
		if(strlen(random_buf) >= MAX_LEN_USER_PASS || strlen(verify_buf) >= MAX_LEN_USER_PASS)
		{
			sprintf(replybuf, "input length error!");
			return replybuf;
		}
		else if(strcmp(g_ava_qr_auth->random,random_buf) != 0)	
		{
			sprintf(replybuf, "auth error 01!");
			return replybuf;
		}
		else if(strcmp(tmp_verify_buf,verify_buf) != 0)
		{
			sprintf(replybuf, "passwd error 02!");
			return replybuf;
		}
		else
		{
			applog(LOG_OP,"Qr code login success!");
			g_ava_qr_login = 1;
			return NULL;
		}
	}
	return NULL;
}

static char *set_avalon_device_password(struct cgpu_info *avalon, char *arg,char *replybuf)
{
	#define PRIVATE_GET "private"
	int ret=0, auth_pass = 0;
	char *ppswd;
	char oldpasswd[WEBPASS_LEN + 1] = {0};
	char newpasswd[WEBPASS_LEN + 1] = {0};
	char passwd_hex[WEBPASS_LEN * 2 + 1] = {0};
	unsigned char passwd_sha[WEBPASS_LEN + 1] = {0};
	uint16_t type = 0;
	struct avalon_info *info = avalon->device_data;
	if(strlen(arg) == 0)
	{
		sprintf(replybuf, "Auth Failed! password invalid!");
		return replybuf;
	}

	ret = sscanf(arg, "%64[^,],%64[^,]", oldpasswd, newpasswd);
	if(ret == 2)
	{
		//check the old password were right
		ppswd = info->webpass[0];
		// passwd not sha256
		sha256((unsigned char*)oldpasswd,strlen(oldpasswd), passwd_sha);
		__bin2hex(passwd_hex, passwd_sha, 32);
		if(strncmp(ppswd, passwd_hex, WEBPASS_SHA256_LEN) == 0)
			auth_pass = 1;


		if(auth_pass) 
		{
			//save the new password
			memset(info->webpass[0],0, strlen(info->webpass[0]));
			// passwd not sha256set_avalon10_device_passwordwebpass[0]
			sha256((unsigned char*)newpasswd,strlen(newpasswd), passwd_sha);
			__bin2hex(passwd_hex, passwd_sha, 32);
			memcpy(info->webpass[0], passwd_hex,WEBPASS_SHA256_LEN);
			type = (AVA_P_SET_SYS << 8)|AVA_P_SET_SYS_WEB_PASS;
			service_msg_data_send(type,(uint8_t*)&info->webpass[0],sizeof(info->webpass[0]));
			sprintf(replybuf, "new password success set.");
			applog(LOG_OP,"new password success set!");
			return NULL;
		} 
		else //the paddword is not match the the old password
		{
			sprintf(replybuf, "Auth Failed! password invalid!");
			return replybuf;
		}
	}
	else
	{
		sprintf(replybuf, "we need 2 arguments, your input is %d arguments.", ret);
		return replybuf;
	}
}

static char *set_avalon_device_help(struct cgpu_info *avalon, char *request, char *replybuf);

static char *set_avalon_volt_adjust_switch(struct cgpu_info *avalon, char *param, char *replybuf)
{
	uint8_t val;
	unsigned int addr;
	uint16_t type = 0;
	if (!(*param))
		return "missing voltage adjust switch info";

	sscanf(param, "%hhd-%d", &val,&addr);

	if (val != AVA_VOLT_ADJ_SWITCH_OFF && val != AVA_VOLT_ADJ_SWITCH_ON)
			return "Invalid value to set_avalon_volt_adjust_switch_info";

	if (addr >= AVALON_DEFAULT_MODULARS) 
	{
		applog(LOG_ERR, "invalid modular index: %d, valid range 0-%d", addr, (AVALON_DEFAULT_MODULARS - 1));
		return "Invalid modular index to set_avalon_volt_adjust_switch_info";
	}
	applog(LOG_OP,"Setting auto volt tuning :%d",val);
	type = (AVA_P_SET_SYS << 8)|AVA_P_SET_SYS_VOLT_TUNING;
	service_msg_data_send(type,(uint8_t*)&val,sizeof(uint16_t));
	return NULL;
}

char *avalon_filter_cleaned(struct cgpu_info *avalon, char *param, char *replybuf)
{
	uint32_t value;
	int ret = sscanf(param,"%d",&value);
	if (ret < 1)
		return "No value passed to avalon-filter-clean";

	if(value == 1)
	{
		applog(LOG_OP, "Set filter cleaning: %d", value);
		service_msg_data_send(((AVA_P_SET_SYS << 8) | AVA_P_SET_SYS_FILTER_CLEAN),NULL,1);
	}
	else
	{
		sprintf(replybuf, "Input param error.");
		return replybuf;
	}
		
	return NULL;
}

static char *hash_sn_read(struct cgpu_info *avalon, char *arg, char *replybuf)
{
	int ret = 0;
	int hash_sh = 0;
	struct avalon_info *info = avalon->device_data;
	if (arg == NULL)
	{
		sprintf(replybuf, "No argument!");
		return replybuf;
	}
	ret = sscanf(arg, "%d", &hash_sh);
	if ((ret == 1) && (hash_sh < info->mm_count))
	{
		sprintf(replybuf, "Hash-%d SN:%s", hash_sh, info->sn[0][hash_sh]);
	}
	else
	{
		sprintf(replybuf, "hash sn read input arguments format error!");
		return replybuf;
	}
	return NULL;
}

void faccfg_lock_set(bool locked)
{
	fac_cfg_locked = locked;
}

bool faccfg_is_locked(void)
{
	return fac_cfg_locked;
}

static char *set_avalon_faclock(struct cgpu_info *avalon, char *arg, char *replybuf)
{
	uint32_t crc;
	char buf[64];
	int ret = -1;
	struct avalon_info *info = avalon->device_data;
	if (!arg || !*arg) 
	{
		sprintf(replybuf, "missing lock setting");
		return replybuf;
	}
	// Calculate key
	memset(buf, '\0', sizeof(buf));
	strcpy(buf, info->dna[0]);
	crc = crc32(0, (uint8_t *)buf, strlen(info->dna[0]));

	sprintf(buf, "%08x", crc);
	if (strcasecmp(arg, "lock") == 0) 
	{
		if (faccfg_is_locked()) 
		{
			applog(LOG_OP, "FAIL: already locked");
			return NULL;
		} 
		else 
		{
			applog(LOG_OP, "Locking product");
			faccfg_lock_set(true);
			ret = 0;
		}
	} 
	else if (strcasecmp(arg, (char *)buf) == 0) 
	{
		if (faccfg_is_locked()) 
		{
			applog(LOG_OP, "Unlocking product");
			faccfg_lock_set(false);
			ret = 0;
		} 
		else 
		{
			applog(LOG_OP, "FAIL: not locked");
			sprintf(replybuf, "FAIL: already unlocked");
			return NULL;
		}
	}

	sprintf(replybuf, "Lock: %s", faccfg_is_locked() ? "True" : "False");
	return (ret == 0) ? NULL : replybuf;
}

static char *set_avalon_facopts(struct cgpu_info *avalon, char *arg, char *replybuf)
{
	uint16_t type = 0;
	int mode = 0, ret;
	char buf[MAX_LEN_FAC_CONF] = {'\0'};
	struct avalon_info *info = avalon->device_data;
	if (strlen(arg) >= MAX_LEN_FAC_CONF)
	{
		sprintf(replybuf, "option is longer than %d: %ld", MAX_LEN_FAC_CONF, strlen(arg));
		return replybuf;
	}

	ret = sscanf(arg, "%d,%[^\n]s", &mode, buf);

	if ((ret == 1 && mode == FACTCFG_QUERY))
	{
		sprintf(replybuf, "FACOPTS_LK[%d]", faccfg_is_locked() ? 1 : -1);
		sprintf(&replybuf[strlen(replybuf)], " WORKMODE[%d]", info->workmode[0]);
		return NULL;
	}
	if (faccfg_is_locked())
	{
		sprintf(replybuf, "Please unlock before setting facopts");
		return replybuf;
	}

	if ((ret == 2 && (mode == FACTCFG_OTHERS_SET_PROD || mode == FACTCFG_OTHERS_SET_MODEL)))
	{
		if (mode == FACTCFG_OTHERS_SET_PROD)
		{
			strcpy(info->hw_info[0].prod, buf);
			applog(LOG_OP, "Set Prod:%s", buf);
			sprintf(replybuf, "Update product ID: %s", buf);
		}
		else if (mode == FACTCFG_OTHERS_SET_MODEL)
		{
			strcpy(info->hw_info[0].model, buf);
			applog(LOG_OP, "Set model:%s", buf);
			sprintf(replybuf, "Update Model ID: %s", buf);
		}
		type = (AVA_P_SET_SYS << 8) | AVA_P_SET_SYS_HWINFO;
		service_msg_data_send(type, (uint8_t*)&info->hw_info[0], sizeof(struct hwcfg));
	}
	else 
	{
		applog(LOG_WARNING, "Something wrong with facopts: %s", arg);
		sprintf(replybuf, "Bad facopts");
		return replybuf;
	}

	return NULL;
}

typedef struct avalon_device_cmd{
	char *name;
	process_cmd_fn fn;
	bool check_request_value;  // true: if(!(request || *request)) return missing request value; false: no check request
	char reserved[3];
}avalon_device_cmd_t;

 avalon_device_cmd_t device_cmds[] = {
	{"help", set_avalon_device_help, false},
	/**** device periph ****/
 	{"voltage", set_avalon_device_voltage, false},
 	{"fan-spd", set_avalon_device_fan_spd, true},
	{"ledmode",set_avalon_ledmode,true},
	{"ledset", set_avalon_device_ledday, true},
	{"lcd", set_avalon_device_lcd, true},
	{"nightlamp",set_avalon_nightlamp,true},
	{"wallpaper", set_avalon_device_wallpaper, true},
	{"hash-sn-read",hash_sn_read,true},
	/**** device sys ****/
	{"volt-adjust-switch",set_avalon_volt_adjust_switch,true},
	{"workmode", set_avalon_device_workmode, true},
 	{"worklevel", set_avalon_device_worklevel, true},
	{"work_mode_lvl", set_avalon_work_mode_lvl, true},
	{"reboot", set_avalon_device_reboot, true},
	{"filter-clean",avalon_filter_cleaned,true},
	{"facopts",set_avalon_facopts,true},
	{"faclock",set_avalon_faclock,true},
	/**** asic sys ****/
	{"frequency", set_avalon_device_freq, true},
	/**** avalon info  ****/
	{"loop", set_avalon_device_loop, false},
	{"password", set_avalon_device_password, true},
	{"qr_auth",set_avalon_qr_auth,true},
};

static char *set_avalon_device_help(struct cgpu_info *avalon, char *request, char *replybuf)
{
	int i;
	char buf[32];

	for(i = 0; i < sizeof(device_cmds)/sizeof(device_cmds[0]); i++)
	{
		sprintf(buf,"%s|", device_cmds[i].name);
		strcat(replybuf,buf);
	}
	return NULL;
}

static char *avalon_set_device(struct cgpu_info *avalon, char *option, char *setting, char *replybuf)
{
	for(int i = 0; i < sizeof(device_cmds)/sizeof(device_cmds[0]); i++) 
	{
		if(strcasecmp(option, device_cmds[i].name) == 0)
		{
			if(device_cmds[i].check_request_value && (!setting || !*setting)) 
			{
				sprintf(replybuf, "missing %s setting", device_cmds[i].name);
				return replybuf;
			}
			return device_cmds[i].fn(avalon, setting, replybuf);
		}
	}

	sprintf(replybuf, "Unknown option: %s", option);
	return replybuf;
}

static void avalon_statline_before(char *buf, size_t bufsiz, struct cgpu_info *avalon)
{
	struct avalon_info *info = avalon->device_data;
	uint8_t flag = 0;
	uint32_t frequency = 0;
	int temp = -273;
	int fanmin = AVALON_DEFAULT_FAN_MAX;
	int i, j, k;
	float ghs_sum = 0, mhsmm = 0;
	double pass_num = 0.0, fail_num = 0.0;

	for (i = 1; i < AVALON_DEFAULT_MODULARS; i++) 
	{
		if (!info->enable[i])
			continue;

		if (fanmin >= info->fan_pct[i])
			fanmin = info->fan_pct[i];

		if (temp < get_temp_max(info, i))
			temp = get_temp_max(info, i);
			
		mhsmm = (float)info->miner[i].mhsmm;
		frequency = (uint32_t)info->miner[i].freq;
		ghs_sum += (mhsmm / 1000);
		#if 1
		if (!strncmp((char *)&(info->little_ver[i]), "851", 3))
		{
			for (j = 0; j < info->miner_count[i]; j++) 
			{
				for (k = 0; k < info->asic_count[i]; k++) 
				{
					pass_num += info->asics[i].spdlog_pass[j][k];
					fail_num += info->asics[i].spdlog_fail[j][k];
				}
			}
			flag = 1;
		}
		#endif
	}

	if (info->mm_count)
		frequency /= info->mm_count;

	if (flag)
		tailsprintf(buf, bufsiz, "%4dMhz %.2fGHS %2dC %.2f%% %3d%%", frequency, ghs_sum, temp,
					(fail_num + pass_num) ? fail_num * 100.0 / (fail_num + pass_num) : 0, fanmin);
	else
		tailsprintf(buf, bufsiz, "%4dMhz %.2fGHS %2dC %3d%%", frequency, ghs_sum, temp, fanmin);
}

struct device_drv avalon_drv = {
	.drv_id = DRIVER_avalon,
	.dname = "avalon",
	.name = "AVALON",
	.set_device = avalon_set_device,
	.get_login = avalon_get_login,
	.get_api_stats = avalon_api_stats,
	.get_set_web_stats = avalon_web_stats,
	.get_statline_before = avalon_statline_before,
	.drv_detect = avalon_detect,
	.thread_prepare = avalon_prepare,
	.hash_work = hash_driver_work,
	.flush_work = avalon_sswork_flush,
	.update_work = avalon_sswork_update,
	.scanwork = avalon_scanhash,
	.max_diff = AVALON_DRV_DIFFMAX,
	.genwork = true,
};
