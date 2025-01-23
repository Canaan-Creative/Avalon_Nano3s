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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "http.h"
#include "logging.h"
#include "miner.h"
#include "driver-avalon.h"
#include "cgi.h"
#include <sha2.h>
struct cgminer_summary 
{
    int ping;
	uint32_t elapsed;
	uint32_t ghsav;
	uint32_t rejected;
	uint32_t accepted;
	uint32_t network_blocks;
	uint32_t bestshare;
	double hashav;
	double hash_5m;
}__attribute__((__packed__));

struct html_info{
    uint8_t id;
    char* pdir;
}info[] = {
    {HTML_SHA,		   "../resource/www/html/sha256.min.js"},
    {HTML_CGPOOLS,     "../resource/www/html/cgpools.html"},
    {HTML_DASHBOARD,   "../resource/www/html/dashboard.html"},
    {HTML_QR_LOGIN,    "../resource/www/html/qr_login.html"},
    {HTML_QR_CODE,     "../resource/www/html/qrcode.min.js"},
    {HTML_LOGIN_NEW,   "../resource/www/html/login.html"}
};

char g_pool_url[MAX_LEN_URL+3];
char g_pool_user[MAX_LEN_USER_PASS+3];
cgminer_pools g_cgminer_pool[POOL_VALID_NUM];
struct cgminer_summary  g_cgi_summary;
web_stats_misc g_stats_misc;
web_stats_net g_stats_net;
web_login g_web_login;
qr_auth g_qr_auth;
bool g_update_pool = true;
bool g_pool_status;
bool g_qr_login = false;
int g_pool_num;

void update_web_value()
{
    #define INVALID_URL_USER	"no active pool"
    struct cgpu_info *cgpu = NULL;
	cgpu = get_devices(0);
    if(cgpu)
    {
        g_cgi_summary.elapsed = total_secs;
        g_cgi_summary.accepted = cgpu->accepted;
        g_cgi_summary.rejected = cgpu->rejected;
        g_cgi_summary.hash_5m = cgpu->rolling5;
        g_cgi_summary.ping = cgpu->share_ping;
        if(g_update_pool)
        {
            g_pool_num = get_pools_stats(g_cgminer_pool);
            if(g_pool_num >= 0)
            {
                sprintf(g_pool_url,"\"%s\"",g_cgminer_pool[g_pool_num].url);
                sprintf(g_pool_user,"\"%s\"",g_cgminer_pool[g_pool_num].worker);
                g_pool_status = true;
            }
            else
            {
                sprintf(g_pool_url,"\"%s\"",INVALID_URL_USER);
                sprintf(g_pool_user,"\"%s\"",INVALID_URL_USER); 
                g_pool_status = false;
            }
        }
        cgpu->drv->get_set_web_stats(cgpu,&g_stats_misc,WEB_GET_MISC_STATS);
        cgpu->drv->get_set_web_stats(cgpu,&g_stats_net,WEB_GET_NET_STATS);
        cgpu->drv->get_set_web_stats(cgpu,&g_web_login,WEB_GET_PASSWD);
        cgpu->drv->get_set_web_stats(cgpu,&g_qr_auth,WEB_SET_AUTH);
        cgpu->drv->get_set_web_stats(cgpu,&g_qr_login,WEB_GET_QR_LOGIN);
    }
}

uint32_t get_dashboard(uint8_t *buf)
{
    struct cgpu_info *cgpu = NULL;
    struct avalon_info *info = NULL;
    uint8_t *pmac = g_stats_net.mac;
    uint8_t asic_status = 0;
    char temp_buf[4096] = {'\0'};
    float rejected_percentage;
    float ghsspd,ghsavg;
    ghsspd = ((float)g_stats_misc.GHSspd)/1000.0;
    ghsavg = ((float)g_stats_misc.GHSavg)/1000.0;

    cgpu = get_devices(0);
	if(cgpu)
		info = cgpu->device_data;


    if(g_stats_misc.asic_cnt)
        asic_status = 0;
    else
        asic_status = 1;

    if ((g_cgi_summary.accepted == 0) || (g_cgi_summary.rejected == 0)) 
    {
        rejected_percentage = 0;
    }
    else 
    {
        rejected_percentage = ((double)g_cgi_summary.rejected/((double)g_cgi_summary.rejected+(double)g_cgi_summary.accepted));
        rejected_percentage = rejected_percentage * 100;
    }

    sprintf((char*)buf, "dashboardCallback({");
    sprintf(temp_buf,
                    "\"hwtype\":\"%s\",\
                    \"sys_status\":\"%d\",\
                    \"elapsed\":\"%d\",\
                    \"workingmode\":\"%d\",\
                    \"workingstatus\":\"%d\",\
                    \"power\":\"%d\",\
                    \"realtime_hash\":\"%.2f\",\
                    \"average_hash\":\"%.2f\",\
                    \"accepted\":\"%d\", \
		            \"reject\":\"%d\", \
                    \"rejected_percentage\":\"%.2f\",\
                    \"fan_status\":\"%d\",\
                    \"fanr\":\"%d\",\
                    \"asic_status\":\"%d\",\
                    \"ping\":\"%d\",\
                    \"power_status\":\"%d\",\
                    \"pool_status\":\"%d\",\
                    \"current_pool\":\"%d\",\
                    \"address\":%s,\
                    \"worker\":%s,\
                    \"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\
                    \"version\":\"%s\",\
                    \"pool1\":\"%s\",\
                    \"worker1\":\"%s\",\
                    \"passwd1\":\"%s\",\
                    \"pool2\":\"%s\",\
                    \"worker2\":\"%s\",\
                    \"passwd2\":\"%s\",\
                    \"pool3\":\"%s\",\
                    \"worker3\":\"%s\",\
                    \"passwd3\":\"%s\",\
                    });\
                    ",
                    info->hw_info[0].prod,g_stats_misc.SoftOFF,
                    g_cgi_summary.elapsed,g_stats_misc.work_mode,g_stats_misc.SoftOFF,g_stats_misc.wallpower,
                    ghsspd,ghsavg,(int)g_cgi_summary.accepted,(int)g_cgi_summary.rejected,rejected_percentage,
                    g_stats_misc.fan1,g_stats_misc.fanr,asic_status,g_cgi_summary.ping,g_stats_misc.power_status,g_pool_status,
                    g_pool_num + 1,g_pool_url,g_pool_user,
                    pmac[0],pmac[1],pmac[2],pmac[3],pmac[4],pmac[5],FWVERSION,
                    g_cgminer_pool[0].url,g_cgminer_pool[0].worker,g_cgminer_pool[0].passwd,
                    g_cgminer_pool[1].url,g_cgminer_pool[1].worker,g_cgminer_pool[1].passwd,
                    g_cgminer_pool[2].url,g_cgminer_pool[2].worker,g_cgminer_pool[2].passwd
                    );
    strcat((char*)buf,temp_buf);
    return strlen((char*)buf);
}

static void get_random_dna(char *random,char *dna)
{
    struct cgpu_info *cgpu = NULL;
    struct avalon_info *info = NULL;
    char dna_buf[17] = "0000000000000000";
    unsigned char sha_dna[SHA_DNA_LEN+1];
    unsigned char sha_ran[SHA_RAN_LEN+1];
    char ran_buf[32] = {'\0'};
    cgpu = get_devices(0);
	if(cgpu)
	{
		info = cgpu->device_data;
        strncpy(dna_buf, info->dna[0], strlen(dna_buf));
	}
    sha256((unsigned char*)&dna_buf, strlen(dna_buf), sha_dna); 
    if(dna)
    {
        memcpy(dna,bin2hex(sha_dna, 24),WEB_PASSWD_LEN);
    }
    if(random)
    {
        memcpy(ran_buf,g_web_login.webpass,RANDOM_LEN); 
        strcat(ran_buf,dna_buf);
        sha256((unsigned char*)&ran_buf, strlen(ran_buf), sha_ran);
        memcpy(random,bin2hex(sha_ran, 8),RANDOM_LEN);
    }
}

static void get_sys_cookie(char *cookie)
{
    char random[RANDOM_LEN + 1] = {'\0'};
    char web_pass[WEB_PASSWD_LEN + 1] = {'\0'};
    get_random_dna(random,NULL);
    strcat(cookie,random);
    memset(web_pass,0,WEB_PASSWD_LEN);
    memcpy(web_pass,g_web_login.webpass,WEB_PASSWD_LEN);
    strcat(cookie,web_pass);
}

uint32_t get_qr_cookie(uint8_t *buf)
{
    char tmp_buf[256];
    char random[RANDOM_LEN + 1] = {'\0'};
    char webpass[WEB_PASSWD_LEN + 1] = {'\0'};
    get_random_dna(random,NULL);
    memcpy(webpass,g_web_login.webpass,WEB_PASSWD_LEN);
    sprintf((char*)buf, "getCookieCallback ({");
    sprintf(tmp_buf, "	\"auth\":\"%s\",\
                        \"code\":\"%s\",\
                        }); \
                        ",
                        random,webpass);
    strcat((char*)buf,tmp_buf);               
    return strlen((char*)buf);
}


uint32_t get_auth(uint8_t *buf)
{
    char tmp_buf[256] = {'\0'};
	char random[RANDOM_LEN + 1] = {'\0'};
    char sha_dna[WEB_PASSWD_LEN + 1] = {'\0'};
    get_random_dna(random,sha_dna);
    memcpy(g_qr_auth.random,random,sizeof(random));
    memcpy(g_qr_auth.sha_dna,sha_dna,sizeof(sha_dna));
    // applog(LOG_WARNING,"auth.random = %s auth.sha_dna = %s",g_qr_auth.random,g_qr_auth.sha_dna);
    sprintf((char*)buf, "getAuthCallback ({");
    sprintf(tmp_buf, "	\"auth\":\"%s\",\
                        \"code\":\"%s\",\
                            });\
                            ",random,sha_dna);
    strcat((char*)buf,tmp_buf);
    return strlen((char*)buf);
}

bool get_qr_login(void)
{
    return g_qr_login;
}

uint8_t set_qr_login(bool val)
{
    g_qr_login = val;
    return 0;
}

void cgminer_reboot_process(void)
{
    struct cgpu_info *cgpu = NULL;
    cgpu = get_devices(0);
    if(cgpu)
    {
        cgpu->drv->get_set_web_stats(cgpu,0,WEB_SET_REBOOT);
    }
}

void cgminer_config_process(uint8_t *url, uint8_t *buf, uint32_t *file_len)
{
    uint8_t *param;
    struct cgpu_info *cgpu = NULL;
	cgpu = get_devices(0);
    #define TMP_LEN 32
    char pool[TMP_LEN] = {'\0'};
    char worker[TMP_LEN] = {'\0'};
    char passwd[TMP_LEN] = {'\0'};

    if((get_http_param_value((char *)url, "pool1") || (get_http_param_value((char *)url, "pool2")) ||
            (get_http_param_value((char *)url, "pool3")))) 
    {
        for(int i = 0; i < POOL_VALID_NUM; i++)
        {
            memset(g_cgminer_pool[i].url, '\0', sizeof(g_cgminer_pool[i].url));
            memset(pool,0,TMP_LEN);
            sprintf(pool,"pool%d",i + 1);
            if((param = get_http_param_value((char *)url, pool)))
                strncpy(g_cgminer_pool[i].url, (char *)param, sizeof(g_cgminer_pool[i].url) - 1);

            memset(g_cgminer_pool[i].worker, '\0', sizeof(g_cgminer_pool[i].worker));
            memset(worker,0,TMP_LEN);
            sprintf(worker,"worker%d",i + 1);
            if((param = get_http_param_value((char *)url, worker)))
                strncpy(g_cgminer_pool[i].worker, (char *)param, sizeof(g_cgminer_pool[i].worker) - 1);

            memset(g_cgminer_pool[i].passwd, '\0', sizeof(g_cgminer_pool[i].passwd));
            memset(passwd,0,TMP_LEN);
            sprintf(passwd,"passwd%d",i + 1);
            if((param = get_http_param_value((char *)url, passwd)))
                strncpy(g_cgminer_pool[i].passwd, (char *)param, sizeof(g_cgminer_pool[i].passwd) - 1);
        }
        if(cgpu)
            cgpu->drv->get_set_web_stats(cgpu,&g_cgminer_pool,WEB_SET_POOLS);
        *file_len = load_html(buf,HTML_CGPOOLS);
        g_update_pool = false;
    } 
    else
    {
        *file_len = load_html(buf,HTML_CGPOOLS);
    }
}

int cookie_verify(int len,const char *cookie_ptr)
{
    char cookie[COOKIE_LEN + 1] = {'\0'};
    get_sys_cookie(cookie);   //get random and webpass
    if((len != 32) || (strncmp(cookie, cookie_ptr, COOKIE_LEN)))
        return -1;
    return 0;
}


uint32_t load_html_file(uint8_t *buf,char *pdir)
{
	FILE *infile;
    infile = fopen(pdir, "rb");
	fseek(infile, 0, SEEK_END);
	int len = ftell(infile);
	fseek(infile, 0, SEEK_SET);
    len = fread(buf,sizeof(unsigned char), len, infile);
	fclose(infile);
	return len > 0 ? len : 0;
}

uint32_t load_html(uint8_t *buf,uint8_t type)
{
    uint32_t file_len = 0;   
    file_len = load_html_file(buf,info[type].pdir);
    buf[file_len] = 0;
    return file_len;    
}

void get_webpass(char* password)
{
    if(password != NULL)
    {
        memcpy(password, g_web_login.webpass, sizeof(g_web_login.webpass));
        applog(LOG_WARNING,"webpass : %s", g_web_login.webpass);
    }
}
