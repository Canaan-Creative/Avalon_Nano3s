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
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "mongoose.h"
#include "http.h"
#include "sysutils.h"
#include "cgi.h"
#include "logging.h"
#include <sha2.h>

#define HTTP_FAILED					0
#define HTTP_OK						1
#define HTTP_RESET					2
#define HTTP_SKIPPED				3

#define DATA_BUF_SIZE		1024
#define RXTX_BUF_LEN   (320 * DATA_BUF_SIZE)
#define MAX_BUF_LEN    (320 * DATA_BUF_SIZE)
uint8_t pHTTP_TX[MAX_BUF_LEN];

static const char *s_debug_level = "2";
static const char *s_listening_address = "0.0.0.0:80";
static const char *s_enable_hexdump = "no";



uint8_t BUFPUB[2048];
struct mg_http_serve_opts opts = {};

uint8_t * get_http_param_value(char* uri, char* param_name)
{
	uint8_t * ret = BUFPUB;

	int len = mg_http_get_var((const struct mg_str *)uri, param_name, (char *)BUFPUB, sizeof(BUFPUB));

	if (len < 0)
		return NULL;
	else
		return ret;
}

uint8_t http_get_cgi_handler(struct mg_connection *c, struct mg_http_message *hm, uint8_t * buf, uint32_t * file_len)
{
	uint8_t ret = HTTP_OK;

	// applog(LOG_WARNING,"get body = %s",hm->uri.ptr);
	//before else not verify 
	if(mg_http_match_uri(hm, "/") || mg_http_match_uri(hm, "/index.cgi") || mg_http_match_uri(hm, "/login.cgi") || mg_http_match_uri(hm, "/poolconfig.cgi") || \
		mg_http_match_uri(hm, "/dashboard.cgi") || mg_http_match_uri(hm, "/cgpools.cgi") || mg_http_match_uri(hm, "/reboot.cgi"))
	{
		*file_len = load_html(buf, HTML_LOGIN_NEW);	
	}
	else if(mg_http_match_uri(hm, "/get_auth.cgi"))
	{
		*file_len = get_auth(buf);
	}
	else if (mg_http_match_uri(hm, "/sha256.min.js")) 
	{
		*file_len = load_html(buf, HTML_SHA);	
	}	
	else if (mg_http_match_uri(hm, "/qrcode.min.js"))
	{
		*file_len = load_html(buf, HTML_QR_CODE);	
	}
	else if(mg_http_match_uri(hm, "/is_login.cgi"))
	{
		if(get_qr_login())
		{
			set_qr_login(false);
			*file_len = get_qr_cookie(buf);
		}
	}
	else //verify
	{
		struct mg_str *cookie_str = mg_http_get_header(hm, "Cookie"); 
		if(cookie_str != NULL) 
		{
			struct mg_str cookie = mg_http_get_header_var(*cookie_str, mg_str("auth"));
			if(cookie_verify(cookie.len,cookie.ptr) < 0)
			{
				*file_len = load_html(buf, HTML_LOGIN_NEW);
			}
			else
			{
				if (mg_http_match_uri(hm, "/get_dashboard.cgi")) 
				{
					*file_len = get_dashboard(buf);
				}	
			}
		}
		else
		{
			*file_len = load_html(buf, HTML_LOGIN_NEW);
		}
	}

	return ret;
}

uint8_t http_post_cgi_handler(struct mg_connection *c, struct mg_http_message *hm, uint8_t * buf, uint32_t * file_len)
{
	uint8_t ret = HTTP_OK;
	// applog(LOG_WARNING,"post body = %s",hm->uri.ptr);
	//before else not verify
	if (mg_http_match_uri(hm, "/qr_login.cgi"))
	{
		*file_len = load_html(buf, HTML_QR_LOGIN);	
	}
	else if (mg_http_match_uri(hm, "/"))
	{
		*file_len = load_html(buf, HTML_QR_LOGIN);	
	}
	else if (mg_http_match_uri(hm, "/logout.cgi"))
	{
		*file_len = load_html(buf, HTML_LOGIN_NEW);
	}
	else //verify
	{
		struct mg_str *cookie_str = mg_http_get_header(hm, "Cookie");
		if(cookie_str != NULL)
		{
			struct mg_str cookie = mg_http_get_header_var(*cookie_str, mg_str("auth"));	
			if(cookie_verify(cookie.len,cookie.ptr) < 0)
			{
				*file_len = load_html(buf, HTML_LOGIN_NEW);
			}
			else
			{
				if(mg_http_match_uri(hm, "/login.cgi"))
				{
					*file_len = load_html(buf, HTML_DASHBOARD);
				}
				else if(mg_http_match_uri(hm, "/cgpools.cgi"))
				{
					cgminer_config_process((uint8_t *)&hm->body, buf,file_len);
				}
				else if(mg_http_match_uri(hm, "/poolconfig.cgi"))
				{
					*file_len = load_html(buf, HTML_CGPOOLS);
				}
				else if(mg_http_match_uri(hm, "/dashboard.cgi"))
				{
					*file_len = load_html(buf, HTML_DASHBOARD);
				}
				else if (mg_http_match_uri(hm, "/reboot.cgi"))
				{
					cgminer_reboot_process();
				}
				else
				{
					ret = HTTP_FAILED;
				}	
			}
		}
		else
		{
			*file_len = load_html(buf, HTML_LOGIN_NEW);
		}
	}
	buf[*file_len] = '\0';//wendy add
	return ret;
}

struct http_file{
	char *name;
	char *path;
}get_file[] =
{
	{"efuse", "/data/factory/efuse_info.txt"},
	{"mm_sys_log", "/data/userdata/log/mm_sys.log"},
	{"cg_sys_log", "/data/userdata/log/cg_sys.log"},
	{"asic_sys_log", "/data/userdata/log/biglog/asic_sys.log"},
	{"mm_op_log", "/data/userdata/log/mm_op.log"},
	{"cg_op_log", "/data/userdata/log/cg_op.log"},
};

void http_post_file_handler(struct mg_connection *c, struct mg_http_message *hm)
{
#define TMPFILE	"/tmp/logfile"
#define USER_NAME_LEN 6
#define USER_PASS_LEN 65
	char user_name[USER_NAME_LEN] = {'\0'};
	char user_pass[USER_PASS_LEN] = {'\0'};
	unsigned char user_passsha[128] = {'\0'};
	char webpass[128] = {'\0'};
	char cmd[128] = {'\0'};

	mg_http_creds(hm, user_name, USER_NAME_LEN ,user_pass, USER_PASS_LEN);
	sha256((unsigned char *)user_pass,strlen(user_pass), user_passsha);

	get_webpass(webpass);

	if(memcmp(user_name, "admin", USER_NAME_LEN) != 0 || memcmp(bin2hex(user_passsha, 32), webpass, USER_PASS_LEN) != 0)
	{
		mg_http_reply(c, 401, "", "%s", "Unauthorized\n");
		return;
	}
	for(uint8_t i = 0; i < sizeof(get_file)/sizeof(get_file[0]); i++) 
	{
		if(mg_strcmp(hm->body, mg_str_s(get_file[i].name)) == 0)
		{
			if(!access(get_file[i].path, F_OK))
			{
				if(strstr(get_file[i].name, "log") == NULL)
				{
					mg_http_serve_file(c, hm, get_file[i].path, &opts);
				}
				else // log
				{
					sprintf(cmd, "cat %s.0 %s > %s 2>/dev/null", get_file[i].path, get_file[i].path, TMPFILE);
					system(cmd);
					mg_http_serve_file(c, hm, TMPFILE, &opts);
				}
			}
			else
			{
				mg_http_reply(c, 404, "", "%s", "Not found\n");
			}
			return;
		}
	}
	mg_http_reply(c, 404, "", "%s", "Not found\n");
}

static void http_listen_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) 
{
#define MAX_URI_LEN 64
    if (ev == MG_EV_HTTP_MSG)
    {
		update_web_value();
        struct mg_http_message *hm = (struct mg_http_message*)ev_data;
		if(hm->uri.len > MAX_URI_LEN)
		{
			mg_http_reply(c, 404, "", "%s", "Not found\n");
			return;
		}

        if (mg_strcmp(hm->method, mg_str_s("GET")) == 0)
        {
            memset(pHTTP_TX, 0, sizeof(pHTTP_TX));
            uint32_t file_len = 0;
            uint8_t content_found = http_get_cgi_handler(c, hm, pHTTP_TX, &file_len);
            if (content_found == HTTP_OK)
                mg_http_reply(c, 200, "", "%s", pHTTP_TX);
            else if(content_found == HTTP_FAILED)
                mg_http_reply(c, 404, "", "%s", "Not found\n");
        }else if (mg_strcmp(hm->method, mg_str_s("POST")) == 0)
        {
			if(mg_strcmp(hm->uri, mg_str_s("/usrdata")) == 0)
			{
				http_post_file_handler(c, hm);
			}
			else
			{
				memset(pHTTP_TX, 0, sizeof(pHTTP_TX));
				uint32_t file_len = 0;
				uint8_t content_found = http_post_cgi_handler(c, hm, pHTTP_TX, &file_len);
				if (content_found == HTTP_OK)
					mg_http_reply(c, 200, "", "%s", pHTTP_TX);
				else
					mg_http_reply(c, 404, "", "%s", "Not found\n");
			}
        }else{
			mg_http_reply(c, 404, "", "%s", "Not found\n");
		}
    }
    (void) fn_data;
}

void *http_thread(void *arg) {
    struct mg_mgr mgr;
    struct mg_connection *connection;

	pthread_detach(pthread_self());
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    applog(LOG_NOTICE,"http_thread create success");

    mg_log_set(s_debug_level);
    mg_mgr_init(&mgr);
    if ((connection = mg_http_listen(&mgr, s_listening_address, http_listen_cb, &mgr)) == NULL)
    {
		applog(LOG_WARNING, "Cannot listen on %s. Use http://ADDR:PORT or :PORT",s_listening_address);
        return NULL;
    }
    if (mg_casecmp(s_enable_hexdump, "yes") == 0)
        connection->is_hexdumping = 1;
    while (1)
    {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);
    applog(LOG_WARNING, "Exiting http_thread");

    return NULL;
}
