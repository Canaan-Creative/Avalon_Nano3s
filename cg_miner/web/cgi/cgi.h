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
#ifndef _CGI_H_
#define _CGI_H_

#include <stdint.h>

#define     DISPLAY_LOG 

#define     HTML_SHA            0x0
#define     HTML_CGPOOLS        0x1
#define     HTML_DASHBOARD      0x2
#define     HTML_QR_LOGIN       0x3
#define     HTML_QR_CODE        0x4
#define     HTML_LOGIN_NEW      0x5



#define     RANDOM_LEN          8
#define     WEB_PASSWD_LEN      24
#define     SHA_DNA_LEN         32
#define     SHA_RAN_LEN         32
#define     COOKIE_LEN          32

bool get_qr_login(void);
uint8_t set_qr_login(bool val);
uint32_t get_qr_cookie(uint8_t *buf);
uint32_t get_auth(uint8_t *buf);
uint32_t get_dashboard(uint8_t * buf);
int cookie_verify(int len,const char *cookie_ptr);
void update_web_value();
void cgminer_reboot_process(void);
void cgminer_config_process(uint8_t *url, uint8_t * buf, uint32_t * file_len);
uint32_t load_html_file(uint8_t *buf,char *pdir);
uint32_t load_html(uint8_t *buf,uint8_t type);
void get_webpass(char* password);

#endif