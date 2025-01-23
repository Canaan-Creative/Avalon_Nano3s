
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include "poolcfg.h"
#include "logging.h"

static int pools_cfg_todefault(void) 
{
    json_t *root, *params, *pools_obj; 
    FILE *file;
    char tmp_buf[TMP_BUF_LEN] = {'\0'};
    root = json_object();  
    if (!root) 
    {  
        applog(LOG_ERR,"func:pools_cfg_todefault Failed to create root JSON object");  
        return -1;  
    } 
    params = json_object();  
    if (!params) 
    {  
        applog(LOG_ERR,"func:pools_cfg_todefault Failed to create params JSON object");  
        json_decref(root);  
        return -1;  
    }
    for(int i = 0; i < POOL_VALID_NUM; i++)
    {
        sprintf(tmp_buf,"pool%d",i);
        pools_obj = json_object();
        json_object_set_new(pools_obj, "url", json_string(""));
        json_object_set_new(pools_obj, "user", json_string(""));
        json_object_set_new(pools_obj, "pass", json_string(""));
        json_object_set_new(params, tmp_buf, pools_obj); 
        memset(tmp_buf,'\0',TMP_BUF_LEN);
    }
    json_object_set_new(root, "pools", params); 
    json_object_set_new(root, "standard",json_string("--lowmem --real-quiet"));
    char *jsonString = json_dumps(root, JSON_INDENT(2));  
    if (!jsonString) 
    {  
        applog(LOG_ERR,"func:pools_cfg_todefault Unable to dump JSON string");  
        json_decref(root);  
        return -1;  
    } 
    file = fopen(FILENAME, "w");
    fputs(jsonString, file);
    fclose(file);
    return 0;
}

void json_parse(struct cgicfg *cgi_info)
{
	json_t* json_pro = NULL;
    json_t* json_url = NULL;
    json_t* json_user = NULL;
    json_t* json_pass = NULL;
	json_t* json_stand = NULL;
    json_t *root = NULL;  
    json_error_t error; 
    char tmp_buf[TMP_BUF_LEN] = {'\0'};
	root = json_load_file(FILENAME,0,&error);
	if (!root) 
    {  
        applog(LOG_ERR,"func:json_parse Error: parsing JSON: %s", error.text);  
        return ;  
    } 
    if (!json_is_object(root)) 
    {  
        applog(LOG_ERR,"func:json_parse Error: JSON is not an object");  
        json_decref(root);  
        return ;  
    }
    json_pro = json_object_get(root,"pools");
    for(int i = 0; i < POOL_VALID_NUM; i++)
    {
        sprintf(tmp_buf,"pool%d",i);
        json_t *name_obj = json_object_get(json_pro, tmp_buf);
        if (json_is_object(name_obj)) 
        {  
            json_url = json_object_get(name_obj, "url");
            json_user = json_object_get(name_obj, "user");
            json_pass = json_object_get(name_obj, "pass");
            if(json_url)
                memcpy(cgi_info->pools[i].url,json_string_value(json_url),MAX_LEN_URL);
            else
                memset(cgi_info->pools[i].url,0,MAX_LEN_URL);
            if(json_user)
                memcpy(cgi_info->pools[i].user,json_string_value(json_user),MAX_LEN_USER_PASS);
            else    
                memset(cgi_info->pools[i].user,0,MAX_LEN_USER_PASS);
            if(json_pass)
                memcpy(cgi_info->pools[i].pass,json_string_value(json_pass),MAX_LEN_USER_PASS);
            else
                memset(cgi_info->pools[i].pass,0,MAX_LEN_USER_PASS);
            memset(tmp_buf,'\0',TMP_BUF_LEN);
        }
    }
	json_stand = json_object_get(root,"standard");
    if (json_stand) 
	    memcpy(cgi_info->standard,json_string_value(json_stand),MAX_LEN_STAND);
    else
        memset(cgi_info->standard,0,MAX_LEN_STAND); 

}

void cgminer_pools_set(uint8_t *pdata,uint8_t poolnum)
{
    struct poolcfg *cgminer_pool = (struct poolcfg *)pdata;
    struct cgicfg cgi_info = {0};
    FILE *file;
    json_t *root, *params, *pools_obj; 
    root = json_object();  
    if (!root) 
    {  
        applog(LOG_ERR,"func:cgminer_pools_set Failed to create root JSON object");  
        return ;  
    } 
    params = json_object();  
    if (!params) 
    {  
        applog(LOG_ERR,"func:cgminer_pools_set Failed to create params JSON object");  
        json_decref(root);  
        return ;  
    }
    char tmp_buf[TMP_BUF_LEN] = {'\0'};
    if (poolnum == POOL_VALID_NUM)
    {
        for(int i = 0; i < POOL_VALID_NUM; i++)
        {
            pools_obj = json_object();
            json_object_set_new(pools_obj, "url", json_string(cgminer_pool[i].url));
            json_object_set_new(pools_obj, "user", json_string(cgminer_pool[i].user));
            json_object_set_new(pools_obj, "pass", json_string(cgminer_pool[i].pass));
            sprintf(tmp_buf,"pool%d",i);
            json_object_set_new(params, tmp_buf, pools_obj); 
            memset(tmp_buf,'\0',TMP_BUF_LEN);
        }       
    }  
    else
    {
        json_parse(&cgi_info); 
        for(int i = 0; i < POOL_VALID_NUM; i++)
        {
            if(i == poolnum)
            {
                pools_obj = json_object();
                json_object_set_new(pools_obj, "url", json_string(cgminer_pool->url));
                json_object_set_new(pools_obj, "user", json_string(cgminer_pool->user));
                json_object_set_new(pools_obj, "pass", json_string(cgminer_pool->pass));
                sprintf(tmp_buf,"pool%d",i);
                json_object_set_new(params, tmp_buf, pools_obj); 
                memset(tmp_buf,'\0',TMP_BUF_LEN);
            }
            else
            {
                pools_obj = json_object();
                json_object_set_new(pools_obj, "url", json_string(cgi_info.pools[i].url));
                json_object_set_new(pools_obj, "user", json_string(cgi_info.pools[i].user));
                json_object_set_new(pools_obj, "pass", json_string(cgi_info.pools[i].pass));
                sprintf(tmp_buf,"pool%d",i);
                json_object_set_new(params, tmp_buf, pools_obj); 
                memset(tmp_buf,'\0',TMP_BUF_LEN);
            }   
            
        }    
    }  
    json_object_set_new(root, "pools", params); 
    json_object_set_new(root, "standard",json_string("--lowmem --real-quiet"));
    char *jsonString = json_dumps(root, JSON_INDENT(2));  
    if (!jsonString) 
    {  
        applog(LOG_ERR,"func:cgminer_pools_set Unable to dump JSON string");  
        json_decref(root);  
        return ;  
    } 
    file = fopen(FILENAME, "w");
    fputs(jsonString, file);
    fclose(file);
}

void cgminer_pools_get(struct cgicfg *cgi_info)
{
	json_parse(cgi_info);
}

int pools_cfg_assemble(void)
{
    json_t *json;  
    json_error_t error; 
    json = json_load_file(FILENAME, 0, &error); 
    if (!json) 
    {  
        applog(LOG_INFO,"pools_cfg_assemble Error parsing JSON: %s ,pools set empty", error.text);  
        pools_cfg_todefault(); 
        return 1;  
    }  
    return 0;
}


void pools_cfg_init(void)
{
    if(access(FILENAME,0) < 0) //file not exist
    {
        applog(LOG_INFO,"pools config file not exist,pools set empty");
        pools_cfg_todefault();
    }
    else
    {
        pools_cfg_assemble();  
    }

}