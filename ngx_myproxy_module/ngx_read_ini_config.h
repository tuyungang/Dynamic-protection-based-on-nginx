/* *******************************************************
 * Call Center On Demand Product Series
 * Copyright (C) 2017 HonDa(Guangzhou.) Technology Ltd., Co.
 * All right reserved
 *
 * @file ini_config.h
 * @brief 
 * @author tuyungang
 * @version v1.0
 * @date 2017-12-01
 * 
 * TODO: 读写ini配置文件
 * 
 * *******************************************************/
#ifndef _INI_CONFIG_H
#define _INI_CONFIG_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include "thread_pool.h"

/*
typedef struct
{
    char LoginName[10];
    char LoginPassword[128];
    char MasterIP[32];
    char StandbyIP[32];
    char SystemName[10];
    char SafeBoxID[128];
}sAgentConfigInfo, *psAgentConfigInfo;
*/

ngx_int_t InitIniConfig();
void trim(char *str);

/* --------------------------------------------------------------------------*/
/**
 * @brief GetIniKeyString 
 * @description 获取字符串值，按section和key值
 *
 * @param section
 * @param key
 * @param vaule
 */
/* ----------------------------------------------------------------------------*/
void GetIniKeyString(const char *section, const char *key, char *vaule);
void GetIniKeyInt(const char *section, const char *key, int *vaule);
void GetIniKeyLong(const char *section, const char *key, long *vaule);

#endif
