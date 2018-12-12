/* *******************************************************
 * Call Center On Demand Product Series
 * Copyright (C) 2017 HonDa(Guangzhou.) Technology Ltd., Co.
 * All right reserved
 *
 * @file ini_config.c
 * @brief 
 * @author tuyungang
 * @version v1.0
 * @date 2017-12-01
 * 
 * TODO: 读写ini配置文件
 * 
 * *******************************************************/
#include "ngx_read_ini_config.h"
//#include "thread_pool.h"

//sAgentConfigInfo *g_ConfigInfo = NULL;
char g_LoginName[10] = {0};
char g_LoginPassword[128] = {0};
char g_MasterIP[32] = {0};
char g_StandbyIP[32] = {0};
char g_Port[10] = {0};
char g_SystemName[10] = {0};
char g_SafeBoxID[128] = {0};
char g_IniFilePath[256] = {0};

char g_CurAbsolutePath[256] = {0};
char g_LogAbsolutePath[256] = {0};
char g_CacheFileAbsolutePath[256] = {0};

ngx_int_t InitIniConfig()
{
    //bool bRet;
    //char g_CurAbsolutePath[256];
    //memset(g_CurAbsolutePath, '\0', 256);
    memset(g_IniFilePath, '\0', 256);
    
    /*
    if (NULL == getcwd(g_CurAbsolutePath, 256)) {
        return false;
    }
    */
    sprintf(g_IniFilePath, "%s/agent_config.ini", g_CurAbsolutePath);
    if (access(g_IniFilePath, F_OK) != 0) {
        return -1;
    }

    return 0;
}

void trim(char *str)
{
    int len = strlen(str);
    char *p = str + len - 1;

    while(*p == ' ')
    {
        p--;
    }

    *(p + 1) = '\0';
}

void GetIniKeyString(const char *section, const char *key, char *value)
{
    if (section == NULL || key == NULL)
        return;
    FILE *pFile = NULL;
    pFile = fopen(g_IniFilePath, "r");
    if (pFile == NULL)
        return;

    char line[256];
    while (!feof(pFile)) {
        memset(line, '\0', 256);
        char *temp = NULL;
        temp = fgets(line, sizeof(line), pFile);
        if (temp == NULL)
            return;
        line[strlen(line) - 1] = '\0';
        if (line[0] == ';' || line[0] == '\r' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        char *start = NULL;
        if ((start = strchr(line, '[')) == NULL) {
            continue;
        }

        trim(start);
        //start[strlen(start) - 1] = '\0';
        if (strncasecmp(start, section, strlen(section)) == 0) {
            char content[256];
            while (!feof(pFile)) {
                memset(content, '\0', 256);
                char *temp1 = NULL; 
                temp1 = fgets(content, sizeof(content), pFile);
                if (temp1 == NULL)
                    return;
                content[strlen(content) - 1] = '\0';
                if (content[0] == ';')
                    continue;
                trim(content);
                char *m_value = NULL;
                m_value = strpbrk(content, "=");
                *m_value++ = '\0';
                if (strncmp(content, key, strlen(content)) == 0) {
                    memcpy(value, m_value, strlen(m_value));
                    break;
                }
            }
            break;
        }
    }
    return;
}

void GetIniKeyInt(const char *section, const char *key, int *value)
{
    if (section == NULL || key == NULL)
        return;
    FILE *pFile = NULL;
    pFile = fopen(g_IniFilePath, "r");
    if (pFile == NULL)
        return;

    char line[256];
    while (!feof(pFile)) {
        memset(line, '\0', 256);
        char *temp = NULL;
        temp = fgets(line, sizeof(line), pFile);
        if (temp == NULL)
            return;
        line[strlen(line) - 1] = '\0';
        if (line[0] == ';' || line[0] == '\r' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        char *start = NULL;
        if ((start = strchr(line, '[')) == NULL) {
            continue;
        }

        trim(start);
        //start[strlen(start) - 1] = '\0';
        if (strncasecmp(start, section, strlen(section)) == 0) {
            char content[256];
            while (!feof(pFile)) {
                memset(content, '\0', 256);
                char *temp1 = NULL; 
                temp1 = fgets(content, sizeof(content), pFile);
                if (temp1 == NULL)
                    return;
                content[strlen(content) - 1] = '\0';
                if (content[0] == ';')
                    continue;
                trim(content);
                char *m_value = NULL;
                m_value = strpbrk(content, "=");
                *m_value++ = '\0';
                if (strncmp(content, key, strlen(content)) == 0) {
                    //memcpy(value, m_value, strlen(m_value));
                    *value = atoi(m_value);
                    break;
                }
            }
            break;
        }
    }
    return;
}

void GetIniKeyLong(const char *section, const char *key, long *value)
{
    if (section == NULL || key == NULL)
        return;
    FILE *pFile = NULL;
    pFile = fopen(g_IniFilePath, "r");
    if (pFile == NULL)
        return;

    char line[256];
    while (!feof(pFile)) {
        memset(line, '\0', 256);
        char *temp = NULL;
        temp = fgets(line, sizeof(line), pFile);
        if (temp == NULL)
            return;
        line[strlen(line) - 1] = '\0';
        if (line[0] == ';' || line[0] == '\r' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        char *start = NULL;
        if ((start = strchr(line, '[')) == NULL) {
            continue;
        }

        trim(start);
        //start[strlen(start) - 1] = '\0';
        if (strncasecmp(start, section, strlen(section)) == 0) {
            char content[256];
            while (!feof(pFile)) {
                memset(content, '\0', 256);
                char *temp1 = NULL; 
                temp1 = fgets(content, sizeof(content), pFile);
                if (temp1 == NULL)
                    return;
                content[strlen(content) - 1] = '\0';
                if (content[0] == ';')
                    continue;
                trim(content);
                char *m_value = NULL;
                m_value = strpbrk(content, "=");
                *m_value++ = '\0';
                if (strncmp(content, key, strlen(content)) == 0) {
                    //memcpy(value, m_value, strlen(m_value));
                    *value = atol(m_value);
                    break;
                }
            }
            break;
        }
    }
    return;
}
