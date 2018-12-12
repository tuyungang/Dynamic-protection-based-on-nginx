#ifndef _NGX_MYTHREAD_POOL_H_INCLUDED_
#define _NGX_MYTHREAD_POOL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
//#include <ngx_event.h>
//#include <ngx_http.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/time.h>

//#include "rdkafka.h"
//#include "sys_queue.h"
#include <ngx_sys_queue.h>
//#include <amqp.h>
//#include <amqp_tcp_socket.h>
//#include <amqp_framing.h>
//#include "utils.h"

#include <cJSON.h>

#define MAX_TASK_SIZE 99999999
#define MAX_EVENT_NUMBER 10000
#define MAX_THREAD_NUM 50
#define MAX_TASKBUF_SIZE  4096
#define MAX_COOKIEBUF_SIZE  4096

//static rd_kafka_t *rk;
//static rd_kafka_topic_t *rkt;
//static int partition = RD_KAFKA_PARTITION_UA;
//static ngx_pid_t ngx_mypid;
//static pthread_key_t  key;

typedef void* (*CB_FUN)(void *);

//任务结构体
typedef struct ngx_task_s
{
    TAILQ_ENTRY(ngx_task_s) m_TaskNext;
	void		*argv; //任务函数的参数（任务执行结束前，要保证参数地址有效）
    char        m_TaskBuf[MAX_TASKBUF_SIZE]; 
	CB_FUN		handler; //任务函数（返回值必须为0   非0值用作增加线程，和销毁线程池）
	//struct task *next; //任务链指针
    //int         m_Read_Idx;
}ngx_task_t;

typedef struct ngx_black_s
{
    TAILQ_ENTRY(ngx_black_s) m_BlackNext;
    char                     m_Cookie[MAX_TASKBUF_SIZE];
}ngx_black_t;

//pthread_mutex_t g_Mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct mythreadpool
{
	//ngx_task_queue_t  tasks;//任务队列
    TAILQ_HEAD(, ngx_task_s)  m_TaskQueue;
    TAILQ_HEAD(, ngx_black_s) m_BlackQueue;

	unsigned int       m_InitThreadNum; //线程数

	//pthread_mutex_t    m_NlistMutex;  //互斥锁
	//pthread_mutex_t    m_Mutex;  //互斥锁
	//pthread_mutex_t    m_BlackMutex;  //互斥锁
    pthread_mutex_t    g_Mutex;
	pthread_cond_t     m_Cond;	//条件锁

}ngx_mythreadpool_t;


/*
typedef struct threadpool
{
	pthread_mutex_t    m_Mutex;  //互斥锁
	pthread_mutex_t    m_BlackMutex;  //互斥锁
	pthread_cond_t     m_Cond;	//条件锁
	//ngx_task_queue_t  tasks;//任务队列
    TAILQ_HEAD(, ngx_task_s)  m_TaskQueue;
    TAILQ_HEAD(, ngx_black_s) m_BlackQueue;

	unsigned int       m_InitThreadNum; //线程数
	unsigned int       m_Thread_Stack_Size; //线程堆栈大小
	unsigned int       m_MaxTaskNum; //最大任务限制
	unsigned int       m_CurTaskNum; //当前任务数

    //amqp_socket_t            *m_Mqsocket;
    //amqp_connection_state_t  m_Mqconn;
    //amqp_basic_properties_t  m_Mqprops;

}ngx_threadpool_t;

//配置参数
typedef struct threadpool_conf
{
	unsigned int m_ThreadNum;    //线程数
	unsigned int m_Thread_Stack_Size;//线程堆栈大小
	unsigned int m_MaxTaskNum;//最大任务限制
}ngx_threadpool_conf_t;

//add by tu
//int m_pipefd[2] = {0};
//static int sig_pipefd[2];

int z_conf_check(ngx_threadpool_conf_t *conf);
int z_threadpool_mutex_init(pthread_mutex_t *mutex);
void z_thread_mutex_destroy(pthread_mutex_t *mutex);
int z_threadpool_cond_init(pthread_cond_t *cond);
int z_thread_cond_init(pthread_cond_t *cond);
int z_thread_mutex_init(pthread_mutex_t *mutex);
void z_thread_cond_destroy(pthread_cond_t *cond);
int z_threadpool_create(ngx_threadpool_t *pool);
void *z_threadpool_cycle(void* argv);
void *z_threadpool_exit_cb(void* argv);
int z_thread_add(ngx_threadpool_t *pool, unsigned int num);
void z_change_maxtask_num(ngx_threadpool_t *pool, unsigned int num);
int z_thread_key_create();
void z_thread_key_destroy();

//初始化一个线程池
ngx_threadpool_t* ngx_threadpool_init(ngx_threadpool_conf_t *conf);

//添加一个任务
int ngx_threadpool_add_task(ngx_threadpool_t *pool, ngx_task_t *task);

//销毁线程池
void ngx_threadpool_destroy(ngx_threadpool_t *pool);

//增加一个线程
int ngx_thread_add(ngx_threadpool_t *pool, unsigned int num);
//更改最大任务限制
int ngx_set_max_tasknum(ngx_threadpool_t *pool,unsigned int num);

//myproxy_workthread_t* GetIdleWorkThread(ngx_threadpool_t *pool, ngx_task_t *task); 

//void ngx_http_myproxy_sig_handler(int sig);
void ngx_http_myproxy_add_epoll_fd(int epollfd, int fd);
void ngx_http_myproxy_delete_epoll_fd(int epollfd, int fd);
void ngx_http_myproxy_mod_epoll_fd(int epollfd, int fd, int ev);
void ngx_close_mysocket_fd(int fd, ngx_log_t *log);
int ngx_http_myproxy_set_fd_attr(int fd, int attr);
ngx_int_t ngx_http_myproxy_create_pidfile(ngx_str_t *name, ngx_log_t *log);
ngx_int_t ngx_http_myproxy_create_aliveflagfile(ngx_str_t *name, ngx_log_t *log);
ngx_int_t ngx_http_myproxy_select_listen(ngx_fd_t fd, ngx_log_t *log);
//ngx_socket_t ngx_http_myproxy_start_socket();

void *ngx_add_blacklist_queue_handler(void *arg);
void *ngx_del_blacklist_queue_handler(void *arg);
void *ngx_send_data_via_mq_handler(void *arg);
//void ngx_rabbitmq_init(void *arg);
//void ngx_rabbitmq_destroy(void *arg);
*/

ngx_mythreadpool_t* ngx_mythreadpool_init(unsigned int init_num);
int z_mythreadpool_create(ngx_mythreadpool_t *pool);
void *z_mythreadpool_cycle(void* arg);

int z_threadpool_cond_init(pthread_cond_t *cond);
int z_threadpool_mutex_init(pthread_mutex_t *mutex);
int z_thread_cond_init(pthread_cond_t *cond);
int z_thread_mutex_init(pthread_mutex_t *mutex);
void z_thread_cond_destroy(pthread_cond_t *cond);
void z_thread_mutex_destroy(pthread_mutex_t *mutex);


void ngx_http_myproxy_add_epoll_fd(int epollfd, int fd);
int ngx_http_myproxy_set_fd_attr(int fd, int attr);
void ngx_close_mysocket_fd(int fd, ngx_log_t *log);
void ngx_http_myproxy_mod_epoll_fd(int epollfd, int fd, int ev);
void ngx_http_myproxy_delete_epoll_fd(int epollfd, int fd);
#endif
