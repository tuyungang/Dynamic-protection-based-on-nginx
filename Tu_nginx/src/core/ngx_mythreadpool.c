#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mythreadpool.h>


//static ngx_pid_t ngx_mypid;
//static pthread_key_t  key;

/*
int z_conf_check(ngx_threadpool_conf_t *conf)
{
	if (conf == NULL){
		return -1;
	}

	if (conf->m_ThreadNum < 1 && conf->m_ThreadNum > MAX_THREAD_NUM){
		return -1;
	}

	if (conf->m_MaxTaskNum < 1){
		conf->m_MaxTaskNum = MAX_TASK_SIZE;
	}
	return 0;
}
*/

int z_threadpool_mutex_init(pthread_mutex_t *mutex)
{
    printf("enter z_threadpool_mutex_init\n");
    int ret = 0;
	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) != 0){
		return -1;
	}

    printf("0 enter z_threadpool_mutex_init\n");
	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0){
		pthread_mutexattr_destroy(&attr);
		return -1;
	}

    printf("1 enter z_threadpool_mutex_init\n");
	if ((ret = pthread_mutex_init(mutex,&attr)) != 0)
        return ret;

    printf("2 enter z_threadpool_mutex_init\n");
	pthread_mutexattr_destroy(&attr);

	return ret;
}

void z_thread_mutex_destroy(pthread_mutex_t *mutex)
{
	pthread_mutex_destroy(mutex);
}

int z_threadpool_cond_init(pthread_cond_t *cond)
{
    printf("enter z_threadpool_cond_init\n");
    int ret = pthread_cond_init(cond, NULL);
    if (ret != 0)
        return ret;
    printf("0 enter z_threadpool_cond_init\n");
    return ret;
    /*
    int ret = 0;
    if ((ret = pthread_cond_init(cond, NULL) != 0))
        return ret;
	return ret;
    */

}

int z_thread_mutex_init(pthread_mutex_t *mutex)
{
    int ret = 0;
	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) != 0){
		return -1;
	}

	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0){
		pthread_mutexattr_destroy(&attr);
		return -1;
	}

	if ((ret = pthread_mutex_init(mutex,&attr)) != 0) {
        pthread_mutexattr_destroy(&attr);
        return ret;
    }
	pthread_mutexattr_destroy(&attr);

	return ret;

}

void z_thread_cond_destroy(pthread_cond_t *cond)
{
	pthread_cond_destroy(cond);
}

int z_mythreadpool_create(ngx_mythreadpool_t *pool)
{
    printf("enter z_mythreadpool_create\n");
	unsigned int i = 0;
	pthread_t  pid;

	for (; i < pool->m_InitThreadNum; ++i)
        pthread_create(&pid, NULL, z_mythreadpool_cycle, pool);
    printf("init num:%d\n", pool->m_InitThreadNum);
    return 1;
}

/*
int z_threadpool_create(ngx_threadpool_t *pool)
{
	unsigned int i = 0;
	pthread_t  pid;
	pthread_attr_t attr;

	if (pthread_attr_init(&attr) != 0){
		return -1;
	}

	if (pool->m_Thread_Stack_Size != 0)
	{
		if (pthread_attr_setstacksize(&attr, pool->m_Thread_Stack_Size) != 0){
			pthread_attr_destroy(&attr);
			return -1;
		}
	}
	for (; i < pool->m_InitThreadNum; ++i)
	{
		pthread_create(&pid, &attr, z_threadpool_cycle, pool);
        printf("start thread:%d ID:%lu\n", i, pid);

	}	
	pthread_attr_destroy(&attr);
	return 0;
}
*/

void *z_mythreadpool_cycle(void* arg)
{
    printf("enter z_mythreadpool_cycle\n");
	ngx_task_t *ptask = NULL;
	ngx_mythreadpool_t *pool = (ngx_mythreadpool_t*)arg;
    int err;

    while (1) {     
        printf("0 enter z_mythreadpool_cycle\n");
        if ((err = pthread_mutex_lock(&pool->g_Mutex)) != 0) {
            printf("1 enter z_mythreadpool_cycle\n");
            if (err == EDEADLK)
                printf("2 enter z_mythreadpool_cycle\n");
            else if (err == EPERM)
                printf("3 enter z_mythreadpool_cycle\n");
            else if (err == EBUSY)
                printf("4 enter z_mythreadpool_cycle\n");
            else if (err== EINVAL)
                printf("5 enter z_mythreadpool_cycle\n");
            else if (err == EAGAIN)
                printf("6 enter z_mythreadpool_cycle\n");

            return NULL;
        }

        printf("thread is running\n");
        while (TAILQ_EMPTY(&pool->m_TaskQueue)) {
            if (pthread_cond_wait(&pool->m_Cond, &pool->g_Mutex) != 0) {
                pthread_mutex_unlock(&pool->g_Mutex);
                return NULL;
            }
        }
        //TODO
        ptask = TAILQ_FIRST(&pool->m_TaskQueue);
        TAILQ_REMOVE(&pool->m_TaskQueue, ptask, m_TaskNext);
        printf("get task\n");
		if (pthread_mutex_unlock(&pool->g_Mutex) != 0){ 
			return NULL;
		}

        //ptask->argv = pool;
		ptask->handler(ptask);  
		free(ptask);
		ptask = NULL;
	}
    printf("thread exit\n");
	pthread_exit(0);
}

/*
void *z_threadpool_cycle(void* argv)
{
    printf("enter z_threadpool_cycle\n");
	unsigned int exit_flag = 0;
	sigset_t set;
	ngx_task_t *ptask = NULL;
	ngx_threadpool_t *pool = (ngx_threadpool_t*)argv;

	sigfillset(&set);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGSEGV);
	sigdelset(&set, SIGBUS);
	//sigdelset(&set, SIGCHLD);
	
	if (pthread_setspecific(key,(void*)&exit_flag) != 0){//设置exit_flag = 0
		return NULL;
	}

	if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0){
		return NULL;
	}

	while (!exit_flag) {         //exit_flag为1时线程退出
        if (pthread_mutex_lock(&pool->m_Mutex) != 0) {
            return NULL;
        }

        printf("thread is running\n");
        while (TAILQ_EMPTY(&pool->m_TaskQueue)) {
            if (pthread_cond_wait(&pool->m_Cond, &pool->m_Mutex) != 0) {
                pthread_mutex_unlock(&pool->m_Mutex);
                return NULL;
            }
        }
        //TODO
        ptask = TAILQ_FIRST(&pool->m_TaskQueue);
        TAILQ_REMOVE(&pool->m_TaskQueue, ptask, m_TaskNext);
        pool->m_CurTaskNum--;
        printf("get task\n");
		if (pthread_mutex_unlock(&pool->m_Mutex) != 0){ //解锁
			return NULL;
		}

        //ptask->argv = pool;
		ptask->handler(ptask);  //执行任务。
		free(ptask);
		ptask = NULL;
	}
    printf("thread exit\n");
	pthread_exit(0);
}

void *z_threadpool_exit_cb(void* argv)
{
    ngx_task_t *tk = (ngx_task_t*)argv;
	unsigned int *lock = (unsigned int*)tk->argv;
	unsigned int *pexit_flag = NULL;
	pexit_flag = (unsigned int *)pthread_getspecific(key);
	*pexit_flag = 1;    //将exit_flag置1
	pthread_setspecific(key, (void*)pexit_flag);
	*lock = 0;
    return pexit_flag;
}

int z_thread_add(ngx_threadpool_t *pool, unsigned int num)
{
	unsigned int i = 0;
	pthread_t  pid;
	pthread_attr_t attr;
	int ret = -1;
	if (pthread_attr_init(&attr) != 0){
		return -1;
	}
	if (pool->m_Thread_Stack_Size != 0)
	{
		if (pthread_attr_setstacksize(&attr, pool->m_Thread_Stack_Size) != 0){
			pthread_attr_destroy(&attr);
			return -1;
		}
	}

    for (; i < num; i++) {
        ret = pthread_create(&pid, &attr, z_threadpool_cycle,pool);
        if (ret != 0)
            return ret; 

        pool->m_InitThreadNum++;
    }

	pthread_attr_destroy(&attr);
	return ret;
}

void z_change_maxtask_num(ngx_threadpool_t *pool, unsigned int num)
{
	pool->m_MaxTaskNum = num;
	if (pool->m_MaxTaskNum < 1)
	{
		pool->m_MaxTaskNum = MAX_TASK_SIZE;
	}
}

inline int z_thread_key_create()
{
	return pthread_key_create(&key, NULL);
}

inline void z_thread_key_destroy()
{
	pthread_key_delete(key);
}
*/

/*
void ngx_rabbitmq_init(void *arg)
{
    ngx_threadpool_t *pool = (ngx_threadpool_t *)arg;
    pool->m_Mqsocket = NULL;
    pool->m_Mqconn = amqp_new_connection();
    pool->m_Mqsocket = amqp_tcp_socket_new(pool->m_Mqconn);
    if (!pool->m_Mqsocket) {
        die("creating MQ TCP socket");
    }

    printf("amqp_tcp_socket_new\n");
    int status = amqp_socket_open(pool->m_Mqsocket, "192.168.2.147", 5672);
    if (status) {
        die("opening MQ TCP socket");
        printf("amqp_socket_open failed\n");
    }
    printf("amqp_socket_open\n");

    die_on_amqp_error(amqp_login(pool->m_Mqconn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, "root", "root"), "Logging in");
    printf("amqp_login\n");
    amqp_channel_open(pool->m_Mqconn, 1);
    printf("amqp_channel_open\n");
    die_on_amqp_error(amqp_get_rpc_reply(pool->m_Mqconn), "Opening channel");
    printf("amqp_get_rpc_reply\n");

    pool->m_Mqprops._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    pool->m_Mqprops.content_type = amqp_cstring_bytes("text/plain");
    pool->m_Mqprops.delivery_mode = 2; //persistent delivery mode 
}

void ngx_rabbitmq_destroy(void *arg)
{
    ngx_threadpool_t *pool = (ngx_threadpool_t *)arg;
    die_on_amqp_error(amqp_channel_close(pool->m_Mqconn, 1, AMQP_REPLY_SUCCESS), "Closing channel");
    die_on_amqp_error(amqp_connection_close(pool->m_Mqconn, AMQP_REPLY_SUCCESS), "Closing connection");
    die_on_error(amqp_destroy_connection(pool->m_Mqconn), "Ending connection");
}
*/

ngx_mythreadpool_t* ngx_mythreadpool_init(unsigned int init_num)
{
    printf("enter ngx_mythreadpool_init\n");
    ngx_mythreadpool_t *pool = NULL;

    do {
        pool = (ngx_mythreadpool_t *)malloc(sizeof(ngx_mythreadpool_t));
		if (pool == NULL){
			break;
		}

        TAILQ_INIT(&pool->m_TaskQueue);
        TAILQ_INIT(&pool->m_BlackQueue);

		pool->m_InitThreadNum = init_num;
        if (z_threadpool_mutex_init(&pool->g_Mutex) != 0) { 
			free(pool);
			break;
		}

        /*
        if (z_threadpool_mutex_init(&pool->m_NlistMutex) != 0) { 
			free(pool);
			break;
		}
        if (z_threadpool_mutex_init(&pool->m_Mutex) != 0) { 
			free(pool);
			break;
		}

        if (z_threadpool_mutex_init(&pool->m_BlackMutex) != 0) { 
			z_thread_mutex_destroy(&pool->m_Mutex);
			free(pool);
			break;
		}
        */

        if (z_threadpool_cond_init(&pool->m_Cond) != 0) { 
			//z_thread_mutex_destroy(&pool->m_NlistMutex);
			//z_thread_mutex_destroy(&pool->m_Mutex);
			//z_thread_mutex_destroy(&pool->m_BlackMutex);
			free(pool);
			break;
		}
        if (z_mythreadpool_create(pool) != 0){   
			//z_thread_mutex_destroy(&pool->m_NlistMutex);
			//z_thread_mutex_destroy(&pool->m_Mutex);
			//z_thread_mutex_destroy(&pool->m_BlackMutex);
			z_thread_cond_destroy(&pool->m_Cond);
			free(pool);
			break;
		}
        return pool;
    } while(0);

    return NULL;
}

/*
ngx_threadpool_t* ngx_threadpool_init(ngx_threadpool_conf_t *conf)
{
	ngx_threadpool_t *pool = NULL;
	//int error_flag_mutex = 0;
	//int error_flag_cond = 0;
	//pthread_attr_t attr;
	do{
		if (z_conf_check(conf) == -1){ //检查参数是否合法
			break;
		}

		pool = (ngx_threadpool_t *)malloc(sizeof(ngx_threadpool_t));//申请线程池句柄
		if (pool == NULL){
			break;
		}

        TAILQ_INIT(&pool->m_TaskQueue);
        TAILQ_INIT(&pool->m_BlackQueue);

		pool->m_InitThreadNum = conf->m_ThreadNum;
		pool->m_Thread_Stack_Size = conf->m_Thread_Stack_Size;
		pool->m_MaxTaskNum = conf->m_MaxTaskNum;
		pool->m_CurTaskNum = 0;

        //ngx_rabbitmq_init(pool);

	
		if (z_thread_key_create() != 0){//创建一个pthread_key_t，用以访问线程全局变量。
			free(pool);
			break;
		}
		if (z_threadpool_mutex_init(&pool->m_Mutex) != 0) { //初始化互斥锁
			z_thread_key_destroy();
			free(pool);
			break;
		}
        if (z_threadpool_mutex_init(&pool->m_BlackMutex) != 0) { //初始化互斥锁
			z_thread_key_destroy();
			free(pool);
			break;
		}
		if (z_threadpool_cond_init(&pool->m_Cond) != 0) {  //初始化条件锁
			z_thread_key_destroy();
			z_thread_mutex_destroy(&pool->m_Mutex);
			free(pool);
			break;
		}

        printf("ready create thread\n");
		if (z_threadpool_create(pool) != 0){       //创建线程池
			z_thread_key_destroy();
			z_thread_mutex_destroy(&pool->m_Mutex);
			z_thread_cond_destroy(&pool->m_Cond);
			free(pool);
			break;
		}
		return pool;
	}while(0);

	return NULL;
}

int ngx_threadpool_add_task(ngx_threadpool_t *pool, ngx_task_t *task)
{
    printf("enter ngx_threadpool_add_task\n");
	if (pthread_mutex_lock(&pool->m_Mutex) != 0){ //加锁
		free(task);
		return -1;
	}

	do{
		if (pool->m_CurTaskNum >= pool->m_MaxTaskNum){//判断工作队列中的任务数是否达到限制
			break;
		}
        TAILQ_INSERT_HEAD(&pool->m_TaskQueue, task, m_TaskNext);
        pool->m_CurTaskNum++;

		if (pthread_cond_signal(&pool->m_Cond) != 0){
			break;
		}
		pthread_mutex_unlock(&pool->m_Mutex);
		return 0;

	}while(0);
	pthread_mutex_unlock(&pool->m_Mutex);
	free(task);
	return -1;

}
*/

/*
void ngx_threadpool_destroy(ngx_threadpool_t *pool)
{
	unsigned int n = 0;
	volatile unsigned int  lock;

	//z_threadpool_exit_cb函数会使对应线程退出
	for (; n < pool->m_InitThreadNum; n++){
		lock = 1;
        ngx_task_t *task = NULL;
        task = (ngx_task_t*)malloc(sizeof(ngx_task_t));
        task->argv = (void*)&lock;
        task->handler = z_threadpool_exit_cb;
        memset(task->m_TaskBuf, '\0', MAX_TASKBUF_SIZE);

		if (ngx_threadpool_add_task(pool, task) != 0){
			return;
		}
		while (lock){
			usleep(1);
		}
	}
	z_thread_mutex_destroy(&pool->m_Mutex);
	z_thread_mutex_destroy(&pool->m_BlackMutex);
	z_thread_cond_destroy(&pool->m_Cond);
	z_thread_key_destroy();
	free(pool);
}
*/

/*
int ngx_thread_add(ngx_threadpool_t *pool, unsigned int num)
{
	int ret = 0;
	if (pthread_mutex_lock(&pool->m_Mutex) != 0){
		return -1;
	}
	ret = z_thread_add(pool, num);
	pthread_mutex_unlock(&pool->m_Mutex);
	return ret;
}

int ngx_set_max_tasknum(ngx_threadpool_t *pool,unsigned int num)
{
	if (pthread_mutex_lock(&pool->m_Mutex) != 0){
		return -1;
	}
	z_change_maxtask_num(pool, num);  //改变最大任务限制
	pthread_mutex_unlock(&pool->m_Mutex);
    return 0;
}
*/

/*
void ngx_http_myproxy_sig_handler(int sig)
{
    int save_errno = errno;
    int msg = sig;
    send(sig_pipefd[1], (char*)&msg, 1, 0);
    errno = save_errno;
}
*/

int ngx_http_myproxy_set_fd_attr(int fd, int attr)
{
    int old_option, new_option;
    old_option = fcntl(fd, F_GETFL);
    new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}

void ngx_http_myproxy_add_epoll_fd(int epollfd, int fd)
{
    struct epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
    ngx_http_myproxy_set_fd_attr(fd, 0);
}

void ngx_http_myproxy_delete_epoll_fd(int epollfd, int fd)
{
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, 0);
}

void ngx_http_myproxy_mod_epoll_fd(int epollfd, int fd, int ev)
{
    struct epoll_event event;
    event.data.fd = fd;
    event.events = ev | EPOLLET;
    //event.events = ev | EPOLLET | EPOLLONESHOT | EPOLLRDHUP;
    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
}

void ngx_close_mysocket_fd(int fd, ngx_log_t *log)
{
    if (close(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "close() mysocket fd failed");
    }
}

/*
ngx_int_t 
ngx_http_myproxy_create_pidfile(ngx_str_t *name, ngx_log_t *log)
{
    size_t len;
    ngx_uint_t create;
    ngx_file_t file;
    u_char pid[NGX_INT64_LEN + 2];
    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = *name;
    file.log = log;
    create = NGX_FILE_TRUNCATE;
    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDWR, create, NGX_FILE_DEFAULT_ACCESS);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, ngx_open_file_n " \"%s\" failed", file.name.data);
        return NGX_ERROR;
    }
    len = ngx_snprintf(pid, NGX_INT64_LEN + 2, "%P%N", ngx_mypid) - pid;
    if (ngx_write_file(&file, pid, len, 0) == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, ngx_close_file_n " \"%s\" failed", file.name.data);
    }

    return NGX_OK;
}
*/

/*
ngx_int_t 
ngx_http_myproxy_create_aliveflagfile(ngx_str_t *name, ngx_log_t *log)
{
    size_t len;
    ngx_uint_t create;
    ngx_file_t file;
    u_char sflag[NGX_INT64_LEN + 2];
    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = *name;
    file.log = log;
    create = NGX_FILE_TRUNCATE;
    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDWR, create, NGX_FILE_DEFAULT_ACCESS);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, ngx_open_file_n " \"%s\" failed", file.name.data);
        return NGX_ERROR;
    }
    len = ngx_snprintf(sflag, NGX_INT64_LEN + 2, "%P%N", 12345) - sflag;
    if (ngx_write_file(&file, sflag, len, 0) == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, ngx_close_file_n " \"%s\" failed", file.name.data);
    }

    return NGX_OK;
}
*/

/*
ngx_int_t 
ngx_http_myproxy_select_listen(ngx_fd_t fd, ngx_log_t *log)
{
    struct timeval tm;
    int len, err = -1;
    tm.tv_sec = 3;  
    tm.tv_usec = 0;  
    fd_set wset;
    FD_ZERO(&wset);  
    FD_SET(fd, &wset);  
    int retval = select(fd + 1, NULL, &wset, NULL, &tm);  
    switch(retval)  
    {  
        case -1:  
        {
            //perror("select");  
            ngx_log_error(NGX_LOG_ERR, log, 0,
                        "my worker process select fail");
            return NGX_ERROR;  
        }
        case 0:  
        {
            //printf("connect timeout\n");  
            ngx_log_error(NGX_LOG_ERR, log, 0,
                        "my worker process select connect timeout");
            return NGX_ERROR;  
        }
        case 1:
        {
            if(FD_ISSET(fd, &wset))  
            {  
                ngx_log_error(NGX_LOG_ERR, log, 0,
                        "build connect successfully!");
                //printf("build connect successfully!\n");
            }
            break;
        }
        default:  
        {
            if(FD_ISSET(fd, &wset))  
            {  
                if(getsockopt(fd,SOL_SOCKET,SO_ERROR, &err, (socklen_t *)&len) < 0)  
                {  
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                        "getsockopt error1");
                    return NGX_ERROR;  
                }  
                if(err != 0)  
                {  
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                        "getsockopt error2");
                    return NGX_ERROR;  
                }  
            }
            break;  
        }
    }
    return NGX_OK;
}
*/

/*
void *ngx_add_blacklist_queue_handler(void *arg)
{
    ngx_task_t *task = (ngx_task_t *)arg;
    ngx_threadpool_t *pool = (ngx_threadpool_t *)(task->argv);
    ngx_black_t *btask = (ngx_black_t *)malloc(sizeof(ngx_black_t));
    memset(btask->m_Cookie, '\0', MAX_TASKBUF_SIZE);
    memcpy(btask->m_Cookie, task->m_TaskBuf, strlen(task->m_TaskBuf));

	if (pthread_mutex_lock(&pool->m_BlackMutex) != 0){ //加锁
        return NULL;
    }
    TAILQ_INSERT_HEAD(&pool->m_BlackQueue, btask, m_BlackNext);
    pthread_mutex_unlock(&pool->m_BlackMutex);
    return NULL;
}
*/

/*
void *ngx_del_blacklist_queue_handler(void *arg)
{ 
    ngx_task_t *task = (ngx_task_t *)arg;
    ngx_threadpool_t *pool = (ngx_threadpool_t *)(task->argv);
	if (pthread_mutex_lock(&pool->m_BlackMutex) != 0){ //加锁
        return NULL;
    }
    if (TAILQ_EMPTY(&pool->m_BlackQueue)) {
        return NULL;
    }
    ngx_black_t *it = NULL;
    TAILQ_FOREACH(it, &pool->m_BlackQueue, m_BlackNext) {
        if (strcmp(it->m_Cookie, task->m_TaskBuf) == 0)
            break;
    }
    if (it == TAILQ_END(&pool->m_BlackQueue)) {
        pthread_mutex_unlock(&pool->m_BlackMutex);
        return NULL;
    }
    TAILQ_REMOVE(&pool->m_BlackQueue, it, m_BlackNext);
    free(it);
    it = NULL;
    pthread_mutex_unlock(&pool->m_BlackMutex);
    return NULL;
}
*/

/*
void *ngx_send_data_via_mq_handler(void *arg)
{
    printf("enter ngx_send_data_via_mq_handler\n");
    ngx_task_t *task = (ngx_task_t *)arg;
    //ngx_threadpool_t *pool = (ngx_threadpool_t *)(task->argv);
    size_t cookie_len;
    unsigned int off_x = 0;
    char cookie[2048] = {0};
    time_t tm;
    size_t url_len, ip_len, method_len, protocol_len, cookie_len;
    unsigned short port;
    unsigned int off_x = 0;
    char url[1024], ip[50] , method[10], protocol[10], cookie[2048];
    memcpy(&tm, task->m_TaskBuf + off_x, sizeof(time_t));
    off_x += sizeof(time_t);
    memcpy(&url_len, task->m_TaskBuf + off_x, sizeof(size_t));
    off_x += sizeof(size_t);
    memcpy(url, task->m_TaskBuf + off_x, url_len);
    off_x += url_len;
    memcpy(&ip_len, task->m_TaskBuf + off_x, sizeof(size_t));
    off_x += sizeof(size_t);
    memcpy(ip, task->m_TaskBuf + off_x, ip_len);
    off_x += ip_len;
    memcpy(&port, task->m_TaskBuf + off_x, sizeof(unsigned short));
    off_x += sizeof(unsigned int);
    memcpy(&method_len, task->m_TaskBuf + off_x, sizeof(size_t));
    off_x += sizeof(size_t);
    memcpy(method, task->m_TaskBuf + off_x, method_len);
    off_x += method_len;
    memcpy(&protocol_len, task->m_TaskBuf + off_x, sizeof(size_t));
    off_x += sizeof(size_t);
    memcpy(protocol, task->m_TaskBuf + off_x, protocol_len);
    off_x += protocol_len;
    memcpy(&cookie_len, task->m_TaskBuf + off_x, sizeof(size_t));
    off_x += sizeof(size_t);
    memcpy(cookie, task->m_TaskBuf + off_x, cookie_len);
    off_x += cookie_len;
    printf("1 ngx_send_data_via_mq_handler\n");

    char *str_out = NULL;
    cJSON *usr = cJSON_CreateObject();
    cJSON_AddNumberToObject(usr, "time", tm);
    cJSON_AddStringToObject(usr, "url", url);
    cJSON_AddStringToObject(usr, "ip", ip);
    cJSON_AddNumberToObject(usr, "port", port);
    cJSON_AddStringToObject(usr, "method", method);
    cJSON_AddStringToObject(usr, "protocol", protocol);
    cJSON_AddStringToObject(usr, "cookie", cookie);
    str_out = cJSON_Print(usr);
    printf("json:%s\n", str_out);

    die_on_error(amqp_basic_publish(pool->m_Mqconn, 1, amqp_cstring_bytes("ip-change"), amqp_cstring_bytes("ip_msg"), 
                                    0, 0,&(pool->m_Mqprops), amqp_cstring_bytes(str_out)),
                "Publishing");
    printf("amqp_basic_publish\n");

    return NULL;
}
*/

/*
ngx_socket_t ngx_http_myproxy_start_socket()
{
    ngx_socket_t ngx_listenfd = socket( PF_INET, SOCK_STREAM, 0 );
    assert( ngx_listenfd >= 0 );
    struct linger tmp = { 1, 0 };
    setsockopt(ngx_listenfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof(tmp));

    int reuse = 1;
    setsockopt(ngx_listenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    ngx_int_t ret = 0;
    in_port_t port = 12345;
    struct sockaddr_in address;
    //bzero( &address, sizeof( address ) );
    memset( &address, 0, sizeof( address ) );
    address.sin_family = AF_INET;
    //inet_pton( AF_INET, local_ip, &address.sin_addr );
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons( port );

    ret = bind( ngx_listenfd, ( struct sockaddr* )&address, sizeof( address ) );
    assert( ret >= 0 );

    ret = listen( ngx_listenfd, 5 );
    assert( ret >= 0 );
    printf("socket fd:%d\n", ngx_listenfd);
    return ngx_listenfd;
}
*/

/*
myproxy_workthread_t* GetIdleWorkThread(ngx_threadpool_t *pool, ngx_task_t *task) 
{
    while (TAILQ_EMPTY(&pool->m_Thread_IdleQueue))
        pthread_cond_wait(&pool->m_IdleCond, &pool->m_IdleMutex);
    pthread_mutex_lock(&pool->m_IdleMutex);
    if (TAILQ_EMPTY(&pool->m_Thread_IdleQueue)) {
        pthread_mutex_unlock(&pool->m_IdleMutex);
        return NULL;
    }

    myproxy_workthread_t *_workthr = TAILQ_FIRST(&pool->m_Thread_IdleQueue);
    TAILQ_REMOVE(&pool->m_Thread_IdleQueue, _workthr, m_WorkThread);
    pool->m_IdleThreadNum--;
    printf("idle thread num:%d\n", pool->m_IdleThreadNum);
    pthread_mutex_unlock(&pool->m_IdleMutex);

    _workthr->m_State = 2; 
    _workthr->m_Task = task;
    pthread_mutex_lock(&pool->m_BusyMutex);
    TAILQ_INSERT_HEAD(&pool->m_Thread_BusyQueue, _workthr, m_WorkThread);
    pool->m_BusyThreadNum++;
    printf("busy thread num:%d\n", pool->m_BusyThreadNum);
    pthread_mutex_unlock(&pool->m_BusyMutex);

    return _workthr;
}
*/

