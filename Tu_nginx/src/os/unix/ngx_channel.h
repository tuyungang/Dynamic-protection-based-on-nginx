
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/*add by tu*/
typedef struct {
    ngx_uint_t command;
    ngx_str_t  sessionid;
}ngx_mychannel_t;

//packet header
typedef struct packet_header
{
    int command;
    int action;
    int check;    //not use
    int pkgSize;
    int pkgTag;   //not use
}PKG_HEAD_STRUCT, *PPKG_HEAD_STRUCT;

//packet body
typedef struct packet_body
{
    char data[1];
}PKG_BODY_STRUCT, *PPKG_BODY_STRUCT;

/*add by tu*/



typedef struct {
    ngx_uint_t  command;
    ngx_pid_t   pid;
    ngx_int_t   slot;
    ngx_fd_t    fd;
} ngx_channel_t;


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);


#endif /* _NGX_CHANNEL_H_INCLUDED_ */
