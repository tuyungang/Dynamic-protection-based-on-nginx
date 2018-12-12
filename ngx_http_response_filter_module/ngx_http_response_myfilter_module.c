#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include "TBase64_code.h"

#if (NGX_DEBUG)
#define HT_HEADF_DEBUG 1
#else
#define HT_HEADF_DEBUG 0
#endif

#define ngx_buffer_init(b) b->pos = b->last = b->start;

static ngx_str_t u_key[] = 
{
    ngx_string("href="),
    ngx_string("src="),
    ngx_string("action=")
    //ngx_string("background:url("),
    //ngx_string("background: url("),
    //ngx_string("background-image:url")
};

typedef struct {
    ngx_flag_t     once;
    ngx_flag_t     regex;
    ngx_flag_t     insensitive;

    /* If it has captured variables? */
    ngx_flag_t     has_captured;

    ngx_str_t      match;
    ngx_array_t   *match_lengths;
    ngx_array_t   *match_values;
#if (NGX_PCRE)
    ngx_regex_t   *match_regex;
    int           *captures;
    ngx_int_t      ncaptures;
#endif

    ngx_str_t      sub;
    ngx_array_t   *sub_lengths;
    ngx_array_t   *sub_values;

    ngx_str_t     ukey;
    ngx_array_t   *ukey_lengths;
    ngx_array_t   *ukey_values;
    
    unsigned       matched;
} sub_pair_t;

typedef struct{
    ngx_array_t *sub_pairs;
    size_t line_buffer_size;
    ngx_bufs_t bufs;
}ngx_http_myfilter_conf_t;

typedef struct{
    ngx_int_t add_prefix;
    ngx_array_t *sub_pairs;
    ngx_chain_t  *in;
    ngx_buf_t *line_in;
    ngx_buf_t *line_dst;
    ngx_buf_t *out_buf;
    ngx_chain_t **last_out;
    ngx_chain_t *out;
    ngx_chain_t *busy;
    ngx_chain_t *free;
    ngx_int_t bufs;
    ngx_uint_t last;
}ngx_http_myfilter_ctx_t;

static void *ngx_http_myfilter_create_conf(ngx_conf_t *cf);
static char *ngx_http_myfilter_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_myfilter_init(ngx_conf_t *cf);
//static ngx_str_t filter_prefix = ngx_string("[my filter prefix]");
static ngx_int_t ngx_http_myfilter_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_myfilter_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_test_content_type(ngx_http_request_t *r);
static ngx_int_t ngx_test_content_compression(ngx_http_request_t *r);
//static ngx_int_t ngx_http_myfilter_body_process_buffer(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_int_t ngx_http_myfilter_body_filter_process_buffer(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_int_t ngx_http_myfilter_output(ngx_http_request_t *r, ngx_http_myfilter_ctx_t *ctx, ngx_chain_t *in);
static char* ngx_http_myfilter_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_myfilter_match(ngx_http_request_t *r, ngx_http_myfilter_ctx_t *b);
static ngx_int_t ngx_http_myfilter_match_fix_url(ngx_http_request_t *r, sub_pair_t *pair, ngx_buf_t *b, ngx_buf_t *dst);
static ngx_buf_t *buffer_append_string(ngx_buf_t *b, u_char *s, size_t len, ngx_pool_t *pool);
static ngx_int_t ngx_http_subs_out_chain_append(ngx_http_request_t *r, ngx_http_myfilter_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_subs_get_chain_buf(ngx_http_request_t *r, ngx_http_myfilter_ctx_t *ctx);
//static void *subs_memmem(const void *l, size_t l_len, const void *s, size_t s_len);
static ngx_int_t ngx_http_myfilter_url_encrypt(ngx_http_request_t *r, u_char *url_in, size_t url_in_len, u_char *url_out, size_t *url_out_len);

static ngx_command_t ngx_http_myfilter_commands[] = {
    { 
        ngx_string("myfilter_init"),
        //NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_myfilter_filter,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL 
    },

    { 
        ngx_string("myfilter_line_buffer_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myfilter_conf_t, line_buffer_size),
        NULL 
    },

    { 
        ngx_string("myfilter_buffers"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_bufs_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myfilter_conf_t, bufs),
        NULL 
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_myfilter_module_ctx = {
    NULL,
    ngx_http_myfilter_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_myfilter_create_conf,
    ngx_http_myfilter_merge_conf
};

ngx_module_t ngx_http_myfilter_module = {
    NGX_MODULE_V1,
    &ngx_http_myfilter_module_ctx,
    ngx_http_myfilter_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING       
};
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static char* ngx_http_myfilter_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_uint_t i;
    sub_pair_t *pair;
    ngx_http_myfilter_conf_t *myconf = conf;
    
    if (myconf->sub_pairs == NULL) {
        myconf->sub_pairs = ngx_array_create(cf->pool, 4, sizeof(sub_pair_t));
        if (myconf->sub_pairs == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    pair = ngx_array_push_n(myconf->sub_pairs, 3);
    if (pair == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(pair, 3 * sizeof(sub_pair_t));
    for (i = 0; i < 3; i++) {
        pair[i].ukey = u_key[i];
        //pair[i].ukey.data = ukey[i];
        //pair[i].ukey.len = ngx_strlen(ukey[i]);
    }
    

    return NGX_CONF_OK;
}

static void *ngx_http_myfilter_create_conf(ngx_conf_t *cf)
{
    ngx_http_myfilter_conf_t *mycf;
    mycf = (ngx_http_myfilter_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_myfilter_conf_t));
    if(mycf == NULL){
        return NULL;
    }
    mycf->line_buffer_size = NGX_CONF_UNSET_SIZE;
    return mycf;
}


static char *ngx_http_myfilter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_myfilter_conf_t *prev = (ngx_http_myfilter_conf_t *)parent;
    ngx_http_myfilter_conf_t *conf = (ngx_http_myfilter_conf_t *)child;

    if (conf->sub_pairs == NULL) {
        if (prev->sub_pairs == NULL) {
            conf->sub_pairs = ngx_array_create(cf->pool, sizeof(u_key) + 1, sizeof(sub_pair_t));
            if (conf->sub_pairs == NULL) {
                return NGX_CONF_ERROR;
            }
        } else {
            conf->sub_pairs = prev->sub_pairs;
        }
    }

    ngx_conf_merge_size_value(conf->line_buffer_size, prev->line_buffer_size, 8 * ngx_pagesize);
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, (128 * 1024) / ngx_pagesize, ngx_pagesize);

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_myfilter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_myfilter_header_filter;
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_myfilter_body_filter;
    return NGX_OK;
}

static ngx_int_t ngx_http_myfilter_header_filter(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[myfilter]: first");

    ngx_uint_t i;
    ngx_uint_t status;
    sub_pair_t *src_pair, *dst_pair;
    ngx_http_myfilter_ctx_t *ctx;
    ngx_http_myfilter_conf_t *conf;
    //ngx_http_core_loc_conf_t *clcf;
    //ngx_http_core_srv_conf_t *cscf;

    /*
    if (r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[myfilter]: http response is not 200");
        return ngx_http_next_header_filter(r);
    }
    */

    if (r->header_sent) {
        return ngx_http_next_header_filter(r);
    }
    if (r->http_version < NGX_HTTP_VERSION_10) {
        return ngx_http_next_header_filter(r);
    }
    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }
    status = r->headers_out.status;
    //clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (status == NGX_HTTP_MOVED_TEMPORARILY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[myfilter]: http response is 302");
        if (r->headers_out.location
                /*&& r->headers_out.location->value.len
                && r->headers_out.location->value.data[0] == '/'
                && clcf->absolute_redirect*/) {

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[myfilter]: another 302 location");

        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[myfilter]: 302 location none");
            /*
            ngx_str_null(&(r->headers_out.location->value));
            ngx_memcpy(r->headers_out.location->value.data, "https://www.baidu.com", ngx_strlen("https://www.baidu.com"));
            r->headers_out.location->value.len = ngx_strlen("https://www.baidu.com");
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[myfilter]: 302 location none end");
            */
        }
        /*
        ngx_list_part_t *part = &r->headers_out.headers.part;
        ngx_table_elt_t *header = part->elts;
        for ( ;; ) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                header = part->elts;
                i = 0;
            }
            if (header[i].hash == 0) {
                continue;
            }
            if (ngx_strncasecmp(header[i].key.data, (u_char *) "Content-Length", ngx_strlen("Content-Length")) == 0) {
                ngx_int_t length = ngx_atoi(header[i].value.data, header[i].value.len);
                ngx_memzero(header[i].value.data, header[i].value.len);
                ngx_memcpy(header[i].value.data, "www.baidu.com", ngx_strlen("www.baidu.com"));
                header[i].value.len = ngx_strlen("www.baidu.com");
                r->headers_out.content_length_n = length;
                break;
            }
        }
        */
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[myfilter]: http response is not 200");
        return ngx_http_next_header_filter(r);
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[myfilter]: http response is 200");

    conf = ngx_http_get_module_loc_conf(r, ngx_http_myfilter_module);
    if (conf == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[myfilter]: ngx_http_get_module_loc_conf error.");
        return ngx_http_next_header_filter(r);
    }

    if (conf->sub_pairs->nelts == 0
            || r->header_only
            || r->headers_out.content_type.len == 0
            || r->headers_out.content_length_n == 0) {

        #if HT_HEADF_DEBUG
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[myfilter]: empty content type or header only ");
        #endif

        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_myfilter_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"[Html_head filter]: cannot allocate ctx memory");
        return ngx_http_next_header_filter(r);
    }
    ctx->add_prefix = 0;
    ngx_http_set_ctx(r, ctx, ngx_http_myfilter_module);

    ctx->sub_pairs = ngx_array_create(r->pool, conf->sub_pairs->nelts, sizeof(sub_pair_t));
    if (conf->sub_pairs == NULL) {
        return NGX_ERROR;
    }

    src_pair = (sub_pair_t *)conf->sub_pairs->elts;
    for (i = 0; i < conf->sub_pairs->nelts; i++) {
        dst_pair = ngx_array_push(ctx->sub_pairs);
        if (dst_pair == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(dst_pair, src_pair + i, sizeof(sub_pair_t));
    }

    if (ctx->line_in == NULL) {
        ctx->line_in = ngx_create_temp_buf(r->pool, conf->line_buffer_size);
        if (ctx->line_in == NULL) {
            return NGX_ERROR;
        }
    }
    if (ctx->line_dst == NULL) {
        ctx->line_dst = ngx_create_temp_buf(r->pool, conf->line_buffer_size);
        if (ctx->line_dst == NULL) {
            return NGX_ERROR;
        }
    }

    if (ngx_test_content_type(r) == 0) {
        #if HT_HEADF_DEBUG
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[myfilter]: content type not html");
        #endif            
        
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_length_n > 0) {
        ctx->add_prefix = 1;
    }

    if (ngx_test_content_compression(r) != 0) {
        //Compression enabled, don't filter   
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[myfilter]: compression enabled");
        return ngx_http_next_header_filter(r);
    }

    r->filter_need_in_memory = 1;
    if (r == r->main) {
        ngx_http_clear_content_length(r);
        //ngx_http_clear_accept_ranges(r);
        ngx_http_clear_last_modified(r);
    }

    //return NGX_OK;
    return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_myfilter_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t *cl, *temp;
    ngx_int_t rc;
    ngx_log_t *log;
    ngx_http_myfilter_ctx_t *ctx;
    ngx_http_myfilter_conf_t *conf;

    log = r->connection->log;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_myfilter_module);
    if (conf == NULL) {
#if HT_HEADF_DEBUG
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[myfilter]: configuration");
#endif
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_myfilter_module);
    if (ctx == NULL || ctx->add_prefix != 1) {
#if HT_HEADF_DEBUG
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[myfilter]: already add prefix");
#endif
        return ngx_http_next_body_filter(r, in);
    }
    
    r->connection->buffered |= NGX_HTTP_SUB_BUFFERED;
    ctx->in = NULL;

    if (in == NULL) {
#if HT_HEADF_DEBUG
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[myfilter]: input chain is null");
#endif
        return ngx_http_next_body_filter(r, in);
    }

    ctx->add_prefix = 2;

    if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[myfilter]: unable to copy"
            " input chain - in");
         
        //return NGX_ERROR;
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->in == NULL) {
        //return NGX_ERROR;
        return ngx_http_next_body_filter(r, in);
    }
    ctx->last_out = &ctx->out;
    ctx->out_buf = NULL;

    for (cl = ctx->in; cl; cl = cl->next) {
        if (cl->buf->last_buf || cl->buf->last_in_chain) {
            ctx->last = 1;
        }
        //rc = ngx_http_myfilter_body_process_buffer(r, cl->buf);
        rc = ngx_http_myfilter_body_filter_process_buffer(r, cl->buf);
        if (rc == NGX_DECLINED) {
            continue;
        } else if (rc == NGX_ERROR) {
            goto failed;
        }
        if (cl->next != NULL) {
            continue;
        }
        ctx->last = 1;
        if (ctx->last) {
            if (ngx_buf_size(ctx->line_in) > 0) {
                if (ngx_http_subs_out_chain_append(r, ctx, ctx->line_in) != NGX_OK) {
                    goto failed;
                }
            }
            if (ctx->out_buf == NULL) {
                ctx->out_buf = ngx_calloc_buf(r->pool);
                if (ctx->out_buf == NULL) {
                    goto failed;
                }
                ctx->out_buf->sync = 1;
                temp = ngx_alloc_chain_link(r->pool);
                if (temp == NULL) {
                    goto failed;
                }
                temp->buf = ctx->out_buf;
                temp->next = NULL;
                *ctx->last_out = temp;
                ctx->last_out = &temp->next;

            }

            ctx->out_buf->last_buf = (r == r->main) ? 1 : 0;
            ctx->out_buf->last_in_chain = cl->buf->last_in_chain;

            break;
        }
    }

    if ((ctx->out == NULL) && (ctx->busy == NULL)) {
        return NGX_OK;
    }

    //return ngx_http_next_body_filter(r, cl);
    return ngx_http_myfilter_output(r, ctx, in);

failed:

    ngx_log_error(NGX_LOG_ERR, log, 0, 
            "[myfilter]: ngx_http_myfilter_body_filter error.");
    return NGX_ERROR;
}

static ngx_int_t ngx_http_subs_out_chain_append(ngx_http_request_t *r, ngx_http_myfilter_ctx_t *ctx, ngx_buf_t *b)
{
    size_t len, capcity;
    
    if (b == NULL || ngx_buf_size(b) == 0) {
        return NGX_OK;
    }
    if (ctx->out_buf == NULL) {
        if (ngx_http_subs_get_chain_buf(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    while (1) {
        len = (size_t)ngx_buf_size(b);
        if (len == 0) {
            break;
        }
        capcity = ctx->out_buf->end - ctx->out_buf->last;
        if (len <= capcity) {
            ctx->out_buf->last = ngx_copy(ctx->out_buf->last, b->pos,len);
            b->pos += len;
            break;
        } else {
            ctx->out_buf->last = ngx_copy(ctx->out_buf->last, b->pos, capcity);
        } 
        b->pos += capcity;
        if (ngx_http_subs_get_chain_buf(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

    }
    return NGX_OK;
}
static ngx_int_t ngx_http_subs_get_chain_buf(ngx_http_request_t *r, ngx_http_myfilter_ctx_t *ctx)
{
    ngx_chain_t *temp;
    ngx_http_myfilter_conf_t *slcf;
    
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_myfilter_module);
    if (ctx->free) {
        temp = ctx->free;
        ctx->free = ctx->free->next;

    } else {
        temp = ngx_alloc_chain_link(r->pool);
        if (temp == NULL) {
            return NGX_ERROR;
        }
        temp->buf = ngx_create_temp_buf(r->pool, slcf->bufs.size);
        if (temp->buf == NULL) {
            return NGX_ERROR;
        }
        temp->buf->tag = (ngx_buf_tag_t)&ngx_http_myfilter_module;
        temp->buf->recycled = 1;
        ctx->bufs++;
    }
    temp->next = NULL;
    ctx->out_buf = temp->buf;
    *ctx->last_out = temp;
    ctx->last_out = &temp->next;

    return NGX_OK;

}

static ngx_int_t ngx_http_myfilter_output(ngx_http_request_t *r, ngx_http_myfilter_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_int_t rc;
    rc = ngx_http_next_body_filter(r, ctx->out);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

#if defined(nginx_version) && (nginx_version >= 1001004)
    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out, (ngx_buf_tag_t)&ngx_http_myfilter_module);

#else
    ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out, (ngx_buf_tag_t)&ngx_http_myfilter_module);

#endif

    if (ctx->last) {
        r->connection->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}

static ngx_int_t ngx_test_content_type(ngx_http_request_t *r)
{
    ngx_str_t tmp;

    if(r->headers_out.content_type.len == 0)
    {
        return 0;
    } 

    tmp.len = r->headers_out.content_type.len;
    tmp.data = ngx_pcalloc(r->pool, sizeof(u_char) * tmp.len ); 

    if(tmp.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[myfilter]: ngx_test_content_type "
            "cannot allocate buffer for content type check");
        return 0;
    }

    ngx_strlow(tmp.data, r->headers_out.content_type.data, tmp.len); 

    if(ngx_strnstr(tmp.data, "text/html", 
                  r->headers_out.content_type.len) != NULL)
    {
        return 1;
    }

   if(ngx_strnstr(tmp.data, "text/plain", 
                  r->headers_out.content_type.len) != NULL)
    {
        return 1;
    }

    return 0; 
}

static ngx_int_t
ngx_test_content_compression(ngx_http_request_t *r)
{
    ngx_str_t tmp;
    
    if(r->headers_out.content_encoding == NULL)
    {//Cannot determine encoding, assume no compression
        return 0; 
    }

    if(r->headers_out.content_encoding->value.len == 0 )
    {
        return 0; 
    }

    tmp.len = r->headers_out.content_encoding->value.len;
    tmp.data = ngx_pcalloc(r->pool, sizeof(u_char) * tmp.len );

    if(tmp.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "[myfilter]: ngx_test_content_compression"
            " cannot allocate buffer for compression check");
            
        return 0;
    }

    ngx_strlow(tmp.data, 
               r->headers_out.content_encoding->value.data, tmp.len); 


    
    if( tmp.len >= (sizeof("gzip") -1) && 
        ngx_strncmp(tmp.data, (u_char*)"gzip" , tmp.len) == 0 )
    {
        return 1; 
    }
    
    if( tmp.len >= (sizeof("deflate") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"deflate" , tmp.len) == 0 )
    {
        return 1; 
    }
    
    if( tmp.len >= (sizeof("compress") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"compress" , tmp.len) == 0 )
    {
        return 1; 
    }
    
   
    if( tmp.len >= (sizeof("br") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"br" , tmp.len) == 0 )
    {
        return 1; 
    }
        
    //Fail safe to false if compression cannot be determined
    return 0; 
}
static ngx_buf_t *buffer_append_string(ngx_buf_t *b, u_char *s, size_t len, ngx_pool_t *pool)
{
    u_char *p;
    ngx_uint_t capacity, size;

    if (len > (size_t)(b->end - b->last)) {
        size = b->last - b->pos;
        capacity = b->end - b->start;
        capacity <<= 1;

        if (capacity < (size + len)) {
            capacity = size + len;
        }
        p = ngx_palloc(pool, capacity);
        if (p == NULL) {
            return NULL;
        }
        b->last = ngx_copy(p, b->pos, size);
        b->start = b->pos = p;
        b->end = p + capacity;
    }
    b->last = ngx_copy(b->last, s, len);
    return b;
}

/*
static void *subs_memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
    register char *cur, *last;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;

    if (l_len == 0 || s_len == 0) {
        return NULL;
    }

    if (l_len < s_len) {
        return NULL;
    }

    if (s_len == 1) {
        return memchr(l, (int)*cs, l_len);
    }

    last = (char *)cl + l_len - s_len;

    for (cur = (char *)cl; cur <= last; cur++) {
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0) {
            return cur;
        }
    }

    return NULL;
}
*/

static ngx_int_t ngx_http_myfilter_url_encrypt(ngx_http_request_t *r, u_char *url_in, size_t url_in_len, u_char *url_out, size_t *url_out_len)
{
    ngx_int_t rc;

    rc = base64_encode((char*)url_in, (int)url_in_len, (char*)url_out, (int*)url_out_len);
    if (rc != 0) {
        return NGX_ERROR;
    }
    *url_out_len = url_in_len;

    /*
    u_char url_key[20];
    memset(url_key, '\0', 20);
    ngx_memcpy(url_key, r->connection->addr_text.data, r->connection->addr_text.len);
    */
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[myfilter ip]");
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, (char*)r->connection->addr_text.data);

    return NGX_OK;
}

static ngx_int_t ngx_http_myfilter_match_fix_url(ngx_http_request_t *r, sub_pair_t *pair, ngx_buf_t *b, ngx_buf_t *dst)
{
    ngx_file_t myfile;
    u_char *sub_start;
    ngx_int_t rc, count = 0;
    u_char mybuf[50] = {0};

    while (b->pos < b->last) {
        /*区分大小写检索*/
        sub_start = ngx_strlcasestrn(b->pos, b->last, pair->ukey.data, pair->ukey.len - 1);
        /*不区分大小写检索*/
        //sub_start = subs_memmem(b->pos, b->last - b->pos, pair->ukey.data, pair->ukey.len);
        if (sub_start == NULL) {
            break;
        }

        if (*(sub_start + pair->ukey.len) != '"') {
            break;
        }

        if (*(b->pos + ((sub_start - b->pos) - 1)) == '.') {
            break;
        }

        if (ngx_strstr(sub_start + pair->ukey.len, "https://") != NULL) {
            ngx_str_t peer_url_flag = ngx_string("/var/run/mypeerupstream.flag");
            myfile.name = peer_url_flag;
            myfile.log = r->connection->log;
            myfile.fd = ngx_open_file(myfile.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);
            if (myfile.fd == NGX_INVALID_FILE) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, ngx_close_file_n " \"%s\" failed", myfile.name.data);
                break;
            }
            ngx_memzero(mybuf, 50);
            ssize_t n = ngx_read_file(&myfile, mybuf, 50, 0);
            if (ngx_close_file(myfile.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, ngx_close_file_n " \"%s\" failed", myfile.name.data);
                break;
            }
            if (n == NGX_ERROR) {
                break;
            }
            while (n-- && (mybuf[n] == CR || mybuf[n] == LF)) {}

            if (ngx_strncmp(sub_start + (pair->ukey.len + 1), mybuf, ngx_strlen(mybuf)) != 0) {
                break;
            }
        }

        u_char *url_in = sub_start + (pair->ukey.len + 1);
        u_char *quo_mark = (u_char*)ngx_strstr(url_in , "\""); 
        if (quo_mark == NULL) {
            break;
        }

        size_t url_in_len = quo_mark - url_in; 
        pair->matched++;
        count++;

        if (buffer_append_string(dst, b->pos, (sub_start + (pair->ukey.len + 1)) - b->pos, r->pool) == NULL) {
            return NGX_ERROR;
        }

        
        /*
        if (buffer_append_string(dst, (u_char*)"10110010", ngx_strlen((u_char*)"10110010"), r->pool) == NULL) {
            return NGX_ERROR;
        }
        */
       

        u_char url_out[1024] = {0};
        size_t url_out_len = 0;

        //TODO:encrypt
        rc = ngx_http_myfilter_url_encrypt(r, url_in, url_in_len, url_out, &url_out_len);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        
        if (buffer_append_string(dst, url_out, url_out_len, r->pool) == NULL) {
            return NGX_ERROR;
        }
        

        /*
        if (buffer_append_string(dst, url_in, url_in_len, r->pool) == NULL) {
            return NGX_ERROR;
        }
        */

        b->pos = sub_start + (pair->ukey.len + url_in_len + 1);
        
        if ((ngx_uint_t)(b->last - b->pos) < pair->ukey.len)
            break;
    }

    return count;
}

static ngx_int_t ngx_http_myfilter_match(ngx_http_request_t *r, ngx_http_myfilter_ctx_t *ctx)
{
    ngx_buf_t *src, *dst, *temp;
    ngx_log_t *log;
    ngx_int_t count, match_count;
    sub_pair_t *pairs, *pair;
    ngx_uint_t i;

    count = 0;
    match_count = 0;
    log = r->connection->log;
    src = ctx->line_in;
    dst = ctx->line_dst;

    pairs = (sub_pair_t *)ctx->sub_pairs->elts;
    for (i = 0; i < ctx->sub_pairs->nelts; i++) {
        pair = &pairs[i];
        if (dst->pos != dst->last) {
            temp = src;
            src = dst;
            dst = temp;
            ngx_buffer_init(dst);
        }
        if ((ngx_uint_t)(src->last - src->pos) < pair->ukey.len) {
            continue;
        }
        count = ngx_http_myfilter_match_fix_url(r, pair, src, dst);
        if (count == NGX_ERROR) {
            goto failed;
        }
        if (count == 0) {
            continue;
        }
        if (src->pos < src->last) {
            if (buffer_append_string(dst, src->pos, src->last - src->pos, r->pool) == NULL) {
                goto failed;
            }
            src->pos = src->last;
        }
        match_count += count;
    }
    if (dst->pos == dst->last) {
        dst = src;
    }
    if (ngx_http_subs_out_chain_append(r, ctx, dst) != NGX_OK) {
        goto failed;
    }
    ngx_buffer_init(ctx->line_in);
    ngx_buffer_init(ctx->line_dst);

    return match_count;

failed:
    ngx_log_error(NGX_LOG_ERR, log, 0, "[myfilter] ngx_http_myfilter_match error.");

    return -1;
}

static ngx_int_t ngx_http_myfilter_body_filter_process_buffer(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char *p, *last, *linefeed;
    ngx_int_t len, rc;
    ngx_http_myfilter_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_myfilter_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (b == NULL) {
        return NGX_DECLINED;
    }
    p = b->pos;
    last = b->last;
    b->pos = b->last;

    if ((last - p) == 0 && ngx_buf_size(ctx->line_in) == 0) {
        return NGX_OK;
    }
    if ((last - p) == 0 && ngx_buf_size(ctx->line_in) && ctx->last) {
        rc = ngx_http_myfilter_match(r, ctx);
        if (rc < 0) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    while (p < last) {
        linefeed = memchr(p, LF, last - p);
        if (linefeed == NULL) {
            if (ctx->last) {
                linefeed = last - 1;
            }
        }
        if (linefeed) {
            len = linefeed - p + 1;
            if (buffer_append_string(ctx->line_in, p, len, r->pool) == NULL) {
                return NGX_ERROR;
            }
            p += len;

            rc = ngx_http_myfilter_match(r, ctx);
            if (rc < 0) {
                return NGX_ERROR;
            }
        } else {
            if (buffer_append_string(ctx->line_in, p, last - p, r->pool) == NULL) {
                return NGX_ERROR;
            }
            break;
        }
    }

    return NGX_OK;
}

/*
static ngx_int_t ngx_http_myfilter_body_process_buffer(ngx_http_request_t *r, ngx_buf_t *b)
{
    ngx_buf_t *b;
    u_char *q_pos, *k_pos, *pos;
    u_char *e_pos = NULL;
    ngx_int_t i = 0, j = 0, iFlag;
    ssize_t position, nLen, nSize, nCount;

    b = ctx->in->buf;
    position = 0;
    nLen = 0;
    nSize = 0;
    pos = b->pos;
    nCount = 0;
    iFlag = 0;

    while ((pos + position) != b->last) {
        while (i < 8){
            if ((q_pos = (u_char*)ngx_strstr(pos + position, url_tags[i])) != NULL) {
                u_char *f_pos = NULL;
                u_char *o_pos = NULL;
                o_pos = q_pos;

                f_pos = (u_char*)ngx_strstr(q_pos, ">");
                if (f_pos == NULL) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "invalid html tag");
                    return NGX_ERROR;
                }
                
                nLen = f_pos - q_pos;
                position = f_pos - b->pos;
                j = 0;
                while (j < 5) {
                    if ((k_pos = (u_char*)ngx_strnstr(o_pos, url_key[j], nLen)) != NULL) {
                        u_char *t_pos = NULL;
                        switch (j) {
                            case 0: {
                                        if ((e_pos = (u_char*)ngx_strstr(k_pos + 6, "\"")) != NULL) {
                                            t_pos = k_pos + 6;
                                            nSize = e_pos - t_pos;
                                        }
                                        break;
                                    }
                            case 1: {
                                        if ((e_pos =(u_char*)ngx_strstr(k_pos + 5, "\"")) != NULL) {
                                            t_pos = k_pos + 5;
                                            nSize = e_pos - t_pos;
                                        }
                                        break;
                                    }
                            case 2: {
                                        if ((e_pos = (u_char*)ngx_strstr(k_pos + 5, "\"")) != NULL) {
                                            t_pos = k_pos + 5;
                                            nSize = e_pos - t_pos;
                                        }
                                        break;
                                    }
                            case 3: {
                                        if ((e_pos = (u_char*)ngx_strstr(k_pos + 8, "\"")) != NULL) {
                                            t_pos = k_pos + 8;
                                            nSize = e_pos - t_pos;
                                        }
                                        break;
                                    }
                            case 4: {
                                        if ((e_pos = (u_char*)ngx_strstr(k_pos + 23, "')")) != NULL) {
                                            t_pos = k_pos + 23;
                                            nSize = e_pos - t_pos;
                                        }
                                        break;
                                    }
                            default: {
                                        nSize = 0;
                                        break;
                                     }
                        }

                        //TODO:

                    }
                    j++;    
                }
                continue;
            }
            position = 0;
            i++;
        }

        u_char * h_pos = NULL;
        u_char * l_pos = NULL;
        u_char * s_pos = NULL;
        u_char * u_pos = NULL;
        u_char * r_pos = NULL;
        ngx_int_t k = 0;
        ssize_t position3 = 0;
        while (1) {
            if ((l_pos = (u_char*)ngx_strstr(pos, "<script type=\"text/javascript\">")) != NULL) {
                r_pos = (u_char*)ngx_strstr(l_pos, "</script>");
                if (r_pos == NULL) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "invalid html javascript tag");
                    return NGX_ERROR;
                }
                nLen = r_pos - l_pos;
                while (k < 2) {
                    if ((h_pos = (u_char*)ngx_strnstr(l_pos + position3, url_js[k], nLen - position3)) != NULL) {
                        //position3 = h_pos - l_pos;
                        switch (k) {
                            case 0: {
                                        if ((s_pos =(u_char*)ngx_strstr(h_pos + 7, "\"")) != NULL) {
                                            u_pos = h_pos + 7;
                                            nSize = s_pos - u_pos;
                                            position3 = s_pos - l_pos;
                                        }
                                        break;
                                    }
                            case 1: {
                                        if ((s_pos =(u_char*)ngx_strstr(h_pos + 6, "\"")) != NULL) {
                                            u_pos = h_pos + 6;
                                            nSize = s_pos - u_pos;
                                            position3 = s_pos - l_pos;
                                        }
                                        break;
                                    }
                            default: {
                                        break;
                                     }
                        }
                        //TODO:
                        if (ngx_http_myproxy_encrypt_url(p, u_pos, nSize, buf, &nCount, &iFlag) != NGX_OK) {
                            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "xor encrypt error");
                        }
                        if (iFlag > 0) {
                            position += nCount;
                        } else if (iFlag < 0) {
                            position -= nCount;
                        }
                        nSize = 0;
                        continue;
                    }
                    position3 = 0;
                    k++;
                }
            }
            break;
        }

        position = b->last - b->pos;
    }


    return NGX_OK;
}
*/

