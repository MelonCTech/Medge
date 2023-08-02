/*
 * Copyright (C) Niklaus F.Schen.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "mln_core.h"
#include "mln_log.h"
#include "mln_http.h"
#include "mln_file.h"
#include "mln_conf.h"
#include "mln_lex.h"
#include "mln_lang.h"

int fds[2] = {-1, -1};
mln_lang_t *lang = NULL;
mln_string_t melang_entry_path = mln_string("/home/nik/Medge/entry.m");
mln_string_t melang_default_base_dir = mln_string("/opt/medge/");
mln_string_t *melang_base_dir = &melang_default_base_dir;
mln_string_t melang_base_dir_in_param;
mln_s8_t medge_default_listen_ip[] = "0.0.0.0";
mln_s8ptr_t medge_listen_ip = medge_default_listen_ip;
mln_u16_t medge_listen_port = 80;
mln_string_t framework_mode = mln_string("multiprocess");
mln_conf_item_t framework_conf = {CONF_STR, .val.s=&framework_mode};
mln_conf_item_t workerproc_conf = {CONF_INT, .val.i=1};
mln_u32_t medge_root_changed = 0;
mln_u32_t enable_chroot_flag = 0;

static void mln_parse_args(int argc, char *argv[]);
static void mln_help(char *name);
static int mln_global_init(void);
static void mln_accept(mln_event_t *ev, int fd, void *data);
static int mln_http_recv_body_handler(mln_http_t *http, mln_chain_t **in, mln_chain_t **nil);
static void mln_recv(mln_event_t *ev, int fd, void *data);
static void mln_quit(mln_event_t *ev, int fd, void *data);
static int mln_launch_melang(mln_event_t *ev, mln_http_t *http);
static int mln_lang_signal(mln_lang_t *lang);
static int mln_lang_clear(mln_lang_t *lang);
static void mln_get_response_from_melang(mln_lang_ctx_t *ctx);
static void mln_send(mln_event_t *ev, int fd, void *data);
static int mln_pack_response_body(mln_http_t *http, mln_chain_t **body_head, mln_chain_t **body_tail);
static int mln_inject_vars(mln_http_t *http, mln_lang_ctx_t *ctx, mln_string_t *base_dir);
static int mln_inject_request(mln_http_t *http, mln_lang_ctx_t *ctx);
static int mln_inject_request_method(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_request_version(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_request_uri(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_request_args(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_request_headers(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_request_headers_handler(void *k, void *v, void *udata);
static int mln_inject_request_body(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_response(mln_http_t *http, mln_lang_ctx_t *ctx);
static int mln_inject_response_version(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_response_code(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_response_headers(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj);
static int mln_inject_base_dir(mln_http_t *http, mln_lang_ctx_t *ctx, mln_string_t *base_dir);
static int mln_get_response_version(mln_http_t *http, mln_lang_ctx_t *ctx);
static int mln_get_response_code(mln_http_t *http, mln_lang_ctx_t *ctx);
static int mln_get_response_headers(mln_http_t *http, mln_lang_ctx_t *ctx);
static int mln_get_response_headers_iterator_cb(mln_rbtree_node_t *node, void *udata);
static int mln_get_response_body(mln_http_t *http, mln_lang_ctx_t *ctx);

static void mln_worker_process(mln_event_t *ev)
{
    struct sockaddr_in addr;
    int val = 1;
    int listenfd;

    if (!getuid() && enable_chroot_flag) {
        if (chroot((char *)(melang_base_dir->data)) < 0) {
            mln_log(warn, "Chroot failed, program will keep running.\n");
        } else {
            medge_root_changed = 1;
        }
    }

    if ((lang = mln_lang_new(ev, mln_lang_signal, mln_lang_clear)) == NULL) {
        mln_log(error, "init lang failed.\n");
        return;
    }
    mln_lang_cache_set(lang);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        mln_log(error, "socketpair error.\n");
        mln_lang_free(lang);
        return;
    }

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        mln_log(error, "listen socket error\n");
        mln_lang_free(lang);
        mln_socket_close(fds[0]);
        mln_socket_close(fds[1]);
        return;
    }
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        mln_log(error, "setsockopt error\n");
        mln_socket_close(listenfd);
        mln_lang_free(lang);
        mln_socket_close(fds[0]);
        mln_socket_close(fds[1]);
        return;
    }
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val)) < 0) {
        mln_log(error, "setsockopt error\n");
        mln_socket_close(listenfd);
        mln_lang_free(lang);
        mln_socket_close(fds[0]);
        mln_socket_close(fds[1]);
        return;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(medge_listen_port);
    addr.sin_addr.s_addr = inet_addr(medge_listen_ip);
    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        mln_log(error, "bind error\n");
        mln_socket_close(listenfd);
        mln_lang_free(lang);
        mln_socket_close(fds[0]);
        mln_socket_close(fds[1]);
        return;
    }
    if (listen(listenfd, 511) < 0) {
        mln_log(error, "listen error\n");
        mln_socket_close(listenfd);
        mln_lang_free(lang);
        mln_socket_close(fds[0]);
        mln_socket_close(fds[1]);
        return;
    }

    if (mln_event_fd_set(ev, \
                         listenfd, \
                         M_EV_RECV|M_EV_NONBLOCK, \
                         M_EV_UNLIMITED, \
                         NULL, \
                         mln_accept) < 0)
    {
        mln_log(error, "listen sock set event error\n");
        mln_socket_close(listenfd);
        mln_lang_free(lang);
        mln_socket_close(fds[0]);
        mln_socket_close(fds[1]);
        return;
    }
}

static void mln_accept(mln_event_t *ev, int fd, void *data)
{
    mln_tcp_conn_t *connection;
    mln_http_t *http;
    int connfd;
    socklen_t len;
    struct sockaddr_in addr;

    while (1) {
        memset(&addr, 0, sizeof(addr));
        len = sizeof(addr);
        connfd = accept(fd, (struct sockaddr *)&addr, &len);
        if (connfd < 0) {
            if (errno == EAGAIN || errno == EMFILE || errno == ENFILE) break;
            if (errno == EINTR) continue;
            mln_log(error, "accept error. %s\n", strerror(errno));
            exit(1);
        }

        connection = (mln_tcp_conn_t *)malloc(sizeof(mln_tcp_conn_t));
        if (connection == NULL) {
            mln_log(error, "No memory.\n");
            close(connfd);
            continue;
        }
        if (mln_tcp_conn_init(connection, connfd) < 0) {
            mln_log(error, "No memory.\n");
            close(connfd);
            free(connection);
            continue;
        }

        http = mln_http_init(connection, NULL, mln_http_recv_body_handler);
        if (http == NULL) {
            mln_log(error, "No memory.\n");
            mln_tcp_conn_destroy(connection);
            free(connection);
            close(connfd);
            continue;
        }

        if (mln_event_fd_set(ev, \
                             connfd, \
                             M_EV_RECV|M_EV_NONBLOCK, \
                             M_EV_UNLIMITED, \
                             http, \
                             mln_recv) < 0)
        {
            mln_log(error, "No memory.\n");
            mln_http_destroy(http);
            mln_tcp_conn_destroy(connection);
            free(connection);
            close(connfd);
            continue;
        }
    }
}

static void mln_quit(mln_event_t *ev, int fd, void *data)
{
    mln_http_t *http = (mln_http_t *)data;
    mln_lang_ctx_t *ctx = (mln_lang_ctx_t *)mln_http_data_get(http);
    mln_tcp_conn_t *connection = mln_http_connection_get(http);

    mln_event_fd_set(ev, fd, M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
    mln_http_destroy(http);
    mln_tcp_conn_destroy(connection);
    free(connection);
    close(fd);

    if (ctx != NULL) mln_lang_job_free(ctx);
}

static void mln_recv(mln_event_t *ev, int fd, void *data)
{
    mln_http_t *http = (mln_http_t *)data;
    mln_tcp_conn_t *connection = mln_http_connection_get(http);
    int ret, rc;
    mln_chain_t *c;

    while (1) {
        ret = mln_tcp_conn_recv(connection, M_C_TYPE_MEMORY);
        if (ret == M_C_FINISH) {
            continue;
        } else if (ret == M_C_NOTYET) {
            c = mln_tcp_conn_remove(connection, M_C_RECV);
            if (c != NULL) {
                rc = mln_http_parse(http, &c);
                if (c != NULL) {
                    mln_tcp_conn_append_chain(connection, c, NULL, M_C_RECV);
                }
                if (rc == M_HTTP_RET_OK) {
                    return;
                } else if (rc == M_HTTP_RET_DONE) {
                    if (mln_launch_melang(ev, http) < 0) {
                        mln_quit(ev, fd, data);
                        return;
                    }
                } else {
                    mln_log(error, "Http parse error. error_code:%u\n", mln_http_error_get(http));
                    mln_quit(ev, fd, data);
                    return;
                }
            }
            break;
        } else if (ret == M_C_CLOSED) {
            c = mln_tcp_conn_remove(connection, M_C_RECV);
            if (c != NULL) {
                rc = mln_http_parse(http, &c);
                if (c != NULL) {
                    mln_tcp_conn_append_chain(connection, c, NULL, M_C_RECV);
                }
                if (rc == M_HTTP_RET_ERROR) {
                    mln_log(error, "Http parse error. error_code:%u\n", mln_http_error_get(http));
                }
            }
            mln_quit(ev, fd, data);
            return;
        } else if (ret == M_C_ERROR) {
            mln_quit(ev, fd, data);
            return;
        }
    }
}

static int mln_http_recv_body_handler(mln_http_t *http, mln_chain_t **in, mln_chain_t **nil)
{
    mln_string_t cl_key = mln_string("Content-Length");
    mln_string_t *cl_val;
    mln_chain_t *c = *in;
    mln_sauto_t len, size = 0;

    if (mln_http_type_get(http) != M_HTTP_REQUEST) {
        return M_HTTP_RET_DONE;
    }

    cl_val = mln_http_field_get(http, &cl_key);
    if (cl_val == NULL) {
        return M_HTTP_RET_DONE;
    }

    len = (mln_sauto_t)atol((char *)(cl_val->data));
    if (!len) {
        return M_HTTP_RET_DONE;
    } else if (len < 0) {
        return M_HTTP_RET_ERROR;
    }

    for (; c != NULL; c = c->next) {
        size += mln_buf_left_size(c->buf);
        if (size >= len) break;
    }
    if (c == NULL)
        return M_HTTP_RET_OK;

    return M_HTTP_RET_DONE;
}

static int mln_launch_melang(mln_event_t *ev, mln_http_t *http)
{
    if (mln_http_data_get(http) != NULL)
        return 0;

    mln_lang_ctx_t *ctx;
    char dir_path[1024] = {0};
    char file_path[1024] = {0};
    mln_string_t dir, file;
    int n;
    mln_string_t key = mln_string("Host");
    mln_string_t *val;

    val = mln_http_field_get(http, &key);
    if (val == NULL) {
        mln_log(error, "No host in request headers.\n");
        return -1;
    }

    if (medge_root_changed)
        n = snprintf(dir_path, sizeof(dir_path) - 1, "/%s", (char *)(val->data));
    else
        n = snprintf(dir_path, sizeof(dir_path) - 1, "%s/%s", (char *)(melang_base_dir->data), (char *)(val->data));
    mln_string_nset(&dir, dir_path, n);

    n = snprintf(file_path, sizeof(file_path) - 1, "%s/entry.m", dir_path);
    mln_string_nset(&file, file_path, n);

    if ((ctx = mln_lang_job_new(lang, M_INPUT_T_FILE, &file, NULL, mln_get_response_from_melang)) == NULL) {
        mln_log(error, "Launch melang [%S] failed.\n", &file);
        return -1;
    }
    mln_http_data_set(http, ctx);
    mln_lang_ctx_data_set(ctx, http);

    return mln_inject_vars(http, ctx, &dir);
}

static int mln_inject_vars(mln_http_t *http, mln_lang_ctx_t *ctx, mln_string_t *base_dir)
{
    if (mln_inject_request(http, ctx) < 0)
        return -1;
    if (mln_inject_response(http, ctx) < 0)
        return -1;
    if (mln_inject_base_dir(http, ctx, base_dir) < 0)
        return -1;
    return 0;
}

static int mln_inject_request(mln_http_t *http, mln_lang_ctx_t *ctx)
{
    mln_lang_var_t *var;
    mln_lang_object_t *obj;
    mln_string_t name = mln_string("Req");
    mln_string_t *dup;

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_obj(ctx, NULL, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    obj = mln_lang_var_val_get(var)->data.obj;

    if (mln_inject_request_method(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }
    if (mln_inject_request_version(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }
    if (mln_inject_request_uri(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }
    if (mln_inject_request_args(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }
    if (mln_inject_request_headers(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }
    if (mln_inject_request_body(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }

    if (mln_lang_symbol_node_join(ctx, M_LANG_SYMBOL_VAR, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }

    return 0;
}

static int mln_inject_request_method(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_u32_t method = mln_http_method_get(http);
    mln_lang_var_t *var = NULL;
    mln_string_t methods[] = {
        mln_string("GET"),
        mln_string("POST"),
        mln_string("HEAD"),
        mln_string("PUT"),
        mln_string("DELETE"),
        mln_string("TRACE"),
        mln_string("CONNECT"),
        mln_string("OPTIONS")
    };
    mln_string_t name = mln_string("method");
    mln_string_t *dup;

    if (method >= sizeof(methods) / sizeof(mln_string_t)) {
        mln_log(error, "Invalid HTTP method.\n");
        return -1;
    }
    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_string(ctx, &methods[method], dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }
    return 0;
}

static int mln_inject_request_version(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_u32_t version = mln_http_version_get(http);
    mln_lang_var_t *var = NULL;
    mln_string_t versions[] = {
        mln_string("HTTP/1.0"),
        mln_string("HTTP/1.1")
    };
    mln_string_t name = mln_string("version");
    mln_string_t *dup;

    if (version >= sizeof(versions) / sizeof(mln_string_t)) {
        mln_log(error, "Invalid HTTP version.\n");
        return -1;
    }
    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_string(ctx, &versions[version], dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }
    return 0;
}

static int mln_inject_request_uri(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_string_t *uri = mln_http_uri_get(http);
    mln_lang_var_t *var;
    mln_string_t name = mln_string("uri");
    mln_string_t *dup;

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_string(ctx, uri, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }
    return 0;
}

static int mln_inject_request_args(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_string_t *args = mln_http_args_get(http);
    mln_lang_var_t *var, kvar, *vvar;
    mln_lang_val_t kval;
    mln_string_t name = mln_string("args");
    mln_string_t *dup, *slices, *s;
    mln_lang_array_t *arr;
    mln_u8ptr_t p, end;
    mln_string_t key, value;

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_array(ctx, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    arr = mln_lang_var_val_get(var)->data.array;

    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }

    if (args == NULL)
        return 0;

    if ((slices = mln_string_slice(args, "&\0")) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    for (s = slices; s->len != 0; ++s) {
        for (p = s->data, end = s->data + s->len; p < end; ++p) {
            if (*p == (mln_u8_t)'=') break;
        }
        mln_string_nset(&key, s->data, p - s->data);
        if (p >= end) {
            mln_string_nset(&value, "", 0);
        } else {
            mln_string_nset(&value, ++p, end - p);
        }

        if ((dup = mln_string_pool_dup(ctx->pool, &key)) == NULL) {
            mln_log(error, "No memory.\n");
            return -1;
        }
        kvar.type = M_LANG_VAR_NORMAL;
        kvar.name = NULL;
        kvar.val = &kval;
        kvar.in_set = NULL;
        kvar.prev = kvar.next = NULL;
        kvar.ref = 1;
        kval.prev = kval.next = NULL;
        kval.data.s = dup;
        kval.type = M_LANG_VAL_TYPE_STRING;
        kval.ref = 1;
        kval.udata = NULL;
        kval.func = NULL;
        kval.not_modify = 0;

        vvar = mln_lang_array_get(ctx, arr, &kvar);
        mln_string_free(dup);
        if (vvar == NULL) {
            mln_log(error, "No memory.\n");
            mln_string_slice_free(slices);
            return -1;
        }
        kvar.type = M_LANG_VAR_NORMAL;
        kvar.name = NULL;
        kvar.val = &kval;
        kvar.in_set = NULL;
        kvar.prev = kvar.next = NULL;
        kvar.ref = 1;
        kval.prev = kval.next = NULL;
        kval.data.s = &value;
        kval.type = M_LANG_VAL_TYPE_STRING;
        kval.ref = 1;
        kval.udata = NULL;
        kval.func = NULL;
        kval.not_modify = 0;
        if (mln_lang_var_value_set(ctx, vvar, &kvar) < 0) {
            mln_log(error, "No memory.\n");
            mln_string_slice_free(slices);
            return -1;
        }
    }
    mln_string_slice_free(slices);
    return 0;
}

static int mln_inject_request_headers(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_lang_var_t *var;
    mln_string_t name = mln_string("headers");
    mln_string_t *dup;
    mln_lang_array_t *arr;
    mln_hash_t *headers = mln_http_header_get(http);

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_array(ctx, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    arr = mln_lang_var_val_get(var)->data.array;

    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }

    if (mln_hash_iterate(headers, mln_inject_request_headers_handler, arr) < 0) {
        return -1;
    }
    return 0;
}

static int mln_inject_request_headers_handler(void *k, void *v, void *udata)
{
    mln_lang_array_t *arr = (mln_lang_array_t *)udata;
    mln_string_t *key;
    mln_lang_var_t var, *vvar;
    mln_lang_val_t val;

    if ((key = mln_string_pool_dup(arr->ctx->pool, (mln_string_t *)k)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    var.type = M_LANG_VAR_NORMAL;
    var.name = NULL;
    var.val = &val;
    var.in_set = NULL;
    var.prev = var.next = NULL;
    var.ref = 1;
    val.prev = val.next = NULL;
    val.data.s = key;
    val.type = M_LANG_VAL_TYPE_STRING;
    val.ref = 1;
    val.udata = NULL;
    val.func = NULL;
    val.not_modify = 0;

    vvar = mln_lang_array_get(arr->ctx, arr, &var);
    mln_string_free(key);
    if (vvar == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    var.type = M_LANG_VAR_NORMAL;
    var.name = NULL;
    var.val = &val;
    var.in_set = NULL;
    var.prev = var.next = NULL;
    var.ref = 1;
    val.prev = val.next = NULL;
    val.data.s = (mln_string_t *)v;
    val.type = M_LANG_VAL_TYPE_STRING;
    val.ref = 1;
    val.udata = NULL;
    val.func = NULL;
    val.not_modify = 0;
    if (mln_lang_var_value_set(arr->ctx, vvar, &var) < 0) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    return 0;
}

static int mln_inject_request_body(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_string_t cl_key = mln_string("Content-Length");
    mln_string_t *cl_val;
    mln_sauto_t len, size, n;
    mln_string_t name = mln_string("body");
    mln_string_t *dup, body;
    mln_u8ptr_t buf, p;
    mln_lang_var_t *var;
    mln_tcp_conn_t *conn = mln_http_connection_get(http);
    mln_chain_t *c = mln_tcp_conn_head(conn, M_C_RECV);

    cl_val = mln_http_field_get(http, &cl_key);
    if (cl_val == NULL) return 0;

    len = (mln_sauto_t)atol((char *)(cl_val->data));
    if (!len) return 0;
    if (len < 0) {
        mln_log(error, "Invalid body length.\n");
        return -1;
    }

    if ((buf = (mln_u8ptr_t)malloc(len)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    for (size = len, p = buf; size > 0 && c != NULL; c = c->next) {
        n = size > mln_buf_left_size(c->buf)? mln_buf_left_size(c->buf): size;
        memcpy(p, c->buf->left_pos, n);
        p += n;
        size -= n;
    }
    mln_string_nset(&body, buf, len);

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_string(ctx, &body, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }
    return 0;
}

static int mln_inject_response(mln_http_t *http, mln_lang_ctx_t *ctx)
{
    mln_lang_var_t *var;
    mln_lang_object_t *obj;
    mln_string_t name = mln_string("Resp");
    mln_string_t *dup;

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_obj(ctx, NULL, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    obj = mln_lang_var_val_get(var)->data.obj;

    if (mln_inject_response_version(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }
    if (mln_inject_response_code(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }
    if (mln_inject_response_headers(http, ctx, obj) < 0) {
        mln_lang_var_free(var);
        return -1;
    }

    if (mln_lang_symbol_node_join(ctx, M_LANG_SYMBOL_VAR, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }

    return 0;
}

static int mln_inject_response_version(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_u32_t version = mln_http_version_get(http);
    mln_lang_var_t *var = NULL;
    mln_string_t versions[] = {
        mln_string("HTTP/1.0"),
        mln_string("HTTP/1.1")
    };
    mln_string_t name = mln_string("version");
    mln_string_t *dup;

    if (version >= sizeof(versions) / sizeof(mln_string_t)) {
        mln_log(error, "Invalid HTTP version.\n");
        return -1;
    }
    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_string(ctx, &versions[version], dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }
    return 0;
}

static int mln_inject_response_code(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_u32_t code = 200;
    mln_lang_var_t *var = NULL;
    mln_string_t name = mln_string("code");
    mln_string_t *dup;

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_int(ctx, code, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);
    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }
    return 0;
}

static int mln_inject_response_headers(mln_http_t *http, mln_lang_ctx_t *ctx, mln_lang_object_t *obj)
{
    mln_lang_var_t *var;
    mln_string_t name = mln_string("headers");
    mln_string_t *dup;

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_array(ctx, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);

    if (mln_lang_set_member_add(ctx->pool, obj->members, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }

    return 0;
}

static int mln_inject_base_dir(mln_http_t *http, mln_lang_ctx_t *ctx, mln_string_t *base_dir)
{
    mln_lang_var_t *var;
    mln_string_t name = mln_string("Basedir");
    mln_string_t *dup;

    if ((dup = mln_string_pool_dup(ctx->pool, &name)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if ((var = mln_lang_var_create_string(ctx, base_dir, dup)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_string_free(dup);
        return -1;
    }
    mln_string_free(dup);

    if (mln_lang_symbol_node_join(ctx, M_LANG_SYMBOL_VAR, var) < 0) {
        mln_log(error, "No memory.\n");
        mln_lang_var_free(var);
        return -1;
    }

    return 0;
}

static int mln_lang_signal(mln_lang_t *lang)
{
    return mln_event_fd_set(mln_lang_event_get(lang), fds[0], M_EV_SEND|M_EV_ONESHOT, M_EV_UNLIMITED, lang, mln_lang_launcher_get(lang));
}

static int mln_lang_clear(mln_lang_t *lang)
{
    return mln_event_fd_set(mln_lang_event_get(lang), fds[0], M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
}

static void mln_get_response_from_melang(mln_lang_ctx_t *ctx)
{
    mln_http_t *http = mln_lang_ctx_data_get(ctx);
    mln_tcp_conn_t *conn = mln_http_connection_get(http);

    mln_http_data_set(http, NULL);

    mln_http_reset(http);
    mln_http_type_set(http, M_HTTP_RESPONSE);

    if (mln_get_response_version(http, ctx) < 0) goto err;
    if (mln_get_response_code(http, ctx) < 0) goto err;
    if (mln_get_response_headers(http, ctx) < 0) goto err;
    if (mln_get_response_body(http, ctx) < 0) goto err;

    mln_event_fd_set(mln_lang_event_get(ctx->lang), mln_tcp_conn_fd_get(conn), M_EV_SEND|M_EV_APPEND|M_EV_NONBLOCK, M_EV_UNLIMITED, http, mln_send);

    return;

err:
    mln_quit(mln_lang_event_get(ctx->lang), mln_tcp_conn_fd_get(conn), http);
}

static int mln_get_response_version(mln_http_t *http, mln_lang_ctx_t *ctx)
{
    mln_lang_var_t *var;
    mln_lang_symbol_node_t *sym;
    mln_string_t resp = mln_string("Resp");
    mln_string_t version = mln_string("version");
    mln_string_t v1_0 = mln_string("HTTP/1.0");
    mln_string_t v1_1 = mln_string("HTTP/1.1");

    if ((sym = mln_lang_symbol_node_search(ctx, &resp, 0)) == NULL) {
        mln_log(error, "Cannot find 'Resp' variable.\n");
        return -1;
    }
    if (sym->type != M_LANG_SYMBOL_VAR) {
        mln_log(error, "Invalid type of 'Resp'.\n");
        return -1;
    }
    var = sym->data.var;
    if (mln_lang_var_val_type_get(var) != M_LANG_VAL_TYPE_OBJECT) {
        mln_log(error, "Invalid type of 'Resp'.\n");
        return -1;
    }
    var = mln_lang_set_member_search(mln_lang_var_val_get(var)->data.obj->members, &version);
    if (var == NULL) {
        mln_log(error, "No 'version' in 'Resp'.\n");
        return -1;
    }
    if (mln_lang_var_val_type_get(var) != M_LANG_VAL_TYPE_STRING) {
        mln_log(error, "Invalid 'version' type of 'Resp'.\n");
        return -1;
    }

    if (!mln_string_strcasecmp(mln_lang_var_val_get(var)->data.s, &v1_0)) {
        mln_http_version_set(http, M_HTTP_VERSION_1_0);
    } else if (!mln_string_strcasecmp(mln_lang_var_val_get(var)->data.s, &v1_1)) {
        mln_http_version_set(http, M_HTTP_VERSION_1_1);
    } else {
        mln_log(error, "Unsupported version of 'Resp'.\n");
        return -1;
    }
    return 0;
}

static int mln_get_response_code(mln_http_t *http, mln_lang_ctx_t *ctx)
{
    mln_lang_var_t *var;
    mln_lang_symbol_node_t *sym;
    mln_string_t resp = mln_string("Resp");
    mln_string_t code = mln_string("code");

    if ((sym = mln_lang_symbol_node_search(ctx, &resp, 0)) == NULL) {
        mln_log(error, "Cannot find 'Resp' variable.\n");
        return -1;
    }
    if (sym->type != M_LANG_SYMBOL_VAR) {
        mln_log(error, "Invalid type of 'Resp'.\n");
        return -1;
    }
    var = sym->data.var;
    if (mln_lang_var_val_type_get(var) != M_LANG_VAL_TYPE_OBJECT) {
        mln_log(error, "Invalid type of 'Resp'.\n");
        return -1;
    }
    var = mln_lang_set_member_search(mln_lang_var_val_get(var)->data.obj->members, &code);
    if (var == NULL) {
        mln_log(error, "No 'code' in 'Resp'.\n");
        return -1;
    }
    if (mln_lang_var_val_type_get(var) != M_LANG_VAL_TYPE_INT) {
        mln_log(error, "Invalid 'code' type of 'Resp'.\n");
        return -1;
    }

    mln_http_status_set(http, mln_lang_var_val_get(var)->data.i);
    return 0;
}

static int mln_get_response_headers(mln_http_t *http, mln_lang_ctx_t *ctx)
{
    mln_lang_var_t *var;
    mln_lang_symbol_node_t *sym;
    mln_string_t resp = mln_string("Resp");
    mln_string_t headers = mln_string("headers");

    if ((sym = mln_lang_symbol_node_search(ctx, &resp, 0)) == NULL) {
        mln_log(error, "Cannot find 'Resp' variable.\n");
        return -1;
    }
    if (sym->type != M_LANG_SYMBOL_VAR) {
        mln_log(error, "Invalid type of 'Resp'.\n");
        return -1;
    }
    var = sym->data.var;
    if (mln_lang_var_val_type_get(var) != M_LANG_VAL_TYPE_OBJECT) {
        mln_log(error, "Invalid type of 'Resp'.\n");
        return -1;
    }
    var = mln_lang_set_member_search(mln_lang_var_val_get(var)->data.obj->members, &headers);
    if (var == NULL) {
        mln_log(error, "No 'headers' in 'Resp'.\n");
        return -1;
    }
    if (mln_lang_var_val_type_get(var) != M_LANG_VAL_TYPE_ARRAY) {
        mln_log(error, "Invalid 'headers' type of 'Resp'.\n");
        return -1;
    }

    if (mln_rbtree_iterate(mln_lang_var_val_get(var)->data.array->elems_key, mln_get_response_headers_iterator_cb, http) < 0)
        return -1;
    return 0;
}

static int mln_get_response_headers_iterator_cb(mln_rbtree_node_t *node, void *udata)
{
    mln_lang_array_elem_t *elem = (mln_lang_array_elem_t *)mln_rbtree_node_data(node);
    mln_http_t *http = (mln_http_t *)udata;
    mln_string_t v, *p;
    mln_u8_t buf[1024] = {0};
    int n;

    if (mln_lang_var_val_type_get(elem->key) != M_LANG_VAL_TYPE_STRING) return 0;
    if (mln_lang_var_val_type_get(elem->value) == M_LANG_VAL_TYPE_INT) {
#if defined(WIN32)
        n = snprintf((char *)buf, sizeof(buf) - 1, "%I64d", mln_lang_var_val_get(elem->value)->data.i);
#elif defined(i386) || defined(__arm__) || defined(__wasm__)
        n = snprintf((char *)buf, sizeof(buf) - 1, "%lld", mln_lang_var_val_get(elem->value)->data.i);
#else
        n = snprintf((char *)buf, sizeof(buf) - 1, "%ld", mln_lang_var_val_get(elem->value)->data.i);
#endif
        mln_string_nset(&v, buf, n);
        p = &v;
    } else if (mln_lang_var_val_type_get(elem->value) == M_LANG_VAL_TYPE_REAL) {
        n = snprintf((char *)buf, sizeof(buf) - 1, "%f", mln_lang_var_val_get(elem->value)->data.f);
        mln_string_nset(&v, buf, n);
        p = &v;
    } else if (mln_lang_var_val_type_get(elem->value) == M_LANG_VAL_TYPE_STRING) {
        p = mln_lang_var_val_get(elem->value)->data.s;
    } else {
        return 0;
    }

    if (mln_http_field_set(http, mln_lang_var_val_get(elem->key)->data.s, p) < 0) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    return 0;
}

static int mln_get_response_body(mln_http_t *http, mln_lang_ctx_t *ctx)
{
    mln_lang_var_t *var;
    mln_lang_symbol_node_t *sym;
    mln_string_t resp = mln_string("Resp");
    mln_string_t body = mln_string("body");
    mln_chain_t *head = NULL, *tail = NULL;
    mln_string_t cl_key = mln_string("Content-Length");
    mln_string_t *cl_val;
    mln_sauto_t len = 0;
    mln_tcp_conn_t *conn = mln_http_connection_get(http);

    cl_val = mln_http_field_get(http, &cl_key);
    if (cl_val != NULL) {
        len = (mln_sauto_t)atol((char *)(cl_val->data));
    }

    if ((sym = mln_lang_symbol_node_search(ctx, &resp, 0)) == NULL) {
        mln_log(error, "Cannot find 'Resp' variable.\n");
        return -1;
    }
    if (sym->type != M_LANG_SYMBOL_VAR) {
        mln_log(error, "Invalid type of 'Resp'.\n");
        return -1;
    }
    var = sym->data.var;
    if (mln_lang_var_val_type_get(var) != M_LANG_VAL_TYPE_OBJECT) {
        mln_log(error, "Invalid type of 'Resp'.\n");
        return -1;
    }
    var = mln_lang_set_member_search(mln_lang_var_val_get(var)->data.obj->members, &body);
    if (var == NULL || mln_lang_var_val_type_get(var) == M_LANG_VAL_TYPE_NIL) goto gen;

    if (mln_lang_var_val_type_get(var) != M_LANG_VAL_TYPE_STRING) {
        mln_log(error, "Invalid 'body' type of 'Resp'.\n");
        return -1;
    }

    mln_http_handler_set(http, mln_pack_response_body);
    mln_http_data_set(http, mln_lang_var_val_get(var)->data.s);

gen:
    if (var == NULL) {
        if (len) {
            mln_log(error, "Invalid 'body' length of 'Resp'.\n");
            mln_http_data_set(http, NULL);
            return -1;
        }
    } else {
        if (len && len != mln_lang_var_val_get(var)->data.s->len) {
            mln_log(error, "Invalid 'body' length of 'Resp'.\n");
            mln_http_data_set(http, NULL);
            return -1;
        }
    }

    if (mln_http_generate(http, &head, &tail) == M_HTTP_RET_ERROR) {
        mln_log(error, "Generate HTTP response failed. %u\n", mln_http_error_get(http));
        mln_http_data_set(http, NULL);
        return -1;
    }
    mln_http_data_set(http, NULL);

    mln_tcp_conn_append_chain(conn, head, tail, M_C_SEND);
    return 0;
}

static int mln_pack_response_body(mln_http_t *http, mln_chain_t **body_head, mln_chain_t **body_tail)
{
    mln_u8ptr_t buf;
    mln_alloc_t *pool = mln_http_pool_get(http);
    mln_string_t *body = (mln_string_t *)mln_http_data_get(http);

    if (body == NULL || !body->len)
        return M_HTTP_RET_DONE;

    buf = (mln_u8ptr_t)mln_alloc_m(pool, body->len);
    if (buf == NULL) {
        mln_http_error_set(http, M_HTTP_INTERNAL_SERVER_ERROR);
        return M_HTTP_RET_ERROR;
    }
    memcpy(buf, body->data, body->len);

    mln_chain_t *c = mln_chain_new(pool);
    if (c == NULL) {
        mln_http_error_set(http, M_HTTP_INTERNAL_SERVER_ERROR);
        return M_HTTP_RET_ERROR;
    }
    mln_buf_t *b = mln_buf_new(pool);
    if (b == NULL) {
        mln_chain_pool_release(c);
        mln_http_error_set(http, M_HTTP_INTERNAL_SERVER_ERROR);
        return M_HTTP_RET_ERROR;
    }
    c->buf = b;
    b->left_pos = b->pos = b->start = buf;
    b->last = b->end = buf + body->len;
    b->in_memory = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    if (*body_head == NULL) {
        *body_head = *body_tail = c;
    } else {
        (*body_tail)->next = c;
        *body_tail = c;
    }

    return M_HTTP_RET_DONE;
}

static void mln_send(mln_event_t *ev, int fd, void *data)
{
    mln_http_t *http = (mln_http_t *)data;
    mln_tcp_conn_t *connection = mln_http_connection_get(http);
    mln_chain_t *c = mln_tcp_conn_head(connection, M_C_SEND);
    int ret;

    while ((c = mln_tcp_conn_head(connection, M_C_SEND)) != NULL) {
        ret = mln_tcp_conn_send(connection);
        if (ret == M_C_FINISH) {
            mln_quit(ev, fd, data);
            break;
        } else if (ret == M_C_NOTYET) {
            mln_chain_pool_release_all(mln_tcp_conn_remove(connection, M_C_SENT));
            mln_event_fd_set(ev, fd, M_EV_SEND|M_EV_APPEND|M_EV_NONBLOCK, M_EV_UNLIMITED, data, mln_send);
            return;
        } else if (ret == M_C_ERROR) {
            mln_quit(ev, fd, data);
            return;
        } else {
            mln_log(error, "Shouldn't be here.\n");
            abort();
        }
    }
}

static int mln_global_init(void)
{
    mln_conf_t *cf;
    mln_conf_domain_t *cd;
    mln_conf_cmd_t *cc;

    cf = mln_conf();
    cd = cf->search(cf, "main");
    cc = cd->search(cd, "framework");
    if (cc == NULL) {
        if ((cc = cd->insert(cd, "framework")) == NULL) {
            mln_log(error, "insert configuration command 'framework' failed.\n");
            return -1;
        }
    }
    if (cc->update(cc, &framework_conf, 1) < 0) {
        mln_log(error, "update configuration command 'framework' failed.\n");
        return -1;
    }

    cc = cd->search(cd, "worker_proc");
    if (cc == NULL) {
        if ((cc = cd->insert(cd, "worker_proc")) == NULL) {
            mln_log(error, "insert configuration command 'worker_proc' failed.\n");
            return -1;
        }
    }
    if (cc->update(cc, &workerproc_conf, 1) < 0) {
        mln_log(error, "update configuration command 'worker_proc' failed.\n");
        return -1;
    }

    return 0;
}

static void mln_parse_args(int argc, char *argv[])
{
    int i;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-a")) {
            if (++i >= argc) goto err;
            medge_listen_ip = argv[i];
        } else if (!strcmp(argv[i], "-p")) {
            if (++i >= argc) goto err;
            medge_listen_port = atoi(argv[i]);
            if (medge_listen_port <= 0) goto err;
        } else if (!strcmp(argv[i], "-w")) {
            if (++i >= argc) goto err;
            workerproc_conf.val.i = atoi(argv[i]);
            if (workerproc_conf.val.i <= 0) goto err;
        } else if (!strcmp(argv[i], "-d")) {
            if (++i >= argc) goto err;
            mln_string_set(&melang_base_dir_in_param, argv[i]);
            melang_base_dir = &melang_base_dir_in_param;
        } else if (!strcmp(argv[i], "-v")) {
            fprintf(stdout, "0.1.0\n");
            exit(0);
        } else if (!strcmp(argv[i], "-D")) {
            enable_chroot_flag = 1;
        } else if (!strcmp(argv[i], "-h")) {
            mln_help(argv[0]);
        } else {
err:
            fprintf(stderr, "Invalid parameter [%s].\n", argv[i]);
            mln_help(argv[0]);
        }
    }

    fprintf(stdout, "Listen: %s:%u\nBase directory: %s\n", (char *)medge_listen_ip, medge_listen_port, (char *)(melang_base_dir->data));
}

static void mln_help(char *name)
{
    fprintf(stdout, "%s OPTIONS\n", name);
    fprintf(stdout, "\t-a Listen address, 0.0.0.0 as default\n");
    fprintf(stdout, "\t-p Listen port, 80 as default\n");
    fprintf(stdout, "\t-w Worker process number, 1 as default\n");
    fprintf(stdout, "\t-d Base directory path of entry script, /opt/medge/ as default\n");
    fprintf(stdout, "\t-D Enable changing root directory. This parameter only work on user 'root'.\n");
    fprintf(stdout, "\t-v Show version\n");
    fprintf(stdout, "\t-h Show help information\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    struct mln_core_attr cattr;

    mln_parse_args(argc, argv);

    cattr.argc = 0;
    cattr.argv = NULL;
    cattr.global_init = mln_global_init;
    cattr.main_thread = NULL;
    cattr.master_process = NULL;
    cattr.worker_process = mln_worker_process;
    return mln_core_init(&cattr);
}

