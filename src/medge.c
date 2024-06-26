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
#include "mln_framework.h"
#include "mln_log.h"
#include "mln_file.h"
#include "mln_conf.h"
#include "medge.h"

mln_string_t me_default_entry_file_name = mln_string("index");
mln_string_t *me_entry_file_name_ptr = &me_default_entry_file_name;
mln_string_t me_default_entry_base_dir = mln_string("/opt/medge/");
mln_string_t *me_entry_base_dir_ptr = &me_default_entry_base_dir;
mln_string_t me_entry_base_dir_in_param;
mln_string_t me_entry_file_name_in_param;
mln_s8_t me_default_listen_ip[] = "0.0.0.0";
mln_s8ptr_t me_listen_ip_ptr = me_default_listen_ip;
mln_u16_t me_listen_port = 80;
mln_string_t me_framework_mode = mln_string("multiprocess");
mln_conf_item_t me_framework_conf = {CONF_STR, .val.s=&me_framework_mode};
mln_conf_item_t me_workerproc_conf = {CONF_INT, .val.i=1};
mln_u32_t me_root_changed = 0;
mln_u32_t me_enable_chroot_flag = 0;
mln_rbtree_t *me_funcs;

static inline me_session_t *me_session_new(mln_tcp_conn_t *conn);
static inline void me_session_free(me_session_t *s);
static int me_symbol_cmp(me_symbol_t *sym1, me_symbol_t *sym2);
static int me_func_cmp(me_func_t *f1, me_func_t *f2);

static void me_parse_args(int argc, char *argv[]);
static void me_help(char *name);
static int me_global_init(void);
static void me_accept(mln_event_t *ev, int fd, void *data);
static int me_http_recv_body_handler(mln_http_t *http, mln_chain_t **in, mln_chain_t **nil);
static void me_recv(mln_event_t *ev, int fd, void *data);
static void me_quit(mln_event_t *ev, int fd, void *data);
static void me_send(mln_event_t *ev, int fd, void *data);
static int me_pack_response_body(mln_http_t *http, mln_chain_t **body_head, mln_chain_t **body_tail);

static inline me_session_t *me_session_new(mln_tcp_conn_t *conn)
{
    struct mln_rbtree_attr rbattr;
    me_session_t *s;
    mln_alloc_t *pool = mln_tcp_conn_pool_get(conn);

    if ((s = (me_session_t *)mln_alloc_m(pool, sizeof(me_session_t))) == NULL) {
        return NULL;
    }

    if ((s->req = mln_http_init(conn, NULL, me_http_recv_body_handler)) == NULL) {
        mln_alloc_free(s);
        return NULL;
    }
    if ((s->resp = mln_http_init(conn, NULL, me_pack_response_body)) == NULL) {
        mln_http_destroy(s->req);
        mln_alloc_free(s);
        return NULL;
    }
    mln_http_type_set(s->resp, M_HTTP_RESPONSE);

    rbattr.pool = pool;
    rbattr.pool_alloc = (rbtree_pool_alloc_handler)mln_alloc_m;
    rbattr.pool_free = (rbtree_pool_free_handler)mln_alloc_free;
    rbattr.cmp = (rbtree_cmp)me_symbol_cmp;
    rbattr.data_free = (rbtree_free_data)me_symbol_free;
    if ((s->symbols = mln_rbtree_new(&rbattr)) == NULL) {
        mln_http_destroy(s->resp);
        mln_http_destroy(s->req);
        mln_alloc_free(s);
        return NULL;
    }

    return s;
}

static inline void me_session_free(me_session_t *s)
{
    if (s == NULL) return;

    if (s->req != NULL) {
        mln_string_free(mln_http_data_get(s->req));
        mln_http_destroy(s->req);
    }
    if (s->resp != NULL) {
        mln_string_free(mln_http_data_get(s->resp));
        mln_http_destroy(s->resp);
    }
    if (s->symbols != NULL) mln_rbtree_free(s->symbols);
    mln_alloc_free(s);
}

me_symbol_t *me_symbol_new(mln_string_t *name, mln_expr_val_t *val)
{
    me_symbol_t *sym;
    if ((sym = (me_symbol_t *)malloc(sizeof(me_symbol_t))) == NULL)
        return NULL;

    sym->name = mln_string_ref(name);
    sym->val = val;
    return sym;
}

void me_symbol_free(me_symbol_t *sym)
{
    if (sym == NULL) return;

    if (sym->name != NULL) mln_string_free(sym->name);
    if (sym->val != NULL) mln_expr_val_free(sym->val);
    free(sym);
}

static int me_symbol_cmp(me_symbol_t *sym1, me_symbol_t *sym2)
{
    return mln_string_strcmp(sym1->name, sym2->name);
}

static int me_func_cmp(me_func_t *f1, me_func_t *f2)
{
    return mln_string_strcmp(&(f1->name), &(f2->name));
}


static void me_worker_process(mln_event_t *ev)
{
    struct sockaddr_in addr;
    int val = 1;
    int listenfd;

    if (!getuid() && me_enable_chroot_flag) {
        if (chroot((char *)(me_entry_base_dir_ptr->data)) < 0) {
            mln_log(warn, "Chroot failed, program will keep running.\n");
        } else {
            me_root_changed = 1;
        }
    }

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        mln_log(error, "listen socket error\n");
        return;
    }
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        mln_log(error, "setsockopt error\n");
        mln_socket_close(listenfd);
        return;
    }
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val)) < 0) {
        mln_log(error, "setsockopt error\n");
        mln_socket_close(listenfd);
        return;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(me_listen_port);
    addr.sin_addr.s_addr = inet_addr(me_listen_ip_ptr);
    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        mln_log(error, "bind error\n");
        mln_socket_close(listenfd);
        return;
    }
    if (listen(listenfd, 511) < 0) {
        mln_log(error, "listen error\n");
        mln_socket_close(listenfd);
        return;
    }

    if (mln_event_fd_set(ev, \
                         listenfd, \
                         M_EV_RECV|M_EV_NONBLOCK, \
                         M_EV_UNLIMITED, \
                         NULL, \
                         me_accept) < 0)
    {
        mln_log(error, "listen sock set event error\n");
        mln_socket_close(listenfd);
        return;
    }
}

static void me_accept(mln_event_t *ev, int fd, void *data)
{
    mln_tcp_conn_t *connection;
    me_session_t *se;
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

        if ((se = me_session_new(connection)) == NULL) {
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
                             se, \
                             me_recv) < 0)
        {
            mln_log(error, "No memory.\n");
            me_session_free(se);
            mln_tcp_conn_destroy(connection);
            free(connection);
            close(connfd);
            continue;
        }
    }
}

static void me_quit(mln_event_t *ev, int fd, void *data)
{
    me_session_t *se = (me_session_t *)data;
    mln_tcp_conn_t *connection = mln_http_connection_get(se->req);

    mln_event_fd_set(ev, fd, M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
    me_session_free(se);
    mln_tcp_conn_destroy(connection);
    free(connection);
    close(fd);
}

static mln_expr_val_t *mln_expr_callback(mln_string_t *name, int is_func, mln_array_t *args, void *data)
{
    mln_rbtree_node_t *rn;
    me_symbol_t *sym, tmp_sym;
    me_func_t *f, tmp_func;
    me_session_t *se = (me_session_t *)data;

    if (!is_func) {
        tmp_sym.name = name;
        rn = mln_rbtree_search(se->symbols, &tmp_sym);
        if (mln_rbtree_null(rn, se->symbols)) {
            return mln_expr_val_new(mln_expr_type_null, NULL, NULL);
        }
        sym = (me_symbol_t *)mln_rbtree_node_data_get(rn);
        return mln_expr_val_dup(sym->val);
    }

    tmp_func.name = *name;
    rn = mln_rbtree_search(me_funcs, &tmp_func);
    if (mln_rbtree_null(rn, me_funcs)) {
        return mln_expr_val_new(mln_expr_type_null, NULL, NULL);
    }
    f = (me_func_t *)mln_rbtree_node_data_get(rn);
    return f->func(se, args);
}

static void me_send_response(mln_event_t *ev, int fd, me_session_t *se)
{
    int n;
    char filepath[1024];
    mln_string_t path;
    mln_expr_val_t *v;
    mln_chain_t *head = NULL, *tail = NULL;
    mln_tcp_conn_t *conn = mln_http_connection_get(se->resp);

    mln_http_version_set(se->resp, mln_http_version_get(se->req));
    n = snprintf(filepath, sizeof(filepath) - 1, "%s/%s", (char *)(me_entry_base_dir_ptr->data), (char *)(me_entry_file_name_ptr->data));
    filepath[n] = 0;
    mln_string_nset(&path, filepath, n);
    if ((v = mln_expr_run_file(&path, mln_expr_callback, se)) == NULL) {
        mln_http_status_set(se->resp, M_HTTP_INTERNAL_SERVER_ERROR);
    } else {
        mln_expr_val_free(v);
    }

    if (mln_http_generate(se->resp, &head, &tail) == M_HTTP_RET_ERROR) {
        mln_log(error, "Generate HTTP response failed. %u\n", mln_http_error_get(se->resp));
        me_quit(ev, fd, se);
        return;
    }
    mln_tcp_conn_append_chain(conn, head, tail, M_C_SEND);

    mln_event_fd_set(ev, fd, M_EV_SEND|M_EV_NONBLOCK, M_EV_UNLIMITED, se, me_send);
}

static void me_recv(mln_event_t *ev, int fd, void *data)
{
    me_session_t *se = (me_session_t *)data;
    mln_http_t *http = se->req;
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
                    me_send_response(ev, fd, se);
                } else {
                    mln_log(error, "Http parse error. error_code:%u\n", mln_http_error_get(http));
                    me_quit(ev, fd, data);
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
            me_quit(ev, fd, data);
            return;
        } else if (ret == M_C_ERROR) {
            me_quit(ev, fd, data);
            return;
        }
    }
}

static int me_http_recv_body_handler(mln_http_t *http, mln_chain_t **in, mln_chain_t **nil)
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

static int me_pack_response_body(mln_http_t *http, mln_chain_t **body_head, mln_chain_t **body_tail)
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

static void me_send(mln_event_t *ev, int fd, void *data)
{
    me_session_t *se = (me_session_t *)data;
    mln_http_t *http = se->resp;
    mln_tcp_conn_t *connection = mln_http_connection_get(http);
    mln_chain_t *c = mln_tcp_conn_head(connection, M_C_SEND);
    int ret;

    while ((c = mln_tcp_conn_head(connection, M_C_SEND)) != NULL) {
        ret = mln_tcp_conn_send(connection);
        if (ret == M_C_FINISH) {
            me_quit(ev, fd, data);
            break;
        } else if (ret == M_C_NOTYET) {
            mln_chain_pool_release_all(mln_tcp_conn_remove(connection, M_C_SENT));
            return;
        } else if (ret == M_C_ERROR) {
            me_quit(ev, fd, data);
            return;
        } else {
            mln_log(error, "Shouldn't be here.\n");
            abort();
        }
    }
}

static int me_global_init(void)
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
    if (cc->update(cc, &me_framework_conf, 1) < 0) {
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
    if (cc->update(cc, &me_workerproc_conf, 1) < 0) {
        mln_log(error, "update configuration command 'worker_proc' failed.\n");
        return -1;
    }

    return 0;
}

static void me_parse_args(int argc, char *argv[])
{
    int i;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-a")) {
            if (++i >= argc) goto err;
            me_listen_ip_ptr = argv[i];
        } else if (!strcmp(argv[i], "-p")) {
            if (++i >= argc) goto err;
            me_listen_port = atoi(argv[i]);
            if (me_listen_port <= 0) goto err;
        } else if (!strcmp(argv[i], "-w")) {
            if (++i >= argc) goto err;
            me_workerproc_conf.val.i = atoi(argv[i]);
            if (me_workerproc_conf.val.i <= 0) goto err;
        } else if (!strcmp(argv[i], "-d")) {
            if (++i >= argc) goto err;
            mln_string_set(&me_entry_base_dir_in_param, argv[i]);
            me_entry_base_dir_ptr = &me_entry_base_dir_in_param;
        } else if (!strcmp(argv[i], "-e")) {
            if (++i >= argc) goto err;
            mln_string_set(&me_entry_file_name_in_param, argv[i]);
            me_entry_file_name_ptr = &me_entry_file_name_in_param;
        } else if (!strcmp(argv[i], "-v")) {
            fprintf(stdout, "0.1.0\n");
            exit(0);
        } else if (!strcmp(argv[i], "-D")) {
            me_enable_chroot_flag = 1;
        } else if (!strcmp(argv[i], "-h")) {
            me_help(argv[0]);
        } else {
err:
            fprintf(stderr, "Invalid parameter [%s].\n", argv[i]);
            me_help(argv[0]);
        }
    }

    fprintf(stdout, "Listen: %s:%u\nBase directory: %s\n", (char *)me_listen_ip_ptr, me_listen_port, (char *)(me_entry_base_dir_ptr->data));
}

static void me_help(char *name)
{
    fprintf(stdout, "%s OPTIONS\n", name);
    fprintf(stdout, "\t-a Listen address, 0.0.0.0 as default\n");
    fprintf(stdout, "\t-p Listen port, 80 as default\n");
    fprintf(stdout, "\t-w Worker process number, 1 as default\n");
    fprintf(stdout, "\t-d Base directory path of entry script, '/opt/medge/' as default\n");
    fprintf(stdout, "\t-e Entry expression file, 'index' as default\n");
    fprintf(stdout, "\t-D Enable changing root directory. This parameter only work on user 'root'.\n");
    fprintf(stdout, "\t-v Show version\n");
    fprintf(stdout, "\t-h Show help information\n");
    exit(0);
}

static inline int me_builtin_module_funcs_load(me_func_t *f)
{
    mln_rbtree_node_t *rn;
    for (; f->func != NULL; ++f) {
        if ((rn = mln_rbtree_node_new(me_funcs, f)) == NULL)
            return -1;

        mln_rbtree_insert(me_funcs, rn);
    }
    return 0;
}

static int me_builtin_funcs_load(void)
{
    struct mln_rbtree_attr rbattr;

    rbattr.pool = NULL;
    rbattr.pool_alloc = NULL;
    rbattr.pool_free = NULL;
    rbattr.cmp = (rbtree_cmp)me_func_cmp;
    rbattr.data_free = NULL;
    if ((me_funcs = mln_rbtree_new(&rbattr)) == NULL) {
        return -1;
    }

    if (me_builtin_module_funcs_load(me_request_export()) < 0) return -1;
    if (me_builtin_module_funcs_load(me_response_export()) < 0) return -1;
    if (me_builtin_module_funcs_load(me_file_export()) < 0) return -1;
    if (me_builtin_module_funcs_load(me_string_export()) < 0) return -1;

    return 0;
}

int main(int argc, char *argv[])
{
    struct mln_framework_attr attr;

    me_parse_args(argc, argv);

    if (me_builtin_funcs_load() < 0) {
        mln_log(error, "Load built-in functions failed.\n");
        return -1;
    }

    attr.argc = 0;
    attr.argv = NULL;
    attr.global_init = me_global_init;
    attr.main_thread = NULL;
    attr.master_process = NULL;
    attr.worker_process = me_worker_process;
    return mln_framework_init(&attr);
}

