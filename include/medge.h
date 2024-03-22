#ifndef __MEDGE_H
#define __MEDGE_H

#include "mln_http.h"
#include "mln_rbtree.h"
#include "mln_string.h"
#include "mln_expr.h"

typedef struct me_session_s me_session_t;
typedef mln_expr_val_t *(*me_func_impl_t)(me_session_t *, mln_array_t *);

struct me_session_s {
    mln_http_t     *req;
    mln_http_t     *resp;
    mln_rbtree_t   *symbols;
};

typedef struct {
    mln_string_t   *name;
    mln_expr_val_t *val;
} me_symbol_t;

typedef struct {
    mln_string_t    name;
    me_func_impl_t  func;
} me_func_t;

extern me_symbol_t *me_symbol_new(mln_string_t *name, mln_expr_val_t *val);
extern void me_symbol_free(me_symbol_t *sym);

extern me_func_t *me_request_export(void);
extern me_func_t *me_response_export(void);
extern me_func_t *me_file_export(void);

#endif
