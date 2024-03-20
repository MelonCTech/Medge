#ifndef __MEDGE_H
#define __MEDGE_H

#include "mln_http.h"
#include "mln_rbtree.h"
#include "mln_string.h"

typedef struct {
    mln_http_t *req;
    mln_http_t *resp;
    mln_rbtree_t *symbols;
} me_session_t;

typedef struct {
    mln_string_t *name;
    mln_expr_val_t *val;
} me_symbol_t;

extern me_symbol_t *me_symbol_new(mln_string_t *name, mln_expr_val_t *val);
extern void me_symbol_free(me_symbol_t *sym);

#endif
