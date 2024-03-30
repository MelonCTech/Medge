#include "medge.h"
#include "mln_log.h"

static mln_expr_val_t *me_get_request_uri(me_session_t *se, mln_array_t *args);

static me_func_t request_funcs[] = {
    {mln_string("getRequestUri"), me_get_request_uri},
    {mln_string(""), NULL},
};

me_func_t *me_request_export(void)
{
    return request_funcs;
}

static mln_expr_val_t *me_get_request_uri(me_session_t *se, mln_array_t *args)
{
    mln_expr_val_t *v;

    if (mln_array_nelts(args)) {
        mln_log(error, "Invalid arguments.\n");
        return NULL;
    }

    if ((v =  mln_expr_val_new(mln_expr_type_string, mln_http_uri_get(se->req), NULL)) == NULL) {
        mln_log(error, "No memory.\n");
        return NULL;
    }
    return v;
}

