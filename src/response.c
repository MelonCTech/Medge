#include "medge.h"
#include "mln_log.h"

static mln_expr_val_t *me_set_response_body(me_session_t *se, mln_array_t *args);

static me_func_t response_funcs[] = {
    {mln_string("setResponseBody"), me_set_response_body},
    {mln_string(""), NULL},
};

me_func_t *me_response_export(void)
{
    return response_funcs;
}

static mln_expr_val_t *me_set_response_body(me_session_t *se, mln_array_t *args)
{
    mln_expr_val_t *v;
    if (mln_array_nelts(args) != 1) {
        mln_log(error, "Invalid arguments.\n");
        return NULL;
    }

    v = (mln_expr_val_t *)mln_array_elts(args);
    if (v->type != mln_expr_type_string) {
        mln_log(error, "Invalid argument type.\n");
        return NULL;
    }

    mln_http_data_set(se->resp, mln_string_ref(v->data.s));
    if ((v = mln_expr_val_dup(v)) == NULL) {
        mln_log(error, "No memory.\n");
        return NULL;
    }
    return v;
}
