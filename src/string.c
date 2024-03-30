#include "medge.h"
#include "mln_log.h"
#include "mln_string.h"

static mln_expr_val_t *me_strcmp(me_session_t *se, mln_array_t *args);

static me_func_t string_funcs[] = {
    {mln_string("strcmp"), me_strcmp},
    {mln_string(""), NULL},
};

me_func_t *me_string_export(void)
{
    return string_funcs;
}

static mln_expr_val_t *me_strcmp(me_session_t *se, mln_array_t *args)
{
    mln_expr_val_t *v;
    mln_string_t *s1, *s2;
    mln_u8_t b;

    if (mln_array_nelts(args) != 2) {
        mln_log(error, "Invalid arguments.\n");
        return NULL;
    }

    v = (mln_expr_val_t *)mln_array_elts(args);
    if (v->type != mln_expr_type_string) {
        mln_log(error, "Invalid type of argument 1.\n");
        return NULL;
    }
    s1 = v->data.s;

    v = (mln_expr_val_t *)mln_array_elts(args) + 1;
    if (v->type != mln_expr_type_string) {
        mln_log(error, "Invalid type of argument 2.\n");
        return NULL;
    }
    s2 = v->data.s;

    b = mln_string_strcmp(s1, s2) == 0? 1: 0;
    if ((v =  mln_expr_val_new(mln_expr_type_bool, &b, NULL)) == NULL) {
        mln_log(error, "No memory.\n");
        return NULL;
    }
    return v;
}
