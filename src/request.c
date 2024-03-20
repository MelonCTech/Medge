#include "medge.h"

static me_func_t request_funcs[] = {
    {mln_string(""), NULL},
};

me_func_t *me_request_export(void)
{
    return request_funcs;
}
