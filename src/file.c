#include "medge.h"
#include "mln_log.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static mln_expr_val_t *me_read_file(me_session_t *se, mln_array_t *args);

static me_func_t file_funcs[] = {
    {mln_string("readFile"), me_read_file},
    {mln_string(""), NULL},
};

me_func_t *me_file_export(void)
{
    return file_funcs;
}

static mln_expr_val_t *me_read_file(me_session_t *se, mln_array_t *args)
{
    mln_expr_val_t *v;
    mln_s64_t size = -1;
    mln_string_t *data;
    int fd;

    if (mln_array_nelts(args) <= 0 || mln_array_nelts(args) > 2) {
        mln_log(error, "Invalid arguments.\n");
        return NULL;
    }

    if (mln_array_nelts(args) == 2) {
        v = ((mln_expr_val_t *)mln_array_elts(args)) + 1;
        if (v->type != mln_expr_type_int) {
            mln_log(error, "Invalid type of argument 2.\n");
            return NULL;
        }
        size = v->data.i;
    }

    v = ((mln_expr_val_t *)mln_array_elts(args));
    if (v->type != mln_expr_type_string) {
        mln_log(error, "Invalid type of argument 1.\n");
        return NULL;
    }

    if ((fd = open((char *)(v->data.s->data), O_RDONLY)) < 0) {
        mln_log(error, "open file '%S' failed, %s\n", v->data.s, strerror(errno));
        return NULL;
    }
    if (size < 0) {
        struct stat st;
        if (fstat(fd, &st) < 0) {
            mln_log(error, "get file '%S' size failed, %s\n", v->data.s, strerror(errno));
            close(fd);
            return NULL;
        }
        size = st.st_size;
    }
    if ((data = mln_string_alloc(size)) == NULL) {
        mln_log(error, "No memory.\n");
        close(fd);
        return NULL;
    }
    if (read(fd, data->data, size) <= 0) {
        mln_log(error, "read file '%S' failed, %s\n", v->data.s, strerror(errno));
        close(fd);
        return NULL;
    }
    close(fd);

    v = mln_expr_val_new(mln_expr_type_string, data, NULL);
    mln_string_free(data);
    if (v == NULL) {
        mln_log(error, "No memory.\n");
        return NULL;
    }

    return v;
}
