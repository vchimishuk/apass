#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "error.h"
#include "mem.h"

struct error *error_create_std(void)
{
    return error_create("%s", strerror(errno));
}

struct error *error_create_silent(void)
{
    struct error *err = mem_malloc(sizeof(struct error));
    err->msg = NULL;

    return err;
}

struct error *error_create(char *fmt, ...)
{
    struct error *err = mem_malloc(sizeof(struct error));

    va_list ap;
    va_start(ap, fmt);
    vasprintf(&(err->msg), fmt, ap);
    va_end(ap);

    return err;
}

void error_destroy(struct error *err)
{
    if (err == NULL) {
        return;
    }

    mem_free(err->msg);
    mem_free(err);
}
