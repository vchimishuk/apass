#include <stdlib.h>
#include <string.h>
#include "exit.h"

void *mem_malloc(size_t size)
{
    void *p = malloc(size);
    if (p == NULL) {
        die("malloc failed");
    }

    return p;
}

void *mem_realloc(void *p, size_t size)
{
    void *q = realloc(p, size);
    if (q == NULL) {
        die("realloc failed");
    }

    return q;
}

void mem_free(void *p)
{
    free(p);
}

void mem_append(char **buf, size_t *size, char *s)
{
    size_t n = strlen(s);
    *buf = realloc(*buf, *size + n);
    if (buf == NULL) {
        die("realloc failed");
    }
    memcpy(*buf + *size, s, n);
    *size += n;
}

int mem_nfind(char *buf, size_t size, char c)
{
    for (size_t i = 0; i < size; i++) {
        if (buf[i] == c) {
            return i;
        }
    }

    return -1;
}

char *mem_strdup(char *s)
{
    char *p = strdup(s);
    if (p == NULL) {
        die("strdup failed");
    }

    return p;
}

char *mem_strndup(char *s, size_t n)
{
    char *p = strndup(s, n);
    if (p == NULL) {
        die("strndup failed");
    }

    return p;
}
