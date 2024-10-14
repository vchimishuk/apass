#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "crypt.h"
#include "exit.h"
#include "file.h"
#include "mem.h"
#include "rand.h"

// FILE FORMAT:
// +-------------------------+
// |  initialization vector  |
// +-------------------------+  ----+
// |     SHA256 checksum     |      |
// +-------------------------+      +- encrypted
// |        records          |      |
// +-------------------------+  ----+

static void serialize(char **buf, size_t *size, struct array *recs)
{
    struct tm *tm;
    size_t n;
    char tbuf[256];

    *buf = NULL;
    for (size_t i = 0; i < recs->size; i++) {
        struct record *r = array_get(recs, i);
        mem_append(buf, size, r->name);
        mem_append(buf, size, "\n");
        mem_append(buf, size, r->pass);
        mem_append(buf, size, "\n");

        tm = localtime(&r->created);
        n = strftime(tbuf, sizeof(tbuf), "%s\n", tm);
        if (n == 0) {
            die("strftime");
        }
        mem_append(buf, size, tbuf);

        tm = localtime(&r->modified);
        n = strftime(tbuf, sizeof(tbuf), "%s\n", tm);
        if (n == 0) {
            die("strftime");
        }
        mem_append(buf, size, tbuf);

        for (size_t j = 0; j < r->attrs->size; j++) {
            struct attr *a = array_get(r->attrs, j);
            mem_append(buf, size, a->name);
            mem_append(buf, size, "=");
            mem_append(buf, size, a->val);
            mem_append(buf, size, "\n");
        }

        mem_append(buf, size, "\n");
    }
}

struct error *deserialize(char *buf, size_t size, struct array **recs)
{
    struct error *err = NULL;
    struct tm tm;
    char *p = buf;
    int s = size;
    int n;

    struct array *rs = array_create();
    while ((n = mem_nfind(p, s, '\n')) > 0) {
        struct record *r = mem_malloc(sizeof(struct record));
        r->attrs = array_create();

        r->name = mem_strndup(p, n);
        p += n + 1;
        s -= n + 1;
        if (s <= 0) {
            err = error_create("invalid file format");
            goto quit;
        }

        n = mem_nfind(p, s, '\n');
        if (n <= 0) {
            err = error_create("invalid file format");
            goto quit;
        }
        r->pass = mem_strndup(p, n);
        p += n + 1;
        s -= n + 1;
        if (s <= 0) {
            err = error_create("invalid file format");
            goto quit;
        }

        n = mem_nfind(p, s, '\n');
        if (n <= 0) {
            err = error_create("invalid file format");
            goto quit;
        }
        if (strptime(p, "%s", &tm) == NULL) {
            err = error_create("invalid file format");
            goto quit;
        }
        r->created = mktime(&tm);
        p += n + 1;
        s -= n + 1;

        n = mem_nfind(p, s, '\n');
        if (n <= 0) {
            err = error_create("invalid file format");
            goto quit;
        }
        if (strptime(p, "%s", &tm) == NULL) {
            err = error_create("invalid file format");
            goto quit;
        }
        r->modified = mktime(&tm);
        p += n + 1;
        s -= n + 1;

        while ((n = mem_nfind(p, s, '\n')) != -1) {
            if (n == 0) {
                p += 1;
                s -= 1;
                break;
            }

            struct attr *a = mem_malloc(sizeof(struct attr));
            n = mem_nfind(p, s, '=');
            a->name = mem_strndup(p, n);
            p += n + 1;
            s -= n + 1;
            if (s <= 0) {
                err = error_create("invalid file format");
                goto quit;
            }

            n = mem_nfind(p, s, '\n');
            a->val = mem_strndup(p, n);
            p += n + 1;
            s -= n + 1;
            if (s <= 0) {
                err = error_create("invalid file format");
                goto quit;
            }

            array_append(r->attrs, a);
        }

        array_append(rs, r);
    }

quit:
    if (err) {
        file_free_records(rs);
    } else {
        *recs = rs;
    }

    return err;
}

struct error *file_read(char *name, char *pass, struct array **recs)
{
    FILE *f = fopen(name, "r");
    if (f == NULL) {
        // File absence is equals to an empty file.
        if (errno == ENOENT) {
            *recs = array_create();
            return NULL;
        } else {
            return error_create_std();
        }
    }

    struct error *err = NULL;
    char *buf = NULL;
    char *data = NULL;
    char *body_hash = NULL;

    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        err = error_create_std();
        goto quit;
    }
    size_t fsize = st.st_size;
    if (fsize > 10 * 1024 * 1024) {
        err = error_create("%s: file is too big", name);
        goto quit;
    }

    size_t blksz = crypt_block_size();
    size_t hashsz = crypt_hash_len();
    if (fsize < blksz + hashsz) {
        err = error_create("%s: file is too small", name);
        goto quit;
    }

    buf = mem_malloc(fsize);
    fread(buf, fsize, 1, f);
    if (ferror(f) > 0) {
        err = error_create_std();
        goto quit;
    }

    char *iv = buf;
    char *edata = buf + blksz;
    size_t edatasz = fsize - blksz;
    data = crypt_decrypt(edata, edatasz, iv, blksz, pass);
    char *hash = data;
    char *body = data + hashsz;
    size_t bodysz = edatasz - hashsz;

    body_hash = crypt_hash(body, bodysz);
    if (memcmp(body_hash, hash, hashsz) != 0) {
        err = error_create("invalid password");
        goto quit;
    }

    err = deserialize(body, bodysz, recs);

quit:
    mem_free(buf);
    mem_free(data);
    mem_free(body_hash);
    fclose(f);

    return err;
}

struct error *file_write(char *name, char *pass, struct array *recs)
{
    struct error *err = NULL;
    char *s = NULL;
    size_t ssz = 0;
    serialize(&s, &ssz, recs);
    char *h = crypt_hash(s, ssz);
    size_t hsz = crypt_hash_len();

    size_t datasz = ssz + hsz;
    char *data = mem_malloc(datasz);
    memcpy(data, h, hsz);
    memcpy(data + hsz, s, ssz);
    mem_free(s);
    mem_free(h);

    size_t blksz = crypt_block_size();
    char *iv = rand_block(blksz);
    char *edata = crypt_encrypt(data, datasz, iv, blksz, pass);

    int n = 0;
    char *tmpname = mem_strcat(name, ".new");
    FILE *f = fopen(tmpname, "w");
    if (f == NULL) {
        err = error_create_std();
        goto quit;
    }
    n = fwrite(iv, blksz, 1, f);
    if (n != 1) {
        err = error_create_std();
        goto quit;
    }
    n = fwrite(edata, datasz, 1, f);
    if (n != 1) {
        err = error_create_std();
        goto quit;
    }
    fclose(f);

    n = rename(tmpname, name);
    if (n != 0) {
        err = error_create_std();
        goto quit;
    }

quit:
    mem_free(iv);
    mem_free(data);
    mem_free(edata);
    mem_free(tmpname);

    return err;
}

void file_free_record(struct record *r)
{
    mem_free(r->name);
    mem_free(r->pass);

    for (size_t i = 0; i < r->attrs->size; i++) {
        struct attr *a = array_get(r->attrs, i);
        mem_free(a->name);
        mem_free(a->val);
        mem_free(a);
    }
    array_destroy(r->attrs);
    mem_free(r);
}

void file_free_records(struct array *recs)
{
    if (recs == NULL) {
        return;
    }
    for (size_t i = 0; i < recs->size; i++) {
        file_free_record(array_get(recs, i));
    }
    array_destroy(recs);
}
