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

static void serialize(char **buf, size_t *size, struct record **records)
{
    for (struct record **r = records; *r != NULL; r++) {
        mem_append(buf, size, (*r)->name);
        mem_append(buf, size, "\n");
        mem_append(buf, size, (*r)->pass);
        mem_append(buf, size, "\n");

        for (struct attr **a = (*r)->attrs; *a != NULL; a++) {
            mem_append(buf, size, (*a)->name);
            mem_append(buf, size, "=");
            mem_append(buf, size, (*a)->val);
            mem_append(buf, size, "\n");
        }

        mem_append(buf, size, "\n");
    }
}

static struct record **deserialize(char *buf, size_t size)
{
    char *p = buf;
    int s = size;
    int n;

    struct record **rs = mem_malloc(sizeof(struct record *));
    rs[0] = NULL;
    int nrs = 0;
    while ((n = mem_nfind(p, s, '\n')) > 0) {
        struct record *r = mem_malloc(sizeof(struct record));
        r->name = mem_strndup(p, n);
        p += n + 1;
        s -= n + 1;
        if (s <= 0) {
            die("invalid file format");
        }

        n = mem_nfind(p, s, '\n');
        r->pass = mem_strndup(p, n);
        p += n + 1;
        s -= n + 1;
        if (s <= 0) {
            die("invalid file format");
        }

        r->attrs = mem_malloc(sizeof(struct attr *));
        r->attrs[0] = NULL;
        int na = 0;
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
                die("invalid file format");
            }

            n = mem_nfind(p, s, '\n');
            a->val = mem_strndup(p, n);
            p += n + 1;
            s -= n + 1;
            if (s <= 0) {
                die("invalid file format");
            }

            na++;
            r->attrs = mem_realloc(r->attrs, sizeof(struct attr *) * (na + 1));
            r->attrs[na - 1] = a;
            r->attrs[na] = NULL;
        }

        nrs++;
        rs = mem_realloc(rs, sizeof(struct record *) * (nrs + 1));
        rs[nrs - 1] = r;
        rs[nrs] = NULL;
    }

    return rs;
}

struct record **file_read(char *name, char *pass)
{
    FILE *f = fopen(name, "r");
    if (f == NULL) {
        if (errno == ENOENT) {
            struct record **rs = mem_malloc(sizeof(struct record *));
            rs[0] = NULL;
            return rs;
        } else {
            return NULL;
        }
    }

    struct record **recs = NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        goto exit;
    }
    size_t fsize = st.st_size;
    if (fsize > 10 * 1024 * 1024) {
        die("%s: file is too big", name);
    }

    size_t blksz = crypt_block_size();
    size_t hashsz = crypt_hash_len();
    if (fsize < blksz + hashsz) {
        die("%s: file is too small", name);
    }

    char *buf = mem_malloc(fsize);
    fread(buf, fsize, 1, f);
    if (ferror(f) > 0) {
        goto exit;
    }

    char *iv = buf;
    char *edata = buf + blksz;
    size_t edatasz = fsize - blksz;
    char *data = crypt_decrypt(edata, edatasz, iv, blksz, pass);
    char *hash = data;
    char *body = data + hashsz;
    size_t bodysz = edatasz - hashsz;

    char *body_hash = crypt_hash(body, bodysz);
    if (memcmp(body_hash, hash, hashsz) != 0) {
        die("%s: file integrity check failed", name);
    }

    recs = deserialize(body, bodysz);
    mem_free(buf);
    mem_free(data);
    mem_free(body_hash);

exit:
    fclose(f);

    return recs;
}

int file_write(char *name, char *pass, struct record **records)
{
    char *s = NULL;
    size_t ssz = 0;
    serialize(&s, &ssz, records);
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
        goto quit;
    }
    n = fwrite(iv, blksz, 1, f);
    if (n != 1) {
        n = -1;
        goto quit;
    }
    n = fwrite(edata, datasz, 1, f);
    if (n != 1) {
        n = -1;
        goto quit;
    }
    fclose(f);

    n = rename(tmpname, name);

quit:
    mem_free(iv);
    mem_free(data);
    mem_free(edata);
    mem_free(tmpname);

    return n;
}

void free_records(struct record **rs)
{
    for (struct record **r = rs; *r != NULL; r++) {
        mem_free((*r)->name);
        mem_free((*r)->pass);
        for (struct attr **a = (*r)->attrs; *a != NULL; a++) {
            mem_free((*a)->name);
            mem_free((*a)->val);
            mem_free(*a);
        }
        mem_free((*r)->attrs);
        mem_free(*r);
    }
    mem_free(rs);
}
