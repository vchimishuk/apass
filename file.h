#ifndef FILE_H_
#define FILE_H_

#include "array.h"
#include "error.h"

struct attr {
    char *name;
    char *val;
};

struct record {
    char *name;
    char *pass;
    time_t created;
    time_t modified;
    struct array *attrs;
};

struct error *file_read(char *name, char *pass, struct array **recs);
struct error *file_write(char *name, char *pass, struct array *recs);
void file_free_record(struct record *r);
void file_free_records(struct array *recs);

#endif /* FILE_H_ */
