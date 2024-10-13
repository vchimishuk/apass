#ifndef ARRAY_H_
#define ARRAY_H_

#include <stdlib.h>

struct array {
    void **data;
    size_t size;
};

struct array *array_create(void);
void array_destroy(struct array *arr);
void *array_get(struct array *arr, size_t idx);
void array_append(struct array *arr, void *item);
void array_remove(struct array *arr, size_t idx);

#endif /* ARRAY_H_ */
