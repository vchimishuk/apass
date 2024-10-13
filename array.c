#include "array.h"
#include "exit.h"
#include "mem.h"

static void assertidx(struct array *arr, size_t idx)
{
    if (idx < 0 || idx >= arr->size) {
        die("invalid index %d for array of %d", idx, arr->size);
    }
}

struct array *array_create(void) {
    struct array *a = mem_malloc(sizeof(struct array));
    a->data = NULL;
    a->size = 0;

    return a;
}

void array_destroy(struct array *arr)
{
    mem_free(arr);
}

void *array_get(struct array *arr, size_t idx)
{
    assertidx(arr, idx);

    return arr->data[idx];
}

void array_append(struct array *arr, void *item)
{
    arr->size++;
    arr->data = mem_realloc(arr->data, sizeof(void *) * arr->size);
    arr->data[arr->size - 1] = item;
}

void array_remove(struct array *arr, size_t idx)
{
    assertidx(arr, idx);
    arr->data[idx] = NULL;
    for (size_t i = idx + 1; i < arr->size; i++) {
        arr->data[i - 1] = arr->data[i];
    }

    arr->size -= 1;
    arr->data = mem_realloc(arr->data, sizeof(void *) * arr->size);
}
