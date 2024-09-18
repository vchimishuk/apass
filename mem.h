#ifndef MEM_H_
#define MEM_H_

#include <stddef.h>
#include <stdlib.h>

void *mem_malloc(size_t size);
void *mem_realloc(void *p, size_t size);
void *mem_free(void *p);
void mem_append(char **buf, size_t *size, char *s);
int mem_nfind(char *buf, size_t size, char c);
char *mem_strdup(char *s);
char *mem_strndup(char *s, size_t n);

#endif /* MEM_H_ */
