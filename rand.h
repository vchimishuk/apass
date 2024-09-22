#ifndef RAND_H_
#define RAND_H_

#include <stdbool.h>

char *rand_password(int len, bool sym);
char *rand_block(size_t size);

#endif /* RAND_H_ */
