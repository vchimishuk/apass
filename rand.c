#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mem.h"
#include "rand.h"

static char *alphabet = "abcdefghijklmnoprsqtuvwxyz";

char *rand_password(int len)
{
    srandom(time(NULL));

    int alen = strlen(alphabet);
    char *pass = mem_malloc(len + 1);
    pass[len] = '\0';

    for (int i = 0; i < len; i++) {
        pass[i] = alphabet[random() % alen];
    }

    return pass;
}

char *rand_block(size_t size)
{
    srandom(time(NULL));

    char *b = mem_malloc(size);
    for (size_t i = 0; i < size; i++) {
        b[i] = random();
    }

    return b;
}
