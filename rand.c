#include <gcrypt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mem.h"
#include "rand.h"

#define ALPHA "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define NUM "0123456789"
#define SYMB "~`!@#$%^&*()_-+={[}]|\\:;\"\'<,>.?/"

static char *alnum = ALPHA NUM;
static char *alnumsym = ALPHA NUM SYMB;

char *rand_password(int len, bool sym)
{
    char *abc = sym ? alnumsym : alnum;
    size_t abcsz = strlen(abc);
    char *pass = mem_malloc(len + 1);
    pass[len] = '\0';

    unsigned char *bytes = NULL;
    int bytessz = 0;
    for (int i = 0, j = 0; i < len;) {
        if (j >= bytessz) {
            if (bytes) {
                mem_free(bytes);
            }
            bytessz = 1024;
            bytes = gcry_random_bytes(bytessz, GCRY_STRONG_RANDOM);
            j = 0;
        }

        char *p = memchr(abc, bytes[j++], abcsz);
        if (p) {
            pass[i++] = *p;
        }
    }

    mem_free(bytes);

    return pass;
}

char *rand_block(size_t size)
{
    return gcry_random_bytes(size, GCRY_STRONG_RANDOM);
}
