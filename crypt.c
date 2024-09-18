#include <gcrypt.h>
#include "crypt.h"
#include "exit.h"
#include "mem.h"
#include "rand.h"

char *crypt_hash(char *buf, size_t len)
{
    char *digest = mem_malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    gcry_md_hash_buffer(GCRY_MD_SHA256, digest, buf, len);

    return digest;
}

size_t crypt_block_size(void)
{
    return gcry_cipher_get_algo_blklen(CRYPT_CIPHER);
}

char *crypt_encrypt(char *buf, size_t bufsz, char *iv, size_t ivsz, char *pass)
{
    gcry_cipher_hd_t hd;
    gcry_error_t err = gcry_cipher_open(&hd, CRYPT_CIPHER,
        GCRY_CIPHER_MODE_CBC, CRYPT_FLAGS);
    if (err != 0) {
        die("gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));
    }

    err = gcry_cipher_setiv(hd, iv, ivsz);
    if (err) {
        die("gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));
    }

    err = gcry_cipher_setkey(hd, pass, strlen(pass));
    if (err) {
        die("gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));
    }

    char *out = mem_malloc(bufsz);
    err = gcry_cipher_encrypt(hd, out, bufsz, buf, bufsz);
    if (err) {
        mem_free(out);
        die("gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));
    }

    gcry_cipher_close(hd);

    return out;
}

char *crypt_decrypt(char *buf, size_t bufsz, char *iv, size_t ivsz, char *pass)
{
    gcry_cipher_hd_t hd;
    gcry_error_t err = gcry_cipher_open(&hd, CRYPT_CIPHER,
        GCRY_CIPHER_MODE_CBC, CRYPT_FLAGS);
    if (err != 0) {
        die("gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));
    }

    err = gcry_cipher_setiv(hd, iv, ivsz);
    if (err) {
        die("gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));
    }

    err = gcry_cipher_setkey(hd, pass, strlen(pass));
    if (err) {
        die("gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));
    }

    char *out = mem_malloc(bufsz);
    err = gcry_cipher_decrypt(hd, out, bufsz, buf, bufsz);
    if (err) {
        mem_free(out);
        die("gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));
    }

    gcry_cipher_close(hd);

    return out;
}
