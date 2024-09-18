#ifndef CRYPT_H_
#define CRYPT_H_

#define CRYPT_CIPHER GCRY_CIPHER_BLOWFISH
#define CRYPT_FLAGS GCRY_CIPHER_CBC_CTS

char *crypt_hash(char *buf, size_t size);
size_t crypt_block_size(void);
char *crypt_encrypt(char *buf, size_t bufsz, char *iv, size_t ivsz, char *pass);
char *crypt_decrypt(char *buf, size_t bufsz, char *iv, size_t ivsz, char *pass);

#endif /* CRYPT_H_ */
