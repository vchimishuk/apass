#ifndef ERROR_H_
#define ERROR_H_

struct error {
    char *msg;
};

struct error *error_create_std(void);
struct error *error_create_silent(void);
struct error *error_create(char *fmt, ...);
void error_destroy(struct error *err);

#endif /* ERROR_H_ */
