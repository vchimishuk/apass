#ifndef FILE_H_
#define FILE_H_

struct attr {
    char *name;
    char *val;
};

struct record {
    char *name;
    char *pass;
    struct attr **attrs;
};

struct record **file_read(char *name, char *pass);
int file_write(char *name, char *pass, struct record **records);
void free_record(struct record *r);
void free_records(struct record **rs);

#endif /* FILE_H_ */
