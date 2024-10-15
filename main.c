#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <readpassphrase.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "exit.h"
#include "file.h"
#include "mem.h"
#include "rand.h"

#define PROG "apass"
#define CLIP "xclip -selection clipboard -wait 5"
#define DEFAULT_PASS_LEN 24
#define PASS_BUF_LEN 256
#define TIME_FMT "%a %b %e %T %Z %Y"

static char dbpass[PASS_BUF_LEN];

static bool yesno(char *msg)
{
    printf("%s", msg);
    printf(" [y/N] ");

    char *ans = NULL;
    size_t nans = 0;
    getline(&ans, &nans, stdin);
    bool yes = strcasecmp("y\n", ans) == 0 || strcasecmp("yes\n", ans) == 0;
    mem_free(ans);

    return yes;
}

static char *password(char *prompt, char *repeat_prompt)
{
    char buf[PASS_BUF_LEN];
    char buf2[PASS_BUF_LEN];

    if (readpassphrase(prompt, buf, sizeof(buf),
            RPP_REQUIRE_TTY) == NULL) {
        die("reading password failed");
    }
    if (readpassphrase(repeat_prompt, buf2, sizeof(buf2),
            RPP_REQUIRE_TTY) == NULL) {
        die("reading password failed");
    }

    if (strcmp(buf, buf2) != 0) {
        return NULL;
    }

    return mem_strdup(buf);
}

static char *clip_cmd(void)
{
    char *clip = getenv("APASS_CLIP");
    if (clip) {
        return mem_strdup(clip);
    }

    return mem_strdup(CLIP);
}

static struct error *clip_copy(char *s)
{
    struct error *err = NULL;
    char *cmd = clip_cmd();
    FILE *p = popen(cmd, "w");
    if (p == NULL) {
        err = error_create_std();
        goto quit;
    }

    int n = fprintf(p, "%s", s);
    if (n < 0) {
        err = error_create_std();
        goto quit;
    }

quit:
    mem_free(cmd);
    if (p) {
        pclose(p);
    }

    return err;
}

static void print_usage(void)
{
    fprintf(stderr, "usage: %s [-h] [-v] [command [opts] [args]]\n", PROG);
}

static void print_usage_get(void)
{
    fprintf(stderr, "usage: %s get [-A] [-a attribute] [-c] name\n", PROG);
}

static void print_usage_info(void)
{
    fprintf(stderr, "usage: %s info name\n", PROG);
}

static void print_usage_list(void)
{
    fprintf(stderr, "usage: %s list\n", PROG);
}

static void print_usage_pass(void)
{
    fprintf(stderr, "usage: %s pass\n", PROG);
}

static void print_usage_remove(void)
{
    fprintf(stderr, "usage: %s remove name\n", PROG);
}

static void print_usage_rename(void)
{
    fprintf(stderr, "usage: %s rename oldname newname\n", PROG);
}

static void print_usage_set(void)
{
    fprintf(stderr, "usage: %s set [-a attribute=value] [-g] [-l] [-p] [-S] "
        "name\n", PROG);
}

static char *home_dir(void)
{
    char *h = getenv("HOME");
    if (h == NULL) {
        struct passwd *pw = getpwuid(getuid());
        if (pw == NULL) {
            die("getpwuid() failed");
        }
        h = pw->pw_dir;
    }

    return mem_strdup(h);
}

static char *xdg_data_dir(void)
{
    char *dir = NULL;

    char *s = getenv("XDG_DATA_HOME");
    if (s != NULL) {
        dir = mem_strdup(s);
    }

    if (dir == NULL) {
        char *h = home_dir();
        dir = mem_strcat(h, "/");
        dir = mem_strcat(dir, ".local/share");
    }

    if (access(dir, F_OK) != 0) {
        mem_free(dir);
        return NULL;
    }

    return dir;
}

static char *db_file(void)
{
    char *db = getenv("APASS_DB");
    if (db) {
        return mem_strdup(db);
    }

    char *dir = xdg_data_dir();
    bool xdg = true;
    if (dir == NULL) {
        dir = home_dir();
        xdg = false;
    }
    char *prdir = mem_strcat(dir, "/");
    if (!xdg) {
        prdir = mem_strcat(prdir, ".");
    }
    prdir = mem_strcat(prdir, PROG);

    if (access(prdir, F_OK) != 0) {
        if (mkdir(prdir, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
            mem_free(prdir);
            die("%s: %s", prdir, strerror(errno));
        }
    }

    prdir = mem_strcat(prdir, "/");
    prdir = mem_strcat(prdir, PROG);
    prdir = mem_strcat(prdir, ".db");

    return prdir;
}

static int valid_name(char *s)
{
    for (char *p = s; *p != '\0'; p++) {
        if (!isprint(*p) || isspace(*p)) {
            return 0;
        }
    }

    return 1;
}

static char *sanitize_value(char *s)
{
    char *p = mem_strdup(s);
    for (char *q = p; *q != '\0'; q++) {
        if (*q == '\n') {
            *q = ' ';
        }
    }

    return p;
}

static struct error *readpassword(void)
{
    if (readpassphrase("Password: ", dbpass, sizeof(dbpass),
            RPP_REQUIRE_TTY) == NULL) {
        return error_create("reading password failed");
    }
    if (strlen(dbpass) < 3) {
        return error_create("password too short");
    }

    return NULL;
}

static struct error *cmd_get(int argc, char **argv)
{
    const size_t bufsz = 1024;
    size_t bufoff = 0;
    char buf[bufsz];
    int n;

    bool all = false;
    bool clip = false;
    char *attr = NULL;

    int ch;
    while ((ch = getopt(argc, argv, "Aa:c")) != -1) {
        switch (ch) {
        case 'A':
            all = true;
            break;
        case 'a':
            attr = optarg;
            break;
        case 'c':
            clip = true;
            break;
        default:
            print_usage_get();
            return error_create_silent();
        }
    }

    if (optind != argc - 1) {
        print_usage_get();
        return error_create_silent();
    }
    char *name = argv[optind];
    char *fname = db_file();
    struct array *recs = NULL;
    struct error *err = NULL;

    err = readpassword();
    if (err) {
        goto quit;
    }

    err = file_read(fname, dbpass, &recs);
    if (err) {
        goto quit;
    }

    struct record *rec = NULL;
    for (size_t i = 0; i < recs->size; i++) {
        struct record *r = array_get(recs, i);
        if (strcmp(r->name, name) == 0) {
            rec = r;
            break;
        }
    }
    if (rec == NULL) {
        err = error_create("%s: no such record", name);
        goto quit;
    }

    buf[0] = '\0';
    if (all || attr == NULL) {
        n = snprintf(buf + bufoff, bufsz - bufoff, "%s", rec->pass);
        if (bufoff > bufsz) {
            die("snprintf");
        }
        bufoff += n;
    }
    for (size_t i = 0; i < rec->attrs->size; i++) {
        struct attr *a = array_get(rec->attrs, i);
        if (all && i == 0) {
            bufoff += snprintf(buf + bufoff, bufsz - bufoff, "\n");
            if (bufoff > bufsz) {
                die("snprintf");
            }
        }
        if (all) {
            bufoff += snprintf(buf + bufoff, bufsz - bufoff, "%s=", a->name);
            if (bufoff > bufsz) {
                die("snprintf");
            }
        }
        if (all || (attr && strcmp(a->name, attr) == 0)) {
            bufoff += snprintf(buf + bufoff, bufsz - bufoff, "%s", a->val);
            if (bufoff > bufsz) {
                die("snprintf");
            }
        }
        if (all && i < rec->attrs->size - 1) {
            bufoff += snprintf(buf + bufoff, bufsz - bufoff, "\n");
            if (bufoff > bufsz) {
                die("snprintf");
            }
        }
    }

    if (clip) {
        clip_copy(buf);
    } else {
        printf("%s\n", buf);
    }

quit:
    mem_free(fname);
    file_free_records(recs);

    return err;
}

static struct error *cmd_info(int argc, char **argv)
{
    if (argc != 2) {
        print_usage_info();
        return error_create_silent();
    }

    struct error *err = NULL;
    struct array *recs = NULL;
    char *name = argv[1];
    char *fname = db_file();
    char buf[256];
    struct tm *tm;

    err = readpassword();
    if (err) {
        goto quit;
    }

    err = file_read(fname, dbpass, &recs);
    if (err) {
        goto quit;
    }

    struct record *rec = NULL;
    for (size_t i = 0; i < recs->size; i++) {
        struct record *r = array_get(recs, i);
        if (strcmp(r->name, name) == 0) {
            rec = r;
            break;
        }
    }
    if (rec == NULL) {
        err = error_create("%s: no such record", name);
        goto quit;
    }

    tm = localtime(&rec->created);
    strftime(buf, sizeof(buf), TIME_FMT, tm);
    printf("Creation time: %s\n", buf);

    tm = localtime(&rec->modified);
    strftime(buf, sizeof(buf), TIME_FMT, tm);
    printf("Modification time: %s\n", buf);

quit:
    mem_free(fname);
    file_free_records(recs);

    return err;
}

static struct error *cmd_list(int argc, __attribute__((unused)) char **argv)
{
    if (argc != 1) {
        print_usage_list();
        return error_create_silent();
    }

    struct error *err;
    struct array *recs = NULL;
    char *fname = db_file();

    err = readpassword();
    if (err) {
        goto quit;
    }

    err = file_read(fname, dbpass, &recs);
    if (err) {
        goto quit;
    }

    for (size_t i = 0; i < recs->size; i++) {
        struct record *r = array_get(recs, i);
        printf("%s\n", r->name);
    }

quit:
    mem_free(fname);
    file_free_records(recs);

    return err;
}

static struct error *cmd_pass(int argc, __attribute__((unused)) char **argv)
{
    if (argc != 1) {
        print_usage_pass();
        return error_create_silent();
    }

    struct error *err = NULL;
    char *fname = db_file();
    char *pass = NULL;
    struct array *recs = NULL;

    err = readpassword();
    if (err) {
        goto quit;
    }

    err = file_read(fname, dbpass, &recs);
    if (err) {
        goto quit;
    }

    pass = password("New password: ", "Repeat new password: ");
    if (pass == NULL) {
        err = error_create("Passwords missmatch! Aborting.");
        goto quit;
    }

    strlcpy(dbpass, pass, PASS_BUF_LEN);

    err = file_write(fname, dbpass, recs);
    if (err) {
        goto quit;
    }

quit:
    mem_free(fname);
    mem_free(pass);
    file_free_records(recs);

    return err;
}

static struct error *cmd_remove(int argc, char **argv)
{
    if (argc != 2) {
        print_usage_remove();
        return error_create_silent();
    }

    struct error *err = NULL;
    char *name = argv[1];
    char *fname = NULL;
    struct array *recs = NULL;

    err = readpassword();
    if (err) {
        goto quit;
    }

    fname = db_file();
    err = file_read(fname, dbpass, &recs);
    if (err) {
        goto quit;
    }

    int idx = -1;
    for (size_t i = 0; i < recs->size; i++) {
        struct record *r = array_get(recs, i);
        if (strcmp(r->name, name) == 0) {
            idx = i;
        }
    }
    if (idx == -1) {
        err = error_create("%s: no such record", name);
        goto quit;
    }
    file_free_record(array_get(recs, idx));
    array_remove(recs, idx);

    err = file_write(fname, dbpass, recs);
    if (err) {
        goto quit;
    }

quit:
    mem_free(fname);
    file_free_records(recs);

    return err;
}

static struct error *cmd_rename(int argc, char **argv)
{
    if (argc != 3) {
        print_usage_rename();
        return error_create_silent();
    }

    char *oldname = argv[1];
    char *newname = argv[2];

    struct error *err = NULL;
    struct array *recs = NULL;
    char *fname = db_file();

    err = readpassword();
    if (err) {
        goto quit;
    }

    err = file_read(fname, dbpass, &recs);
    if (err) {
        goto quit;
    }

    struct record *rec = NULL;
    for (size_t i = 0; i < recs->size; i++) {
        struct record *r = array_get(recs, i);
        if (strcmp(r->name, oldname) == 0) {
            rec = r;
            break;
        }
    }
    if (rec == NULL) {
        err = error_create("%s: no such record", oldname);
        goto quit;
    }
    mem_free(rec->name);
    rec->name = mem_strdup(newname);

    err = file_write(fname, dbpass, recs);
    if (err) {
        goto quit;
    }

quit:
    mem_free(fname);
    file_free_records(recs);

    return err;
}

static struct error *cmd_set(int argc, char **argv)
{
    struct error *err = NULL;
    bool generate = false;
    bool setpass = false;
    bool sym = true;
    long len = DEFAULT_PASS_LEN;

    struct array *attr_names = array_create();
    struct array *attr_vals = array_create();

    int ch;
    while ((ch = getopt(argc, argv, "a:gl:pS")) != -1) {
        char *p;
        switch (ch) {
        case 'a':
            p = strstr(optarg, "=");
            if (p == NULL) {
                return error_create("%s: invalid attribute format", optarg);
            }
            char *aname = mem_strndup(optarg, p - optarg);
            if (!valid_name(aname)) {
                err = error_create("%s: invalid attribute", aname);
                free(aname);
                return err;
            }
            array_append(attr_names, aname);
            array_append(attr_vals, sanitize_value(p + 1));
            break;
        case 'g':
            generate = true;
            break;
        case 'l':
            len = strtol(optarg, NULL, 10);
            if (errno != 0 || len < 1 || len > 256) {
                return error_create("%s: invalid length", optarg);
            }
            break;
        case 'p':
            setpass = true;
            break;
        case 'S':
            sym = false;
            break;
        default:
            print_usage_set();
            return error_create_silent();
        }
    }

    char *fname = db_file();
    struct array *recs = NULL;

    // Default mode is set password even if -p flag is not specified.
    if (attr_names->size == 0) {
        setpass = true;
    }

    if (optind != argc - 1) {
        print_usage_set();
        err = error_create_silent();
        goto quit;
    }

    char *name = argv[optind];
    if (!valid_name(name)) {
        err = error_create("%s: invalid name", name);
        goto quit;
    }

    err = readpassword();
    if (err) {
        goto quit;
    }

    err = file_read(fname, dbpass, &recs);
    if (err) {
        goto quit;
    }

    struct record *rec = NULL;
    for (size_t i = 0; i < recs->size; i++) {
        struct record *r = array_get(recs, i);
        if (strcmp(r->name, name) == 0) {
            rec = r;
        }
    }

    if (rec == NULL) {
        rec = mem_malloc(sizeof(struct record));
        rec->name = mem_strdup(name);
        rec->pass = NULL;
        rec->created = time(NULL);
        rec->modified = rec->created;
        rec->attrs = array_create();
        array_append(recs, rec);

        // Force to set password for the new record.
        setpass = true;
    }

    if (setpass) {
        if (rec->pass != NULL) {
            bool replace = yesno("Password already exists. Overwrite it?");
            if (!replace) {
                goto quit;
            }
        }

        char *pass;
        if (generate) {
            pass = rand_password(len, sym);
        } else {
            int n;
            char *prompt;
            char *repeat_prompt;
            n = asprintf(&prompt, "New password for `%s`: ", name);
            if (n < 0) {
                die("asprintf");
            }
            n = asprintf(&repeat_prompt, "Repeat new password for `%s`: ", name);
            if (n < 0) {
                die("asprintf");
            }

            pass = password(prompt, repeat_prompt);
            mem_free(prompt);
            mem_free(repeat_prompt);
            if (pass == NULL) {
                err = error_create("Passwords missmatch! Aborting.");
                goto quit;
            }
        }
        mem_free(rec->pass);
        rec->pass = pass;
        rec->modified = time(NULL);
    }

    for (size_t i = 0; i < attr_names->size; i++) {
        char *name = array_get(attr_names, i);
        struct attr *attr = NULL;

        for (size_t j = 0; j < rec->attrs->size; j++) {
            struct attr *a = array_get(rec->attrs, j);
            if (strcmp(a->name, name) == 0) {
                attr = a;
            }
        }

        if (attr == NULL) {
            attr = mem_malloc(sizeof(struct attr));
            attr->name = name;
            attr->val = array_get(attr_vals, i);
            array_append(rec->attrs, attr);
        } else {
            bool replace = yesno("Attribute already exists. Overwrite it?");
            if (!replace) {
                goto quit;
            }

            mem_free(attr->val);
            attr->val = mem_strdup(array_get(attr_vals, i));
        }
    }

    err = file_write(fname, dbpass, recs);
    if (err) {
        goto quit;
    }

quit:
    mem_free(fname);
    file_free_records(recs);

    for (size_t i = 0; i < attr_names->size; i++) {
        mem_free(array_get(attr_names, i));
        mem_free(array_get(attr_vals, i));
    }
    array_destroy(attr_names);
    array_destroy(attr_vals);

    return err;
}

struct command {
    char *name;
    struct error *(*exec)(int, char **);
};

struct command commands[] = {
    {"get", cmd_get},
    {"info", cmd_info},
    {"list", cmd_list},
    {"pass", cmd_pass},
    {"remove", cmd_remove},
    {"rename", cmd_rename},
    {"set", cmd_set},
    {NULL, NULL},
};

static struct command *find_command(char *name)
{
    for (struct command *c = commands; c->name != NULL; c++) {
        if (strcmp(c->name, name) == 0) {
            return c;
        }
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        print_usage();
        return EXIT_FAILURE;
    }

    struct error *err = NULL;
    struct command *cmd = find_command(argv[1]);
    int cargc;
    char **cargv;
    if (cmd != NULL) {
        cargc = argc - 1;
        cargv = argv + 1;
    } else {
        cmd = find_command("get");
        if (cmd == NULL) {
            die("find_command");
        }
        cargc = argc;
        cargv = argv;
    }

    umask(S_IWGRP | S_IRGRP | S_IWOTH | S_IROTH);

    err = cmd->exec(cargc, cargv);
    if (err) {
        if (err->msg) {
            fprintf(stderr, "%s: %s\n", PROG, err->msg);
        }
        error_destroy(err);

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
