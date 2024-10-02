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

#define DEFAULT_PASS_LEN 24

static char *prog = "apass";
static char dbpass[256];

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

static char *password(void)
{
    char buf[256];
    char buf2[256];

    if (readpassphrase("Password: ", buf, sizeof(buf),
            RPP_REQUIRE_TTY) == NULL) {
        die("reading password failed");
    }
    if (readpassphrase("Repeat password: ", buf2, sizeof(buf2),
            RPP_REQUIRE_TTY) == NULL) {
        die("reading password failed");
    }

    if (strcmp(buf, buf2) != 0) {
        return NULL;
    }

    return mem_strdup(buf);
}

static int error(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "apass: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    return EXIT_FAILURE;
}

static int usage_get(void)
{
    fprintf(stderr, "usage: %s get [-A] [-a attribute] name\n", prog);

    return EXIT_FAILURE;
}

static int usage_list(void)
{
    fprintf(stderr, "usage: %s list\n", prog);

    return EXIT_FAILURE;
}

static int usage_remove(void)
{
    fprintf(stderr, "usage: %s remove name\n", prog);

    return EXIT_FAILURE;
}

static int usage_rename(void)
{
    fprintf(stderr, "usage: %s rename oldname newname\n", prog);

    return EXIT_FAILURE;
}

static int usage_set(void)
{
    fprintf(stderr, "usage: %s set [-a attribute=value] [-g] [-l] [-p] [-S] "
        "name\n", prog);

    return EXIT_FAILURE;
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
    prdir = mem_strcat(prdir, prog);

    if (access(prdir, F_OK) != 0) {
        if (mkdir(prdir, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
            mem_free(prdir);
            die("%s: %s", prdir, strerror(errno));
        }
    }

    prdir = mem_strcat(prdir, "/");
    prdir = mem_strcat(prdir, prog);
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

static int cmd_get(int argc, char **argv)
{
    bool all = false;
    char *attr = NULL;

    int ch;
    while ((ch = getopt(argc, argv, "Aa:")) != -1) {
        switch (ch) {
        case 'A':
            all = true;
            break;
        case 'a':
            attr = optarg;
            break;
        default:
            return usage_get();
        }
    }

    if (optind != argc - 1) {
        return usage_get();
    }
    char *name = argv[optind];

    char *fname = db_file();
    struct record **recs = file_read(fname, dbpass);
    mem_free(fname);
    if (recs == NULL) {
        return error(strerror(errno));
    }

    struct record *rec = NULL;
    for (struct record **r = recs; *r != NULL; r++) {
        if (strcmp((*r)->name, name) == 0) {
            rec = *r;
            break;
        }
    }
    if (rec == NULL) {
        file_free_records(recs);
        return error("%s: no such record", name);
    }

    if (all || attr == NULL) {
        printf("%s\n", rec->pass);
    }
    for (struct attr **a = rec->attrs; *a != NULL; a++) {
        if (all) {
            printf("%s=", (*a)->name);
        }
        if (all || (attr && strcmp((*a)->name, attr) == 0)) {
            printf("%s\n", (*a)->val);
        }
    }

    file_free_records(recs);

    return 0;
}

static int cmd_list(int argc, __attribute__((unused)) char **argv)
{
    if (argc != 1) {
        return usage_list();
    }

    char *fname = db_file();
    struct record **recs = file_read(fname, dbpass);
    mem_free(fname);
    if (recs == NULL) {
        return error(strerror(errno));
    }

    for (struct record **r = recs; *r != NULL; r++) {
        printf("%s\n", (*r)->name);
    }

    file_free_records(recs);

    return 0;
}

static int cmd_remove(int argc, char **argv)
{
    if (argc != 2) {
        return usage_remove();
    }

    int ret = 0;
    char *name = argv[1];
    char *fname = NULL;
    struct record **recs = NULL;

    fname = db_file();
    recs = file_read(fname, dbpass);
    if (recs == NULL) {
        ret = error(strerror(errno));
        goto quit;
    }

    int k = -1;
    int i = 0;
    for (; recs[i] != NULL; i++) {
        if (strcmp(recs[i]->name, name) == 0) {
            k = i;
        }
    }
    if (k == -1) {
        ret = error("%s: no such record");
        goto quit;
    }
    file_free_record(recs[k]);
    recs[k] = NULL;
    if (k < i - 1) {
        recs[k] = recs[i - 1];
        recs[i - 1] = NULL;
    }

    if (file_write(fname, dbpass, recs) != 0) {
        ret = error(strerror(errno));
        goto quit;
    }

quit:
    mem_free(fname);
    file_free_records(recs);

    return ret;
}

static int cmd_rename(int argc, char **argv)
{
    if (argc != 3) {
        return usage_rename();
    }

    char *oldname = argv[1];
    char *newname = argv[2];

    int ret = 0;
    char *fname = db_file();
    struct record **recs = file_read(fname, dbpass);
    if (recs == NULL) {
        ret = error(strerror(errno));
        goto quit;
    }

    struct record *rec = NULL;
    for (struct record **r = recs; *r != NULL; r++) {
        if (strcmp((*r)->name, oldname) == 0) {
            rec = *r;
            break;
        }
    }
    if (rec == NULL) {
        ret = error("%s: no such record");
        goto quit;
    }
    mem_free(rec->name);
    rec->name = mem_strdup(newname);

    if (file_write(fname, dbpass, recs) != 0) {
        ret = error(strerror(errno));
        goto quit;
    }

quit:
    mem_free(fname);
    file_free_records(recs);

    return ret;
}

static int cmd_set(int argc, char **argv)
{
    int ret = 0;
    bool generate = false;
    bool setpass = false;
    bool sym = true;
    long len = DEFAULT_PASS_LEN;

    int nattrs = 0;
    char **attrs = mem_malloc(sizeof(char *));
    attrs[0] = NULL;
    char **attrvs = mem_malloc(sizeof(char *));
    attrvs[0] = NULL;

    int ch;
    while ((ch = getopt(argc, argv, "a:gl:pS")) != -1) {
        char *p;
        switch (ch) {
        case 'a':
            p = strstr(optarg, "=");
            if (p == NULL) {
                return error("%s: invalid attribute format", optarg);
            }
            char *aname = mem_strndup(optarg, p - optarg);
            if (!valid_name(aname)) {
                int err = error("%s: invalid attribute", aname);
                free(aname);
                return err;
            }
            nattrs++;
            attrs = mem_realloc(attrs, sizeof(char *) * (nattrs + 1));
            attrs[nattrs - 1] = aname;
            attrs[nattrs] = NULL;
            attrvs = mem_realloc(attrvs, sizeof(char *) * (nattrs + 1));
            attrvs[nattrs - 1] = sanitize_value(p + 1);
            attrvs[nattrs] = NULL;
            break;
        case 'g':
            generate = true;
            break;
        case 'l':
            len = strtol(optarg, NULL, 10);
            if (errno != 0 || len < 1 || len > 256) {
                return error("%s: invalid length", optarg);
            }
            break;
        case 'p':
            setpass = true;
            break;
        case 'S':
            sym = false;
            break;
        default:
            return usage_set();
        }
    }

    // Default mode is set password even if -p flag is not specified.
    if (nattrs == 0) {
        setpass = true;
    }

    if (optind != argc - 1) {
        return usage_set();
    }

    char *fname = db_file();
    struct record **recs = NULL;

    char *name = argv[optind];
    if (!valid_name(name)) {
        ret = error("%s: invalid name", name);
        goto quit;
    }

    recs = file_read(fname, dbpass);
    if (recs == NULL) {
        ret = error(strerror(errno));
        goto quit;
    }

    struct record *rec = NULL;
    int nrecs = 0;
    for (struct record **r = recs; *r != NULL; r++) {
        if (strcmp((*r)->name, name) == 0) {
            rec = *r;
        }
        nrecs++;
    }

    if (rec == NULL) {
        rec = mem_malloc(sizeof(struct record));
        rec->name = mem_strdup(name);
        rec->pass = NULL;
        rec->attrs = mem_malloc(sizeof(struct attr *));
        rec->attrs[0] = NULL;

        nrecs++;
        recs = mem_realloc(recs, sizeof(struct record *) * (nrecs + 1));
        recs[nrecs - 1] = rec;
        recs[nrecs] = NULL;

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
            pass = password();
            if (pass == NULL) {
                fprintf(stderr, "Passwords missmatch! Aborting.\n");
                ret = 1;
                goto quit;
            }
        }
        mem_free(rec->pass);
        rec->pass = pass;
    }

    for (int i = 0; i < nattrs; i++) {
        struct attr *at = NULL;
        int nat = 0;
        for (struct attr **a = rec->attrs; *a != NULL; a++) {
            if (strcmp((*a)->name, attrs[i]) == 0) {
                at = *a;
            }
            nat++;
        }

        if (at == NULL) {
            at = mem_malloc(sizeof(struct attr));
            at->name = attrs[i];
            at->val = attrvs[i];
            nat++;
            rec->attrs = mem_realloc(rec->attrs,
                sizeof(struct attr *) * (nat + 1));
            rec->attrs[nat - 1] = at;
            rec->attrs[nat] = NULL;
        } else {
            bool replace = yesno("Attribute already exists. Overwrite it?");
            if (!replace) {
                goto quit;
            }

            mem_free(at->name);
            at->name = attrs[i];
            mem_free(at->val);
            at->val = attrvs[i];
        }
    }

    if (file_write(fname, dbpass, recs) != 0) {
        ret = error(strerror(errno));
        goto quit;
    }

quit:
    mem_free(fname);
    file_free_records(recs);
    mem_free(attrs);
    mem_free(attrvs);

    return ret;
}

struct command {
    char *name;
    int (*exec)(int, char **);
};

struct command commands[] = {
    {"get", cmd_get},
    {"list", cmd_list},
    // {"pass", cmd_pass},
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
        die("TODO: usage()");
    }

    struct command *cmd = find_command(argv[1]);
    int cargc;
    char **cargv;
    if (cmd != NULL) {
        cargc = argc - 1;
        cargv = argv + 1;
    } else {
        cmd = find_command("get");
        if (cmd == NULL) {
            die("TODO: usage()");
        }
        cargc = argc;
        cargv = argv;
    }

    umask(S_IWGRP | S_IRGRP | S_IWOTH | S_IROTH);

    if (readpassphrase("Password: ", dbpass, sizeof(dbpass),
            RPP_REQUIRE_TTY) == NULL) {
        return error("reading password failed");
    }
    if (strlen(dbpass) < 3) {
        return error("password too short");
    }

    return cmd->exec(cargc, cargv);
}
