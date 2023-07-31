#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>

#include <fcntl.h>

#include <getopt.h>

#include <xxh3.h>
#include <git2.h>
#include <yaml.h>

#define REPOS_DIR "repos"
#define REPO_DIR_LEN 23 // repos 5 + xxh3 64-bit 16 + / 1 + null 1
#define MIRRORS_DIR "mirrors"
#define MIRROR_REMOTE "origin"
#define MIRROR_FETCHSPEC "+refs/*:refs/*"
#define MIRROR_CONFIG "remote."MIRROR_REMOTE".mirror"

#define ALLOC_BASE 10
#define ALLOC_MULTIPLY 2

#define pr_error(format, arg...) \
    fprintf(stderr, "%s:%d(error): "format, __FUNCTION__, __LINE__, ##arg)

#define pr_error_with_errno(format, arg...) \
    pr_error(format", errno: %d, error: %s\n", ##arg, errno, strerror(errno))

#define pr_warn(format, arg...) \
    fprintf(stderr, "%s:%d(warn): "format, __FUNCTION__, __LINE__, ##arg)

#ifdef DEBUGGING
#define pr_debug(format, arg...) \
    fprintf(stderr, "%s:%d(debug): "format, __FUNCTION__, __LINE__, ##arg)
#else
#define pr_debug(format, arg...)
#endif

enum wanted_type {
    WANTED_TYPE_COMMIT,
    WANTED_TYPE_BRANCH,
    WANTED_TYPE_TAG,
    WANTED_TYPE_HEAD,
};

struct wanted_base {
    enum wanted_type type;
    struct wanted_commit *previous, *next;
};

struct wanted_commit {
    struct wanted_base base;
    git_oid id;
    char id_hex_string[GIT_OID_MAX_HEXSIZE + 1];
};

struct wanted_reference {
    struct wanted_commit commit;
    bool commit_resolved;
    char *reference;
    unsigned short reference_len;
};

struct wanted_objects {
    struct wanted_base *objects_head;
    bool all_branches;
    bool all_tags;
    bool dynamic;
};

enum repo_added_from {
    REPO_ADDED_FROM_CONFIG,
    RPEO_ADDED_FROM_SUBMODULES,
};

struct repo {
    char *url;
    unsigned short url_len;
    XXH64_hash_t url_hash;
    char dir[REPO_DIR_LEN];
    git_repository *repository;
    struct wanted_objects wanted_objects;
    enum repo_added_from added_from;
};

static const struct repo REPO_INIT = {0};

struct config {
    struct repo *repos;
    unsigned long repos_count;
    unsigned long repos_allocated;
    git_fetch_options fetch_options;
    char proxy_url[PATH_MAX];
    unsigned short proxy_after;
};

#define INDENT "  "
#define STRVAL(x) ((x) ? (char*)(x) : "")

void indent(int level)
{
    int i;
    for (i = 0; i < level; i++) {
        printf("%s", INDENT);
    }
}

static inline void help() {
    fputs(
        "git-mirrorer\n"
        "  --config/-c [path to .yaml config file] or a single - for reading from stdin\n"
        "  --help/-h\n"
        "  --version/-v\n",
        stderr
    );
}

ssize_t buffer_read_from_fd(unsigned char **buffer, int fd) {
    if (buffer == NULL || fd < 0) {
        pr_error("Internal: invalid arguments\n");
        return -1;
    }
    if ((*buffer = malloc(0x10000)) == NULL) {
        pr_error("Failed to allocate memory\n");
        return -1;
    }
    size_t size_alloc = 0x10000;
    ssize_t size_total = 0, size_current = 0;
    for(;;) {
        if (size_alloc - size_total < 0x10000) {
            while (size_alloc - size_total < 0x10000) {
                if (size_alloc == SIZE_MAX) { // This shouldn't be possible
                    pr_error("Couldn't allocate more memory, allocated size already at size max\n");
                    size_total = -1;
                    goto free_buffer;
                } else if (size_alloc >= SIZE_MAX / 2) {
                    size_alloc = SIZE_MAX;
                } else {
                    size_alloc *= 2;
                }
            }
            unsigned char *buffer_new = realloc(*buffer, size_alloc);
            if (buffer_new == NULL) {
                pr_error("Failed to allocate more memory\n");
                size_total = -1;
                goto free_buffer;
            }
            *buffer = buffer_new;
        }
        size_current = read(fd, *buffer + size_total, 0x10000);
        if (size_current == 0) {
            break;
        }
        if (size_current < 0) {
            if (errno == EAGAIN || 
#if (EAGAIN != EWOULDBLOCK)
                errno == EWOULDBLOCK || 
#endif
                errno == EINTR) {
            } else {
                pr_error_with_errno("Failed to read");
                size_total = -1;
                goto free_buffer;
            }
        }
        size_total += size_current;
    }
free_buffer:
    if (*buffer == NULL) free(*buffer);
    return size_total;
}


void print_event(yaml_event_t *event) {
    static int level = 0;

    switch (event->type) {
    case YAML_NO_EVENT:
        indent(level);
        printf("no-event\n");
        break;
    case YAML_STREAM_START_EVENT:
        indent(level++);
        printf("stream-start-event\n");
        break;
    case YAML_STREAM_END_EVENT:
        indent(--level);
        printf("stream-end-event\n");
        break;
    case YAML_DOCUMENT_START_EVENT:
        indent(level++);
        printf("document-start-event\n");
        break;
    case YAML_DOCUMENT_END_EVENT:
        indent(--level);
        printf("document-end-event\n");
        break;
    case YAML_ALIAS_EVENT:
        indent(level);
        printf("alias-event\n");
        break;
    case YAML_SCALAR_EVENT:
        indent(level);
        printf("scalar-event={value=\"%s\", length=%d}\n",
                STRVAL(event->data.scalar.value),
                (int)event->data.scalar.length);
        break;
    case YAML_SEQUENCE_START_EVENT:
        indent(level++);
        printf("sequence-start-event\n");
        break;
    case YAML_SEQUENCE_END_EVENT:
        indent(--level);
        printf("sequence-end-event\n");
        break;
    case YAML_MAPPING_START_EVENT:
        indent(level++);
        printf("mapping-start-event\n");
        break;
    case YAML_MAPPING_END_EVENT:
        indent(--level);
        printf("mapping-end-event\n");
        break;
    }
    if (level < 0) {
        fprintf(stderr, "indentation underflow!\n");
        level = 0;
    }
}

int config_from_yaml(
    struct config *const restrict config, 
    unsigned char const *const restrict yaml_buffer,
    size_t yaml_size
){
    yaml_parser_t parser;
    yaml_event_t event;
    yaml_event_type_t event_type;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, yaml_buffer, yaml_size);

    do {
        if (!yaml_parser_parse(&parser, &event))
            goto error;
        print_event(&event);
        event_type = event.type;
        yaml_event_delete(&event);
    } while (event_type != YAML_STREAM_END_EVENT);

    yaml_parser_delete(&parser);
    return 0;

error:
    pr_error("Failed to parse: %s\n", parser.problem);
    yaml_parser_delete(&parser);
    return 1;
}

int main(int const argc, char *argv[]) {
    char *config_path = NULL;
    unsigned short len_config_path = 0;
    struct option const long_options[] = {
        {"config",          required_argument,  NULL,   'c'},
        {"help",            no_argument,        NULL,   'h'},
        {"version",         no_argument,        NULL,   'v'},
        {0},
    };
    int c, option_index = 0;
    int r = -1;
    while ((c = getopt_long(argc, argv, "c:hv", 
        long_options, &option_index)) != -1) {
        switch (c) {
        case 'c':
            if (optarg[0] == '-' && optarg[1] == '\0') { // config from stdin
                pr_warn("Config set to read from stdin\n");
                if (config_path) free(config_path);
                config_path = NULL;
                len_config_path = 0;
            } else {
                pr_warn("Config set to file '%s'\n", optarg);
                unsigned char len_config_path_new = strlen(optarg);
                if (len_config_path_new == 0) {
                    pr_error("Config file path empty\n");
                    goto free_config_path;
                }
                if (len_config_path_new > len_config_path) {
                    char *config_path_new = NULL;
                    if (config_path == NULL) {
                        config_path_new = malloc(len_config_path_new + 1);
                    } else {
                        config_path_new = realloc(config_path, len_config_path_new + 1);
                    }
                    if (config_path_new == NULL) {
                        pr_error("Failed to allocate memory for config path\n");
                        r = -1;
                        goto free_config_path;
                    }
                    config_path = config_path_new;
                }
                strncpy(config_path, optarg, len_config_path = len_config_path_new);
                config_path[len_config_path] = '\0';
            }
            break;
        case 'h':
            help();
            return 0;
        case 'v':
            pr_warn("unknown\n");
            r = 0;
            goto free_config_path;
        default:
            pr_error("Unexpected argument, %d (-%c) '%s'\n", c, c, argv[optind - 1]);
            r = -1;
            goto free_config_path;
        }
    }
    int config_fd = STDIN_FILENO;
    if (config_path) {
        if ((config_fd = open(config_path, O_RDONLY)) < 0) {
            pr_error_with_errno("Failed to open config file '%s'", config_path);
            r = -1;
            goto free_config_path;
        }
    } else {
        if (isatty(STDIN_FILENO)) {
            pr_warn("Standard input (stdin) is connected to a terminal, but you've configured to read config from stdin, this might not be what you want and may lead to your terminal being jammed\n");
        }
    }
    unsigned char *config_buffer;
    ssize_t config_size = buffer_read_from_fd(&config_buffer, config_fd);
    if (config_size < 0) {
        pr_error("Failed to read config into buffer\n");
        goto free_config_path;
    }
    free(config_path);
    config_path = NULL;

    struct config config;
    config_from_yaml(&config, config_buffer, config_size);
    // yaml_parse(config_buffer, config_size);

    r = 0;
free_config_path:
    if (config_path) free(config_path);
    return r;
}