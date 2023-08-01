#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

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

#ifndef VERSION
#define VERSION "unknown"
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
    // char dir[REPO_DIR_LEN];
    char *dir_path;
    char dir_name[17];
    git_repository *repository;
    struct wanted_objects wanted_objects;
    enum repo_added_from added_from;
};

static const struct repo REPO_INIT = {0};

struct config {
    struct repo *repos;
    unsigned long   repos_count,
                    repos_allocated;
    git_fetch_options fetch_options;
    char    *proxy_url,
            *dir_repos,
            *dir_archives,
            *dir_checkouts;
    unsigned short  proxy_after,
                    len_proxy_url,
                    len_dir_repos,
                    len_dir_archives,
                    len_dir_checkouts;
};

int sideband_progress(char const *string, int len, void *payload);
int fetch_progress(git_indexer_progress const *stats, void *payload);

struct config const CONFIG_INIT = {
    .repos = NULL,
    .repos_count = 0,
    .repos_allocated = 0,
    .fetch_options = { 
        .version = GIT_FETCH_OPTIONS_VERSION, 
        .callbacks = {
            .version = GIT_REMOTE_CALLBACKS_VERSION,
            .sideband_progress = sideband_progress,
            .transfer_progress = fetch_progress,
            0,
        },
        .prune = GIT_FETCH_PRUNE_UNSPECIFIED, 
        .update_fetchhead = 1,
        .download_tags = GIT_REMOTE_DOWNLOAD_TAGS_UNSPECIFIED, 
        .proxy_opts = GIT_PROXY_OPTIONS_INIT,
        0,
    },
    .proxy_url = NULL,
    .proxy_after = 0,
};

int sideband_progress(char const *string, int len, void *payload) {
	(void)payload; /* unused */
    pr_warn("remote: %.*s", len, string);
	return 0;
}

static inline void print_progress(git_indexer_progress const *const restrict stats) {

	int network_percent = stats->total_objects > 0 ?
		(100*stats->received_objects) / stats->total_objects :
		0;
	int index_percent = stats->total_objects > 0 ?
		(100*stats->indexed_objects) / stats->total_objects :
		0;

	size_t kbytes = stats->received_bytes / 1024;

	if (stats->total_objects &&
		stats->received_objects == stats->total_objects) {
		printf("Resolving deltas %u/%u\r",
		       stats->indexed_deltas,
		       stats->total_deltas);
	} else {
		printf("net %3d%% (%4zu  kb, %5u/%5u)  /  idx %3d%% (%5u/%5u)\n",
		   network_percent, kbytes,
		   stats->received_objects, stats->total_objects,
		   index_percent, stats->indexed_objects, stats->total_objects);
	}
}

int fetch_progress(git_indexer_progress const *stats, void *payload) {
	(void)payload; /* unused */
	print_progress(stats);
	return 0;
}

// Dumb help message
static inline void help() {
    fputs(
        "git-mirrorer\n"
        "  --config/-c\t[path to .yaml config file]"
            " or a single - for reading from stdin; if not set, read from stdin\n"
        "  --help/-h\tprint this message\n"
        "  --version/-v\tprint the version\n",
        stderr
    );
}

static inline void version() {
    fputs(
        "git-mirrorer version "VERSION" by 7Ji, licensed under GPLv3 or later\n", 
        stderr);
}

// Read from fd until EOF, return the size being read, or -1 if failed, the pointer should be free'd by caller
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
                    pr_error(
                        "Couldn't allocate more memory, "
                        "allocated size already at size max\n");
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


enum YAML_CONFIG_PARSING_STATUS {
    YAML_CONFIG_PARSING_STATUS_NONE,
    YAML_CONFIG_PARSING_STATUS_STREAM,
    YAML_CONFIG_PARSING_STATUS_DOCUMENT,
    YAML_CONFIG_PARSING_STATUS_SECTION,
    YAML_CONFIG_PARSING_STATUS_PROXY,
    YAML_CONFIG_PARSING_STATUS_PROXY_AFTER,
    YAML_CONFIG_PARSING_STATUS_DIR_REPOS,
    YAML_CONFIG_PARSING_STATUS_DIR_ARCHIVES,
    YAML_CONFIG_PARSING_STATUS_DIR_CHECKOUTS,
    YAML_CONFIG_PARSING_STATUS_REPOS,
    YAML_CONFIG_PARSING_STATUS_REPOS_LIST,
    YAML_CONFIG_PARSING_STATUS_REPO_URL,
    YAML_CONFIG_PARSING_STATUS_REPO_AFTER_URL,
    YAML_CONFIG_PARSING_STATUS_REPO_SECTION,
    YAML_CONFIG_PARSING_STATUS_REPO_WANTED,
    // YAML_CONFIG_PARSING_STATUS_REPOS_URL_VALUES,
};

struct config_yaml_parse_state {
    int level;
    unsigned short 
        stream_start,
        stream_end,
        document_start,
        document_end,
        global,
        repos;
    unsigned short repo_id;
    enum YAML_CONFIG_PARSING_STATUS status;
};

int config_add_repo_and_init_with_url(
    struct config *const restrict config,
    char const *const restrict url,
    unsigned short const len_url
) {
    if (config == NULL || url == NULL || len_url == 0) {
        pr_error("Internal: invalid argument\n");
        return -1;
    }
    if (config->repos == NULL) {
        if ((config->repos = malloc(sizeof *config->repos *
            (config->repos_allocated = ALLOC_BASE))) == NULL) {
            pr_error("Failed to allocate memory for repos\n");
            return -1;
        }
    }
    if (++config->repos_count >= config->repos_allocated) {
        while (config->repos_count >= (config->repos_allocated *= ALLOC_MULTIPLY)) {
            if (config->repos_allocated == ULONG_MAX) {
                pr_error("Impossible to allocate more memory\n");
                return -1;
            } else if (config->repos_allocated >= ULONG_MAX / ALLOC_MULTIPLY) {
                config->repos_allocated = ULONG_MAX;
            }
        }
        struct repo *repos_new = realloc(config->repos, 
            sizeof *repos_new * config->repos_allocated);
        if (repos_new == NULL) {
            pr_error("Failed to re-allocate memory\n");
            return -1;
        }
        config->repos = repos_new;
    }
    struct repo *repo = config->repos + config->repos_count - 1;
    *repo = REPO_INIT;
    if ((repo->url = malloc(len_url + 1)) == NULL) {
        pr_error("Failed to allocate memory for url\n");
        --config->repos_count;
        return -1;
    }
    memcpy(repo->url, url, len_url);
    repo->url[len_url] = '\0';
    repo->url_len = len_url;
    repo->url_hash = XXH3_64bits(url, len_url);
    if (snprintf(repo->dir_name, sizeof repo->dir_name, "%016lx", repo->url_hash) < 0) {
        pr_error_with_errno("Failed to generate hashed dir name");
        free(repo->url);
        --config->repos_count;
        return -1;
    }
    return 0;
}

int config_update_from_yaml_event(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct config_yaml_parse_state *const restrict state
) {
    switch (state->status) {
    case YAML_CONFIG_PARSING_STATUS_NONE:
        switch (event->type) {
        case YAML_STREAM_START_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_STREAM;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_STREAM:
        switch (event->type) {
        case YAML_DOCUMENT_START_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_DOCUMENT;
            break;
        case YAML_STREAM_END_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_NONE;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_DOCUMENT:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        case YAML_DOCUMENT_END_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_STREAM;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            char const *const key = (char const *)event->data.scalar.value;
            switch (event->data.scalar.length) {
            case 5:
                if (!strncmp(key, "proxy", 5))
                    state->status = YAML_CONFIG_PARSING_STATUS_PROXY;
                else if (!strncmp(key, "repos", 5))
                    state->status = YAML_CONFIG_PARSING_STATUS_REPOS;
                break;
            case 9:
                if (!strncmp(key, "dir_repos", 9))
                    state->status = YAML_CONFIG_PARSING_STATUS_DIR_REPOS;
                break;
            case 12:
                if (!strncmp(key, "dir_archives", 12))
                    state->status = YAML_CONFIG_PARSING_STATUS_DIR_ARCHIVES;
                break;
            case 13:
                if (!strncmp(key, "dir_checkouts", 13))
                    state->status = YAML_CONFIG_PARSING_STATUS_DIR_CHECKOUTS;
                break;
            }
            if (state->status == YAML_CONFIG_PARSING_STATUS_SECTION) {
                pr_error("Unrecognized config key '%s'\n", key);
                return -1;
            }
            break;
        }
        case YAML_MAPPING_END_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_DOCUMENT;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_PROXY:
    case YAML_CONFIG_PARSING_STATUS_DIR_REPOS:
    case YAML_CONFIG_PARSING_STATUS_DIR_ARCHIVES:
    case YAML_CONFIG_PARSING_STATUS_DIR_CHECKOUTS:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            char **value = NULL;
            unsigned short *len = NULL;
            switch (state->status) {
            case YAML_CONFIG_PARSING_STATUS_PROXY:
                value = &config->proxy_url;
                len = &config->len_proxy_url;
                break;
            case YAML_CONFIG_PARSING_STATUS_DIR_REPOS:
                value = &config->dir_repos;
                len = &config->len_dir_repos;
                break;
            case YAML_CONFIG_PARSING_STATUS_DIR_ARCHIVES:
                value = &config->dir_archives;
                len = &config->len_dir_archives;
                break;
            case YAML_CONFIG_PARSING_STATUS_DIR_CHECKOUTS:
                value = &config->dir_checkouts;
                len = &config->len_dir_checkouts;
                break;
            default:
                pr_error("Internal: impossible value\n");
                return -1;
            }
            if (value == NULL || len == NULL) {
                pr_error("Internal: impossible value\n");
                return -1;
            }
            if (*value != NULL) free(*value);
            if ((*value = malloc(event->data.scalar.length + 1)) == NULL) {
                pr_error("Failed to allocate memory\n");
                return -1;
            }
            memcpy(*value, event->data.scalar.value, event->data.scalar.length);
            *value[event->data.scalar.length] = '\0';
            *len = event->data.scalar.length;
            state->status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        }
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_PROXY_AFTER:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            config->proxy_after = strtoul(
                (char const *)event->data.scalar.value, NULL, 10);
            state->status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPOS:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPOS_LIST;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPOS_LIST:
        switch (event->type) {
        case YAML_SCALAR_EVENT: // url-only repo
            if (config_add_repo_and_init_with_url(
                config,
                (char const *)event->data.scalar.value,
                event->data.scalar.length
            )) {
                pr_error("Failed to add repo with url '%s'\n", 
                    (char const *) event->data.scalar.value);
                return -1;
            }
            break;
        case YAML_SEQUENCE_END_EVENT: // all end
            state->status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        case YAML_MAPPING_START_EVENT: // advanced repo config
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_URL;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_URL: // only accept repo url as mapping name
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            if (config_add_repo_and_init_with_url(
                config,
                (char const *)event->data.scalar.value,
                event->data.scalar.length
            )) {
                pr_error("Failed to add repo with url '%s'\n", 
                    (char const *) event->data.scalar.value);
                return -1;
            }
            state->repo_id = config->repos_count - 1;
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_AFTER_URL;
            break;
        // case YAML_MAPPING_END_EVENT:
        //     state->status = YAML_CONFIG_PARSING_STATUS_REPOS_LIST;
        //     break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_AFTER_URL:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_SECTION;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_SECTION:
        switch(event->type) {
        case YAML_SCALAR_EVENT: {
            char const *const key = (char const *)event->data.scalar.value;
            switch (event->data.scalar.length) {
            case 6:
                if (!strncmp(key, "wanted", 6))
                    state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED;
                break;
            }
            if (state->status == YAML_CONFIG_PARSING_STATUS_REPO_SECTION) {
                pr_error("Unrecognized config key '%s'\n", key);
                return -1;
            }
            break;
        }
        default:
            goto unexpected_event_type;
        }
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED:
        break;
    return 0;
    }
unexpected_event_type:
    pr_error(
        "Unexpected event type %d for current status %d\n", 
        event->type, state->status);
    return -1;
}

int config_from_yaml(
    struct config *const restrict config, 
    unsigned char const *const restrict yaml_buffer,
    size_t yaml_size
){
    yaml_parser_t parser;
    yaml_event_t event;
    yaml_event_type_t event_type;

    *config = CONFIG_INIT;
    struct config_yaml_parse_state state = {0};
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, yaml_buffer, yaml_size);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            pr_error("Failed to parse: %s\n", parser.problem);
            goto error;
        }
        if (config_update_from_yaml_event(config, &event, &state)) {
            pr_error("Failed to update config from yaml event\n");
            goto error;
        }
        event_type = event.type;
        yaml_event_delete(&event);
    } while (event_type != YAML_STREAM_END_EVENT);

    yaml_parser_delete(&parser);
    return 0;

error:
    yaml_parser_delete(&parser);
    return -1;
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
        case 'v':
            version();
            r = 0;
            goto free_config_path;
        case 'h':
            version();
            fputc('\n', stderr);
            help();
            return 0;
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