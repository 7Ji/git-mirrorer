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

#define DIR_REPOS   "repos"
#define DIR_ARCHIVES    "archives"
#define DIR_CHECKOUTS   "checkouts"

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
    WANTED_TYPE_UNKNOWN,
    WANTED_TYPE_ALL_BRANCHES,
    WANTED_TYPE_ALL_TAGS,
    WANTED_TYPE_COMMIT,
    WANTED_TYPE_BRANCH,
    WANTED_TYPE_TAG,
    WANTED_TYPE_HEAD,
};

#define WANTED_TYPE_MAX WANTED_TYPE_HEAD

char const *WANTED_TYPE_STRINGS[] = {
    "unknown",
    "all_branches",
    "all_tags",
    "commit",
    "branch",
    "tag",
    "head"
};

struct wanted_base {
    enum wanted_type type;
    char *name;
    unsigned short name_len;
    bool archive;
    bool checkout;
    struct wanted_base *previous, *next;
};

struct wanted_base const WANTED_BASE_INIT = {0};

struct wanted_commit {
    struct wanted_base base;
    git_oid id;
    char id_hex_string[GIT_OID_MAX_HEXSIZE + 1];
};

struct wanted_commit const WANTED_COMMIT_INIT = {0};

struct wanted_reference {
    struct wanted_commit commit;
    bool commit_resolved;
    // char *reference;
    // unsigned short reference_len;
};

struct wanted_reference const WANTED_REFERENCE_INIT = {0};

struct wanted_objects {
    struct wanted_base *objects_head;
    struct wanted_base *objects_tail;
    unsigned long objects_count;
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
    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_LIST,
    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT,
    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_AFTER_OBJECT,
    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION,
    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_TYPE,
    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_ARCHIVE,
    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_CHECKOUT,
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
    long repo_id;
    enum YAML_CONFIG_PARSING_STATUS status;
};

static const struct repo REPO_INIT = {0};

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

int config_add_repo_and_init_with_url(
    struct config *const restrict config,
    char const *const restrict url,
    unsigned short const len_url
) {
    // pr_warn("Adding\n");
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
    XXH64_hash_t url_hash = XXH3_64bits(url, len_url);
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (config->repos[i].url_hash == url_hash) {
            pr_error("Repo '%s' was already defined, duplication not allowed\n", url);
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
    if (snprintf(repo->dir_name, sizeof repo->dir_name, "%016lx", url_hash) < 0) {
        pr_error_with_errno("Failed to generate hashed dir name");
        --config->repos_count;
        return -1;
    }
    if ((repo->url = malloc(len_url + 1)) == NULL) {
        pr_error("Failed to allocate memory for url\n");
        --config->repos_count;
        return -1;
    }
    memcpy(repo->url, url, len_url);
    repo->url[len_url] = '\0';
    repo->url_len = len_url;
    repo->url_hash = url_hash;
    return 0;
}

static inline bool object_name_is_sha1(
    char const *const restrict object
) {
    for (unsigned short i = 0; i < 40; ++i) {
        switch (object[i]) {
        case '0'...'9':
        case 'a'...'f':
        case 'A'...'F':
            break;
        default:
            return false;
        }
    }
    return true;
}

enum wanted_type wanted_object_guess_type(
    char const *const restrict object,
    unsigned short len_object
) {
    switch (len_object) {
    case 4:
        if (!strncmp(object, "HEAD", 4)) return WANTED_TYPE_HEAD;
        break;
    case 8:
        if (!strncmp(object, "all_tags", 8)) return WANTED_TYPE_ALL_TAGS;
        break;
    case 12:
        if (!strncmp(object, "all_branches", 12)) return WANTED_TYPE_ALL_BRANCHES;
        break;
    case 40:
        if (object_name_is_sha1(object)) return WANTED_TYPE_COMMIT;
        break;
    default:
        break;
    }
    pr_error("Failed to figure out the type of wanted object '%s', "
        "try to set it explicitly e.g. type: branch\n", object);
    return WANTED_TYPE_UNKNOWN;
}

int wanted_object_guess_type_self_optional(struct wanted_base *wanted_object) {
    if (wanted_object->type != WANTED_TYPE_UNKNOWN) return 0;
    if ((wanted_object->type = wanted_object_guess_type(
        wanted_object->name, wanted_object->name_len
    )) == WANTED_TYPE_UNKNOWN) {
        pr_error("Failed to guess type\n");
        return -1;
    }
    return 0;
}

int wanted_object_fill_type_from_string(
    struct wanted_base *wanted_object,
    char const *const restrict type
) {
    for (enum wanted_type i = 1; i <= WANTED_TYPE_MAX; ++i) {
        if (!strcmp(type, WANTED_TYPE_STRINGS[i])) {
            wanted_object->type = i;
            return 0;
        }
    }
    return -1;
}

int wanted_object_complete_commit_from_base(
    struct wanted_base **wanted_object
) {
    git_oid oid;
    if (git_oid_fromstr(&oid, (*wanted_object)->name)) {
        pr_error("Failed to resolve '%s' to a git object id\n", (*wanted_object)->name);
        return -1;
    }
    struct wanted_commit *wanted_commit = malloc(sizeof *wanted_commit);
    if (wanted_commit == NULL) {
        pr_error("Failed to allocate memory\n");
        return -1;
    }
    *wanted_commit = WANTED_COMMIT_INIT;
    if (git_oid_tostr(
            wanted_commit->id_hex_string,
            sizeof wanted_commit->id_hex_string, 
            &oid
        )[0] == '\0') {
        pr_error("Failed to format git oid hex string\n");
        free(wanted_commit);
        return -1;
    }
    wanted_commit->base = **wanted_object;
    wanted_commit->id = oid;
    if ((*wanted_object)->previous) (*wanted_object)->previous->next = (struct wanted_base *)wanted_commit;
    if ((*wanted_object)->next) (*wanted_object)->next->previous = (struct wanted_base *)wanted_commit;
    free(*wanted_object);
    *wanted_object = (struct wanted_base *)wanted_commit;
    return 0;
}

int wanted_object_complete_reference_from_base(
    struct wanted_base **wanted_object
) {
    struct wanted_reference *wanted_reference = malloc(sizeof *wanted_reference);
    if (wanted_reference == NULL) {
        pr_error("Failed to allocate memory\n");
        return -1;
    }
    *wanted_reference = WANTED_REFERENCE_INIT;
    wanted_reference->commit.base = **wanted_object;
    if ((*wanted_object)->previous) (*wanted_object)->previous->next = (struct wanted_base *)wanted_reference;
    if ((*wanted_object)->next) (*wanted_object)->next->previous = (struct wanted_base *)wanted_reference;
    free(*wanted_object);
    *wanted_object = (struct wanted_base *)wanted_reference;
    return 0;
}

int wanted_object_complete_from_base(
    struct wanted_base **wanted_object
) {
    switch ((*wanted_object)->type) {
    case WANTED_TYPE_UNKNOWN:
        pr_error("Impossible to complete an object with unknown type\n");
        return -1;
    case WANTED_TYPE_ALL_BRANCHES: // These two does not need to be upgraded
    case WANTED_TYPE_ALL_TAGS:
        return 0;
    case WANTED_TYPE_COMMIT:
        return wanted_object_complete_commit_from_base(wanted_object);
    case WANTED_TYPE_BRANCH:
    case WANTED_TYPE_TAG:
    case WANTED_TYPE_HEAD:
        return wanted_object_complete_reference_from_base(wanted_object);
    default:
        pr_error("Impossible routine\n");
        return -1;
    }
    return 0;
}

int config_repo_add_wanted_object (
    struct config *const restrict config,
    long repo_id,
    char const *const restrict object,
    unsigned short len_object,
    bool guess_type
) {
    if (config == NULL || repo_id < 0 || object == NULL || object[0] == '\0') {
        pr_error("Internal: invalida argument\n");
        return -1;
    }
    enum wanted_type wanted_type = WANTED_TYPE_UNKNOWN;
    if (guess_type) {
        if ((wanted_type = wanted_object_guess_type(object, len_object)) 
            == WANTED_TYPE_UNKNOWN) {
            pr_error("Failed to guess object type of '%s'\n", object);
            return -1;
        }
    }
    struct repo *const repo = config->repos + repo_id;
    struct wanted_base *wanted_object = malloc(sizeof *wanted_object);
    if (wanted_object == NULL) {
        pr_error("Failed to allocate memory\n");
        return -1;
    }
    *wanted_object = WANTED_BASE_INIT;
    if ((wanted_object->name = malloc(len_object + 1)) == NULL) {
        pr_error("Failed to allocate memory\n");
        goto free_wanted_object;
    }
    memcpy(wanted_object->name, object, len_object);
    wanted_object->name[len_object] = '\0';
    wanted_object->name_len = len_object;
    if (guess_type) {
        wanted_object->type = wanted_type;
        if (wanted_object_complete_from_base(&wanted_object)) {
            pr_error("Failed to complete object\n");
            goto free_name;
        }
    }
    if (repo->wanted_objects.objects_count == 0) {
        repo->wanted_objects.objects_head = wanted_object;
        repo->wanted_objects.objects_tail = wanted_object;
    } else {
        repo->wanted_objects.objects_tail->next = wanted_object;
        wanted_object->previous = repo->wanted_objects.objects_tail;
        repo->wanted_objects.objects_tail = wanted_object;
    }
    ++repo->wanted_objects.objects_count;
    return 0;

free_name:
    free(wanted_object->name);
free_wanted_object:
    free(wanted_object);
    return -1;
}

// 0 for false, 1 for true, -1 for error parsing
int bool_from_string(
    char const *const restrict string
) {
    if (string == NULL || string[0] == '\0') {
        return -1;
    }
    if (!strcasecmp(string, "yes") || !strcmp(string, "true")) {
        return 1;
    }
    if (!strcasecmp(string, "no") || !strcmp(string, "false")) {
        return 0;
    }
    return -1;
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
            case 11:
                if (!strncmp(key, "proxy_after", 11))
                    state->status = YAML_CONFIG_PARSING_STATUS_PROXY_AFTER;
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
            (*value)[event->data.scalar.length] = '\0';
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
        case YAML_MAPPING_END_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPOS_LIST;
            break;
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
        case YAML_MAPPING_END_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_URL;
            state->repo_id = -1;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED_LIST;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_LIST:
        switch (event->type) {
        case YAML_SCALAR_EVENT: 
            if (config_repo_add_wanted_object(
                config, state->repo_id, (char const *)event->data.scalar.value,
                event->data.scalar.length, true
            )) {
                pr_error("Failed to add wanted object\n");
                return -1;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT;
            break;
        case YAML_SEQUENCE_END_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_SECTION;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            if (config_repo_add_wanted_object(
                config, state->repo_id, (char const *)event->data.scalar.value,
                event->data.scalar.length, false
            )) {
                pr_error("Failed to add wanted object\n");
                return -1;
            }
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED_AFTER_OBJECT;
            break;
        case YAML_MAPPING_END_EVENT: {
            if (wanted_object_guess_type_self_optional(
                (config->repos + state->repo_id)-> wanted_objects.objects_tail) ||
                wanted_object_complete_from_base(
                    &((config->repos + state->repo_id)-> wanted_objects.objects_tail)
                )) {
                pr_error("Failed to finish wanted object\n");
                return -1;
            }
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED_LIST;
            break;
        }
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_AFTER_OBJECT:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:{
            char const *const key = (char const *)event->data.scalar.value;
            switch (event->data.scalar.length) {
            case 4:
                if (!strncmp(key, "type", 4))
                    state->status = 
                    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_TYPE;
                break;
            case 7:
                if (!strncmp(key, "archive", 7))
                    state->status = 
                    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_ARCHIVE;
                break;
            case 8:
                if (!strncmp(key, "checkout", 8))
                    state->status = 
                    YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_CHECKOUT;
            }
            if (state->status == YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION) {
                pr_error("Unrecognized config key '%s'\n", key);
                return -1;
            }
            break;
        }
        case YAML_MAPPING_END_EVENT:
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_TYPE:
        switch (event->type) {
        case YAML_SCALAR_EVENT: 
            if (wanted_object_fill_type_from_string(
                (config->repos + state->repo_id)->wanted_objects.objects_tail,
                (char const *)event->data.scalar.value
            )) {
                pr_error("Invalid object type '%s'\n", (char const *)event->data.scalar.value);
                return -1;
            }
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_ARCHIVE:
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_CHECKOUT:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            int bool_value = bool_from_string((char const *)event->data.scalar.value);
            if (bool_value < 0) {
                pr_error("Failed to parse '%s' into a bool value\n", 
                    (char const *)event->data.scalar.value);
                return -1;
            }
            if (state->status == YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_ARCHIVE) {
                config->repos[state->repo_id].wanted_objects.objects_tail->archive
                    = bool_value;
            } else {
                config->repos[state->repo_id].wanted_objects.objects_tail->checkout
                    = bool_value;
            }
            state->status = YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION;
            break;
        }
        default:
            goto unexpected_event_type;
        }
        break;
    }
    return 0;
unexpected_event_type:
    pr_error(
        "Unexpected YAML event type %d for current status %d\n", 
        event->type, state->status);
    return -1;
}

void print_config_repo_wanted(struct wanted_objects const *const restrict wanted_objects) {
    for (struct wanted_base *wanted_object = wanted_objects->objects_head;
        wanted_object; wanted_object = wanted_object->next) {
        fprintf(stderr,
            "       - %s:\n"
            "           type: %d (%s)\n"
            "           archive: %s\n"
            "           checkout: %s\n",
            wanted_object->name,
            wanted_object->type,
            WANTED_TYPE_STRINGS[wanted_object->type],
            wanted_object->archive ? "yes" : "no",
            wanted_object->checkout ? "yes" : "no"
        );
    }

}

void print_config_repo(struct repo const *const restrict repo) {
    fprintf(stderr,
        " - %s:\n"
        "     hash: %016lx\n",
        repo->url,
        repo->url_hash);
    if (repo->wanted_objects.objects_count) {
        fprintf(stderr,
        "     wanted (%lu):\n", repo->wanted_objects.objects_count);
        print_config_repo_wanted(&repo->wanted_objects);
    }

}

void print_config(struct config const *const restrict config) {
    fprintf(stderr,
        "\n"
        "proxy: %s\n"
        "proxy_after: %hu\n"
        "dir_repos: %s\n"
        "dir_archives: %s\n"
        "dir_checkouts: %s\n",
        config->proxy_url,
        config->proxy_after,
        config->dir_repos,
        config->dir_archives,
        config->dir_checkouts);
    if (config->repos_count) {
        fprintf(stderr, "repos (%lu): \n", config->repos_count);
        for (unsigned long i = 0; i < config->repos_count; ++i) {
            print_config_repo(config->repos + i);
        }
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

    struct config_yaml_parse_state state = {0};
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, yaml_buffer, yaml_size);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            pr_error("Failed to parse: %s\n", parser.problem);
            goto error;
        }
        if (config_update_from_yaml_event(config, &event, &state)) {
            pr_error("Failed to update config from yaml event"
#ifdef DEBUGGING
            ", current read config:\n");
            print_config(config);
#else
            );
#endif
            goto error;
        }
        event_type = event.type;
        yaml_event_delete(&event);
    } while (event_type != YAML_STREAM_END_EVENT);

    yaml_parser_delete(&parser);

#ifdef DEBUGGING
    pr_warn("Config is as follows:\n");
    print_config(config);
#endif
    return 0;

error:
    yaml_parser_delete(&parser);
    return -1;
}

int config_finish(
    struct config *const restrict config
) {
    if (config->dir_repos == NULL) {
        if ((config->dir_repos = malloc(sizeof(DIR_REPOS))) == NULL) {
            return -1;
        }
        memcpy(config->dir_repos, DIR_REPOS, sizeof(DIR_REPOS));
    }
    if (config->dir_archives == NULL) {
        if ((config->dir_archives = malloc(sizeof(DIR_ARCHIVES))) == NULL) {
            return -1;
        }
        memcpy(config->dir_archives, DIR_ARCHIVES, sizeof(DIR_ARCHIVES));
    }
    if (config->dir_checkouts == NULL) {
        if ((config->dir_checkouts = malloc(sizeof(DIR_CHECKOUTS))) == NULL) {
            return -1;
        }
        memcpy(config->dir_checkouts, DIR_CHECKOUTS, sizeof(DIR_CHECKOUTS));
    }
    if (config->proxy_url && config->proxy_url[0] != '\0') {
        config->fetch_options.proxy_opts.url = config->proxy_url;
    } else if (config->proxy_after) {
        pr_warn("You've set proxy_after but not set proxy, fixing proxy_after to 0\n");
        config->proxy_after = 0;
    }
    pr_warn("Finished config, config is as follows:\n");
    print_config(config);
    return 0;
}

int config_read(
    struct config *const restrict config,
    char const *const restrict config_path
) {
    int config_fd = STDIN_FILENO;
    if (config_path && strcmp(config_path, "-")) {
        pr_warn("Using '%s' as config file\n", config_path);
        if ((config_fd = open(config_path, O_RDONLY)) < 0) {
            pr_error_with_errno("Failed to open config file '%s'", config_path);
            return -1;
        }
    } else {
        pr_warn("Reading config from stdin\n");
        if (isatty(STDIN_FILENO)) {
            pr_warn("Standard input (stdin) is connected to a terminal, but you've configured to read config from stdin, this might not be what you want and may lead to your terminal being jammed\n");
        }
    }
    unsigned char *config_buffer;
    ssize_t config_size = buffer_read_from_fd(&config_buffer, config_fd);
    if (config_size < 0) {
        pr_error("Failed to read config into buffer\n");
        return -1;
    }
    *config = CONFIG_INIT;
    if (config_from_yaml(config, config_buffer, config_size)) {
        pr_error("Failed to read config from YAML\n");
        free(config_buffer);
        return -1;
    }
    free(config_buffer);
    if (config_finish(config)) {
        pr_error("Failed to finish config\n");
        return -1;
    }
    return 0;
}

int main(int const argc, char *argv[]) {
    char *config_path = NULL;
    struct option const long_options[] = {
        {"config",          required_argument,  NULL,   'c'},
        {"help",            no_argument,        NULL,   'h'},
        {"version",         no_argument,        NULL,   'v'},
        {0},
    };
    int c, option_index = 0;
    while ((c = getopt_long(argc, argv, "c:hv", 
        long_options, &option_index)) != -1) {
        switch (c) {
        case 'c':
            config_path = optarg;
            break;
        case 'v':
            version();
            return 0;
        case 'h':
            version();
            fputc('\n', stderr);
            help();
            return 0;
        default:
            pr_error("Unexpected argument, %d (-%c) '%s'\n", c, c, argv[optind - 1]);
            return -1;
        }
    }
    struct config config;
    if (config_read(&config, config_path)) {
        pr_error("Failed to read config\n");
        return -1;
    }
    pr_warn("Shutting down\n");
    return 0;
}