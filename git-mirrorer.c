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

struct wanted_base const WANTED_ALL_BRANCHES_INIT = {
    .type = WANTED_TYPE_ALL_BRANCHES, 0 };

struct wanted_base const WANTED_ALL_TAGS_INIT = {
    .type = WANTED_TYPE_ALL_TAGS, 0 };

struct wanted_commit {
    struct wanted_base base;
    git_oid id;
    char id_hex_string[GIT_OID_MAX_HEXSIZE + 1];
};

struct wanted_commit const WANTED_COMMIT_INIT = {
    .base.type = WANTED_TYPE_COMMIT, 0};

struct wanted_reference {
    struct wanted_commit commit;
    bool commit_resolved;
};

struct wanted_reference const WANTED_REFERENCE_INIT = {0};

struct wanted_reference const WANTED_BRANCH_INIT = {
    .commit.base.type = WANTED_TYPE_BRANCH, 0 };

struct wanted_reference const WANTED_TAG_INIT = {
    .commit.base.type = WANTED_TYPE_TAG, 0 };

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
    char *dir_path;
    unsigned short dir_path_len;
    char dir_name[17];
    git_repository *repository;
    struct wanted_objects wanted_objects;
    enum repo_added_from added_from;
    bool updated;
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

int mirror_repo_ensure_wanted_commit(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_commit *const restrict wanted_commit
);

int sideband_progress(char const *string, int len, void *payload) {
	(void)payload; /* unused */
    pr_warn("remote: %.*s", len, string);
	return 0;
}

static inline void print_progress(
    git_indexer_progress const *const restrict stats) {

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
        "git-mirrorer version "VERSION" by 7Ji, "
        "licensed under GPLv3 or later\n", 
        stderr);
}

// Read from fd until EOF, 
// return the size being read, or -1 if failed, 
// the pointer should be free'd by caller
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
            pr_error(
                "Repo '%s' was already defined, duplication not allowed\n",
                 url);
            return -1;
        }
    }
    if (++config->repos_count >= config->repos_allocated) {
        while (config->repos_count >= (
            config->repos_allocated *= ALLOC_MULTIPLY)) {
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
    if (snprintf(
        repo->dir_name, sizeof repo->dir_name, "%016lx", url_hash) < 0) {
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
    case 3:
        if (!strncasecmp(object, "dev", 3)) return WANTED_TYPE_BRANCH;
        break;
    case 4:
        if (!strncmp(object, "HEAD", 4)) return WANTED_TYPE_HEAD;
        else if (!strncasecmp(object, "main", 4)) return WANTED_TYPE_BRANCH;
        break;
    case 6:
        if (!strncasecmp(object, "master", 6)) return WANTED_TYPE_BRANCH;
        break;
    case 8:
        if (!strncasecmp(object, "all_tags", 8)) return WANTED_TYPE_ALL_TAGS;
        break;
    case 12:
        if (!strncasecmp(object, "all_branches", 12)) 
            return WANTED_TYPE_ALL_BRANCHES;
        break;
    case 40:
        if (object_name_is_sha1(object)) return WANTED_TYPE_COMMIT;
        break;
    default:
        break;
    }
    switch (object[0]) {
    case 'v':
    case 'V':
        switch (object[1]) {
        case '0'...'9':
            return WANTED_TYPE_TAG;
        default:
            break;
        }
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
        pr_error("Failed to resolve '%s' to a git object id\n",
            (*wanted_object)->name);
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
    if ((*wanted_object)->previous) 
        (*wanted_object)->previous->next = (struct wanted_base *)wanted_commit;
    if ((*wanted_object)->next) 
        (*wanted_object)->next->previous = (struct wanted_base *)wanted_commit;
    free(*wanted_object);
    *wanted_object = (struct wanted_base *)wanted_commit;
    return 0;
}

int wanted_object_complete_reference_from_base(
    struct wanted_base **wanted_object
) {
    struct wanted_reference *wanted_reference = 
        malloc(sizeof *wanted_reference);
    if (wanted_reference == NULL) {
        pr_error("Failed to allocate memory\n");
        return -1;
    }
    *wanted_reference = WANTED_REFERENCE_INIT;
    wanted_reference->commit.base = **wanted_object;
    if ((*wanted_object)->previous) 
        (*wanted_object)->previous->next = 
            (struct wanted_base *)wanted_reference;
    if ((*wanted_object)->next) 
        (*wanted_object)->next->previous = 
            (struct wanted_base *)wanted_reference;
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
    case YAML_CONFIG_PARSING_STATUS_REPO_URL: 
        // only accept repo url as mapping name
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
                    (config->repos + state->repo_id)
                        -> wanted_objects.objects_tail) ||
                wanted_object_complete_from_base(
                    &((config->repos + state->repo_id)
                        -> wanted_objects.objects_tail))) {
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
            state->status = 
                YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION;
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
            if (state->status == 
                YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION) {
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
                pr_error(
                    "Invalid object type '%s'\n", 
                    (char const *)event->data.scalar.value);
                return -1;
            }
            state->status = 
                YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_ARCHIVE:
    case YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_CHECKOUT:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            int bool_value = bool_from_string(
                (char const *)event->data.scalar.value);
            if (bool_value < 0) {
                pr_error("Failed to parse '%s' into a bool value\n", 
                    (char const *)event->data.scalar.value);
                return -1;
            }
            if (state->status == 
                YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_ARCHIVE) {
                config->repos[state->repo_id]
                    .wanted_objects.objects_tail->archive
                        = bool_value;
            } else {
                config->repos[state->repo_id]
                    .wanted_objects.objects_tail->checkout
                        = bool_value;
            }
            state->status = 
                YAML_CONFIG_PARSING_STATUS_REPO_WANTED_OBJECT_SECTION;
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

void print_config_repo_wanted(
    struct wanted_objects const *const restrict wanted_objects) {
    for (struct wanted_base *wanted_object = wanted_objects->objects_head;
        wanted_object; wanted_object = wanted_object->next) {
        fprintf(stderr,
            "|        - %s:\n"
            "|            type: %d (%s)\n"
            "|            archive: %s\n"
            "|            checkout: %s\n",
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
        "|  - %s:\n"
        "|      hash: %016lx\n"
        "|      dir: %s\n",
        repo->url,
        repo->url_hash,
        repo->dir_path);
    if (repo->wanted_objects.objects_count) {
        fprintf(stderr,
        "|      wanted (%lu, %s):\n", 
            repo->wanted_objects.objects_count,
            repo->wanted_objects.dynamic ? "dynamic" : "static");
        print_config_repo_wanted(&repo->wanted_objects);
    }

}

void print_config(struct config const *const restrict config) {
    fprintf(stderr,
        "| proxy: %s\n"
        "| proxy_after: %hu\n"
        "| dir_repos: %s\n"
        "| dir_archives: %s\n"
        "| dir_checkouts: %s\n",
        config->proxy_url,
        config->proxy_after,
        config->dir_repos,
        config->dir_archives,
        config->dir_checkouts);
    if (config->repos_count) {
        fprintf(stderr, "| repos (%lu): \n", config->repos_count);
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

int config_repo_finish(
    struct repo *const restrict repo,
    char const *const restrict dir_repos,
    unsigned short len_dir_repos
) {
    if (repo == NULL || dir_repos == NULL || len_dir_repos == 0) {
        pr_error("Internal: invalid arguments\n");
        return -1;
    }
    if (repo->wanted_objects.objects_count == 0) {
        pr_warn(
            "Repo '%s' does not have wanted objects defined, "
            "adding HEAD as wanted\n",
            repo->url);
        struct wanted_reference *wanted_head = malloc(sizeof *wanted_head);
        if (wanted_head == NULL) {
            pr_error("Failed to allocate memory\n");
            return -1;
        }
        *wanted_head = WANTED_REFERENCE_INIT;
        if ((wanted_head->commit.base.name = malloc(sizeof("HEAD"))) == NULL) {
            free(wanted_head);
            pr_error("Failed to allocate memory\n");
            return -1;
        }
        strncpy(wanted_head->commit.base.name, "HEAD", 5);
        wanted_head->commit.base.name_len = 4;
        wanted_head->commit.base.type = WANTED_TYPE_HEAD;
        repo->wanted_objects.objects_head = (struct wanted_base *)wanted_head;
        repo->wanted_objects.objects_tail = (struct wanted_base *)wanted_head;
        ++repo->wanted_objects.objects_count;
    }
    for (struct wanted_base *wanted_object = repo->wanted_objects.objects_head;
        wanted_object != NULL;
        wanted_object = wanted_object->next) {
        switch (wanted_object->type) {
        case WANTED_TYPE_UNKNOWN:
            pr_error(
                "Type of wanted object '%s' for repo '%s' is unknown, "
                "you must set it explicitly\n", wanted_object->name, repo->url);
            return -1;
        case WANTED_TYPE_ALL_BRANCHES:
        case WANTED_TYPE_ALL_TAGS:
        case WANTED_TYPE_BRANCH:
        case WANTED_TYPE_TAG:
        case WANTED_TYPE_HEAD:
            repo->wanted_objects.dynamic = true;
            break;
        default:
            break;
        }
    }
    repo->dir_path_len = len_dir_repos + sizeof repo->dir_name;
    if ((repo->dir_path = malloc(repo->dir_path_len + 1)) == NULL) {
        pr_error(
            "Failed to allocate memory for dir path of repo '%s'\n",
            repo->url);
        return -1;
    }
    if (snprintf(repo->dir_path, repo->dir_path_len + 1, "%s/%s", 
        dir_repos, repo->dir_name) < 0) {
        free(repo->dir_path);
        pr_error_with_errno(
            "Failed to format dir path of repo '%s'\n",
            repo->url);
        return -1;
    }
    pr_warn("Repo '%s' will be stored at '%s'\n", repo->url, repo->dir_path);
    // repo->
    return 0;
}

int config_finish(
    struct config *const restrict config
) {
    if (config->dir_repos == NULL) {
        if ((config->dir_repos = malloc(sizeof(DIR_REPOS))) == NULL) {
            return -1;
        }
        memcpy(config->dir_repos, DIR_REPOS, sizeof(DIR_REPOS));
        config->len_dir_repos = sizeof(DIR_REPOS) - 1;
    }
    if (config->dir_archives == NULL) {
        if ((config->dir_archives = malloc(sizeof(DIR_ARCHIVES))) == NULL) {
            return -1;
        }
        memcpy(config->dir_archives, DIR_ARCHIVES, sizeof(DIR_ARCHIVES));
        config->len_dir_archives = sizeof(DIR_ARCHIVES) - 1;
    }
    if (config->dir_checkouts == NULL) {
        if ((config->dir_checkouts = malloc(sizeof(DIR_CHECKOUTS))) == NULL) {
            return -1;
        }
        memcpy(config->dir_checkouts, DIR_CHECKOUTS, sizeof(DIR_CHECKOUTS));
        config->len_dir_checkouts = sizeof(DIR_CHECKOUTS) - 1;
    }
    if (config->proxy_url && config->proxy_url[0] != '\0') {
        config->fetch_options.proxy_opts.url = config->proxy_url;
    } else if (config->proxy_after) {
        pr_warn(
            "You've set proxy_after but not set proxy, "
            "fixing proxy_after to 0\n");
        config->proxy_after = 0;
    }
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (config_repo_finish(
            config->repos + i, config->dir_repos, config->len_dir_repos)) {
            pr_error("Failed to finish repo\n");
        }
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
            pr_warn(
                "Standard input (stdin) is connected to a terminal, "
                "but you've configured to read config from stdin, "
                "this might not be what you want and may lead to "
                "your terminal being jammed\n");
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

// 0 existing and opened, 1 does not exist but created, -1 error
int repo_open_or_init_bare(
    struct repo *const restrict repo
) {
    if (repo == NULL || repo->url[0] == '\0' || 
        repo->dir_path == NULL || repo->dir_path[0] == '\0') {
        pr_error("Internal: invalid argument\n");
        return -1;
    }
    if (repo->repository != NULL) {
        pr_error("Repository already opened for repo '%s'\n", repo->url);
        return -1;
    }
    int r = git_repository_open_bare(&repo->repository, repo->dir_path);
    switch (r) {
    case GIT_OK:
        pr_warn(
            "Opened existing bare repository '%s' for repo '%s'\n",
            repo->dir_path, repo->url);
        return 0;
    case GIT_ENOTFOUND:
        pr_warn(
            "Dir '%s' for repo '%s' does not exist yet, trying to create it\n", 
            repo->dir_path, repo->url);
        r = git_repository_init(&repo->repository, repo->dir_path, 1);
        if (r < 0) {
            pr_error(
                "Failed to initialize a bare repostitory at '%s' "
                "for repo '%s', "
                "libgit return %d\n", 
                repo->dir_path, repo->url, r);
            return -1;
        } else {
            git_remote *remote;
            r = git_remote_create_with_fetchspec(
                &remote, repo->repository, MIRROR_REMOTE, 
                repo->url, MIRROR_FETCHSPEC);
            if (r < 0) {
                pr_error(
                    "Failed to create remote '"MIRROR_REMOTE"' "
                    "with fetch spec '"MIRROR_FETCHSPEC"' for url '%s', "
                    "libgit returns %d\n",
                    repo->url, r);
                git_repository_free(repo->repository);
                return -1;
            }
            git_config *config;
            r = git_repository_config(&config, repo->repository);
            if (r < 0) {
                pr_error(
                    "Failed to get config for repo for url '%s', "
                    "libgit return %d\n", repo->url, r);
                git_remote_free(remote);
                git_repository_free(repo->repository);
                return -1;
            }
            r = git_config_set_bool(config, MIRROR_CONFIG, true);
            if (r < 0) {
                pr_error(
                    "Failed to set config '"MIRROR_CONFIG"' to true for "
                    "repo for url '%s, libgit return %d\n", repo->url, r);
                git_config_free(config);
                git_remote_free(remote);
                git_repository_free(repo->repository);
                return -1;
            }
            git_config_free(config);
            git_remote_free(remote);
            return 1;
        }
    default:
        pr_error(
            "Failed to open bare repository at '%s' for repo '%s' "
            "and cannot fix libgit return %d\n", repo->dir_path, repo->url, r);
        return -1;
    }

    return 0;
}

int update_repo(
    struct config *const restrict config,
    unsigned long const repo_id
) {
    struct repo *const restrict repo = config->repos + repo_id;
    pr_warn("Updating repo '%s'...\n", repo->url);
    git_remote *remote;
    int r = git_remote_lookup(&remote, repo->repository, MIRROR_REMOTE) < 0;
    if (r) {
        pr_error(
            "Failed to lookup remote '"MIRROR_REMOTE"' from local repo "
            "for url '%s', libgit return %d\n", repo->url, r);
        return -1;
    }
    char const *const repo_remote_url = git_remote_url(remote);
    if (strcmp(repo_remote_url, repo->url)) {
        pr_error(
            "Configured remote url is '%s' instead of '%s', give up\n",
            repo_remote_url, repo->url);
        r = -1;
        goto free_remote;
    }
    git_strarray strarray;
    r = git_remote_get_fetch_refspecs(&strarray, remote);
    if (r < 0) {
        pr_error(
            "Failed to get fetch refspecs strarry for '%s', libgit return %d\n",
            repo->url, r);
        r = -1;
        goto free_strarray;
    }
    if (strarray.count != 1) {
        pr_error(
            "Refspec more than one for '%s', refuse to continue\n", 
            repo->url);
        r = -1;
        goto free_strarray;
    }
    if (strcmp(strarray.strings[0], MIRROR_FETCHSPEC)) {
        pr_error(
            "Fetch spec is '%s' instead of '"MIRROR_FETCHSPEC"' "
            "for '%s', give up\n",
            strarray.strings[0], repo->url);
        r = -1;
        goto free_strarray;
    }
    pr_warn("Begging fetching for '%s'\n", repo->url);
    config->fetch_options.proxy_opts.type = GIT_PROXY_NONE;
    for (unsigned short try = 0; try <= config->proxy_after; ++try) {
        if (try == config->proxy_after) {
            if (try) 
                pr_warn(
                    "Failed for %hu times, use proxy\n", config->proxy_after);
            config->fetch_options.proxy_opts.type = GIT_PROXY_SPECIFIED;
        }
        r = git_remote_fetch(remote, NULL, &config->fetch_options, NULL);
        if (r) {
            pr_error(
                "Failed to fetch, libgit return %d%s\n", 
                r, try < config->proxy_after ? ", will retry" : "");
        } else {
            break;
        }
    }
    if (r) {
        pr_error("Failed to update repo, considered failure\n");
        r = -1;
        goto free_strarray;
    }
    pr_warn("Ending fetching for '%s'\n", repo->url);
    repo->updated = true;
    r = 0;
free_strarray:
    git_strarray_free(&strarray);
free_remote:
    git_remote_free(remote);
    return r;
}

int repo_prepare_open_or_create(
    struct config *const restrict config,
    unsigned long const repo_id
) {
    struct repo *const restrict repo = config->repos + repo_id;
    switch (repo_open_or_init_bare(repo)) {
    case -1:
        pr_error("Failed to open or init bare repo for '%s'\n", repo->url);
        return -1;
    case 0:
        break;
    case 1:
        pr_warn(
            "Repo '%s' just created locally, need to update\n", repo->url);
        if (update_repo(config, repo_id)) {
            pr_error(
                "Failed to update freshly created repo '%s'\n", repo->url);
            return -1;
        }
        break;
    }
    return 0;
}

int config_repos_prepare_open_or_create(
    struct config *const restrict config
) {
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (repo_prepare_open_or_create(config, i)) {
            pr_error("Failed to open or create repo '%s' at '%s'\n", 
                (config->repos + i)->url, (config->repos + i)->dir_path);
            return -1;
        }
    }
    return 0;
}

int config_free(
    struct config *const restrict config
) {
    if (config->dir_archives) free (config->dir_archives);
    if (config->dir_repos) free (config->dir_repos);
    if (config->dir_checkouts) free (config->dir_checkouts);
    if (config->proxy_url) free (config->proxy_url);
    if (config->repos) {
        for (unsigned long i = 0; i < config->repos_count; ++i) {
            struct repo *const restrict repo = config->repos + i;
            if (repo->url) free (repo->url);
            if (repo->dir_path) free (repo->dir_path);
            if (repo->wanted_objects.objects_count) {
                for (struct wanted_base *wanted_object = 
                    repo->wanted_objects.objects_head;
                    wanted_object != NULL;
                    wanted_object = wanted_object->next) {
                    if (wanted_object->name) free (wanted_object->name);
                    if (wanted_object->previous) free (wanted_object->previous);
                }
                if (repo->wanted_objects.objects_tail)
                    free (repo->wanted_objects.objects_tail);
            }
            if (repo->repository) git_repository_free(repo->repository);
        }
        free (config->repos);
    }
    return 0;
}


// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_parse_parse_submodule_in_tree(
    struct config *const restrict config,
    unsigned long repo_id,
    git_tree const *const restrict tree, 
    char const *const restrict path,
    unsigned short len_path,
    char const *const restrict url,
    unsigned short len_url
) {
    (void )len_path;
    git_tree_entry *entry;
    if (git_tree_entry_bypath(&entry, tree, path)) {
        pr_error(
            "Path '%s' of submodule does not exist in tree, "
            "bad .gitmodules file?\n", path);
        return -1;
    }
    if (git_tree_entry_type(entry) != GIT_OBJECT_COMMIT) {
        pr_error("Object at path '%s' in tree is not a commit\n", path);
        goto free_entry;
    }
    struct wanted_commit *wanted_commit = malloc(sizeof *wanted_commit);
    if (wanted_commit == NULL) {
        pr_error("Failed to allocate memory for wanted commit\n");
        goto free_entry;
    }
    *wanted_commit = WANTED_COMMIT_INIT;
    wanted_commit->id = *git_tree_entry_id(entry);
    if (git_oid_tostr(
            wanted_commit->id_hex_string,
            sizeof wanted_commit->id_hex_string, 
            &wanted_commit->id
        )[0] == '\0') {
        pr_error("Failed to format commit into hex string\n");
        goto free_wanted_commit;
    }
    if ((wanted_commit->base.name = malloc(GIT_OID_MAX_HEXSIZE + 1)) == NULL) {
        pr_error("Failed to allocate memory for commit name\n");
        goto free_wanted_commit;
    }
    memcpy(wanted_commit->base.name, wanted_commit->id_hex_string, 
        sizeof wanted_commit->id_hex_string);
    wanted_commit->base.name_len = GIT_OID_MAX_HEXSIZE;
    pr_warn(
        "Specific commit '%s' is needed for submodule at path '%s' "
        "with url '%s'\n", wanted_commit->id_hex_string, path, url);
    XXH64_hash_t url_hash = XXH3_64bits(url, len_url);
    bool repo_in_config = false;
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo *const restrict repo_cmp = 
            config->repos + i;
        if (repo_cmp->url_hash == url_hash) {
            repo_cmp->wanted_objects.objects_tail->next = 
                (struct wanted_base *)wanted_commit;
            wanted_commit->base.previous = 
                repo_cmp->wanted_objects.objects_tail;
            repo_cmp->wanted_objects.objects_tail = 
                (struct wanted_base *)wanted_commit;
            ++repo_cmp->wanted_objects.objects_count;
            if (i >= repo_id) {
                // Note, i >= repo_id includes the current repo.
                // I decide not to care if a commit could reference itself
                // via a submodule, it just does not make sense as a commit
                // hash is only ever generated after you've submitted a tree
                // including all submodules. The chance a commit hash would be
                // generated with the same content of itself is just unlikely.
                // So, we don't need to do sanity check, as I don't believe
                // this will cause infinite loop
                pr_warn("Added wanted commit '%s' to repo '%s', will handle "
                        "that commit later\n", 
                        wanted_commit->id_hex_string, repo_cmp->url);
            } else {
                // Only care the case we've already gone through
                // the repo.
                pr_warn("Added wanted commit '%s' to parsed repo '%s', "
                    "need to go back to handle that specific commit\n",
                    wanted_commit->id_hex_string, repo_cmp->url);
                if (mirror_repo_ensure_wanted_commit(
                        config, repo_id, wanted_commit)) {
                    pr_error("Failed to handle added commit '%s' to parsed "
                    "repo '%s'\n", wanted_commit->id_hex_string, repo_cmp->url);
                    goto free_entry;
                }
            }
            repo_in_config = true;
            break;
        }
    }
    if (!repo_in_config) {
        pr_warn("Repo '%s' was not seen before, need to add it\n", url);
        if (config_add_repo_and_init_with_url(config, url, len_url)) {
            pr_error("Failed to add repo '%s'\n", url);
            goto free_name;
        }
        // THIS WILL CHANGE DURING THE ABOVE FUNCTION
        unsigned long repo_new_id = config->repos_count - 1;
        struct repo *const restrict repo_new =
            config->repos + repo_new_id;
        repo_new->added_from = RPEO_ADDED_FROM_SUBMODULES;
        repo_new->wanted_objects.objects_count = 1;
        repo_new->wanted_objects.objects_head = 
            (struct wanted_base *)wanted_commit;
        repo_new->wanted_objects.objects_tail = 
            (struct wanted_base *)wanted_commit;
        if (config_repo_finish(
                repo_new, config->dir_repos, config->len_dir_repos) || 
            repo_prepare_open_or_create(
                config, repo_new_id)) {
            pr_error("Failed to insert repo '%s' with its only wanted commit "
                "'%s' to repos\n",
                repo_new->url, wanted_commit->id_hex_string);
            goto free_entry;
        }
    }
    git_tree_entry_free(entry);
    return 0;
free_name:
    free(wanted_commit->base.name);
free_wanted_commit:
    free(wanted_commit);
free_entry:
    git_tree_entry_free(entry);
    return -1;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_parse_gitmodules_blob(
    struct config *const restrict config,
    unsigned long repo_id,
    git_tree const *const tree,
    git_blob *const restrict blob_gitmodules
) {
    const char *blob_gitmodules_ro_buffer = 
        git_blob_rawcontent(blob_gitmodules);
    if (blob_gitmodules_ro_buffer == NULL) {
        pr_error("Failed to get a ro buffer for gitmodules\n");
        return -1;
    }
    git_object_size_t blob_gitmodules_size = 
        git_blob_rawsize(blob_gitmodules);
    if (blob_gitmodules_size == 0) {
        pr_error("Tree entry .gitmodules blob size is 0\n");
        return -1;
    }
    char submodule_name[NAME_MAX] = "\0";
    char submodule_path[PATH_MAX] = "\0";
    char submodule_url[PATH_MAX] = "\0";
    unsigned short  len_submodule_name = 0,
                    len_submodule_path = 0,
                    len_submodule_url = 0;
    for (git_object_size_t id_start = 0; id_start < blob_gitmodules_size; ) {
        switch (blob_gitmodules_ro_buffer[id_start]) {
        case '\0':
        case '\n':
        case '\r':
        case '\b':
            ++id_start;
            continue;
        }
        unsigned short line_length = 0;
        git_object_size_t id_end = id_start + 1;
        for (; id_end < blob_gitmodules_size && line_length == 0;) {
            switch (blob_gitmodules_ro_buffer[id_end]) {
            case '\0':
            case '\n':
                line_length = id_end - id_start;
                break;
            default:
                ++id_end;
                break;
            }
        }
        if (line_length > 7) { // The shortest, "\turl = "
            char const *line = blob_gitmodules_ro_buffer + id_start;
            char const *line_end = blob_gitmodules_ro_buffer + id_end;
            switch (blob_gitmodules_ro_buffer[id_start]) {
            case '[':
                if (!strncmp(line + 1, "submodule \"", 11)) {
                    if (submodule_name[0]) {
                        pr_error(
                            "Incomplete submodule definition for '%s'\n", 
                            submodule_name);
                        return -1;
                    }
                    char const *submodule_name_start = line + 12;
                    char const *right_quote = submodule_name_start;
                    for (;
                        *right_quote != '"' && right_quote < line_end; 
                        ++right_quote);
                    len_submodule_name = right_quote - submodule_name_start;
                    strncpy(
                        submodule_name,
                        submodule_name_start,
                        len_submodule_name);
                    submodule_name[len_submodule_name] = '\0';
                }
                break;
            case '\t':
                char const *value = NULL;
                char *submodule_value = NULL;
                unsigned short *len_submodule_value = NULL;
                if (!strncmp(line + 1, "path = ", 7)) {
                    value = line + 8;
                    submodule_value = submodule_path;
                    len_submodule_value = &len_submodule_path;
                } else if (!strncmp(line + 1, "url = ", 6)) {
                    value = line + 7;
                    submodule_value = submodule_url;
                    len_submodule_value = &len_submodule_url;
                }
                if (value) {
                    if (submodule_name[0] == '\0') {
                        pr_error(
                            "Submodule definition begins before "
                            "the submodule name\n");
                        return -1;
                    }
                    if (submodule_value[0] != '\0') {
                        pr_error("Duplicated value definition for "
                            "submodule '%s'\n", submodule_name);
                        return -1;
                    }
                    *len_submodule_value = line_end - value;
                    strncpy(submodule_value, value, *len_submodule_value);
                    submodule_value[*len_submodule_value] = '\0';
                    if (submodule_path[0] != '\0' && 
                        submodule_url[0] != '\0') {
                        pr_warn(
                            "Submodule '%s', path '%s', url '%s'\n", 
                            submodule_name, submodule_path, submodule_url);
                        if (mirror_repo_parse_parse_submodule_in_tree(
                            config, repo_id, tree, 
                                    submodule_path, len_submodule_path,
                                    submodule_url, len_submodule_url)) {
                            pr_error(
                                "Failed to recursively clone or update "
                                "submodule '%s' (url '%s')\n", 
                                submodule_name, submodule_url);
                            return -1;
                        }
                        submodule_name[0] = '\0';
                        submodule_path[0] = '\0';
                        submodule_url[0] = '\0';
                    }
                }
                break;
            default:
                break;
            }
        }
        id_start = id_end + 1;
    }
    return 0;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_parse_submodules(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_commit *const restrict wanted_commit,
    git_tree const *const tree,
    git_tree_entry const *const entry_gitmodules
) {
    struct repo const *restrict repo = config->repos + repo_id;
    if (git_tree_entry_type(entry_gitmodules) != GIT_OBJECT_BLOB) {
        pr_error(
            "Tree entry .gitmodules in commit '%s' for repo '%s' "
            "is not a blob\n",
            wanted_commit->id_hex_string, repo->url);
        return -1;
    }
    git_object *object_gitmodules;
    int r = git_tree_entry_to_object(
        &object_gitmodules, repo->repository, entry_gitmodules);
    if (r) {
        pr_error("Failed to convert tree entry for gitmodules to object\n");
        return -1;
    }
    git_blob *blob_gitmodules = (git_blob *)object_gitmodules;
    r = mirror_repo_parse_gitmodules_blob(
        config, repo_id, tree, blob_gitmodules);
    repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to parse gitmodules blob\n");
        r = -1;
        goto free_object;
    }
    r = 0;
free_object:
    free(object_gitmodules);
    return r;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_ensure_wanted_commit(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_commit *const restrict wanted_commit
) {
    struct repo *restrict repo = config->repos + repo_id;
    git_commit *commit;
    int r = git_commit_lookup(&commit, repo->repository, &wanted_commit->id);
    if (r) {
        if (repo->updated) {
            pr_error(
                "Failed to lookup commit '%s' in repo '%s' "
                "even it's up-to-date, "
                "libgit return %d, consider failure\n", 
                wanted_commit->id_hex_string, repo->url, r);
            return -1;
        }
        pr_warn(
            "Commit '%s' does not exist in repo '%s' (libgit return %d), "
            "but the repo is not updated yet, "
            "trying to update the repo before looking up the commit again\n", 
            wanted_commit->id_hex_string, repo->url, r);
        if (update_repo(config, repo_id)) {
            pr_error("Failed to update repo\n");
            return -1;
        }
        if ((r = git_commit_lookup(
            &commit, repo->repository, &wanted_commit->id))) {
            pr_error(
                "Failed to lookup commit '%s' in repo '%s' "
                "even after updating the repo, libgit return %d, "
                "consider failure\n",
                wanted_commit->id_hex_string, repo->url, r);
            return -1;
        }
    }
    git_tree *tree;
    if ((r = git_commit_tree(&tree, commit))) {
        pr_error(
            "Failed to get the commit tree pointed by commit '%s' "
            "in repo '%s', libgit return %d\n", 
            wanted_commit->id_hex_string, repo->url, r);
        r = -1;
        goto free_commit;
    }
    git_tree_entry const *const entry_gitmodules = 
        git_tree_entry_byname(tree, ".gitmodules");
    if (entry_gitmodules != NULL) {
        pr_warn(
            "Found .gitmodules in commit tree of '%s' for repo '%s', "
            "parsing submodules\n", wanted_commit->id_hex_string, repo->url);
        r = mirror_repo_parse_submodules(
            config, repo_id, wanted_commit, tree, entry_gitmodules);
        repo = config->repos + repo_id;
        if (r) {
            pr_error(
                "Failed to parse submodules in commit tree of '%s' "
                "for repo '%s'\n", 
                wanted_commit->id_hex_string, repo->url);
            r = -1;
            goto free_commit;
        }
    }
    pr_warn("Ensured existence of commit '%s' in repo '%s'\n",
        wanted_commit->id_hex_string, repo->url);
    r = 0;
free_commit:
    git_commit_free(commit);
    return r;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_ensure_wanted_head(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_reference *const restrict wanted_head
) {
    struct repo *restrict repo = config->repos + repo_id;
    git_reference *head;
    int r = git_repository_head(&head, repo->repository);
    switch (r) {
    case GIT_OK:
        break;
    case GIT_EUNBORNBRANCH:
        pr_error("Failed to resolve head, HEAD points to a non-"
            "existing branch\n");
        return -1;
    case GIT_ENOTFOUND:
        pr_error("Failed to resolve head, HEAD is missing\n");
        return -1;
    default:
        pr_error("Failed to find head, unhandled libgit return %d\n", r);
        return -1;
    }
    git_object *object;
    if ((r = git_reference_peel(&object, head, GIT_OBJECT_COMMIT))) {
        pr_error(
            "Failed to peel HEAD into a commit object, libgit return %d\n",
            r);
        return -1;
    }
    git_commit *commit = (git_commit *)object;
    wanted_head->commit_resolved = true;
    wanted_head->commit.id = *git_commit_id(commit);
    if (git_oid_tostr(
            wanted_head->commit.id_hex_string,
            sizeof wanted_head->commit.id_hex_string, 
            &wanted_head->commit.id
        )[0] == '\0') {
        pr_error("Failed to format git oid hex string\n");
        git_object_free(object);
        return -1;
    }
    git_object_free(object);
    pr_warn("Resolved HEAD of repo '%s' to commit '%s', working on that commit "
        "instead\n",
        repo->url, wanted_head->commit.id_hex_string);
    r = mirror_repo_ensure_wanted_commit(config, repo_id, &wanted_head->commit);
    repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensuring robust of commit '%s' resolved from HEAD "
        "of repo '%s'\n", wanted_head->commit.id_hex_string, repo->url);
        return -1;
    }
    pr_warn("Ensured existence of HEAD in repo '%s'\n", repo->url);
    return 0;
}

// int mirror_repo_ensure_wanted_reference(
//     struct config *const restrict config,
//     struct repo *const restrict repo,
//     struct wanted_base *wanted_object
// ) {
//     if (!repo->updated) {
//         if (update_repo(config, repo)) {
//             pr_error(
//                 "Failed to make sure repo '%s' is up-to-date before "
//                 "resolving reference\n", repo->url);
//             return -1;
//         }
//     }
//     switch (wanted_object->type) {
//     case WANTED_TYPE_ALL_BRANCHES:
//     case WANTED_TYPE_ALL_TAGS:
//         // git_branch_iterator
//         break;
//     case WANTED_TYPE_BRANCH:
//     case WANTED_TYPE_TAG:

//         break;
//     default:
//         pr_error("Impossible wanted object type\n");
//         return -1;
//     }


//     // mirror_repo_ensure_wanted_commit();
//     return 0;
// }

int mirror_repo(
    struct config *const restrict config,
    unsigned long const repo_id
) {
    struct repo *restrict repo = config->repos + repo_id;
    pr_warn("Mirroring repo '%s'\n", repo->url);
    if (repo->wanted_objects.dynamic && !repo->updated) {
        pr_warn(
            "Dynamic wanted objects set for repo '%s', need to update\n", 
            repo->url);
        if (update_repo(config, repo_id)) {
            pr_error(
                "Failed to update repo '%s' to prepare for "
                "dynamic wanted objects\n",
                repo->url);
            return -1;
        }
    }
    int r = -1;
    for (struct wanted_base *wanted_object = repo->wanted_objects.objects_head;
        wanted_object != NULL;
        wanted_object = wanted_object->next) {
        switch (wanted_object->type) {
        case WANTED_TYPE_COMMIT:
            r = mirror_repo_ensure_wanted_commit(
                config, repo_id, (struct wanted_commit *)wanted_object);
            repo = config->repos + repo_id;
            if (r) {
                pr_error(
                    "Failed to ensure commit '%s' robust for repo '%s'",
                    wanted_object->name, repo->url);
                return -1;   
            }
            break;
        case WANTED_TYPE_ALL_BRANCHES:
        case WANTED_TYPE_ALL_TAGS:
        case WANTED_TYPE_BRANCH:
        case WANTED_TYPE_TAG:
        case WANTED_TYPE_HEAD:
            if (!repo->updated) {
                if (update_repo(config, repo_id)) {
                    pr_error(
                        "Failed to make sure repo '%s' is up-to-date before "
                        "resolving reference\n", repo->url);
                    return -1;
                }
            }
            switch (wanted_object->type) {
            case WANTED_TYPE_ALL_BRANCHES:
            case WANTED_TYPE_ALL_TAGS:
            case WANTED_TYPE_BRANCH:
            case WANTED_TYPE_TAG:
                pr_error("WIP!!!\n");
                return -1;
            case WANTED_TYPE_HEAD:
                r = mirror_repo_ensure_wanted_head(
                    config, repo_id, (struct wanted_reference *)wanted_object);
                repo = config->repos + repo_id;
                if (r) {
                    pr_error("Failed to ensure HEAD robust for repo '%s'",
                    repo->url);
                    return -1;
                }
                break;
            default:
                pr_error("Impossible wanted object type\n");
                return -1;
            }
            break;
        case WANTED_TYPE_UNKNOWN:
        default:
            pr_error(
                "Impossible wanted type unknown for wanted object '%s' "
                "for repo '%s'\n",
                wanted_object->name, repo->url);
            return -1;
        }
    }
    pr_warn("Finished mirroring repo '%s'\n", repo->url);
    return 0;
}

int mirror_all_repos(
    struct config *const restrict config
) {
    if (config_repos_prepare_open_or_create(config)) {
        pr_error("Failed to prepare repos\n");
        return -1;
    }
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (mirror_repo(config, i)) {
            pr_error("Failed to mirror all repos\n");
            return -1;
        }
    }
    pr_warn("Finished mirroring all repos\n");
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
            pr_error(
                "Unexpected argument, %d (-%c) '%s'\n", c, c, argv[optind - 1]);
            return -1;
        }
    }
    struct config config;
    if (config_read(&config, config_path)) {
        pr_error("Failed to read config\n");
        return -1;
    }
    if (config.repos_count == 0) {
        pr_warn("No repos defined, early quit\n");
        return 0;
    }
    pr_warn("Initializing libgit2\n");
    git_libgit2_init();
    int r = mirror_all_repos(&config);
    if (r) {
        pr_error("Failed to mirro all repos\n");
    }
    config_free(&config);
    pr_warn("Shutting down libgit2\n");
    git_libgit2_shutdown();
    return r;
}