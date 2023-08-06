#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <getopt.h>
#include <dirent.h>

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
    printf("[ERROR] %s:%d: "format, __FUNCTION__, __LINE__, ##arg)

#define pr_error_with_errno(format, arg...) \
    pr_error(format", errno: %d, error: %s\n", ##arg, errno, strerror(errno))

#define pr_warn(format, arg...) \
    printf("[WARN] "format, ##arg)

#define pr_info(format, arg...) \
    printf("[INFO] "format, ##arg)

#ifdef DEBUGGING
#define pr_debug(format, arg...) \
    printf("[DEBUG] %s:%d: "format, __FUNCTION__, __LINE__, ##arg)
#else
#define pr_debug(format, arg...)
#endif

#ifndef VERSION
#define VERSION "unknown"
#endif

#define TAR_POSIX_HEADER_MTIME_LEN 12
#define TAR_POSIX_HEADER_NAME_LEN 100

#define TAR_POSIX_HEADER_DECLARE {/* byte offset */\
    char name[100];               /*   0 */\
    char mode[8];                 /* 100 octal mode string %07o */\
    char uid[8];                  /* 108 octal uid string %07o */\
    char gid[8];                  /* 116 octal gid string %07o */\
    char size[12];                /* 124 octal size %011o */\
    char mtime[12];               /* 136 octal mtime string %011o */\
    char chksum[8];               /* 148 octal checksum string %06o + space */\
    char typeflag;                /* 156 either TAR_{REG,LINK,DIR}TYPE */\
    char linkname[100];           /* 157 symlink target */\
    char magic[6];                /* 257 ustar\0 */\
    char version[2];              /* 263 \0 0*/\
    char uname[32];               /* 265 uname + padding \0 */\
    char gname[32];               /* 297 gname + padding \0 */\
    char devmajor[8];             /* 329 all 0 */\
    char devminor[8];             /* 337 all 0 */\
    char prefix[155];             /* 345 all 0 */\
                                  /* 500 */\
}

struct tar_posix_header TAR_POSIX_HEADER_DECLARE;

struct tar_posix_header_512_block {
    union {
        struct tar_posix_header header;
        struct TAR_POSIX_HEADER_DECLARE;
    };
    unsigned char padding[12];
};

unsigned char const EMPTY_512_BLOCK[512] = {0};

#define TAR_POSIX_MAGIC   "ustar"        /* ustar and a null */
#define TAR_POSIX_VERSION "00"           /* 00 and no null */
#define TAR_GNU_MAGIC     "ustar "
#define TAR_GNU_VERSION   " "
#define TAR_MAGIC TAR_GNU_MAGIC
#define TAR_VERSION TAR_GNU_VERSION
// Basically, posix is "ustar\000", gnu is "ustar  \0"

/* Values used in typeflag field.  */
#define TAR_REGTYPE  '0'            /* regular file */
#define TAR_LNKTYPE  '1'            /* link */
#define TAR_SYMTYPE  '2'
#define TAR_DIRTYPE  '5'            /* directory */

#define GNUTAR_LONGLINK 'K'
#define GNUTAR_LONGNAME 'L'

#define TAR_LONGLINKTYPE GNUTAR_LONGLINK
#define TAR_LONGNAMETYPE GNUTAR_LONGNAME

#define GNUTAR_LONGLINK_NAME    "././@LongLink"

#define TAR_MODE(X)     "0000" #X
#define TAR_MODE_644    TAR_MODE(644)
#define TAR_MODE_755    TAR_MODE(755)
#define TAR_MODE_777    TAR_MODE(777)
#define TAR_HEADER_7_BYTE_0 "0000000"
#define TAR_UID_ROOT    TAR_HEADER_7_BYTE_0
#define TAR_GID_ROOT    TAR_HEADER_7_BYTE_0
#define TAR_HEADER_11_BYTE_0 "00000000000"
#define TAR_SIZE_0      TAR_HEADER_11_BYTE_0
#define TAR_MTIME_0     TAR_HEADER_11_BYTE_0
#define TAR_CHECKSUM_BLANK  "      "
#define TAR_DEVMAJOR    TAR_HEADER_7_BYTE_0
#define TAR_DEVMINOR    TAR_HEADER_7_BYTE_0

#define TAR_INIT(NAME, MODE, TYPEFLAG) {\
    .name = NAME, \
    .mode = TAR_MODE(MODE), \
    .uid = TAR_UID_ROOT, \
    .gid = TAR_GID_ROOT, \
    .size = TAR_SIZE_0, \
    .mtime = TAR_MTIME_0, \
    .chksum = TAR_CHECKSUM_BLANK, \
    .typeflag = TYPEFLAG, \
    .linkname = "", \
    .magic = TAR_MAGIC, \
    .version =  TAR_VERSION, \
    .uname = "root", \
    .gname = "root", \
    .devmajor = "", \
    .devminor = "", \
    .prefix = "" \
}

#define TAR_POSIX_INIT(MODE, TYPEFLAG) TAR_INIT("", MODE, TYPEFLAG)

struct tar_posix_header const TAR_POSIX_HEADER_FILE_REG_INIT = 
    TAR_POSIX_INIT(644, TAR_REGTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_FILE_EXE_INIT = 
    TAR_POSIX_INIT(755, TAR_REGTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_SYMLINK_INIT = 
    TAR_POSIX_INIT(777, TAR_SYMTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_FOLDER_INIT = 
    TAR_POSIX_INIT(755, TAR_DIRTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_GNU_LONGLINK_INIT = 
    TAR_INIT(GNUTAR_LONGLINK_NAME, 644, TAR_LONGLINKTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_GNU_LONGNAME_INIT = 
    TAR_INIT(GNUTAR_LONGLINK_NAME, 644, TAR_LONGNAMETYPE);

// struct tar_posix_header const TAR_POSIX_HEADER_LONGLINK

enum wanted_type {
    WANTED_TYPE_UNKNOWN,
    WANTED_TYPE_ALL_BRANCHES,
    WANTED_TYPE_ALL_TAGS,
    WANTED_TYPE_REFERENCE,
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
    "reference",
    "commit",
    "branch",
    "tag",
    "head"
};

#define WANTED_BASE_DECLARE {\
    enum wanted_type type;\
    char *name;\
    unsigned short name_len;\
    bool archive;\
    bool checkout;\
    struct wanted_base *previous, *next;\
}

struct wanted_base WANTED_BASE_DECLARE;

struct wanted_base const WANTED_BASE_INIT = {0};

struct wanted_base const WANTED_ALL_BRANCHES_INIT = {
    .type = WANTED_TYPE_ALL_BRANCHES, 0 };

struct wanted_base const WANTED_ALL_TAGS_INIT = {
    .type = WANTED_TYPE_ALL_TAGS, 0 };

struct wanted_commit_submodule {
    char *path;
    unsigned short path_len;
    char *url;
    unsigned short url_len;
    XXH64_hash_t url_hash;
    unsigned long repo_id;
    git_oid id;
    char id_hex_string[GIT_OID_MAX_HEXSIZE + 1];
};

struct wanted_commit_submodule const WANTED_COMMIT_SUBMODULE_INIT = {
    .repo_id = (unsigned long) -1, {{0}}};

#define WANTED_COMMIT_DECLARE { \
    union { \
        struct wanted_base base; \
        struct WANTED_BASE_DECLARE; \
    }; \
    git_oid id; \
    char id_hex_string[GIT_OID_MAX_HEXSIZE + 1]; \
    struct wanted_commit_submodule *submodules; \
    unsigned long submodules_count; \
    unsigned long submodules_allocated; \
}

struct wanted_commit WANTED_COMMIT_DECLARE;

struct wanted_commit const WANTED_COMMIT_INIT = {
    .base.type = WANTED_TYPE_COMMIT, 0};

#define WANTED_REFERENCE_DECLARE { \
    union { \
        struct wanted_commit commit; \
        struct WANTED_COMMIT_DECLARE; \
    }; \
    bool commit_resolved; \
}

struct wanted_reference WANTED_REFERENCE_DECLARE;

struct wanted_any {
    union {
        struct wanted_reference reference;
        struct WANTED_REFERENCE_DECLARE;
    };
};

struct wanted_reference const WANTED_REFERENCE_INIT = {
    .commit.base.type = WANTED_TYPE_REFERENCE, 0};

struct wanted_reference const WANTED_BRANCH_INIT = {
    .commit.base.type = WANTED_TYPE_BRANCH, 0 };

struct wanted_reference const WANTED_TAG_INIT = {
    .commit.base.type = WANTED_TYPE_TAG, 0 };

struct wanted_reference const WANTED_HEAD_INIT = {
    .commit.base.type = WANTED_TYPE_HEAD, 0 };

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
    char    *url,
            *url_no_scheme_sanitized;
    unsigned short  url_len,
                    url_no_scheme_sanitized_len,
                    url_no_scheme_sanitized_parts;
    XXH64_hash_t    url_hash,
                    url_no_scheme_sanitized_hash;
    char *symlink_path;
    unsigned short symlink_path_len;
    char *symlink_target;
    unsigned short symlink_target_len;
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
                    len_dir_checkouts,
                    export_threads;
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

struct export_commit_treewalk_payload {
    struct config const *const restrict config;
    struct repo const *const restrict repo;
    struct wanted_commit const *const restrict wanted_commit;
    char *const restrict submodule_path;
    unsigned short const submodule_path_len;
    bool const archive;
    char const *const restrict mtime;
    int const fd_archive;
    bool const checkout;
    char const *const restrict dir_checkout;
};

int export_commit_treewalk_callback(
	char const *const restrict root, 
    git_tree_entry const *const restrict entry,
    void *payload
);

int wanted_compare_commit(
    struct wanted_commit const *const restrict a,
    struct wanted_commit const *const restrict b
) {
    if (a->base.type != b->base.type ||
        a->base.type != WANTED_TYPE_COMMIT) {
        pr_error("Objects not both commits\n");
        return -1;
    }
    if (a->base.name_len != b->base.name_len ||
        a->base.name_len != GIT_OID_MAX_HEXSIZE) {
        pr_error("Object names not both commit hash\n");
        return -2;
    }
    if (a->base.archive != b->base.archive) {
        return 1;
    }
    if (a->base.checkout != b->base.checkout) {
        return 2;
    }
    if (git_oid_cmp(&a->id, &b->id)) {
        return 3;
    }
    return 0;
};

int mirror_repo_ensure_wanted_commit(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_commit *const restrict wanted_commit
);

int sideband_progress(char const *string, int len, void *payload) {
	(void)payload; /* unused */
    printf("remote: %.*s", len, string);
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
		printf("net %3d%% (%4zu  kb, %5u/%5u)  /  idx %3d%% (%5u/%5u)\r",
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

int mkdir_allow_existing(
    char *const restrict path
) {
    if (mkdir(path, 0755)) {
        if (errno == EEXIST) {
            struct stat stat_buffer;
            if (stat(path, &stat_buffer)) {
                pr_error_with_errno("Failed to stat '%s'", path);
                return -1;
            }
            if ((stat_buffer.st_mode & S_IFMT) == S_IFDIR) {
                return 0;
            } else {
                pr_error("Exisitng '%s' is not a folder\n", path);
                return -1;
            }
        } else {
            pr_error_with_errno("Failed to mkdir '%s'", path);
            return -1;
        }
    }
    return 0;
}

int mkdir_recursively(
    char *const restrict path
) {
    for (char *c = path; ; ++c) {
        switch (*c) {
        case '\0':
            return mkdir_allow_existing(path);
        case '/':
            *c = '\0';
            if (mkdir_allow_existing(path)) {
                *c = '/';
                pr_error("Failed to mkdir recursively '%s'\n", path);
                return -1;
            }   
            *c = '/';
            break;
        default:
            break;
        }
    }
}

static inline unsigned int 
    tar_header_checksum(struct tar_posix_header *header) {
    unsigned int checksum = 0;
    for (unsigned i = 0; i < sizeof *header; ++i) {
        switch (i) {
        case 148 ... 155:
            checksum += ' ';
            break;
        default:
            checksum += ((unsigned char *)header)[i];
            break;
        }
    }
    return checksum;
}

int tar_header_checksum_self(struct tar_posix_header *header) {
    if (snprintf(header->chksum, sizeof header->chksum - 1, "%06o", 
        tar_header_checksum(header)) < 0) {
        pr_error_with_errno("Failed to format header checksum");
        return -1;
    }
    header->chksum[sizeof header->chksum - 1] = ' ';
    return 0;
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

// May re-allocate config->repos
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
    char url_no_scheme_sanitized[PATH_MAX];
    unsigned short  url_no_scheme_sanitized_len = 0,
                    url_no_scheme_sanitized_parts = 1;
    char const *url_no_scheme = url;
    for (char const *c = url; *c != '\0'; ++c) {
        if (*c == ':' && *(c + 1) == '/' && *(c + 2) == '/') {
            if (*(c + 3) == '\0') {
                pr_error("Illegal URL '%s': ending with scheme\n",
                    url);
                return -1;
            }
            url_no_scheme = c + 3;
            break;
        }
    }
    for (char const *c = url_no_scheme; *c; ++c) {
        if (*c == '/') {
            // Skip all continous leading /
            for (; *(c + 1) =='/'; ++c);
            // When the above loop ends, we're at the last /
            // of potentially a list of /
            // In case url is like a/b/c/, ending with /,
            // we don't want to copy the ending /
            if (*(c + 1) == '\0') break;
            ++url_no_scheme_sanitized_parts;
        }
        url_no_scheme_sanitized[url_no_scheme_sanitized_len++] = *c;
    }
    if (url_no_scheme_sanitized_len == 0) {
        pr_error("Sanitized url for url '%s' is empty\n", url);
        return -1;
    }
    url_no_scheme_sanitized[url_no_scheme_sanitized_len] = '\0';
    XXH64_hash_t url_hash = XXH3_64bits(url, len_url);
    XXH64_hash_t url_no_scheme_sanitized_hash = XXH3_64bits(
        url_no_scheme_sanitized, url_no_scheme_sanitized_len);
#ifdef PRE_CREATE_SANITIZED_DIRS
    bool sanitized_duplicated = false;
#endif
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo const *const restrict repo_cmp = config->repos + i;
        if (repo_cmp->url_hash == url_hash) {
            pr_error(
                "Repo '%s' was already defined, duplication not allowed\n",
                 url);
            return -1;
        }
        if (repo_cmp->url_no_scheme_sanitized_hash == 
                url_no_scheme_sanitized_hash) {
            pr_warn("Repo '%s' and '%s' share the same no scheme sanitized "
            "url '%s', this is not recommended and you should check upstream "
            "if they are acutally the same repo\n",
                url, repo_cmp->url, url_no_scheme_sanitized);
#ifdef PRE_CREATE_SANITIZED_DIRS
            sanitized_duplicated = true;
#endif
        }
    }
#ifdef PRE_CREATE_SANITIZED_DIRS
    if (!sanitized_duplicated) {
        char dir_sanitized_link[PATH_MAX];
        char const *dirs[] = {
            config->dir_archives, config->dir_checkouts
        };
        for (unsigned short i = 0; i < sizeof dirs / sizeof *dirs; ++i) {
            if (dirs[i] == NULL) continue;
            if (snprintf(dir_sanitized_link, PATH_MAX, "%s/links/%s", 
                dirs[i], url_no_scheme_sanitized) < 0) {
                pr_error_with_errno(
                    "Failed to format sanitized link dir for '%s'", dirs[i]);
                return -1;
            }
            if (mkdir_recursively(dir_sanitized_link)) {
                pr_error("Failed to mkdir '%s' recursively\n", 
                        dir_sanitized_link);
                return -1;
            }
        }
    }
#endif
    if (++config->repos_count > config->repos_allocated) {
        while (config->repos_count > (
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
    if ((repo->url_no_scheme_sanitized = 
        malloc(url_no_scheme_sanitized_len + 1)) == NULL) {
        pr_error("Failed to allocate memory for no scheme sanitized url");
        free(repo->url);
        --config->repos_count;
        return -1;
    }
    memcpy(repo->url, url, len_url + 1);
    repo->url_len = len_url;
    repo->url_hash = url_hash;
    memcpy(repo->url_no_scheme_sanitized, url_no_scheme_sanitized, 
        url_no_scheme_sanitized_len + 1);
    repo->url_no_scheme_sanitized_len = url_no_scheme_sanitized_len;
    repo->url_no_scheme_sanitized_hash = url_no_scheme_sanitized_hash;
    repo->url_no_scheme_sanitized_parts = url_no_scheme_sanitized_parts;
    pr_info("Added repo '%s', hash '%016lx', no scheme sanitized url '%s'\n", 
            repo->url,
            repo->url_hash,
            repo->url_no_scheme_sanitized);
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
    if (!strncmp(object, "refs/", 5)) return WANTED_TYPE_REFERENCE;
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
    if ((*wanted_object)->previous) {
        (*wanted_object)->previous->next = (struct wanted_base *)wanted_commit;
        wanted_commit->base.previous = (*wanted_object)->previous;
    }
    if ((*wanted_object)->next) {
        (*wanted_object)->next->previous = (struct wanted_base *)wanted_commit;
        wanted_commit->base.next = (*wanted_object)->next;
    }
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
    if ((*wanted_object)->previous) {   
        (*wanted_object)->previous->next = 
            (struct wanted_base *)wanted_reference;
        wanted_reference->commit.base.previous = (*wanted_object)->previous;
    }
    if ((*wanted_object)->next) {
        (*wanted_object)->next->previous = 
            (struct wanted_base *)wanted_reference;
        wanted_reference->commit.base.next = (*wanted_object)->next;
    }
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
    case WANTED_TYPE_REFERENCE:
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
        if (wanted_object_complete_from_base(
                &wanted_object)) {
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
                        -> wanted_objects.objects_tail)) {
                pr_error("Failed to guess type\n");
                return -1;
            }
            struct wanted_objects *const wanted_objects =
                &(config->repos + state->repo_id)->wanted_objects;
            int r = wanted_object_complete_from_base(
                        &wanted_objects->objects_tail);
            if (wanted_objects->objects_count == 1)
                wanted_objects->objects_head = wanted_objects->objects_tail;
            if (r) {
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
        printf(
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
        switch (wanted_object->type) {
        case WANTED_TYPE_BRANCH:
        case WANTED_TYPE_TAG:
        case WANTED_TYPE_REFERENCE:
        case WANTED_TYPE_HEAD:
            struct wanted_reference *wanted_reference = 
                (struct wanted_reference *) wanted_object;
            if (wanted_reference->commit_resolved) {
                printf(
                    "|            commit: %s\n",
                    wanted_reference->commit.id_hex_string);
            }
            __attribute__((fallthrough));
        case WANTED_TYPE_COMMIT:
            struct wanted_commit *wanted_commit = 
                (struct wanted_commit *) wanted_object;
            if (wanted_commit->submodules_count) {
                printf(
                    "|            submodules:\n");
            }
            for (unsigned long i = 0; 
                i < wanted_commit->submodules_count; 
                ++i) {
                struct wanted_commit_submodule * wanted_commit_submodule =
                    wanted_commit->submodules + i;
                printf(
                    "|              - path: %s\n"
                    "|                url: %s\n"
                    "|                repo_id: %lu\n"
                    "|                commit: %s\n",
                    wanted_commit_submodule->path,
                    wanted_commit_submodule->url,
                    wanted_commit_submodule->repo_id,
                    wanted_commit_submodule->id_hex_string);
            }
            // break;
        default:
            break;
        }
    }

}

void print_config_repo(struct repo const *const restrict repo) {
    printf(
        "|  - %s%s:\n"
        "|      hash: %016lx\n"
        "|      dir: %s\n"
        "|      sanitized: %s\n"
        "|      symlink: %s\n",
        repo->url,
        repo->added_from ? " (added from submodule)" : "",
        repo->url_hash,
        repo->dir_path,
        repo->url_no_scheme_sanitized,
        repo->symlink_path);
    if (repo->wanted_objects.objects_count) {
        printf(
        "|      wanted (%lu, %s):\n", 
            repo->wanted_objects.objects_count,
            repo->wanted_objects.dynamic ? "dynamic" : "static");
        print_config_repo_wanted(&repo->wanted_objects);
    }
}

void print_config(struct config const *const restrict config) {
    printf(
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
        printf("| repos (%lu): \n", config->repos_count);
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
    return 0;

error:
    yaml_parser_delete(&parser);
    return -1;
}

int guarantee_symlink (
    char const *const restrict symlink_path,
    unsigned short const len_symlink_path,
    char const *const restrict symlink_target
) {
    char path[PATH_MAX];
    ssize_t len = readlink(symlink_path, path, PATH_MAX);
    if (len < 0) {
        switch (errno) {
        case ENOENT:
            break;
        default:
            pr_error_with_errno("Failed to read link at '%s'", symlink_path);
            return -1;
        }
    } else {
        path[len] = '\0';
        if (strcmp(path, symlink_target)) {
            pr_warn("Symlink at '%s' points to '%s' instead of '%s', "
            "if you see this message for too many times, you've probably set "
            "too many repos with same path but different schemes.\n",
            symlink_path, path, symlink_target);
            if (unlink(symlink_path) < 0) {
                pr_error_with_errno("Faild to unlink '%s'", symlink_path);
                return -1;
            }
        } else {
            pr_info("Symlink '%s' -> '%s' already existing\n",
                symlink_path, symlink_target);
            return 0;
        }
    }
    if (symlink(symlink_target, symlink_path) < 0) {
        switch (errno) {
        case ENOENT:
            break;
        default:
            pr_error_with_errno(
                "Failed to create symlink '%s' -> '%s'",
                symlink_path, symlink_target);
            return -1;
        }
    } else {
        pr_info("Created symlink '%s' -> '%s'\n", 
            symlink_path, symlink_target);
        return 0;
    }
    char symlink_path_dup[PATH_MAX];
    strncpy(symlink_path_dup, symlink_path, PATH_MAX);
    unsigned short last_sep = 0;
    for (unsigned short i = len_symlink_path; i > 0; --i) {
        char *c = symlink_path_dup + i;
        if (*c == '/') {
            if (!last_sep) {
                last_sep = i;
            }
            *c = '\0';
            if (mkdir(symlink_path_dup, 0755)) {
                if (errno != ENOENT) {
                    pr_error_with_errno(
                        "Failed to create folder '%s' as parent of symlink "
                        "'%s' -> '%s'",
                        symlink_path_dup, symlink_path, symlink_target);
                    return -1;
                }
            } else {
                for (unsigned short j = i; j < last_sep; ++j) {
                    c = symlink_path_dup + j;
                    if (*c == '\0') {
                        *c = '/';
                        if (mkdir(symlink_path_dup, 0755)) {
                            pr_error_with_errno(
                                "Failed to create folder '%s' as parent of "
                                "symlink '%s' -> '%s'",
                                symlink_path_dup, symlink_path, symlink_target);
                            return -1;
                        }
                    }
                }
                break;
            }
        }
    }
    if (symlink(symlink_target, symlink_path) < 0) {
        pr_error_with_errno(
            "Failed to create symlink '%s' -> '%s'",
            symlink_path, symlink_target);
        return -1;
    }
    pr_info("Created symlink '%s' -> '%s'\n", 
        symlink_path, symlink_target);
    return 0;
}


int config_repo_generate_symlink(
    struct repo *const restrict repo,
    char const *const restrict dir_repos
) {
    char symlink_path[PATH_MAX] = "";
    char symlink_target[PATH_MAX] = "";
    int r = snprintf(symlink_path, PATH_MAX, "%s/links/%s", dir_repos, 
                    repo->url_no_scheme_sanitized);
    if (r < 0) {
        pr_error_with_errno("Failed to fill symlink path");
        return -1;
    } else if (r <= 6) {
        pr_error("Impossible routine\n");
        return -1;
    }
    unsigned short const len_symlink_path = r;
    unsigned short const len_symlink_target = 
        sizeof repo->dir_name - 1 + repo->url_no_scheme_sanitized_parts * 3;
    char *symlink_target_current = symlink_target;
    // Supposed sanitized url is github.com/7Ji/ampart.git, parts is 3
    // Link would be created at repos/links/github.com/7Ji/ampart.git
    // Target should be ../../../[hash]
    for (unsigned short i = 0; i < repo->url_no_scheme_sanitized_parts; ++i) {
        symlink_target_current = stpcpy(symlink_target_current, "../");
    }
    symlink_target_current = stpcpy(symlink_target_current, repo->dir_name);
    *symlink_target_current = '\0';
    if (guarantee_symlink(symlink_path, len_symlink_path, symlink_target)) {
        pr_error("Failed to guarantee a symlink at '%s' pointing to '%s'\n",
            symlink_path, symlink_target);
        return -1;
    }
    if ((repo->symlink_path = malloc(
        (repo->symlink_path_len = len_symlink_path) + 1)) == NULL) {
        pr_error("Failed to allocate memory for symlink path\n");
        return -1;
    }
    if ((repo->symlink_target = malloc(
        (repo->symlink_target_len = len_symlink_target) + 1)) == NULL) {
        pr_error("Failed to allocate memory for symlink target\n");
        free(repo->symlink_path);
        repo->symlink_path = NULL;
        return -1;
    }
    memcpy(repo->symlink_path, symlink_path, repo->symlink_path_len + 1);
    memcpy(repo->symlink_target, symlink_target, repo->symlink_target_len + 1);
    return 0;
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
    if (config_repo_generate_symlink(repo, dir_repos)) {
        pr_error("Failed to generate symlinks for repo '%s'\n", repo->url);
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
    pr_info("Repo '%s' will be stored at '%s'\n", repo->url, repo->dir_path);
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
    pr_info("Repos will be stored in '%s'\n", config->dir_repos);
    if (config->dir_archives == NULL) {
        if ((config->dir_archives = malloc(sizeof(DIR_ARCHIVES))) == NULL) {
            return -1;
        }
        memcpy(config->dir_archives, DIR_ARCHIVES, sizeof(DIR_ARCHIVES));
        config->len_dir_archives = sizeof(DIR_ARCHIVES) - 1;
    }
    pr_info("Archives will be stored in '%s'\n", config->dir_archives);
    if (config->dir_checkouts == NULL) {
        if ((config->dir_checkouts = malloc(sizeof(DIR_CHECKOUTS))) == NULL) {
            return -1;
        }
        memcpy(config->dir_checkouts, DIR_CHECKOUTS, sizeof(DIR_CHECKOUTS));
        config->len_dir_checkouts = sizeof(DIR_CHECKOUTS) - 1;
    }
    pr_info("Checkouts will be stored in '%s'\n", config->dir_checkouts);
    char path[PATH_MAX];
    char const *dirs[] = {
        config->dir_repos,
        config->dir_checkouts,
        config->dir_archives,
    };
    for (unsigned short i = 0; i < sizeof dirs / sizeof *dirs; ++i) {
        if (snprintf(path, PATH_MAX, "%s/links", dirs[i]) < 0) {
            pr_error_with_errno(
                "Failed to format links dir for '%s'", dirs[i]);
            return -1;
        }
        if (mkdir_recursively(path)) {
            pr_error("Failed to mkdir '%s' recursively\n", path);
            return -1;
        }
    }
    if (config->proxy_url && config->proxy_url[0] != '\0') {
        if (config->proxy_after) {
            pr_info("Will use proxy '%s' after %hu failed fetches\n", 
                config->proxy_url, config->proxy_after);
        } else {
            pr_info("Will use proxy '%s'\n", config->proxy_url);
        }
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
            return -1;
        }
    }
#ifdef DEBUGGING
    pr_info("Finished config, config is as follows:\n");
    print_config(config);
#endif
    return 0;
}

int config_read(
    struct config *const restrict config,
    char const *const restrict config_path
) {
    int config_fd = STDIN_FILENO;
    if (config_path && strcmp(config_path, "-")) {
        pr_info("Using '%s' as config file\n", config_path);
        if ((config_fd = open(config_path, O_RDONLY)) < 0) {
            pr_error_with_errno("Failed to open config file '%s'", config_path);
            return -1;
        }
    } else {
        pr_info("Reading config from stdin\n");
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
        pr_info(
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
    pr_info("Updating repo '%s'...\n", repo->url);
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
    pr_info("Beginning fetching from '%s'\n", repo->url);
    config->fetch_options.proxy_opts.type = GIT_PROXY_NONE;
    for (unsigned short try = 0; try <= config->proxy_after + 3; ++try) {
        if (try == config->proxy_after) {
            if (try) 
                pr_warn(
                    "Failed for %hu times, use proxy\n", config->proxy_after);
            config->fetch_options.proxy_opts.type = GIT_PROXY_SPECIFIED;
            // config->fetch_options.proxy_opts.
        }
        r = git_remote_fetch(remote, NULL, &config->fetch_options, NULL);
        if (r) {
            pr_error(
                "Failed to fetch, libgit return %d%s\n", 
                r, try < config->proxy_after + 3 ? ", will retry" : "");
        } else {
            break;
        }
    }
    if (r) {
        pr_error("Failed to update repo, considered failure\n");
        r = -1;
        goto free_strarray;
    }
    git_remote_head const **heads;
    size_t heads_count;
    if (git_remote_ls(&heads, &heads_count, remote)) {
        pr_error("Failed to ls remote\n");
        r = -1;
        goto free_strarray;
    } else {
        for (size_t i = 0; i < heads_count; ++i) {
            git_remote_head const *const head = heads[i];
            if (!strcmp(head->name, "HEAD")) {
                if (head->symref_target == NULL) {
                    pr_warn("Remote HEAD points to no branch\n");
                    break;
                }
                pr_info("Remote HEAD points to '%s' now\n", head->symref_target);
                if ((r = git_repository_set_head(
                        repo->repository, head->symref_target))) {
                    pr_error("Failed to update repo '%s' HEAD to '%s'\n",
                        repo->url, head->symref_target);
                    r = -1;
                    goto free_strarray;
                }
                pr_info("Set local HEAD of repo '%s' to '%s'\n",
                    repo->url, head->symref_target);
                break;
            }
        }
    }

    pr_info("Ending fetching from '%s'\n", repo->url);
    repo->updated = true;
    r = 0;
free_strarray:
    git_strarray_free(&strarray);
free_remote:
    git_remote_free(remote);
    return r;
}

int repo_prepare_open_or_create_if_needed(
    struct config *const restrict config,
    unsigned long const repo_id
) {
    struct repo *const restrict repo = config->repos + repo_id;
    if (repo->repository != NULL) return 0;
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
            if (repo->url_no_scheme_sanitized)
                free(repo->url_no_scheme_sanitized);
            if (repo->dir_path) free (repo->dir_path);
            if (repo->symlink_path) free (repo->symlink_path);
            if (repo->symlink_target) free (repo->symlink_target);
            if (repo->wanted_objects.objects_count) {
                for (struct wanted_base *wanted_object = 
                    repo->wanted_objects.objects_head;
                    wanted_object != NULL;
                    wanted_object = wanted_object->next) {
                    if (wanted_object->name) free (wanted_object->name);
                    if (wanted_object->previous) free (wanted_object->previous);
                    if (wanted_object->type == WANTED_TYPE_COMMIT &&
                        ((struct wanted_commit *)wanted_object)->submodules)
                        free(
                            ((struct wanted_commit *)wanted_object)
                                ->submodules);
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

int mirror_repo_add_submodule_to_wanted_commit(
    struct wanted_commit *const restrict wanted_commit,
    char const *const restrict path,
    unsigned short len_path,
    char const *const restrict url,
    unsigned short len_url
) {
    if (wanted_commit->submodules == NULL) {
        if ((wanted_commit->submodules = malloc(
            sizeof *wanted_commit->submodules * (
                wanted_commit->submodules_allocated = ALLOC_BASE
            ))) == NULL)  {
            pr_error("Failed to allocate memory for submodules\n");
            goto error;
        }
    }
    if (++wanted_commit->submodules_count >
        wanted_commit->submodules_allocated ) {
        while (wanted_commit->submodules_count > (
            wanted_commit->submodules_allocated *= ALLOC_MULTIPLY
        )) {
            if (wanted_commit->submodules_allocated == ULONG_MAX) {
                pr_error("Failed to allocate more memory for submodules\n");
                goto error;
            } else if (wanted_commit->submodules_allocated >= ULONG_MAX / 2) {
                wanted_commit->submodules_allocated = ULONG_MAX / 2;
            }
        }
        struct wanted_commit_submodule *submodules_new = realloc(
            wanted_commit->submodules,
            sizeof *submodules_new * wanted_commit->submodules_allocated);
        if (submodules_new == NULL) {
            pr_error("Failed to re-allocate memory\n");
            goto error;
        }
        wanted_commit->submodules = submodules_new;
    }
    struct wanted_commit_submodule *wanted_commit_submodule =
        wanted_commit->submodules + wanted_commit->submodules_count - 1;
    *wanted_commit_submodule = WANTED_COMMIT_SUBMODULE_INIT;
    if ((wanted_commit_submodule->path = malloc(len_path + 1)) == NULL) {
        goto reduce_submodules_count;
    }
    if ((wanted_commit_submodule->url = malloc(len_url + 1)) == NULL) {
        goto free_path;
    }
    wanted_commit_submodule->url_hash = XXH3_64bits(url, len_url);
    memcpy(wanted_commit_submodule->path, path, len_path + 1);
    memcpy(wanted_commit_submodule->url, url, len_url + 1);
    wanted_commit_submodule->path_len = len_path;
    wanted_commit_submodule->url_len = len_url;
    return 0;
free_path:
    free(wanted_commit_submodule->path);
reduce_submodules_count:
    --wanted_commit->submodules_count;
error:
    return -1;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_parse_parse_submodule_in_tree(
    struct config *const restrict config,
    unsigned long repo_id,
    struct wanted_commit *const restrict wanted_commit,
    git_tree const *const restrict tree, 
    char const *const restrict path,
    unsigned short len_path,
    char const *const restrict url,
    unsigned short len_url
) {
    (void )len_path;
    if (mirror_repo_add_submodule_to_wanted_commit(
        wanted_commit, path, len_path, url, len_url
    )) {
        pr_error("Failed to add submodule with path '%s' url '%s' "
            "to commit '%s'\n",
            path, url, wanted_commit->id_hex_string);
        return -1;
    }
    struct wanted_commit_submodule *wanted_commit_submodule = 
        wanted_commit->submodules + wanted_commit->submodules_count - 1;
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
    wanted_commit_submodule->id = *git_tree_entry_id(entry);
    if (git_oid_tostr(
            wanted_commit_submodule->id_hex_string,
            sizeof wanted_commit_submodule->id_hex_string, 
            &wanted_commit_submodule->id
        )[0] == '\0') {
        pr_error("Failed to format commit id into hex string\n");
        goto free_entry;
    }
    pr_info(
        "Specific commit '%s' is needed for submodule at path '%s' "
        "with url '%s'\n", wanted_commit_submodule->id_hex_string, path, url);
    bool commit_added = false;
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo *const restrict repo_cmp = config->repos + i;
        if (repo_cmp->url_hash == wanted_commit_submodule->url_hash) {
            wanted_commit_submodule->repo_id = i;
            for (struct wanted_base *wanted_object =
                repo_cmp->wanted_objects.objects_head;
                wanted_object != NULL;
                wanted_object = wanted_object->next) {
                if (wanted_object->type != WANTED_TYPE_COMMIT) continue;
                struct wanted_commit *wanted_commit_cmp = 
                    (struct wanted_commit *)wanted_object;
                if (wanted_commit_cmp->base.archive != 
                        WANTED_COMMIT_INIT.base.archive) continue;
                if (wanted_commit_cmp->base.checkout !=
                        WANTED_COMMIT_INIT.base.checkout) continue;
                if (git_oid_cmp(
                    &wanted_commit_cmp->id,
                    &wanted_commit_submodule->id)) continue;
                pr_warn(
                    "Already added commit '%s' to repo '%s', skipped\n",
                    wanted_commit_cmp->id_hex_string, repo_cmp->url);
                commit_added = true;
                break;
            }
            break;
        }
    }
    if (wanted_commit_submodule->repo_id == (unsigned long) -1) {
        pr_warn("Repo '%s' was not seen before, need to add it\n", url);
        if (config_add_repo_and_init_with_url(config, url, len_url)) {
            pr_error("Failed to add repo '%s'\n", url);
            goto free_entry;
        }
        wanted_commit_submodule->repo_id = config->repos_count - 1;
        (config->repos + wanted_commit_submodule->repo_id)->added_from = 
            RPEO_ADDED_FROM_SUBMODULES;
    }
    if (wanted_commit_submodule->repo_id == (unsigned long) -1) {
        pr_error("Submodule '%s' with url '%s' for commmit '%s' of repo '%s' "
        "still missing target repo id, refuse to continue\n",
            path, url, wanted_commit->base.name, config->repos[repo_id].url);
        goto free_entry;
    }
    struct wanted_commit *wanted_commit_in_target_repo = NULL;
    if (!commit_added) {
        struct repo *const restrict repo_target = 
            config->repos + wanted_commit_submodule->repo_id;
        if ((wanted_commit_in_target_repo = 
            malloc(sizeof *wanted_commit_in_target_repo)) == NULL) {
            pr_error("Failed to allocate memory for wanted commit '%s' "
                "in target repo '%s'\n", 
                wanted_commit_submodule->id_hex_string,
                repo_target->url);
            goto free_entry;
        }
        *wanted_commit_in_target_repo = WANTED_COMMIT_INIT;
        if ((wanted_commit_in_target_repo->base.name = 
                malloc(GIT_OID_MAX_HEXSIZE + 1)) == NULL) {
            pr_error("Failed to allocate memory for wanted namme of "
                "commit '%s' to add to repo '%s'\n",
                wanted_commit_submodule->id_hex_string,
                repo_target->url);
            goto free_wanted_commit_in_target_repo;
        }
        wanted_commit_in_target_repo->base.name_len = GIT_OID_MAX_HEXSIZE;
        wanted_commit_in_target_repo->id = wanted_commit_submodule->id;
        memcpy(wanted_commit_in_target_repo->id_hex_string, 
                wanted_commit_submodule->id_hex_string,
                sizeof wanted_commit_in_target_repo->id_hex_string);
        memcpy(wanted_commit_in_target_repo->base.name, 
                wanted_commit_in_target_repo->id_hex_string,
                sizeof wanted_commit_in_target_repo->id_hex_string);
        struct wanted_objects *const wanted_objects = 
            &repo_target->wanted_objects;
        if (wanted_objects->objects_tail) {
            wanted_objects->objects_tail->next = 
                (struct wanted_base *) wanted_commit_in_target_repo;
            wanted_commit_in_target_repo->base.previous = 
                wanted_objects->objects_tail;
        }
        wanted_objects->objects_tail = 
            (struct wanted_base *) wanted_commit_in_target_repo;
        if (wanted_objects->objects_count++ == 0) {
            wanted_objects->objects_head = 
                (struct wanted_base *) wanted_commit_in_target_repo;
            if (config_repo_finish(
                    repo_target, config->dir_repos, config->len_dir_repos)) {
                pr_error(
                    "Failed to append repo '%s' to repos\n", repo_target->url);
                goto free_entry;
            }
        }
        if (wanted_commit_submodule->repo_id >= repo_id) {
            pr_info("Added commit '%s' as wanted to repo '%s', will handle "
                "that repo later\n", wanted_commit_in_target_repo->base.name, 
                                     repo_target->url);

        } else {
            pr_warn("Added commit '%s' as wanted to parsaed repo '%s', "
            "need to go back to handle that specific commit\n",
            wanted_commit_in_target_repo->base.name, repo_target->url);
            if (mirror_repo_ensure_wanted_commit(
                    config, wanted_commit_submodule->repo_id, 
                    wanted_commit_in_target_repo)) {
                pr_error("Failed to handle added wanted commit '%s' to parsed"
                "repo '%s'\n", wanted_commit_in_target_repo->base.name, 
                    repo_target->url);
                goto free_entry;
            }
        }
    }
    
    git_tree_entry_free(entry);
    return 0;
free_wanted_commit_in_target_repo:
    free(wanted_commit_in_target_repo);
free_entry:
    git_tree_entry_free(entry);
    return -1;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_parse_gitmodules_blob(
    struct config *const restrict config,
    unsigned long repo_id,
    struct wanted_commit *const restrict wanted_commit,
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
                        pr_info(
                            "Submodule '%s', path '%s', url '%s'\n", 
                            submodule_name, submodule_path, submodule_url);
                        if (mirror_repo_parse_parse_submodule_in_tree(
                            config, repo_id, wanted_commit, tree, 
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
        config, repo_id, wanted_commit, tree, blob_gitmodules);
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
    int r = repo_prepare_open_or_create_if_needed(config, repo_id);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened\n", repo->url);
        return -1;
    }
    git_commit *commit;
    r = git_commit_lookup(&commit, repo->repository, &wanted_commit->id);
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
    pr_info("Ensured existence of commit '%s' in repo '%s'\n",
        wanted_commit->id_hex_string, repo->url);
    r = 0;
free_commit:
    git_commit_free(commit);
    return r;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_ensure_wanted_reference_common(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_reference *const restrict wanted_reference,
    git_reference *reference
) {
    struct repo *restrict repo = config->repos + repo_id;
    char const *const reference_name = wanted_reference->commit.base.name;
    git_object *object;
    int r;
    if ((r = git_reference_peel(&object, reference, GIT_OBJECT_COMMIT))) {
        pr_error(
            "Failed to peel reference '%s' into a commit object, "
            "libgit return %d\n",
            reference_name, r);
        return -1;
    }
    git_commit *commit = (git_commit *)object;
    wanted_reference->commit_resolved = true;
    wanted_reference->commit.id = *git_commit_id(commit);
    if (git_oid_tostr(
            wanted_reference->commit.id_hex_string,
            sizeof wanted_reference->commit.id_hex_string, 
            &wanted_reference->commit.id
        )[0] == '\0') {
        pr_error("Failed to format git oid hex string\n");
        git_object_free(object);
        return -1;
    }
    git_object_free(object);
    pr_info("Resolved reference '%s' of repo '%s' to commit '%s', "
        "working on that commit instead\n",
        reference_name, repo->url, 
        wanted_reference->commit.id_hex_string);
    r = mirror_repo_ensure_wanted_commit(
        config, repo_id, &wanted_reference->commit);
    repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensuring robust of commit '%s' resolved from "
            "reference '%s' of repo '%s'\n", 
            wanted_reference->commit.id_hex_string, 
            reference_name,
            repo->url);
        return -1;
    }
    pr_info("Ensured existence and robust of reference '%s' in repo '%s'\n",
        reference_name, repo->url);
    return 0;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_ensure_wanted_head(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_reference *const restrict wanted_head
) {
    int r = repo_prepare_open_or_create_if_needed(config, repo_id);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened\n", repo->url);
        return -1;
    }
    git_reference *head;
    r = git_repository_head(&head, repo->repository);
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
    r = mirror_repo_ensure_wanted_reference_common(
        config, repo_id, wanted_head, head);
    git_reference_free(head);
    return r;
}

// May re-allocate the config->repos array, must re-assign repo after calling
int mirror_repo_ensure_wanted_branch(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_reference *const restrict wanted_branch
) {
    int r = repo_prepare_open_or_create_if_needed(config, repo_id);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened\n", repo->url);
        return -1;
    }
    char const *const branch = wanted_branch->commit.base.name;
    git_reference *reference;
    r = git_branch_lookup(
        &reference, repo->repository, branch, GIT_BRANCH_LOCAL);
    switch (r) {
    case GIT_OK:
        break;
    case GIT_ENOTFOUND:
        pr_error("Branch '%s' was not found in repo '%s'\n",
            branch, repo->url);
        return -1;
    case GIT_EINVALIDSPEC:
        pr_error("'%s' is an illegal branch spec\n", branch);
        return -1;
    default:
        pr_error("Failed to find branch '%s', "
            "unhandled libgit return %d\n",
            branch, r);
        return -1;
    }
    r = mirror_repo_ensure_wanted_reference_common(
        config, repo_id, wanted_branch, reference);
    git_reference_free(reference);
    return r;
}

int mirror_repo_ensure_wanted_tag(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_reference *const restrict wanted_tag
) {
    int r = repo_prepare_open_or_create_if_needed(config, repo_id);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened\n", repo->url);
        return -1;
    }
    char ref_name[NAME_MAX];
    char const *const tag_name = wanted_tag->commit.base.name;
    if (snprintf(ref_name, sizeof ref_name, "refs/tags/%s", tag_name) < 0) {
        pr_error_with_errno(
            "Failed to generate full ref name of tag '%s' for repo '%s'",
            tag_name, repo->url);
        return -1;
    }
    git_reference *reference;
    r = git_reference_lookup(&reference, repo->repository, ref_name);
    switch (r) {
    case GIT_OK:
        break;
    case GIT_ENOTFOUND:
        pr_error("Tag '%s' (full ref name '%s') was not found in repo '%s'\n",
            tag_name, ref_name, repo->url);
        return -1;
    case GIT_EINVALIDSPEC:
        pr_error("Tag '%s' (full ref name '%s') is an illegal branch spec\n", 
            tag_name, ref_name);
        return -1;
    default:
        pr_error("Failed to find tag '%s' (full ref name '%s'), "
            "unhandled libgit return %d\n",
            tag_name, ref_name, r);
        return -1;
    }
    r = mirror_repo_ensure_wanted_reference_common(
        config, repo_id, wanted_tag, reference);
    git_reference_free(reference);
    return r;
}

int mirror_repo_ensure_wanted_reference(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_reference *const restrict wanted_reference
) {
    int r = repo_prepare_open_or_create_if_needed(config, repo_id);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened\n", repo->url);
        return -1;
    }
    git_reference *reference;
    r = git_reference_lookup(&reference, repo->repository, 
        wanted_reference->commit.base.name);
    switch (r) {
    case GIT_OK:
        break;
    case GIT_ENOTFOUND:
        pr_error("Reference '%s' was not found in repo '%s'\n",
            wanted_reference->commit.base.name, repo->url);
        return -1;
    case GIT_EINVALIDSPEC:
        pr_error("Reference '%s' is an illegal branch spec\n", 
            wanted_reference->commit.base.name);
        return -1;
    default:
        pr_error("Failed to find reference '%s', "
            "unhandled libgit return %d\n",
            wanted_reference->commit.base.name, r);
        return -1;
    }
    r = mirror_repo_ensure_wanted_reference_common(
        config, repo_id, wanted_reference, reference);
    git_reference_free(reference);
    return r;
}

int repo_add_wanted_reference(
    struct repo *const restrict repo,
    char const *const restrict reference_name,
    bool const archive,
    bool const checkout
) {
    if (strncmp(reference_name, "refs/", 5)) {
        pr_error("Reference does not start with 'refs/'\n");
        return -1;
    }
    struct wanted_reference *const restrict wanted_reference =
        malloc(sizeof *wanted_reference);
    if (wanted_reference == NULL) {
        pr_error("Failed to allocate memory for more wanted references\n");
        return -1;
    }
    *wanted_reference = WANTED_REFERENCE_INIT;
    wanted_reference->commit.base.name_len = strlen(reference_name);
    wanted_reference->commit.base.name = 
        malloc(wanted_reference->commit.base.name_len);
    if (wanted_reference->commit.base.name == NULL) {
        pr_error("Failed to allocate memory for reference name\n");
        free(wanted_reference);
        return -1;
    }
    memcpy(wanted_reference->commit.base.name, reference_name,
        wanted_reference->commit.base.name_len);
    wanted_reference->commit.base.archive = archive;
    wanted_reference->commit.base.checkout = checkout;
    struct wanted_objects *const wanted_objects = &repo->wanted_objects;
    wanted_objects->dynamic = true;
    ++wanted_objects->objects_count;
    wanted_objects->objects_tail->next = 
        (struct wanted_base *) wanted_reference;
    wanted_reference->commit.base.previous = 
        wanted_objects->objects_tail;
    wanted_objects->objects_tail = (struct wanted_base *) wanted_reference;
    pr_info("Added wanted reference '%s' to repo '%s'\n", 
        wanted_reference->commit.base.name, repo->url);
    return 0;
}

int mirror_repo_ensure_all_branches(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_base *const restrict wanted_all_branches
) {
    int r = repo_prepare_open_or_create_if_needed(config, repo_id);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened, libgit return %d\n", 
            repo->url, r);
        return -1;
    }
    git_branch_iterator *branch_iterator;
    if ((r = git_branch_iterator_new(
        &branch_iterator, repo->repository, GIT_BRANCH_LOCAL))) {
        pr_error("Failed to create branch iterator for repo '%s', "
        "libgit return %d\n", repo->url, r);
    }
    git_reference *reference;
    git_branch_t branch_t;
    pr_info(
        "Looping through all branches to create "
        "individual wanted references\n");
    while ((r = git_branch_next(
        &reference, &branch_t, branch_iterator)) == GIT_OK) {
        char const *const reference_name = git_reference_name(reference);
        pr_info("Found branch '%s'\n", reference_name);
        if (branch_t != GIT_BRANCH_LOCAL) {
            pr_error("Found branch is not a local branch\n");
            return -1;
        }
        if (strncmp(reference_name, "refs/", 5)) {
            pr_error("Reference does not start with 'refs/'\n");
            return -1;
        }
        if (repo_add_wanted_reference(repo, reference_name, 
            wanted_all_branches->archive, wanted_all_branches->checkout)) {
            pr_error("Failed to add branch reference '%s' as wannted to "
            "repo '%s'\n", reference_name, repo->url);
            return -1;
        }
    }
    switch (r) {
    case GIT_OK:
        pr_error("Got GIT_OK at the end, this shouldn't happen\n");
        return -1;
    case GIT_ITEROVER:
        return 0;
    default:
        pr_error(
            "Failed to iterate through all banches, libgit return %d\n", r);
        return -1;
    }
}

struct mirror_repo_ensure_all_tags_foreach_callback_payload {
    struct repo *const restrict repo;
    bool const archive;
    bool const checkout;
};

int mirror_repo_ensure_all_tags_foreach_callback(
    char const *name, git_oid *oid, void *payload
) {
    (void) oid;
    struct mirror_repo_ensure_all_tags_foreach_callback_payload 
        *const restrict private_payload = 
        (struct mirror_repo_ensure_all_tags_foreach_callback_payload *
            const restrict) payload;
    if (repo_add_wanted_reference(private_payload->repo, name, 
        private_payload->archive, private_payload->checkout)) {
        pr_error("Failed to add tag reference '%s' as wannted to "
        "repo '%s'\n", name, private_payload->repo->url);
        return -1;
    }
    return 0;
}

int mirror_repo_ensure_all_tags(
    struct config *const restrict config,
    unsigned long const repo_id,
    struct wanted_base *const restrict wanted_all_tags
) {
    (void) wanted_all_tags;
    int r = repo_prepare_open_or_create_if_needed(config, repo_id);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened, libgit return %d\n", 
            repo->url, r);
        return -1;
    }
    struct mirror_repo_ensure_all_tags_foreach_callback_payload 
        const private_payload = {
            .repo = repo,
            .archive = wanted_all_tags->archive,
            .checkout = wanted_all_tags->checkout,
        };
    pr_info(
        "Looping through all tags to create individual wanted references\n");
    if ((r = git_tag_foreach(
        repo->repository, mirror_repo_ensure_all_tags_foreach_callback,
        (void *)&private_payload))) {
        pr_error("Failed git_tag_foreach callback, libgit return %d\n", r);
        return -1;
    }
    return 0;
}

int mirror_repo(
    struct config *const restrict config,
    unsigned long const repo_id
) {
    int r = repo_prepare_open_or_create_if_needed(config, repo_id);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened\n", repo->url);
        return -1;
    }
    pr_info("Mirroring repo '%s'\n", repo->url);
    r = -1;
    for (struct wanted_base *wanted_object = repo->wanted_objects.objects_head;
        wanted_object != NULL;
        wanted_object = wanted_object->next) {
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
        case WANTED_TYPE_REFERENCE:
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
            case WANTED_TYPE_ALL_TAGS:
                r = mirror_repo_ensure_all_tags(
                    config, repo_id, (struct wanted_base *)wanted_object);
                repo = config->repos + repo_id;
                if (r) {
                    pr_error(
                        "Failed to ensure all tags robust for repo '%s'\n",
                        repo->url
                    );
                    return -1;
                }
                break;
            case WANTED_TYPE_ALL_BRANCHES:
                r = mirror_repo_ensure_all_branches(
                    config, repo_id, (struct wanted_base *)wanted_object);
                repo = config->repos + repo_id;
                if (r) {
                    pr_error(
                        "Failed to ensure all branches robust for repo '%s'\n",
                        repo->url
                    );
                    return -1;
                }
                break;
            case WANTED_TYPE_BRANCH:
                r = mirror_repo_ensure_wanted_branch(
                    config, repo_id, (struct wanted_reference *)wanted_object);
                repo = config->repos + repo_id;
                if (r) {
                    pr_error(
                        "Failed to ensure branch '%s' robust for repo '%s'\n",
                        wanted_object->name, repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_TAG:
                r = mirror_repo_ensure_wanted_tag(
                    config, repo_id, (struct wanted_reference *)wanted_object);
                repo = config->repos + repo_id;
                if (r) {
                    pr_error(
                        "Failed to ensure tag '%s' robust for repo '%s'\n",
                        wanted_object->name, repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_REFERENCE:
                r = mirror_repo_ensure_wanted_reference(
                    config, repo_id, (struct wanted_reference *)wanted_object);
                repo = config->repos + repo_id;
                if (r) {
                    pr_error(
                        "Failed to ensure reference '%s' robust "
                        "for repo '%s'\n",
                        wanted_object->name, repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_HEAD:
                r = mirror_repo_ensure_wanted_head(
                    config, repo_id, (struct wanted_reference *)wanted_object);
                repo = config->repos + repo_id;
                if (r) {
                    pr_error("Failed to ensure HEAD robust for repo '%s'\n",
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
    pr_info("Finished mirroring repo '%s'\n", repo->url);
    return 0;
}

int mirror_all_repos(
    struct config *const restrict config
) {
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (mirror_repo(config, i)) {
            pr_error("Failed to mirror all repos\n");
            return -1;
        }
    }
    pr_info("Finished mirroring all repos\n");
    return 0;
}

int tar_write_and_pad_to_512_block(
    int const tar_fd,
    void const *const restrict data,
    size_t const size
) {
    if (lseek(tar_fd, 0, SEEK_CUR) % 512) {
        pr_error("Tar not at 512 offset\n");
        return -1;
    }
    size_t size_written = 0;
    while (size_written < size) {
        ssize_t size_written_this = write(
            tar_fd, data + size_written, size - size_written);
        if (size_written_this < 0) {
             switch (errno) {
            case EAGAIN:
#if (EAGAIN != EWOULDBLOCK)
            case EWOULDBLOCK:
#endif
            case EINTR:
                break;
            default:
                pr_error_with_errno(
                    "Failed to write %lu bytes to tar", size - size_written);
                return -1;
            }
        } else {
            size_written += size_written_this;
        }
    }
    size_t lone_bytes = size % 512;
    if (lone_bytes) {
        size_t padding = 512 - lone_bytes;
        size_written = 0;
        while (size_written < padding) {
            ssize_t size_written_this = write(
                tar_fd, EMPTY_512_BLOCK, padding - size_written);
            if (size_written_this < 0) {
                switch (errno) {
                case EAGAIN:
#if (EAGAIN != EWOULDBLOCK)
                case EWOULDBLOCK:
#endif
                case EINTR:
                    break;
                default:
                    pr_error_with_errno(
                        "Failed to pad %lu bytes to tar", size - size_written);
                    return -1;
                }
            } else {
                size_written += size_written_this;
            }
        }
    }
    if (lseek(tar_fd, 0, SEEK_CUR) % 512) {
        pr_error("Tar not at 512 offset\n");
        return -1;
    }
    return 0;
}

int tar_append_longlink_optional(
    int const tar_fd,
    char const *const restrict link,
    unsigned short const len_link
) {
    struct tar_posix_header longlink_header;
    if (len_link < sizeof longlink_header.linkname) return 0;
    longlink_header = TAR_POSIX_HEADER_GNU_LONGLINK_INIT;
    if (snprintf(longlink_header.size, sizeof longlink_header.size, 
                    "%011o", len_link + 1) < 0) {
        pr_error("Failed to format long link size\n");
        return -1;
    }
    if (tar_header_checksum_self(&longlink_header)) {
        pr_error("Failed to calculate header checksum\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(
        tar_fd, &longlink_header, sizeof longlink_header)) {
        pr_error("Failed to write data to tar\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(tar_fd, link, len_link + 1)) {
        pr_error("Failed to write longlink to tar\n");
        return -1;
    }
    return 0;
}

int tar_append_longname_optional(
    int const tar_fd,
    char const *const restrict name,
    unsigned short const len_name
) {
    struct tar_posix_header longname_header;
    if (len_name < sizeof longname_header.name) return 0;
    longname_header = TAR_POSIX_HEADER_GNU_LONGNAME_INIT;
    if (snprintf(longname_header.size, sizeof longname_header.size, 
                    "%011o", len_name + 1) < 0) {
        pr_error("Failed to format long name size\n");
        return -1;
    }
    if (tar_header_checksum_self(&longname_header)) {
        pr_error("Failed to calculate header checksum\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(
        tar_fd, &longname_header, sizeof longname_header)) {
        pr_error("Failed to write data to tar\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(tar_fd, name, len_name + 1)) {
        pr_error("Failed to write longname to tar\n");
        return -1;
    }
    return 0;
}

int tar_append_symlink(
    int const tar_fd,
    char const *const restrict mtime,
    char const *const restrict name,
    unsigned short const len_name,
    char const *const restrict link,
    unsigned short const len_link
) {
    if (tar_append_longlink_optional(tar_fd, link, len_link)) {
        pr_error("Failed to create longlink\n");
        return -1;
    }
    if (tar_append_longname_optional(tar_fd, name, len_name)) {
        pr_error("Failed to create longname\n");
        return -1;
    }
    struct tar_posix_header symlink_header =
        TAR_POSIX_HEADER_SYMLINK_INIT;
    memcpy(symlink_header.mtime, mtime, sizeof symlink_header.mtime);
    memcpy(symlink_header.name, name, 
        len_name > sizeof symlink_header.name ? 
            sizeof symlink_header.name : len_name);
    memcpy(symlink_header.linkname, link, 
        len_link > sizeof symlink_header.linkname ? 
            sizeof symlink_header.linkname : len_link);
    if (tar_header_checksum_self(&symlink_header)) {
        pr_error("Failed to calculate header checksum\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(
        tar_fd, &symlink_header, sizeof symlink_header)) {
        pr_error("Failed to write data to tar\n");
        return -1;
    }
    return 0;
}

int tar_append_regular_file(
    int const tar_fd,
    void const *const restrict ro_buffer,
    git_object_size_t size,
    char const *const restrict mtime,
    char const *const restrict name,
    unsigned short const len_name,
    mode_t mode
) {
    if (tar_append_longname_optional(tar_fd, name, len_name)) {
        pr_error("Failed to create longname\n");
        return -1;
    }
    struct tar_posix_header regular_file_header;
    switch (mode) {
    case 0644:
        regular_file_header = TAR_POSIX_HEADER_FILE_REG_INIT;
        break;
    case 0755:
        regular_file_header = TAR_POSIX_HEADER_FILE_EXE_INIT;
        break;
    default:
        pr_warn("%03o mode is not expected, but we accept it for now\n", mode);
        regular_file_header = TAR_POSIX_HEADER_FILE_REG_INIT;
        if (snprintf(regular_file_header.mode, sizeof regular_file_header.mode, 
            "%07o", mode) < 0) {
            pr_error("Failed to format mode string\n");
            return -1;
        }
        break;
    };
    if (snprintf(regular_file_header.size, sizeof regular_file_header.size, 
                    "%011lo", size) < 0) {
        pr_error("Failed to format long name size\n");
        return -1;
    }
    memcpy(regular_file_header.mtime, mtime, sizeof regular_file_header.mtime);
    memcpy(regular_file_header.name, name, 
        len_name > sizeof regular_file_header.name ?
         sizeof regular_file_header.name : len_name);
    if (tar_header_checksum_self(&regular_file_header)) {
        pr_error("Failed to calculate header checksum\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(
        tar_fd, &regular_file_header, sizeof regular_file_header)) {
        pr_error("Failed to write regular file header to tar\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(tar_fd, ro_buffer, size)) {
        pr_error("Failed to write file data to tar\n");
        return -1;
    }
    return 0;
}

int tar_append_folder(
    int const tar_fd,
    char const *const restrict mtime,
    char const *const restrict name,
    unsigned short const len_name
) {
    if (tar_append_longname_optional(tar_fd, name, len_name)) {
        pr_error("Failed to create longname\n");
        return -1;
    }
    struct tar_posix_header folder_header = TAR_POSIX_HEADER_FOLDER_INIT;
    memcpy(folder_header.mtime, mtime, sizeof folder_header.mtime);
    memcpy(folder_header.name, name, 
        len_name > sizeof folder_header.name ?
         sizeof folder_header.name : len_name);
    if (tar_header_checksum_self(&folder_header)) {
        pr_error("Failed to calculate header checksum\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(
        tar_fd, &folder_header, sizeof folder_header)) {
        pr_error("Failed to write folder header to tar\n");
        return -1;
    }
    return 0;
}

int tar_finish(
    int const tar_fd
) {
    unsigned char const eof_marker[512 * 2] = {0};
    if (tar_write_and_pad_to_512_block(tar_fd, eof_marker, 512 * 2)) {
        pr_error("Failed to write EOF mark to tar file\n");
        return -1;
    }
    return 0;
}

int export_commit_tree_entry_blob_file_regular_to_archive(
    void const *const restrict ro_buffer,
    git_object_size_t size,
    char const *const restrict path,
    unsigned short const len_path,
    char const *const restrict mtime,
    int const fd_archive,
    mode_t mode
){
    if (tar_append_regular_file(
        fd_archive, ro_buffer, size, mtime, path, len_path, mode)) {
        pr_error("Failed to append regular file '%s' to archive\n", path);
        return -1;
    }
    return 0;
}

int export_commit_tree_entry_blob_file_regular_to_checkout(
    void const *const restrict ro_buffer,
    git_object_size_t size,
    char const *const restrict path,
    char const *const restrict dir_checkout,
    mode_t mode
){
    char path_checkout[PATH_MAX];
    if (snprintf(path_checkout, PATH_MAX, "%s/%s", dir_checkout, path) < 0) {
        pr_error_with_errno("Failed to format checkout name");
        return -1;
    }
    int blob_fd = open(path_checkout, O_WRONLY | O_CREAT, mode);
    if (blob_fd < 0) {
        pr_error("Failed to create file '%s' with mode 0o%o\n",
            path_checkout, mode);
        return -1;
    }
    if (size) {
        git_object_size_t size_written = 0;
        while (size_written < size) {
            ssize_t size_written_this =
                write(blob_fd,
                    ro_buffer + size_written, 
                    size - size_written);
            if (size_written_this < 0) {
                switch (errno) {
                case EAGAIN:
#if (EAGAIN != EWOULDBLOCK)
                case EWOULDBLOCK:
#endif
                case EINTR:
                    break;
                default:
                    pr_error_with_errno(
                        "Failed to write %lu bytes to file '%s'",
                        size - size_written,
                        path_checkout);
                    close(blob_fd);
                    return -1;
                }
            } else {
                size_written += size_written_this;
            }
        }
    }
    close(blob_fd);
    return 0;
}

int export_commit_tree_entry_blob_file_regular(
    void const *const restrict ro_buffer,
    git_object_size_t size,
    char const *const restrict path,
    unsigned short const len_path,
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    bool const checkout,    
    char const *const restrict dir_checkout,
    mode_t mode
) {
    if (archive) {
        if (export_commit_tree_entry_blob_file_regular_to_archive(
            ro_buffer, size, path, len_path, mtime, fd_archive, mode)) {
            pr_error("Failed to archive commit tree entry blob regular file "
                "at '%s'\n", path);
            return -1;
        }
    }
    if (checkout) {
        if (export_commit_tree_entry_blob_file_regular_to_checkout(
            ro_buffer, size, path, dir_checkout, mode)) {
            pr_error("Failed to checkout commit tree entry blob regular file "
                "at '%s'\n", path);
            return -1;
        }
    }
    return 0;
}

int export_commit_tree_entry_blob_file_symlink_to_archive(
    char const *const restrict ro_buffer,
    char const *const restrict path,
    unsigned short const len_path,
    char const *const restrict mtime,
    int const fd_archive
) {
    char link[PATH_MAX];
    unsigned short len_link = 
        stpncpy(link, ro_buffer, PATH_MAX) - link;
    if (tar_append_symlink(
        fd_archive, mtime, path, len_path, link, len_link)) {
        pr_error("Failed to append symlink to archive\n");
        return -1;
    }
    return 0;
}


int export_commit_tree_entry_blob_file_symlink_to_checkout(
    char const *const restrict ro_buffer,
    char const *const restrict path,
    char const *const restrict dir_checkout
) {
    char path_checkout[PATH_MAX];
    if (snprintf(path_checkout, PATH_MAX, "%s/%s", dir_checkout, path) < 0) {
        pr_error_with_errno("Failed to format checkout name");
        return -1;
    }
    if (symlink(ro_buffer, path_checkout) < 0) {
        pr_error_with_errno("Failed to create symlink '%s' -> '%s'",
            path_checkout, ro_buffer);
        return -1;
    }
    return 0;
}

int export_commit_tree_entry_blob_file_symlink(
    char const *const restrict ro_buffer,
    char const *const restrict path,
    unsigned short const len_path,
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    bool const checkout,    
    char const *const restrict dir_checkout
) {
    if (archive) {
        if (export_commit_tree_entry_blob_file_symlink_to_archive(
            ro_buffer, path, len_path, mtime, fd_archive)) {
            pr_error("Failed to archive commit tree entry blob file symlink "
                "at '%s'\n", path);
            return -1;
        }
    }
    if (checkout) {
        if (export_commit_tree_entry_blob_file_symlink_to_checkout(
            ro_buffer, path, dir_checkout)) {
            pr_error("Failed to checkout commit tree entry blob file symlink "
                "at '%s'\n", path);
            return -1;
        }
    }
    return 0;
}

int export_commit_tree_entry_blob(
    git_tree_entry const *const restrict entry,
    char const *const restrict path,
    unsigned short const len_path,
    struct repo const *const restrict repo,
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    bool const checkout,    
    char const *const restrict dir_checkout
) {
    git_object *object;
    int r = git_tree_entry_to_object(
        &object, repo->repository, entry);
    if (r) {
        pr_error(
            "Failed to convert entry to object, libgit return %d\n",
            r);
        return -1;
    }
    void const *const restrict ro_buffer = 
        git_blob_rawcontent((git_blob *)object);
    switch (git_tree_entry_filemode(entry)) {
    case GIT_FILEMODE_BLOB:
        r = export_commit_tree_entry_blob_file_regular(
            ro_buffer,
            git_blob_rawsize((git_blob *)object),
            path, len_path, 
            archive, mtime, fd_archive, 
            checkout, dir_checkout, 
            0644);
        break;
    case GIT_FILEMODE_BLOB_EXECUTABLE:
        r = export_commit_tree_entry_blob_file_regular(
            ro_buffer, 
            git_blob_rawsize((git_blob *)object), 
            path, len_path, 
            archive, mtime, fd_archive, 
            checkout, dir_checkout, 
            0755);
        break;
    case GIT_FILEMODE_LINK:
        r = export_commit_tree_entry_blob_file_symlink(
            ro_buffer, path, len_path, 
            archive, mtime, fd_archive, checkout, dir_checkout);
        break;
    default:
        pr_error("Impossible tree entry filemode %d\n", 
                git_tree_entry_filemode(entry));
        r = -1;
        break;
    }
    free(object);
    return r;
};

int export_commit_tree_entry_tree_to_archive(
    char const *const restrict path,
    unsigned short const len_path,
    char const *const restrict mtime,
    int const fd_archive
) {
    char path_with_slash[PATH_MAX];
    memcpy(path_with_slash, path, len_path);
    path_with_slash[len_path] = '/';
    path_with_slash[len_path + 1] = '\0';
    if (tar_append_folder(fd_archive, mtime, path_with_slash, len_path + 1)) {
        pr_error("Failed to append folder '%s' to archive\n", path);
        return -1;
    }
    return 0;
}

int export_commit_tree_entry_tree_to_checkout(
    char const *const restrict path,
    char const *const restrict dir_checkout
) {
    char path_checkout[PATH_MAX];
    if (snprintf(path_checkout, PATH_MAX, "%s/%s", dir_checkout, path) < 0) {
        pr_error_with_errno("Failed to format checkout name");
        return -1;
    }
    if (mkdir(path_checkout, 0755)) {
        pr_error_with_errno("Failed to create folder '%s'", 
            path_checkout);
        return -1;
    }
    return 0;
}


int export_commit_tree_entry_tree(
    char const *const restrict path,
    unsigned short const len_path,
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    bool const checkout,    
    char const *const restrict dir_checkout
) {
    if (archive) {
        if (export_commit_tree_entry_tree_to_archive(
            path, len_path, mtime, fd_archive)) {
            pr_error("Failed to export '%s' to archive\n", path);
            return -1;
        }
    }
    if (checkout) {
        if (export_commit_tree_entry_tree_to_checkout(path, dir_checkout)) {
            pr_error("Failed to export '%s' to checkout\n", path);
            return -1;
        }
    }
    return 0;
};

int export_commit_tree_entry_commit(
	char const *const restrict root,
    git_tree_entry const *const restrict entry,
    char const *const restrict path,
    unsigned short const len_path,
    struct config const *const restrict config,
    // struct repo const *const restrict repo,
    struct wanted_commit const *const restrict wanted_commit,
    char *const restrict submodule_path,
    unsigned short const submodule_path_len,
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    bool const checkout,    
    char const *const restrict dir_checkout
) {
    // Export self as a tree (folder)
    if (export_commit_tree_entry_tree(
        path, len_path, 
        archive, mtime, fd_archive, 
        checkout, dir_checkout)) {
        pr_error("Failed to export submodule '%s' as a tree\n", path);
        return -1;
    }

    // Find which wanted submodule commit the entry is
    git_oid const *const submodule_commit_id = git_tree_entry_id(entry);
    struct wanted_commit_submodule *wanted_commit_submodule = NULL;
    for (unsigned long i = 0; i < wanted_commit->submodules_count; ++i) {
        if (!git_oid_cmp(
            &wanted_commit->submodules[i].id, submodule_commit_id)) {
            wanted_commit_submodule = wanted_commit->submodules + i;
            break;
        }
    }
    if (wanted_commit_submodule == NULL) {
        pr_error("Failed to find corresponding wanted commit submodule\n");
        return -1;
    }

    // Find that wanted commit in target repo
    struct repo const *const restrict target_repo = 
        config->repos + wanted_commit_submodule->repo_id;
    struct wanted_commit const *restrict wanted_commit_in_target_repo = NULL;
    for (wanted_commit_in_target_repo = (struct wanted_commit *)
            target_repo->wanted_objects.objects_head;
        wanted_commit_in_target_repo != NULL;
        wanted_commit_in_target_repo = (struct wanted_commit *)
            wanted_commit_in_target_repo->base.next) {
        if (wanted_commit_in_target_repo->base.type == WANTED_TYPE_COMMIT &&
            !git_oid_cmp(
                &wanted_commit_in_target_repo->id, submodule_commit_id)) {
            break;
        }
    }
    if (wanted_commit_in_target_repo == NULL) {
        pr_error("Failed to find corresponding wanted commit in target repo\n");
        return -1;
    }

    // Recursively export
    char const *const restrict name = git_tree_entry_name(entry);
    unsigned short submodule_path_len_r = 
        submodule_path_len + strlen(name) + strlen(root) + 1;
    if (submodule_path_len_r >= PATH_MAX) {
        pr_error("Path too long!\n");
        return -1;
    }
    int r = -1;
    if (sprintf(submodule_path + submodule_path_len, 
        "%s%s/", root, name) < 0) {
        pr_error_with_errno("Failed to format name");
        goto revert_submodule_path;
    }
    
    git_commit *commit;
    if (git_commit_lookup(
        &commit, target_repo->repository, submodule_commit_id)) {
        pr_error("Failed to lookup commit\n");
        goto revert_submodule_path;
    }
    git_tree *tree;
    if (git_commit_tree(&tree, commit)) {
        pr_error("Failed to get tree pointed by commit\n");
        goto free_commit;
    }
    char mtime_r[TAR_POSIX_HEADER_MTIME_LEN] = "";
    if (snprintf(
        mtime_r, TAR_POSIX_HEADER_MTIME_LEN, "%011lo", git_commit_time(commit)
    ) < 0) {
        pr_error("Failed to format mtime\n");
        goto free_commit;
    }
    struct export_commit_treewalk_payload submodule_payload = {
        .config = config,
        .repo = target_repo,
        .wanted_commit = wanted_commit_in_target_repo,
        .submodule_path = submodule_path,
        .submodule_path_len = submodule_path_len_r,
        .archive = archive,
        .mtime = mtime_r,
        .fd_archive = fd_archive,
        .checkout = checkout,
        .dir_checkout = dir_checkout,
    };
    if (git_tree_walk(
        tree, GIT_TREEWALK_PRE, export_commit_treewalk_callback, 
            &submodule_payload)) {
        pr_error("Failed to walk tree recursively\n");
        goto free_commit;
    }
    r = 0;
free_commit:
    git_commit_free(commit);
revert_submodule_path:
    submodule_path[submodule_path_len] = '\0';
    return r;
};

int export_commit_treewalk_callback(
	char const *const restrict root, 
    git_tree_entry const *const restrict entry,
    void *payload
) {
    struct export_commit_treewalk_payload *const restrict private_payload =
        (struct export_commit_treewalk_payload *const restrict) payload;
    bool const archive = private_payload->archive;
    bool const checkout = private_payload->checkout;
    if (archive || checkout); 
    else {
        pr_error("Neither archive nor checkout needed\n");
        return -1;
    }
    char path[PATH_MAX];
    int r = snprintf(
        path, PATH_MAX, "%s%s%s", private_payload->submodule_path,
        root, git_tree_entry_name(entry));
    if (r < 0) {
        pr_error("Failed to format entry path\n");
        return -1;
    }
    unsigned short len_path = r;
    char const *const restrict mtime = private_payload->mtime;
    int const fd_archive = private_payload->fd_archive;
    char const *const restrict dir_checkout = private_payload->dir_checkout;
    switch (git_tree_entry_type(entry)) {
    case GIT_OBJECT_BLOB:
        return export_commit_tree_entry_blob(
            entry, path, len_path, private_payload->repo, 
            archive, mtime, fd_archive, 
            checkout, dir_checkout);
    case GIT_OBJECT_TREE:
        return export_commit_tree_entry_tree(
            path, len_path, 
            archive, mtime, fd_archive,
            checkout, dir_checkout);
    case GIT_OBJECT_COMMIT:
        return export_commit_tree_entry_commit(
            root, entry, path, len_path, private_payload->config, 
            private_payload->wanted_commit, private_payload->submodule_path,
            private_payload->submodule_path_len, archive, mtime, fd_archive,
            checkout, dir_checkout);
    default:
        pr_error("Impossible tree entry type %d\n", git_tree_entry_type(entry));
        return -1;
    }
}

int remove_dir_recursively(
    DIR * const restrict dir_p
) {
    struct dirent *entry;
    errno = 0;
    int dir_fd = dirfd(dir_p);
    while ((entry = readdir(dir_p)) != NULL) {
        if (entry->d_name[0] == '.') {
            switch (entry->d_name[1]) {
            case '\0':
                continue;
            case '.':
                if (entry->d_name[2] == '\0') continue;
                break;
            }
        }
        switch (entry->d_type) {
        case DT_REG:
            if (unlinkat(dir_fd, entry->d_name, 0)) {
                pr_error_with_errno(
                    "Failed to delete '%s' recursively", entry->d_name);
                return -1;
            }
            break;
        case DT_DIR: {
            int dir_fd_r = openat(dir_fd, entry->d_name, O_RDONLY);
            if (dir_fd_r < 0) {
                pr_error_with_errno(
                    "Failed to open dir entry '%s'", entry->d_name);
                return -1;
            }
            DIR *dir_p_r = fdopendir(dir_fd_r);
            if (dir_p_r == NULL) {
                pr_error_with_errno(
                    "Failed to open '%s' as subdir", entry->d_name);
                close(dir_fd_r);
                return -1;
            }
            if (remove_dir_recursively(dir_p_r)) {
                pr_error("Failed to remove dir '%s' recursively\n",
                    entry->d_name);
                closedir(dir_p_r);
                return -1;
            }
            closedir(dir_p_r);
            if (unlinkat(dir_fd, entry->d_name, AT_REMOVEDIR)) {
                pr_error_with_errno(
                    "Failed to rmdir '%s' recursively", entry->d_name);
                return -1;
            }
            break;
        }
        default:
            pr_error("Unsupported file type %d\n", entry->d_type);
            return -1;
        }

    }
    if (errno) {
        pr_error_with_errno("Failed to read dir\n");
        return -1;
    }
    return 0;
}

int ensure_path_non_exist( // essentially rm -rf
    char const *const restrict path
) {
    struct stat stat_buffer;
    if (stat(path, &stat_buffer)) {
        switch(errno) {
        case ENOENT:
            return 0;
        default:
            pr_error_with_errno("Failed to get stat of path '%s'", path);
            return -1;
        }
    }
    mode_t mode = stat_buffer.st_mode & S_IFMT;
    switch (mode) {
    case S_IFDIR: {
        DIR *const restrict dir_p = opendir(path);
        if (dir_p == NULL) {
            pr_error_with_errno("Failed to opendir '%s'", path);
            return -1;
        }
        if (remove_dir_recursively(dir_p)) {
            pr_error("Failed to remove '%s' recursively\n", path);
            closedir(dir_p);
            return -1;
        }
        closedir(dir_p);
        if (rmdir(path)) {
            pr_error_with_errno("Failed to rmdir '%s'", path);
            return -1;
        }
        break;
    }
    case S_IFREG:
        if (unlink(path)) {
            pr_error_with_errno("Failed to remove regular file '%s'", path);
            return -1;
        }
        break;
    default:
        pr_error("Cannot remove existing '%s' with type %d\n", path, mode);
        return -1;
    }
    return 0;
}

int export_commit(
    struct config const *const restrict config,
    struct repo const *const restrict repo,
    struct wanted_commit const *const restrict wanted_commit
) {
    bool archive = wanted_commit->base.archive;
    bool checkout = wanted_commit->base.checkout;
    char dir_checkout[PATH_MAX];
    char dir_checkout_work[PATH_MAX];
    char file_archive[PATH_MAX];
    char file_archive_work[PATH_MAX];
    int fd_archive = -1;
    int r;
    struct stat stat_buffer;
    if (checkout) {
        r = snprintf(
            dir_checkout, PATH_MAX, "%s/%s", 
            config->dir_checkouts, wanted_commit->id_hex_string);
        if (r < 0) {
            pr_error_with_errno("Failed to format checkout dir");
            return -1;
        } else if (r >= PATH_MAX - 6) {
            pr_error("Dir checkout path '%s' too long\n", 
            dir_checkout);
            return -1;
        }
        pr_info(
            "Will checkout repo '%s' commit '%s' to '%s'\n",
            repo->url, wanted_commit->id_hex_string, 
            dir_checkout);
        if (stat(dir_checkout, &stat_buffer)) {
            switch (errno) {
            case ENOENT:
                break;
            default:
                pr_error_with_errno(
                    "Failed to check stat of existing '%s'", dir_checkout);
                return -1;
            }
        } else {
            if ((stat_buffer.st_mode & S_IFMT) == S_IFDIR) {
                pr_warn("Already checked out to '%s', no neeed to "
                    "checkout for this run\n", dir_checkout);
                checkout = false;
            } else {
                if (ensure_path_non_exist(dir_checkout)) {
                    pr_error_with_errno(
                        "Failed to remove existing non-folder '%s'",
                        dir_checkout);
                    return -1;
                }
            }
        }
    };
    if (archive) {
        r = snprintf(
            file_archive, PATH_MAX, "%s/%s.tar", 
            config->dir_archives, wanted_commit->id_hex_string);
        if (r < 0) {
            pr_error_with_errno("Failed to format archive file");
            return -1;
        } else if (r >= PATH_MAX - 6) {
            pr_error("Archive file path '%s' too long\n", 
            file_archive);
            return -1;
        }
        pr_info(
            "Will archive repo '%s' commit '%s' into '%s'\n",
            repo->url, wanted_commit->id_hex_string, 
            file_archive);
        if (stat(file_archive, &stat_buffer)) {
            switch (errno) {
            case ENOENT:
                break;
            default:
                pr_error_with_errno(
                    "Failed to check stat of existing '%s'", file_archive);
                return -1;
            }
        } else {
            if ((stat_buffer.st_mode & S_IFMT) == S_IFREG) {
                pr_warn("Already archived '%s', no neeed to "
                    "archive for this run\n", file_archive);
                archive = false;
            } else {
                if (ensure_path_non_exist(file_archive)) {
                    pr_error_with_errno(
                        "Failed to remove existing '%s'",
                        file_archive);
                    return -1;
                }
            }
        }

    }
    if (checkout) {
        r = snprintf(dir_checkout_work, PATH_MAX, "%s.work", dir_checkout);
        if (r < 0) {
            pr_error_with_errno("Failed to format work dir");
            return -1;
        }
        if (ensure_path_non_exist(dir_checkout_work)) {
            pr_error_with_errno("Failed to ensure '%s' non-exist", 
                dir_checkout_work);
            return -1;
        }
        if (mkdir_recursively(dir_checkout_work)) {
            pr_error("Failed to mkdir work folder '%s.work'\n",
                dir_checkout);
            return -1;
        }
    }
    if (archive) {
        r = snprintf(file_archive_work, PATH_MAX, "%s.work", file_archive);
        if (r < 0) {
            pr_error_with_errno("Failed to format archive work file");
            return -1;
        }
        if (ensure_path_non_exist(file_archive_work)) {
            pr_error_with_errno("Failed to ensure '%s' non-exist", 
                file_archive_work);
            return -1;
        }
        fd_archive = open(file_archive_work, O_WRONLY | O_CREAT, 0644);
        if (fd_archive < 0) {
            pr_error_with_errno(
                "Failed to create file '%s.work' and open it as write-only",
                file_archive_work);
            return -1;
        }
    }
    if (!archive && !checkout) {
        if (fd_archive >= 0) close(fd_archive);
        return 0;
    }
    git_commit *commit;
    if (git_commit_lookup(
            &commit, repo->repository, &wanted_commit->id)) {
        pr_error("Failed to lookup commit\n");
        if (fd_archive >= 0) close(fd_archive);
        return -1;
    }
    git_tree *tree;
    if (git_commit_tree(&tree, commit)) {
        pr_error("Failed to get the tree pointed by commit\n");
        git_commit_free(commit);
        if (fd_archive >= 0) close(fd_archive);
        return -1;
    }
    pr_info("Started exporting repo '%s' commit '%s'\n",
        repo->url, wanted_commit->id_hex_string);
    char submodule_path[PATH_MAX] = "";
    char mtime[TAR_POSIX_HEADER_MTIME_LEN] = "";
    if (snprintf(
        mtime, TAR_POSIX_HEADER_MTIME_LEN, "%011lo", git_commit_time(commit)
    ) < 0) {
        pr_error("Failed to format mtime\n");
        git_commit_free(commit);
        if (fd_archive >= 0) close(fd_archive);
        return -1;
    }
    struct export_commit_treewalk_payload export_commit_treewalk_payload = {
        .config = config,
        .repo = repo,
        .wanted_commit = wanted_commit,
        .submodule_path = submodule_path,
        .submodule_path_len = 0,
        .archive = archive,
        .mtime = mtime, // second, 
        // there's also git_commit_time_offset(commit), one offset for a minute
        .fd_archive = fd_archive,
        .checkout = checkout,
        .dir_checkout = dir_checkout_work,
    };
    if (git_tree_walk(
        tree, GIT_TREEWALK_PRE, export_commit_treewalk_callback, 
        (void *)&export_commit_treewalk_payload)) {
        pr_error("Failed to walk through tree\n");
        git_commit_free(commit);
        if (fd_archive >= 0) close(fd_archive);
        return -1;
    }
    git_commit_free(commit);
    pr_info("Ended exporting repo '%s' commit '%s'\n",
        repo->url, wanted_commit->id_hex_string);
    if (checkout) {
        if (rename(dir_checkout_work, dir_checkout)) {
            pr_error("Failed to move '%s' to '%s'\n", dir_checkout_work,
                dir_checkout);
            return -1;
        }
        pr_info("Atomic checkout finish, '%s' <- '%s'\n", 
                dir_checkout, dir_checkout_work);
    }
    if (archive) {
        if (tar_finish(fd_archive)) {
            pr_error("Failed to finish tar\n");
            close (fd_archive);
            return -1;
        }
        close(fd_archive);
        if (rename(file_archive_work, file_archive)) {
            pr_error("Failed to move '%s' to '%s'\n", file_archive_work,
                file_archive);
        }
        pr_info("Atomic archive finish, '%s' <- '%s'\n", 
                file_archive, file_archive_work);
    }
    return 0;
}

int export_all_repos(
    struct config const *const restrict config
) {
    if (config->export_threads <= 1) {
        pr_info("Single threaded exporting repos\n");
    }
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo const *const repo = config->repos + i;
        for (struct wanted_base const *wanted_object = 
            repo->wanted_objects.objects_head;
            wanted_object != NULL;
            wanted_object = wanted_object->next) {
            switch (wanted_object->type) {
            case WANTED_TYPE_BRANCH:
            case WANTED_TYPE_TAG:
            case WANTED_TYPE_REFERENCE:
                if (!((struct wanted_reference const *)wanted_object)
                    ->commit_resolved) {
                    pr_error("Reference '%s' is not resolved into commit\n",
                            wanted_object->name);
                    return -1;
                }
                __attribute__((fallthrough));
            case WANTED_TYPE_HEAD:
                if (!((struct wanted_reference const *)wanted_object)
                    ->commit_resolved) {
                    pr_warn("Reference '%s' is not resolved into commit\n",
                            wanted_object->name);
                    break;
                }
                __attribute__((fallthrough));
            case WANTED_TYPE_COMMIT: {
                struct wanted_commit const * const wanted_commit = 
                    (struct wanted_commit const *const)wanted_object;
                if (export_commit(config, repo, wanted_commit)) {
                    pr_error("Failed to export commit '%s' of repo '%s'\n",
                        wanted_commit->id_hex_string, repo->url);
                    return -1;
                }
                break;
            }
            default:
                break;
            }
        }
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
    pr_info("Initializing libgit2\n");
    git_libgit2_init();
    int r = mirror_all_repos(&config);
    if (r) {
        pr_error("Failed to mirro all repos\n");
        goto shutdown;
    }
    if ((r = export_all_repos(&config))) {
        pr_error("Failed to export all repos (archives and checkouts)\n");
        goto shutdown;
    }
shutdown:
#ifdef DEBUGGING
    pr_info("Current config before shutting down:\n");
    print_config(&config);
#endif
    config_free(&config);
    pr_info("Shutting down libgit2\n");
    git_libgit2_shutdown();
    return r;
}