/*
git-mirrorer, to mirror, archive and checkout git repos even across submodules
Copyright (C) 2023-present Guoxin "7Ji" Pu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
This file is written in A SINGLE FILE, ON PURPOSE.
It could be easily splitted up, but I kept it as a single file to ensure most
cross-module calling could be inlined. 
Yeah, split, incremental, then LTO, and similar performance could be achieved, 
but that comes with great compilation time penalty.
*/

#define _GNU_SOURCE

/* C */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

/* POSIX */
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <dirent.h>

/* LINUX */
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <linux/limits.h>

/* EXTERNAL */
#include <xxh3.h>
#include <git2.h>
#include <yaml.h>

/* Print formatters */
#define pr_with_prefix_and_source(prefix, format, arg...) \
    printf("["prefix"] %s:%d: "format, __FUNCTION__, __LINE__, ##arg)
#define pr_with_prefix(prefix, format, arg...) \
    printf("["prefix"] "format, ##arg)

#ifdef DEBUGGING
#define pr_debug(format, arg...) \
    pr_with_prefix_and_source("DEBUG", format, ##arg)
#else /* no-op debugging print */
#define pr_debug(format, arg...)
#endif
#define pr_info(format, arg...) pr_with_prefix("INFO", format, ##arg)
#define pr_warn(format, arg...) pr_with_prefix("WARN", format, ##arg)
#define pr_error(format, arg...)  \
    pr_with_prefix_and_source("ERROR", format, ##arg)
#define pr_error_with_errno(format, arg...) \
    pr_error(format", errno: %d, error: %s\n", ##arg, errno, strerror(errno))
#define pr_error_with_libgit_error(format, arg...) \
    pr_error(format", libgit return %d (%d: %s)\n", ##arg, \
        r, git_error_last()->klass, git_error_last()->message)
#define pr_error_with_pthread_error(format, arg...) \
    pr_error(format", pthread error: (%d: %s)\n", ##arg, pr, strerror(pr))

#define fpr_with_prefix_and_source(file, prefix, format, arg...) \
    fprintf(file, "["prefix"] %s:%d: "format, __FUNCTION__, __LINE__, ##arg)
#define fpr_with_prefix(file, prefix, format, arg...) \
    fprintf(file, "["prefix"] "format, ##arg)

#define fpr_info(file, format, arg...) \
    fpr_with_prefix("INFO", format, ##arg)
#define fpr_warn(file, format, arg...) \
    fpr_with_prefix("WARN", format, ##arg)
#define fpr_error(file, format, arg...) \
    fpr_with_prefix_and_source(file, "ERROR", format, ##arg)
#define fpr_error_with_errno(file, format, arg...) \
    fpr_error(file, format", errno: %d, error: %s\n", \
        ##arg, errno, strerror(errno))

/* String */

/*
 Packed data structure so we don't need to have A LOT of
 different pointers for all of the strings we need that
 each need to be free'd seperately

 The other struct that allocates string inside this buffer
 shouldn't need to have a sentry value to mark invalid
 offset, as a length of 0 is enough even if the offset
 is at its init value 0
*/
struct string_buffer {
    char *buffer;
    unsigned int used, size;
};

#define buffer_get_string(string_buffer, name) \
    string_buffer->buffer + name##_offset

#define get_string_from(parent, name) \
    parent->string_buffer.buffer + name##_offset

#define STRING_DECLARE(NAME) \
    unsigned int NAME##_offset; \
    unsigned short len_##NAME

#define LAZY_ALLOC_STRING_STACK_SIZE    NAME_MAX + 1

struct lazy_alloc_string {
    char stack[LAZY_ALLOC_STRING_STACK_SIZE];
    char *heap;
    char *string;
    size_t len; // The length without terminating NULL
    size_t alloc;
};

/* Dynamic array */
#define DYNAMIC_ARRAY_DECLARE_RAW(POINTER, NAME) \
    POINTER; \
    unsigned long NAME##s_count, \
                  NAME##s_allocated; \

#define DYNAMIC_ARRAY_DECLARE(TYPE, NAME) \
    DYNAMIC_ARRAY_DECLARE_RAW(TYPE *NAME##s, NAME)

#define DYNAMIC_ARRAY_DECLARE_SAME(NAME) \
    DYNAMIC_ARRAY_DECLARE(struct NAME, NAME)

#define ALLOC_BASE          10
#define ALLOC_MULTIPLIER    2
#ifdef  CHUNK_SIZE
#define CHUNK_SIZE  PAGE_SIZE
#else
#define CHUNK_SIZE  4096
#endif

#define get_last(x) x + x##_count - 1

#define free_if_allocated(name) if (name) free(name)
#define free_if_allocated_to_null(name) if (name) { free(name); name = NULL; }

#define dynamic_array_free(name) \
    free_if_allocated_to_null(name); \
    name##_count = 0; \
    name##_allocated = 0;

/* Commit */

#define COMMIT_ID_DECLARE { \
    git_oid oid; \
    unsigned int oid_hex_offset; \
}

struct commit_id COMMIT_ID_DECLARE;

#define COMMIT_ID_UNION_DECLARE \
    union { \
        struct commit_id id; \
        struct COMMIT_ID_DECLARE; \
    }

struct submodule {
    COMMIT_ID_UNION_DECLARE;
    STRING_DECLARE(path);
    STRING_DECLARE(url);
    XXH64_hash_t hash_url;
    unsigned long   target_repo_id,
                    target_commit_id;
};

struct submodule const SUBMODULE_INIT = {
    .target_repo_id = (unsigned long) -1,
    .target_commit_id = (unsigned long) -1};

struct commit {
    COMMIT_ID_UNION_DECLARE;
    git_commit *git_commit;
    DYNAMIC_ARRAY_DECLARE_SAME(submodule);
    bool    /*submodules_parsed,*/
            archive,
            checkout;
};

struct commit const COMMIT_INIT = {0};

#define git_commit_free_if_allocated(name) if (name) git_commit_free(name)
#define git_commit_free_if_allocated_to_null(name) \
    if (name) { git_commit_free(name); name = NULL; }
#define git_commit_free_to_null(name) git_commit_free(name); name = NULL;

/* Wanted objects */

enum wanted_type {
    WANTED_TYPE_UNKNOWN,
    WANTED_TYPE_ALL_BRANCHES,
    WANTED_TYPE_ALL_TAGS,
    WANTED_TYPE_REFERENCE,
    WANTED_TYPE_BRANCH,
    WANTED_TYPE_TAG,
    WANTED_TYPE_HEAD,
    WANTED_TYPE_COMMIT,
};

#define WANTED_TYPE_MAX WANTED_TYPE_HEAD

char const *wanted_type_strings[] = {
    "unknown",
    "all_branches",
    "all_tags",
    "reference",
    "branch",
    "tag",
    "head",
    "commit",
};

#define WANTED_BASE_DECLARE {\
    enum wanted_type type;\
    STRING_DECLARE(name); \
    bool archive;\
    bool checkout;\
}

struct wanted_base WANTED_BASE_DECLARE;

struct wanted_base const WANTED_BASE_INIT = {0};

struct wanted_base const WANTED_BASE_HEAD_INIT = {
    .type = WANTED_TYPE_HEAD};

struct wanted_base const WANTED_BASE_ALL_BRANCHES_INIT = {
    .type = WANTED_TYPE_ALL_BRANCHES };

struct wanted_base const WANTED_BASE_ALL_TAGS_INIT = {
    .type = WANTED_TYPE_ALL_TAGS };

#define WANTED_COMMIT_DECLARE { \
    union { \
        struct wanted_base base; \
        struct WANTED_BASE_DECLARE; \
    }; \
    COMMIT_ID_UNION_DECLARE; \
    unsigned long parsed_commit_id; \
}

struct wanted_commit WANTED_COMMIT_DECLARE;

struct wanted_commit const WANTED_COMMIT_INIT = {
    .base.type = WANTED_TYPE_COMMIT, .parsed_commit_id = (unsigned long) -1};

#define WANTED_REFERENCE_DECLARE { \
    union { \
        struct wanted_commit commit; \
        struct WANTED_COMMIT_DECLARE; \
    }; \
    bool commit_parsed; \
}

struct wanted_reference WANTED_REFERENCE_DECLARE;

struct wanted_object {
    union {
        struct wanted_reference reference;
        struct WANTED_REFERENCE_DECLARE;
    };
};

struct wanted_object const WANTED_OBJECT_INIT = {
    .type = WANTED_TYPE_UNKNOWN, .parsed_commit_id = (unsigned long) -1};

struct wanted_reference const WANTED_REFERENCE_INIT = {
    .type = WANTED_TYPE_REFERENCE,
    .parsed_commit_id = (unsigned long) -1};

struct wanted_reference const WANTED_BRANCH_INIT = {
    .type = WANTED_TYPE_BRANCH,
    .parsed_commit_id = (unsigned long) -1};

struct wanted_reference const WANTED_TAG_INIT = {
    .type = WANTED_TYPE_TAG,
    .parsed_commit_id = (unsigned long) -1};

struct wanted_reference const WANTED_HEAD_INIT = {
    .type = WANTED_TYPE_HEAD,
    .parsed_commit_id = (unsigned long) -1};


/* Hash */

#define hash_type   XXH64_hash_t
#define hash_calculate(data, size)  XXH3_64bits(data, size)
#define HASH_NAME   "64bit xxh3 hash"
#define HASH_FORMAT "%016lx"
#define HASH_STRING_LEN  16


/* Repo */

#define REPO_COMMON_DECLARE { \
    STRING_DECLARE(url); \
    STRING_DECLARE(long_name); \
    STRING_DECLARE(short_name); \
    hash_type   hash_url, \
                hash_long_name, \
                hash_short_name, \
                hash_domain; \
    unsigned short depth_long_name; \
    char hash_url_string[HASH_STRING_LEN + 1]; \
}

struct repo_common REPO_COMMON_DECLARE;

struct repo_config {
    union {
        struct repo_common common;
        struct REPO_COMMON_DECLARE;
    };
    DYNAMIC_ARRAY_DECLARE(struct wanted_base, wanted_object);
};

struct repo_work {
    union {
        struct repo_common common;
        struct REPO_COMMON_DECLARE;
    };
    DYNAMIC_ARRAY_DECLARE_SAME(wanted_object);
    DYNAMIC_ARRAY_DECLARE_SAME(commit);
    unsigned long wanted_objects_count_original;
    git_repository *git_repository;
    bool from_config, wanted_dynamic, need_update, updated;
};

#define git_repository_free_if_allocated(name) \
    if (name) git_repository_free(name)
#define git_repository_free_if_allocated_to_null(name) \
    if (name) { git_repository_free(name); name = NULL; }

struct repo_domain_group {
    hash_type domain;
    DYNAMIC_ARRAY_DECLARE(struct repo_work *, repo);
};

struct repo_domain_map {
    DYNAMIC_ARRAY_DECLARE(struct repo_domain_group, group);
};

struct repo_commit_pair {
    struct repo_work *repo;
    struct commit *commit;
};

/* Config */

struct archive_pipe_arg {
    unsigned int offset;
    unsigned short len;
};

#define ARCHIVE_PIPE_ARGS_MAX_COUNT 64

#define CONFIG_STATIC_DECLARE { \
    STRING_DECLARE(proxy_url); \
    STRING_DECLARE(dir_repos); \
    STRING_DECLARE(dir_archives); \
    STRING_DECLARE(dir_checkouts); \
    STRING_DECLARE(archive_suffix); \
    unsigned int    daemon_interval; \
    int             timeout_connect; \
    unsigned short  proxy_after, \
                    connections_per_server, \
                    export_threads, \
                    clean_links_pass; \
    bool    archive_gh_prefix, \
            clean_repos, \
            clean_archives, \
            clean_checkouts, \
            daemon; \
}

struct config_static CONFIG_STATIC_DECLARE;

struct config {
    struct string_buffer string_buffer;
    DYNAMIC_ARRAY_DECLARE(struct repo_config, repo);
    DYNAMIC_ARRAY_DECLARE(struct wanted_base, empty_wanted_object);
    DYNAMIC_ARRAY_DECLARE(struct wanted_base, always_wanted_object);
    DYNAMIC_ARRAY_DECLARE_SAME(archive_pipe_arg); \
    union {
        struct config_static _static;
        struct CONFIG_STATIC_DECLARE;
    };
};

#define config_get_string(name) \
    get_string_from(config, name)

#define DIR_DATA    "data"
#define DIR_LINKS   "links"
#define DIR_REPOS_DEFAULT   "repos"
#define DIR_ARCHIVES_DEFAULT    "archives"
#define DIR_CHECKOUTS_DEFAULT   "checkouts"
#define ARCHIVE_SUFFIX_DEFAULT  ".tar"
#define CONNECTIONS_PER_SERVER_DEFAULT 10
#define EXPORT_THREADS_DEFAULT  10
#define CLEAN_LINKS_PASS_DEFAULT    1
#define DAEMON_INTERVAL_DEFAULT 60

struct config const CONFIG_INIT = {
    .connections_per_server = CONNECTIONS_PER_SERVER_DEFAULT,
    .export_threads = EXPORT_THREADS_DEFAULT,
    .clean_links_pass = CLEAN_LINKS_PASS_DEFAULT,
    .daemon_interval = DAEMON_INTERVAL_DEFAULT,
    .string_buffer = {
        .used = 1,
    },
};


/* Work */

struct work_keep {
    unsigned int offset;
    unsigned short len;
};

struct work_directory {
    STRING_DECLARE(path);
    int datafd;
    int linkfd;
    DYNAMIC_ARRAY_DECLARE(struct work_keep, keep);
};

#define WORK_DIRECTORY_INIT_ASSIGN .datafd = -1, .linkfd = -1
struct work_directory const WORK_DIRECTORY_INIT = {
    WORK_DIRECTORY_INIT_ASSIGN};

struct work_handle {
    struct string_buffer string_buffer;
    DYNAMIC_ARRAY_DECLARE(struct repo_work, repo);
    DYNAMIC_ARRAY_DECLARE_SAME(archive_pipe_arg); \
    struct work_directory dir_repos,
                          dir_archives,
                          dir_checkouts;
    git_transport_message_cb cb_sideband;
    git_indexer_progress_cb cb_fetch;
    int cwd; // File decriptor of the current work directory, to quick return
    union {
        struct config_static _static;
        struct CONFIG_STATIC_DECLARE;
    };
};

#define work_handle_get_string(name) \
    get_string_from(work_handle, name)

struct work_handle const WORK_HANDLE_INIT = {
    .dir_repos = {WORK_DIRECTORY_INIT_ASSIGN},
    .dir_archives = {WORK_DIRECTORY_INIT_ASSIGN},
    .dir_checkouts = {WORK_DIRECTORY_INIT_ASSIGN}
};

/* IO */

#define BUFFER_READ_CHUNK CHUNK_SIZE * 64

/* TAR */

#define TAR_HEADER_MTIME_LEN 12

struct tar_header {/* byte offset */\
    char name[100];     /*   0 */\
    char mode[8];       /* 100 octal mode string %07o */\
    char uid[8];        /* 108 octal uid string %07o */\
    char gid[8];        /* 116 octal gid string %07o */\
    char size[12];      /* 124 octal size %011o */\
    char mtime[12];     /* 136 octal mtime string %011o */\
    char chksum[8];     /* 148 octal checksum string %06o + space */\
    char typeflag;      /* 156 either TAR_{REG,LINK,DIR}TYPE */\
    char linkname[100]; /* 157 symlink target */\
    char magic[6];      /* 257 ustar\0 */\
    char version[2];    /* 263 \0 0*/\
    char uname[32];     /* 265 uname + padding \0 */\
    char gname[32];     /* 297 gname + padding \0 */\
    char devmajor[8];   /* 329 all 0 */\
    char devminor[8];   /* 337 all 0 */\
    char prefix[155];   /* 345 all 0 */\
                        /* 500 */\
};


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
#define PAX_TAR_GLOBAL_HEADER_TYPE 'g'

#define GNUTAR_LONGLINK 'K'
#define GNUTAR_LONGNAME 'L'

#define TAR_LONGLINK_TYPE GNUTAR_LONGLINK
#define TAR_LONGNAME_TYPE GNUTAR_LONGNAME
#define TAR_GLOBAL_HEADER_TYPE    PAX_TAR_GLOBAL_HEADER_TYPE

#define GNUTAR_LONGLINK_NAME    "././@LongLink"

#define PAXTAR_GLOBAL_HEADER_NAME "pax_global_header"

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

struct tar_header const TAR_HEADER_FILE_REG_INIT =
    TAR_POSIX_INIT(644, TAR_REGTYPE);

struct tar_header const TAR_HEADER_FILE_EXE_INIT =
    TAR_POSIX_INIT(755, TAR_REGTYPE);

struct tar_header const TAR_HEADER_SYMLINK_INIT =
    TAR_POSIX_INIT(777, TAR_SYMTYPE);

struct tar_header const TAR_HEADER_FOLDER_INIT =
    TAR_POSIX_INIT(755, TAR_DIRTYPE);

struct tar_header const TAR_HEADER_GNU_LONGLINK_INIT =
    TAR_INIT(GNUTAR_LONGLINK_NAME, 644, TAR_LONGLINK_TYPE);

struct tar_header const TAR_HEADER_GNU_LONGNAME_INIT =
    TAR_INIT(GNUTAR_LONGLINK_NAME, 644, TAR_LONGNAME_TYPE);

struct tar_header const TAR_HEADER_PAX_GLOBAL_HEADER_INIT =
    TAR_INIT(PAXTAR_GLOBAL_HEADER_NAME, 666, TAR_GLOBAL_HEADER_TYPE);

/* To help padding */
unsigned char const EMPTY_512_BLOCK[512] = {0};


/* YAML Config */

#define yamlconf_add_string(config, event) \
    string_buffer_add(&config->string_buffer, \
            (char const *)event->data.scalar.value, event->data.scalar.length)

char const *yamlconf_event_type_strings[] = {
    "no",
    "stream start",
    "stream end",
    "document start",
    "document end",
    "alias",
    "scalar",
    "sequence start",
    "sequence end",
    "mapping start",
    "mapping end",
};

enum yamlconf_wanted_type {
    YAMLCONF_WANTED_UNKNOWN,
    YAMLCONF_WANTED_GLOBAL_EMPTY,
    YAMLCONF_WANTED_GLOBAL_ALWAYS,
    YAMLCONF_WANTED_REPO,
};

char const *yamlconf_wanted_type_strings[] = {
    "unknown",
    "global, when repo empty",
    "global, always to repo",
    "repo",
};

enum yamlconf_parsing_status {
    YAMLCONF_PARSING_STATUS_NONE,
    YAMLCONF_PARSING_STATUS_STREAM,
    YAMLCONF_PARSING_STATUS_DOCUMENT,
    YAMLCONF_PARSING_STATUS_SECTION,
    YAMLCONF_PARSING_STATUS_DAEMON,
    YAMLCONF_PARSING_STATUS_DAEMON_INTERVAL,
    YAMLCONF_PARSING_STATUS_PROXY,
    YAMLCONF_PARSING_STATUS_PROXY_AFTER,
    YAMLCONF_PARSING_STATUS_CONNECT_TIMEOUT,
    YAMLCONF_PARSING_STATUS_DIR_REPOS,
    YAMLCONF_PARSING_STATUS_DIR_ARCHIVES,
    YAMLCONF_PARSING_STATUS_DIR_CHECKOUTS,
    YAMLCONF_PARSING_STATUS_ARCHIVE,
    YAMLCONF_PARSING_STATUS_ARCHIVE_SECTION,
    YAMLCONF_PARSING_STATUS_ARCHIVE_GHPREFIX,
    YAMLCONF_PARSING_STATUS_ARCHIVE_SUFFIX,
    YAMLCONF_PARSING_STATUS_ARCHIVE_PIPE,
    YAMLCONF_PARSING_STATUS_ARCHIVE_PIPE_LIST,
    YAMLCONF_PARSING_STATUS_CLEAN,
    YAMLCONF_PARSING_STATUS_CLEAN_SECTION,
    YAMLCONF_PARSING_STATUS_CLEAN_REPOS,
    YAMLCONF_PARSING_STATUS_CLEAN_ARCHIVES,
    YAMLCONF_PARSING_STATUS_CLEAN_CHECKOUTS,
    YAMLCONF_PARSING_STATUS_CLEAN_LINKS_PASS,
    YAMLCONF_PARSING_STATUS_EXPORT_THREADS,
    YAMLCONF_PARSING_STATUS_CONNECTIONS_PER_SERVER,
    YAMLCONF_PARSING_STATUS_WANTED,
    YAMLCONF_PARSING_STATUS_WANTED_SECTION,
    YAMLCONF_PARSING_STATUS_WANTED_SECTION_START,
    YAMLCONF_PARSING_STATUS_WANTED_LIST,
    YAMLCONF_PARSING_STATUS_WANTED_OBJECT,
    YAMLCONF_PARSING_STATUS_WANTED_OBJECT_START,
    YAMLCONF_PARSING_STATUS_WANTED_OBJECT_SECTION,
    YAMLCONF_PARSING_STATUS_WANTED_OBJECT_TYPE,
    YAMLCONF_PARSING_STATUS_WANTED_OBJECT_ARCHIVE,
    YAMLCONF_PARSING_STATUS_WANTED_OBJECT_CHECKOUT,
    YAMLCONF_PARSING_STATUS_REPOS,
    YAMLCONF_PARSING_STATUS_REPOS_LIST,
    YAMLCONF_PARSING_STATUS_REPO_URL,
    YAMLCONF_PARSING_STATUS_REPO_AFTER_URL,
    YAMLCONF_PARSING_STATUS_REPO_SECTION,
};

char const *yamlconf_parsing_status_strings[] = {
    "none",
    "stream",
    "document",
    "section",
    "daemon",
    "daemon interval",
    "proxy",
    "proxy after",
    "connect timeout",
    "dir repos",
    "dir archives",
    "dir checkouts",
    "archive",
    "archive section",
    "archive github-like prefix",
    "archive suffix",
    "archive pipe",
    "archive pipe list",
    "clean",
    "clean section",
    "clean repos",
    "clean archives",
    "clean checkouts",
    "clean links pass",
    "export threads",
    "connections per server"
    "wanted",
    "wanted section",
    "wanted section start",
    "wanted list",
    "wanted object",
    "wanted object start",
    "wanted object section",
    "wanted object type",
    "wanted object archive",
    "wanted object checkout",
    "repos",
    "repos list",
    "repo url",
    "repo after url",
    "repo section",
};

struct yamlconf_parsing_handle {
    enum yamlconf_parsing_status status;
    enum yamlconf_wanted_type wanted_type;
};

/* Git mirror */
#define GMR_REMOTE "origin"
#define GMR_FETCHSPEC "+refs/*:refs/*"
#define GMR_CONFIG "remote."GMR_REMOTE".mirror"

char const *gmr_refspecs_strings[] = {
    GMR_FETCHSPEC,
    NULL
};

static git_strarray const gmr_refspecs = {
    .count = 1,
    .strings = (char **)gmr_refspecs_strings
};

struct gmr_payload {
    char const *const restrict url;
    time_t first_transfer;
    time_t *last_transfer;
};

/* Console lock */
pthread_mutex_t console_mutex = PTHREAD_MUTEX_INITIALIZER;

#define console_with_trylock(job) \
    console_locked = console_trylock(); \
    job; \
    if (console_locked) console_unlock() \

#define console_with_lock(job) \
    console_locked = console_lock(); \
    if (console_locked) { \
        job; \
        console_unlock(); \
    }

/* Functions */

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
        "git-mirrorer version "
#ifdef VERSION
        VERSION
#else
        "UNKNOWN"
#endif
        " by Guoxin \"7Ji\" Pu, "
        "licensed under GNU Affero General Public License v3 or later\n",
        stderr);
}

int string_buffer_add(
    struct string_buffer *const restrict sbuffer,
    char const *const restrict string,
    unsigned short const len
) {
    unsigned int used_new;
    char *buffer_new;
    if (!sbuffer->buffer) {
        if (!(sbuffer->buffer = malloc(sbuffer->size = CHUNK_SIZE))) {
            pr_error_with_errno(
                "Failed to allocate memory for string buffer");
            return -1;
        }
    }
    if ((used_new = sbuffer->used + len + 1) > sbuffer->size) {
        while (used_new > sbuffer->size) {
            if (sbuffer->size == UINT_MAX) {
                pr_error("Impossible to allocate more memory, "
                    "wanted size at UINT_MAX\n");
                return -1;
            } else if (sbuffer->size >= UINT_MAX / ALLOC_MULTIPLIER) {
                sbuffer->size = UINT_MAX;
            } else {
                sbuffer->size *= ALLOC_MULTIPLIER;
            }
        }
        if (!(buffer_new = realloc(sbuffer->buffer, sbuffer->size))) {
            pr_error_with_errno("Failed to allocate more memory");
            return -1;
        }
        sbuffer->buffer = buffer_new;
    }
    memcpy(sbuffer->buffer + sbuffer->used, string, len);
    *(sbuffer->buffer + sbuffer->used + len) = '\0';
    sbuffer->used = used_new;
    return 0;
}

int string_buffer_free(
    struct string_buffer *const restrict sbuffer
) {
    if (!sbuffer) {
        pr_error("Internal: called passed NULL pointer to us\n");
        return -1;
    }
    free_if_allocated_to_null(sbuffer->buffer);
    sbuffer->size = 0;
    sbuffer->used = 0;
    return 0;
}


int string_buffer_partial_free(
    struct string_buffer *const restrict sbuffer
) {
    char *buffer_new;
    if (!sbuffer) {
        pr_error("Internal: called passed NULL pointer to us\n");
        return -1;
    }
    if (!sbuffer->used) {
        free_if_allocated_to_null(sbuffer->buffer);
        sbuffer->size = 0;
        return 0;
    }
    if (!sbuffer->buffer) {
        pr_error("String buffer not allocated but it's marked as used\n");
        return -1;
    }
    if (sbuffer->size == sbuffer->used) return 0;
    if (sbuffer->used > sbuffer->size) {
        pr_error("Used buffer larger than size, impossible\n");
        return -1;
    }
    if (!(buffer_new = realloc(sbuffer->buffer, sbuffer->used))) {
        pr_error_with_errno("Failed to re-allocate memory for buffer");
        return -1;
    }
    sbuffer->buffer = buffer_new;
    sbuffer->size = sbuffer->used;
    return 0;
}

int string_buffer_clone(
    struct string_buffer *const restrict target,
    struct string_buffer const *const restrict source
) {
    if (target && source);
    else {
        pr_error("Internal: called passed NULL pointer to us\n");
        return -1;
    }
    target->size = (source->used + CHUNK_SIZE - 1) / CHUNK_SIZE  * CHUNK_SIZE;
    if (!(target->buffer = malloc(target->size))) {
        pr_error_with_errno("Failed to allocate memory for new string buffer");
        return -1;
    }
    if (!(target->used = source->used)) return 0;
    memcpy(target->buffer, source->buffer, target->used);
    return 0;
}

static inline
void lazy_alloc_string_init(
    struct lazy_alloc_string *const restrict string
) {
    string->stack[0] = '\0';
    string->heap = NULL;
    string->string = string->stack;
    string->len = 0;
    string->alloc = 0;
}

static inline
void lazy_alloc_string_init_maxed(
    struct lazy_alloc_string *const restrict string
) {
    string->stack[0] = '\0';
    string->heap = NULL;
    string->string = string->stack;
    string->len = LAZY_ALLOC_STRING_STACK_SIZE - 1;
    string->alloc = 0;
}

static inline
int lazy_alloc_string_init_with(
    struct lazy_alloc_string *const restrict string,
    void const *const restrict content,
    size_t const len
) {
    if (len >= LAZY_ALLOC_STRING_STACK_SIZE) {
        if (!(string->heap = malloc((
                string->alloc = (len + 1) / 0x1000 * 0x1000))))
        {
            pr_error_with_errno("Failed to allocate memory for string");
            return -1;
        }
        string->string = string->heap;
    } else {
        string->heap = NULL;
        string->string = string->stack;
        string->alloc = 0;
    }
    memcpy(string->string, content, len);
    string->string[len] = '\0';
    string->len = len;
    return 0;
}

static inline
int lazy_alloc_string_alloc(
    struct lazy_alloc_string *const restrict string,
    size_t const len
) {
    if (len >= LAZY_ALLOC_STRING_STACK_SIZE) {
        if (len >= string->alloc) {
            free_if_allocated(string->heap);
            if (!(string->heap = malloc((
                string->alloc = (len + 1) / 0x1000 * 0x1000))))
            {
                pr_error_with_errno("Failed to allocate memory for string");
                return -1;
            }
        }
        string->string = string->heap;
    } else {
        string->string = string->stack;
    }
    return 0;
}

static inline
int lazy_alloc_string_setlen_discard(
    struct lazy_alloc_string *const restrict string,
    size_t const len
) {
    if (lazy_alloc_string_alloc(string, len)) return -1;
    string->string[(string->len = len)] = '\0';
    return 0;
}

static inline
int lazy_alloc_string_setlen_keep(
    struct lazy_alloc_string *const restrict string,
    size_t const len
) {
    char const *const restrict old_string = string->string;
    if (lazy_alloc_string_alloc(string, len)) return -1;
    if (old_string != string->string) {
        if (string->len) memcpy(string->string, old_string, string->len);
    }
    string->string[(string->len = len)] = '\0';
    return 0;
}

static inline
int lazy_alloc_string_replace(
    struct lazy_alloc_string *const restrict string,
    void const *const restrict content,
    size_t const len
) {
    if (lazy_alloc_string_setlen_discard(string, len)) {
        pr_error("Failed to set length for lazy alloc string\n");
        return -1;
    }
    memcpy(string->string, content, len);
    return 0;
}

static inline
void lazy_alloc_string_free(
    struct lazy_alloc_string *const restrict string
) {
    free_if_allocated(string->heap);
}

int dynamic_array_add(
    void **const restrict array,
    size_t const size, // Size of an array member
    unsigned long *const restrict count,
    unsigned long *const restrict alloc
) {
    void *array_new;
    if (array && count && alloc);
    else {
        pr_error("Caller passed NULL pointer to us\n");
        return -1;
    }
    if (!*array) {
        if (!(*array = malloc(size * (*alloc = ALLOC_BASE)))) {
            pr_error_with_errno("Failed to allocate memory to init array");
            return -1;
        }
    }
    if (++*count <= *alloc) return 0;
    while (*count > *alloc) {
        if (*alloc == ULONG_MAX) {
            pr_error("Impossible to allocate more memory, allocate count"
                "at max possible value\n");
            return -1;
        } else if (*alloc >= ULONG_MAX / ALLOC_MULTIPLIER) {
            *alloc = ULONG_MAX;
        } else {
            *alloc *= ALLOC_MULTIPLIER;
        }
    }
    if (!(array_new = realloc(*array, size * *alloc))) {
        pr_error_with_errno("Failed to re-allocate memory for array");
        return -1;
    }
    *array = array_new;
    return 0;
}

#define dynamic_array_add_to(name) \
    dynamic_array_add((void **)&name, sizeof *name, \
        &name##_count, &name##_allocated)

int dynamic_array_partial_free(
    void **const restrict array,
    size_t const size, // Size of an array member
    unsigned long const count,
    unsigned long *const restrict alloc
) {
    void *array_new;
    if (array && alloc);
    else {
        pr_error("Caller passed NULL pointer to us\n");
        return -1;
    }
    if (!count) {
        free_if_allocated_to_null(*array);
        *alloc = 0;
        return 0;
    }
    if (!*array) {
        pr_error("Array not allocated but it's marked as used\n");
        return -1;
    }
    if (count == *alloc) return 0;
    if (count > *alloc) {
        pr_error("Current count larger than allocated, impossible\n");
        return -1;
    }
    if (!(array_new = realloc(*array, size * count))) {
        pr_error_with_errno("Failed to re-allocate memory for array");
        return -1;
    }
    *array = array_new;
    *alloc = count;
    return 0;
}

#define dynamic_array_partial_free_to(name) \
    dynamic_array_partial_free((void **)&name, sizeof *name, \
        name##_count, &name##_allocated)

/* Return -1 for error */
size_t buffer_read_from_fd(
    unsigned char **const restrict buffer,
    int const fd
) {
    size_t size_alloc = BUFFER_READ_CHUNK,
           size_total = 0;
    ssize_t size_current = 0;
    unsigned char *buffer_new;
    if (!buffer || fd < 0) {
        pr_error("Caller passed NULL pointer or "
                 "invalid file descriptor to us\n");
        return -1;
    }
    if (!(*buffer = malloc(size_alloc))) {
        pr_error("Failed to allocate memory\n");
        return -1;
    }
    for(;;) {
        if (size_alloc - size_total < BUFFER_READ_CHUNK) {
            while (size_alloc - size_total < BUFFER_READ_CHUNK) {
                if (size_alloc == SIZE_MAX) { // This shouldn't be possible
                    pr_error(
                        "Couldn't allocate more memory, "
                        "allocated size already at size max\n");
                    goto on_error;
                } else if (size_alloc >= SIZE_MAX / 2) {
                    size_alloc = SIZE_MAX;
                } else {
                    size_alloc *= 2;
                }
            }
            if (!(buffer_new = realloc(*buffer, size_alloc))) {
                pr_error("Failed to allocate more memory\n");
                goto on_error;
            }
            *buffer = buffer_new;
        }
        if (!(size_current = read(
                fd, *buffer + size_total, BUFFER_READ_CHUNK)))
                    break;
        if (size_current < 0) {
            switch (errno) {
            case EAGAIN:
#if (EAGAIN != EWOULDBLOCK)
            case EWOULDBLOCK:
#endif
            case EINTR:
                break;
            default:
                pr_error_with_errno("Failed to read");
                goto on_error;
            }
        }
        size_total += size_current;
    }
    if (size_alloc - size_total >= CHUNK_SIZE) {
        if (!(buffer_new = realloc(*buffer, size_total))) {
            pr_error_with_errno("Failed to release memory");
            goto on_error;
        }
        *buffer = buffer_new;
    }
    return size_total;
on_error:
    free_if_allocated_to_null(*buffer);
    return (size_t)-1;
}

#define YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_RAW(value, target_status) \
    if (!strcmp(key, value)) \
        handle->status = YAMLCONF_PARSING_STATUS_##target_status

#define YAMLCONF_PARSE_SECTION_LENGTH_VALUE_TO_STATUS( \
            length, value, status) \
    case length: \
        YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_RAW(value, status); \
        break;

#define YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS( \
            value, status) \
        YAMLCONF_PARSE_SECTION_LENGTH_VALUE_TO_STATUS( \
            sizeof value - 1, value, status)

#define YAMLCONF_PARSE_SECTION_LENGTH_VALUE_TO_STATUS_TWO( \
            length, value1, status1, value2, status2) \
    case length: \
        YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_RAW(value1, status1); \
        else YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_RAW(value2, status2); \
        break;

#define YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_TWO( \
            value1, status1, value2, status2) \
static_assert(sizeof value1 == sizeof value2, "length different"); \
        YAMLCONF_PARSE_SECTION_LENGTH_VALUE_TO_STATUS_TWO( \
            sizeof value1 - 1, value1, status1, value2, status2)

static inline
int yamlconf_parse_section(
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    char const *const key = (char const *)event->data.scalar.value;
    switch (event->data.scalar.length) {
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_TWO(
        "proxy", PROXY, "repos", REPOS);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_TWO(
        "wanted", WANTED, "daemon", DAEMON);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_TWO(\
        "archive", ARCHIVE, "cleanup", CLEAN);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("dir_repos", DIR_REPOS);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("proxy_after", PROXY_AFTER);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("dir_archives", DIR_ARCHIVES);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("dir_checkouts", DIR_CHECKOUTS);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("export_threads", EXPORT_THREADS);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS_TWO(
        "daemon_interval", DAEMON_INTERVAL,
        "connect_timeout", CONNECT_TIMEOUT);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS(
        "connections_per_server", CONNECTIONS_PER_SERVER);
    }
    if (handle->status == YAMLCONF_PARSING_STATUS_SECTION) {
        pr_error("Unrecognized config key '%s'\n", key);
        return -1;
    }
    return 0;
}

#define YAMLCONF_PARSE_STRING_ASSIGN(NAME) \
    offset = &config->NAME##_offset; \
    len = &config->len_##NAME

static inline
int yamlconf_parse_string(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    unsigned int *offset = NULL;
    unsigned short *len = NULL;
    switch (handle->status) {
    case YAMLCONF_PARSING_STATUS_PROXY:
        YAMLCONF_PARSE_STRING_ASSIGN(proxy_url);
        break;
    case YAMLCONF_PARSING_STATUS_DIR_REPOS:
        YAMLCONF_PARSE_STRING_ASSIGN(dir_repos);
        break;
    case YAMLCONF_PARSING_STATUS_DIR_ARCHIVES:
        YAMLCONF_PARSE_STRING_ASSIGN(dir_archives);
        break;
    case YAMLCONF_PARSING_STATUS_DIR_CHECKOUTS:
        YAMLCONF_PARSE_STRING_ASSIGN(dir_checkouts);
        break;
    case YAMLCONF_PARSING_STATUS_ARCHIVE_SUFFIX:
        YAMLCONF_PARSE_STRING_ASSIGN(archive_suffix);
        break;
    default:
        pr_error("Internal: impossible value\n");
        return -1;
    }
    if (offset && len);
    else {
        pr_error("Internal: impossible value\n");
        return -1;
    }
    *offset = config->string_buffer.used;
    if (yamlconf_add_string(config, event)) {
        pr_error("Failed to add '%s' to string buffer\n",
            event->data.scalar.value);
        *offset = 0;
        return -1;
    }
    *len = event->data.scalar.length;
    switch (handle->status) {
    case YAMLCONF_PARSING_STATUS_PROXY:
    case YAMLCONF_PARSING_STATUS_DIR_REPOS:
    case YAMLCONF_PARSING_STATUS_DIR_ARCHIVES:
    case YAMLCONF_PARSING_STATUS_DIR_CHECKOUTS:
        handle->status = YAMLCONF_PARSING_STATUS_SECTION;
        break;
    case YAMLCONF_PARSING_STATUS_ARCHIVE_SUFFIX:
        handle->status = YAMLCONF_PARSING_STATUS_ARCHIVE_SECTION;
        break;
    default:
        pr_error("Impossible status\n");
        return -1;
    }
    return 0;
}

static inline
int yamlconf_parse_archive_section(
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    char const *const key = (char const *)event->data.scalar.value;
    switch (event->data.scalar.length) {
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("suffix", ARCHIVE_SUFFIX);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("pipe_through", ARCHIVE_PIPE);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS(
        "github_like_prefix", ARCHIVE_GHPREFIX);
    }
    if (handle->status == YAMLCONF_PARSING_STATUS_ARCHIVE_SECTION) {
        pr_error("Unrecognized key '%s'\n", key);
        return -1;
    }
    return 0;
}

static inline
int yamlconf_parse_clean_section(
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    char const *const key = (char const *)event->data.scalar.value;
    switch (event->data.scalar.length) {
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("repos", CLEAN_REPOS);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("archives", CLEAN_ARCHIVES);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("checkouts", CLEAN_CHECKOUTS);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("links_pass", CLEAN_LINKS_PASS);
    }
    if (handle->status == YAMLCONF_PARSING_STATUS_CLEAN_SECTION) {
        pr_error("Unrecognized config key '%s'\n", key);
        return -1;
    }
    return 0;
}

static inline
int yamlconf_parse_wanted_section(
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    char const *const key = (char const *)event->data.scalar.value;
    switch (event->data.scalar.length) {
    case 5:
        if (!strcmp(key, "empty")) {
            handle->status = YAMLCONF_PARSING_STATUS_WANTED_SECTION_START;
            handle->wanted_type = YAMLCONF_WANTED_GLOBAL_EMPTY;
        }
        break;
    case 6:
        if (!strcmp(key, "always")) {
            handle->status = YAMLCONF_PARSING_STATUS_WANTED_SECTION_START;
            handle->wanted_type = YAMLCONF_WANTED_GLOBAL_ALWAYS;
        }
        break;
    }
    if (handle->status == YAMLCONF_PARSING_STATUS_WANTED_SECTION) {
        pr_error("Unrecognized config key '%s'\n", key);
        return -1;
    }
    return 0;
}

static inline
int yamlconf_parse_archive_pipe(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    config->archive_pipe_args_count = 0;
    if (event->data.scalar.length == 0) {
        return 0;
    }
    unsigned short const args_length = event->data.scalar.length;
    struct lazy_alloc_string string;
    if (lazy_alloc_string_init_with(&string, event->data.scalar.value, 
                                    args_length)) 
    {
        pr_error("Failed to prepare args buffer to parse\n");
        return -1;
    }
    char *args_buffer = string.string;
    // Go first run to 1) remove all whitespaces and 2) count args
    bool arg_parsing = false;
    for (unsigned short i = 0; i < args_length; ++i) {
        if (arg_parsing) {
            switch (args_buffer[i]) {
            case '\t':
            case '\n':
            case '\v':
            case '\f':
            case '\r':
            case ' ':
                args_buffer[i] = '\0';
                __attribute__((fallthrough));
            case '\0':
                arg_parsing = false;
                break;
            }
        } else {
            switch (args_buffer[i]) {
                case '\t':
                case '\n':
                case '\v':
                case '\f':
                case '\r':
                case ' ':
                case '\0':
                    break;
                default:
                    arg_parsing = true;
                    ++config->archive_pipe_args_count;
            }
        }
    }
    int r;
    if (!config->archive_pipe_args_count) {
        // only whitespace, empty arg
        r = 0;
        goto free_args_buffer;
    }
    bool need_alloc;
    if (config->archive_pipe_args) {
        if (config->archive_pipe_args_count >
                config->archive_pipe_args_allocated) {
            free(config->archive_pipe_args);
            need_alloc = true;
        } else {
            need_alloc = false;
        }
    } else {
        need_alloc = true;
    }
    if (need_alloc) {
        if (!(config->archive_pipe_args = malloc(
                sizeof *config->archive_pipe_args *
                    config->archive_pipe_args_count))) {
            pr_error_with_errno(
                "Failed to allocate memory for archive pipe args");
            config->archive_pipe_args_allocated = 0;
            r = -1;
            goto free_args_buffer;
        }
        config->archive_pipe_args_allocated = config->archive_pipe_args_count;
    }
    unsigned int id = 0;
    unsigned int start = 0;
    arg_parsing = false;
    for (unsigned short i = 0; i < args_length + 1; ++i) {
        if (arg_parsing) {
            if (!args_buffer[i]) {
                arg_parsing = false;
                if (string_buffer_add(
                        &config->string_buffer,
                        args_buffer + start,
                        (config->archive_pipe_args[id].len =
                            i - start))) {
                    pr_error("Failed to add arg to string buffer\n");
                    r = -1;
                    goto free_args_buffer;
                }
                if (++id > config->archive_pipe_args_count) {
                    pr_error("Too many args\n");
                    r = -1;
                    goto free_args_buffer;
                }
            }
        } else {
            if (args_buffer[i]) {
                arg_parsing = true;
                start = i;
                config->archive_pipe_args[id].offset =
                    config->string_buffer.used;
            }
        }
    }
    if (id != config->archive_pipe_args_count) {
        pr_error("Impossible value\n");
        r = -1;
        goto free_args_buffer;
    }
    handle->status = YAMLCONF_PARSING_STATUS_ARCHIVE_SECTION;
    r = 0;
free_args_buffer:
    lazy_alloc_string_free(&string);
    return r;
}

static inline
int yamlconf_parse_archive_pipe_list(
    struct config *const restrict config,
    yaml_event_t const *const restrict event
) {
    struct archive_pipe_arg arg = {
        .offset = config->string_buffer.used,
        .len = event->data.scalar.length
    };
    if (yamlconf_add_string(config, event)) {
        pr_error("Failed to add string\n");
        return -1;
    }
    if (dynamic_array_add_to(config->archive_pipe_args)) {
        pr_error("Failed to add pipe arg to arrary\n");
        return -1;
    }
    *(get_last(config->archive_pipe_args)) = arg;
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

enum wanted_type wanted_type_guess_from_name(
    char const *const restrict name,
    unsigned short len_name
) {
    switch (len_name) {
    case 3:
        if (!strncasecmp(name, "dev", 3)) return WANTED_TYPE_BRANCH;
        break;
    case 4:
        if (!strncmp(name, "HEAD", 4)) return WANTED_TYPE_HEAD;
        else if (!strncasecmp(name, "main", 4)) return WANTED_TYPE_BRANCH;
        break;
    case 6:
        if (!strncasecmp(name, "master", 6)) return WANTED_TYPE_BRANCH;
        break;
    case 8:
        if (!strncasecmp(name, "all_tags", 8)) return WANTED_TYPE_ALL_TAGS;
        break;
    case 12:
        if (!strncasecmp(name, "all_branches", 12))
            return WANTED_TYPE_ALL_BRANCHES;
        break;
    case 40:
        if (object_name_is_sha1(name)) return WANTED_TYPE_COMMIT;
        break;
    default:
        break;
    }
    switch (name[0]) {
    case 'v':
    case 'V':
        switch (name[1]) {
        case '0'...'9':
            return WANTED_TYPE_TAG;
        default:
            break;
        }
        break;
    default:
        break;
    }
    if (!strncmp(name, "refs/", 5)) return WANTED_TYPE_REFERENCE;
    pr_error("Failed to figure out the type of wanted object '%s', "
        "try to set it explicitly e.g. type: branch\n", name);
    return WANTED_TYPE_UNKNOWN;
}

#define YAMLCONF_PARSE_WANTED_LIST_ASSIGN(PREFIX) \
    wanted_objects = &PREFIX##wanted_objects; \
    count = &PREFIX##wanted_objects_count; \
    alloc = &PREFIX##wanted_objects_allocated

static inline
int yamlconf_parse_wanted_list_add_object(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle,
    bool const guess_type
) {
    char const *const name = (char const *)event->data.scalar.value;
    unsigned short const len_name = event->data.scalar.length;
    enum wanted_type type;
    if (guess_type) {
        if (!(type = wanted_type_guess_from_name(name, len_name))) {
            pr_error("Failed to guess type of '%s'\n", name);
            return -1;
        }
    } else {
        type = WANTED_TYPE_UNKNOWN;
    }
    struct wanted_base **wanted_objects = NULL;
    unsigned long *count = NULL, *alloc = NULL;
    switch (handle->wanted_type) {
    case YAMLCONF_WANTED_UNKNOWN:
        pr_error("Wanted type unknown\n");
        return -1;
    case YAMLCONF_WANTED_GLOBAL_EMPTY:
        YAMLCONF_PARSE_WANTED_LIST_ASSIGN(config->empty_);
        break;
    case YAMLCONF_WANTED_GLOBAL_ALWAYS:
        YAMLCONF_PARSE_WANTED_LIST_ASSIGN(config->always_);
        break;
    case YAMLCONF_WANTED_REPO:
        struct repo_config *repo = get_last(config->repos);
        wanted_objects = &repo->wanted_objects;
        count = &repo->wanted_objects_count;
        alloc = &repo->wanted_objects_allocated;
        break;
    }
    if (dynamic_array_add((void **)wanted_objects, sizeof **wanted_objects,
                        count, alloc)) {
        pr_error("Failed to add wanted object to array\n");
        return -1;
    }
    struct wanted_base *wanted_object_last = *wanted_objects + *count - 1;
    wanted_object_last->name_offset = config->string_buffer.used;
    if (string_buffer_add(&config->string_buffer, name, len_name)) {
        pr_error("Failed to add string\n");
        return -1;
    }
    wanted_object_last->len_name = len_name;
    wanted_object_last->archive = false;
    wanted_object_last->checkout = false;
    wanted_object_last->type = type;
    return 0;
}

#define yamlconf_parse_wanted_list(config, event, handle) \
    yamlconf_parse_wanted_list_add_object(config, event, handle, true)

static inline
int yamlconf_parse_wanted_list_end(
    struct yamlconf_parsing_handle *const restrict handle
) {
    switch (handle->wanted_type) {
    case YAMLCONF_WANTED_UNKNOWN:
        pr_error("Current wanted type (global/empty/repo) unknown\n");
        return -1;
    case YAMLCONF_WANTED_GLOBAL_EMPTY:
    case YAMLCONF_WANTED_GLOBAL_ALWAYS:
        handle->status = YAMLCONF_PARSING_STATUS_WANTED_SECTION;
        break;
    case YAMLCONF_WANTED_REPO:
        handle->status = YAMLCONF_PARSING_STATUS_REPO_SECTION;
        break;
    }
    handle->wanted_type = YAMLCONF_WANTED_UNKNOWN;
    return 0;
}

static inline
int yamlconf_parse_wanted_object(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    int r = yamlconf_parse_wanted_list_add_object(
        config, event, handle, false);
    handle->status = YAMLCONF_PARSING_STATUS_WANTED_OBJECT_START;
    return r;
}

static inline
struct wanted_base *yamlconf_get_last_wanted_object(
    struct config *const restrict config,
    enum yamlconf_wanted_type type
) {
    switch (type) {
    case YAMLCONF_WANTED_UNKNOWN:
        pr_error("Wanted type unknown\n");
        return NULL;
    case YAMLCONF_WANTED_GLOBAL_EMPTY:
        return get_last(config->empty_wanted_objects);
    case YAMLCONF_WANTED_GLOBAL_ALWAYS:
        return get_last(config->always_wanted_objects);
    case YAMLCONF_WANTED_REPO:
        struct repo_config const *const restrict repo
            = get_last(config->repos);
        return get_last(repo->wanted_objects);
    }
    return NULL;
}

static inline
int yamlconf_parse_wanted_object_end(
    struct config *const restrict config,
    struct yamlconf_parsing_handle *const restrict handle
) {
    struct wanted_base *const restrict wanted_object =
        yamlconf_get_last_wanted_object(config, handle->wanted_type);
    if (wanted_object == NULL) {
        pr_error("Failed to get last wanted object\n");
        return -1;
    }
    if (!wanted_object->type) {
        if (!(wanted_object->type = wanted_type_guess_from_name(
            config_get_string(wanted_object->name),
            wanted_object->len_name))) {
            pr_error("Failed to guess type\n");
            return -1;
        }
    }
    handle->status = YAMLCONF_PARSING_STATUS_WANTED_LIST;
    return 0;
}

static inline
int yamlconf_parse_wanted_object_section(
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    char const *const key = (char const *)event->data.scalar.value;
    switch (event->data.scalar.length) {
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("type", WANTED_OBJECT_TYPE);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("archive", WANTED_OBJECT_ARCHIVE);
    YAMLCONF_PARSE_SECTION_VALUE_TO_STATUS("checkout", WANTED_OBJECT_CHECKOUT);
    }
    if (handle->status == YAMLCONF_PARSING_STATUS_WANTED_OBJECT_SECTION) {
        pr_error("Unrecognized config key '%s'\n", key);
        return -1;
    }
    return 0;
}

static inline
int yamlconf_parse_wanted_object_type(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    struct wanted_base *restrict wanted_object =
        yamlconf_get_last_wanted_object(config, handle->wanted_type);
    if (wanted_object == NULL) {
        pr_error("Failed to get last wanted object\n");
        return -1;
    }
    char const *const type_string =
        (char const *)event->data.scalar.value;
    wanted_object->type = WANTED_TYPE_UNKNOWN;
    for (enum wanted_type type_cmp = WANTED_TYPE_UNKNOWN;
        type_cmp < WANTED_TYPE_MAX; ++type_cmp) {
        if (!strcasecmp(wanted_type_strings[type_cmp], type_string)) {
            wanted_object->type = type_cmp;
            break;
        }
    }
    switch (wanted_object->type) {
    case WANTED_TYPE_UNKNOWN:
        pr_error("Wanted type still unknown after setting\n");
        return -1;
    case WANTED_TYPE_ALL_BRANCHES:
    case WANTED_TYPE_ALL_TAGS:
    case WANTED_TYPE_HEAD:
        pr_error("Not allowed to manually set type %d ('%s' =~ '%s')\n",
            wanted_object->type,
            wanted_type_strings[wanted_object->type],
            type_string);
        return -1;
    default:
        break;
    }
    handle->status = YAMLCONF_PARSING_STATUS_WANTED_OBJECT_SECTION;
    return 0;
}

static inline
int yamlconf_parse_unsigned_integer(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    unsigned long value = strtoul(
        (char const *)event->data.scalar.value, NULL, 10);
    switch (handle->status) {
    case YAMLCONF_PARSING_STATUS_DAEMON_INTERVAL:
        config->daemon_interval = value;
        break;
    case YAMLCONF_PARSING_STATUS_PROXY_AFTER:
        config->proxy_after = value;
        break;
    case YAMLCONF_PARSING_STATUS_CONNECT_TIMEOUT:
        config->timeout_connect = value;
        break;
    case YAMLCONF_PARSING_STATUS_EXPORT_THREADS:
        config->export_threads = value;
        break;
    case YAMLCONF_PARSING_STATUS_CONNECTIONS_PER_SERVER:
        config->connections_per_server = value;
        break;
    case YAMLCONF_PARSING_STATUS_CLEAN_LINKS_PASS:
        config->clean_links_pass = value;
        break;
    default: goto impossible_status;
    }
    switch (handle->status) {
    case YAMLCONF_PARSING_STATUS_DAEMON_INTERVAL:
    case YAMLCONF_PARSING_STATUS_PROXY_AFTER:
    case YAMLCONF_PARSING_STATUS_CONNECT_TIMEOUT:
    case YAMLCONF_PARSING_STATUS_EXPORT_THREADS:
    case YAMLCONF_PARSING_STATUS_CONNECTIONS_PER_SERVER:
        handle->status = YAMLCONF_PARSING_STATUS_SECTION;
        break;
    case YAMLCONF_PARSING_STATUS_CLEAN_LINKS_PASS:
        handle->status = YAMLCONF_PARSING_STATUS_CLEAN_SECTION;
        break;
    default: goto impossible_status;
    }
    return 0;
impossible_status:
    pr_error("Impossible status %d (%s)\n", handle->status,
        yamlconf_parsing_status_strings[handle->status]);
    return -1;
}

int repo_common_init_from_url(
    struct repo_common *const restrict repo,
    struct string_buffer *const restrict sbuffer,
    char const *restrict url,
    unsigned short len_url
) {
    // Drop trailing slashes
    while (len_url && url[len_url - 1] == '/') {
        --len_url;
    }
#ifndef TREAT_DOTGIT_AS_DIFFERENT_REPO
    // Drop trailing .git
    if (len_url >= 4 && !strncmp(url + len_url - 4, ".git", 4)) {
        len_url -= 4;
    }
#endif
    if (!len_url) {
        pr_error("URL is empty\n");
        return -1;
    }
    repo->url_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, url, repo->len_url = len_url)) {
        pr_error("Failed to add URL to string buffer\n");
        return -1;
    }
    if ((snprintf(repo->hash_url_string,
                  HASH_STRING_LEN + 1,
                  HASH_FORMAT,
                  repo->hash_url = hash_calculate(url, len_url)
                  ) != HASH_STRING_LEN)) {
        pr_error_with_errno("Failed to format hash string");
        return -1;
    }
    for (unsigned short i = 0; i < len_url - 2; ++i) {
        if (!strncmp(url + i, "://", 3)) {
            unsigned short const offset = i + 3;
            if (offset == len_url) {
                pr_error("Illegal URL '%s': ending with scheme\n",
                    url);
                return -1;
            }
            url += offset;
            len_url -= offset;
            break;
        }
    }
    // Drop leading slashes
    while (*url == '/') {
        ++url;
        --len_url;
    }
    // The above logic should change url_simple to like the following:
    // https://github.com/xxx/yyy.git -> github.com/xxx/yyy
    // file:///what/ever.git/ -> what/ever

    // Long name always ends with .git
        // (mainly used for local path)
    // Short name always ends without .git
        // (mainly used for gh-like archive prefix)
#ifdef TREAT_DOTGIT_AS_DIFFERENT_REPO
    if (len_url < 0x100) {
        long_name = long_name_stack;
    } else {
        if (!(long_name_heap = malloc(len_url + 1))) {
            pr_error("Failed to allocate memory for long name\n");
            return -1;
        }
        long_name = long_name_heap;
    }
    long_name[0] = '\0';
#else
    struct lazy_alloc_string long_name;
    lazy_alloc_string_init(&long_name);
    if (lazy_alloc_string_setlen_discard(&long_name, len_url + 4)) {
        pr_error("Failed to prepare long name buffer\n");
        return -1;
    }
#endif
    repo->len_long_name = 0;
    repo->depth_long_name = 1; // depth always starts from 1
    repo->hash_domain = 0;
    bool has_domain = false;
    unsigned short short_name_offset = 0;
    int r;
    for (unsigned short i = 0; i < len_url; ++i) {
        if (url[i] == '/') {
            if (repo->depth_long_name == 1) {
                // Only record hash, won't access string later
                repo->hash_domain = hash_calculate(url,
                                                   repo->len_long_name);
                has_domain = true;
            }
            // Skip all continous leading /
            for (; url[i + 1] =='/' && i < len_url; ++i);
            // When the above loop ends, we're at the last /
            // of potentially a list of /
            // In case url is like a/b/c/, ending with /,
            // we don't want to copy the ending /
            if (i >= len_url - 1) break;
            ++repo->depth_long_name;
            short_name_offset = i + 1;
        }
        long_name.string[repo->len_long_name++] = url[i];
    }
    if (!has_domain) {
        pr_error("Url '%s' does not have domain\n",
                    sbuffer->buffer + repo->url_offset);
        r = -1;
        goto free_long_name;
    }
    if (!repo->len_long_name) {
        pr_error("Long name for url '%s' is empty\n",
                    sbuffer->buffer + repo->url_offset);
        r = -1;
        goto free_long_name;
    }
#ifndef TREAT_DOTGIT_AS_DIFFERENT_REPO
    memcpy(long_name.string + repo->len_long_name, ".git", 4);
    repo->len_long_name += 4;
#endif
    repo->long_name_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, long_name.string, repo->len_long_name)) {
        long_name.string[repo->len_long_name] = '\0';
        pr_error("Failed to add long name '%s' to string buffer\n",
                    long_name.string);
        r = -1;
        goto free_long_name;
    }
    repo->hash_long_name = hash_calculate(long_name.string,repo->len_long_name);


    // user/repo.git
    //      ^~~ short_name_offset is here, len_url is 13, offset 5, len 8
    // user/.git
    //      ^~~ the extreme case, len_url is 9, offset is 5, diff is 4
    if ((repo->len_short_name = len_url - short_name_offset) >= 4 &&
        !strncmp(".git", url + len_url - 4, 4))
    {
        repo->len_short_name -= 4;
    }
    if (!repo->len_short_name) {
        pr_error("Short name for repo '%s' is empty\n",
                    sbuffer->buffer + repo->url_offset);
        r = -1;
        goto free_long_name;
    }
    char const *const short_name = url + short_name_offset;
    repo->short_name_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, short_name, repo->len_short_name)) {
        pr_error("Failed to add short name '%s' to string buffer\n",
                url + short_name_offset);
        r = -1;
        goto free_long_name;
    }
    repo->hash_short_name = hash_calculate(short_name, repo->len_short_name);
    r = 0;
free_long_name:
    lazy_alloc_string_free(&long_name);
    return r;
}

static inline
int repo_config_init_from_url(
    struct repo_config *const restrict repo,
    struct string_buffer *const restrict sbuffer,
    char const *const restrict url,
    unsigned short len_url
) {
    repo->wanted_objects = NULL;
    repo->wanted_objects_allocated = 0;
    repo->wanted_objects_count = 0;
    return repo_common_init_from_url(
        &repo->common, sbuffer, url, len_url);
}

static inline
int yamlconf_parse_repos_list_add(
    struct config *const restrict config,
    yaml_event_t const *const restrict event
) {
    char const *const restrict url = (char const *)event->data.scalar.value;
    unsigned short const len_url = event->data.scalar.length;
    struct repo_config repo;
    if (repo_config_init_from_url(
            &repo, &config->string_buffer, url, len_url)) {
        pr_error("Failed to init repo\n");
        return -1;
    }
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo_config const *const restrict repo_cmp =
            config->repos + i;
        if (repo_cmp->hash_url == repo.hash_url) {
            pr_error("Repo '%s' already defined\n",
                config_get_string(repo.url));
            return -1;
        }
        if (repo_cmp->hash_long_name == repo.hash_long_name) {
            pr_warn("Repo '%s' has the same long name '%s' as repo '%s'\n",
                config_get_string(repo.url),
                config_get_string(repo.long_name),
                config_get_string(repo_cmp->url));
        }
        if (repo_cmp->hash_long_name == repo.hash_long_name) {
            pr_warn("Repo '%s' has the same short name '%s' as repo '%s'\n",
                config_get_string(repo.url),
                config_get_string(repo.short_name),
                config_get_string(repo_cmp->url));
        }
    }
    if (dynamic_array_add_to(config->repos)) {
        pr_error("Failed to add repo\n");
        return -1;
    }
    *(get_last(config->repos)) = repo;
    return 0;
}

static inline
int yamlconf_parse_repo_url(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    int r = yamlconf_parse_repos_list_add(config, event);
    handle->status = YAMLCONF_PARSING_STATUS_REPO_AFTER_URL;
    return r;
}

static inline
int yamlconf_parse_repo_section(
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    char const *const key = (char const *)event->data.scalar.value;
    switch (event->data.scalar.length) {
    case 6:
        if (!strncmp(key, "wanted", 6)) {
            handle->status = YAMLCONF_PARSING_STATUS_WANTED_SECTION_START;
            handle->wanted_type = YAMLCONF_WANTED_REPO;
        }
        break;
    }
    if (handle->status == YAMLCONF_PARSING_STATUS_REPO_SECTION) {
        pr_error("Unrecognized config key '%s'\n", key);
        return -1;
    }
    return 0;
}

// 0 for false, 1 for true, -1 for error parsing
static inline
int bool_from_string(
    char const *const restrict string
) {
    if (string == NULL || string[0] == '\0') {
        return -1;
    }
    if (strcasecmp(string, "yes") &&
        strcasecmp(string, "true") &&
        strcasecmp(string, "enabled"));
    else {
        return 1;
    }
    if (strcasecmp(string, "no") &&
        strcasecmp(string, "false") &&
        strcasecmp(string, "disabled"));
    else {
        return 0;
    }
    return -1;
}

static inline
int yamlconf_parse_boolean(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    int bool_value = bool_from_string(
        (char const *)event->data.scalar.value);
    if (bool_value < 0) {
        pr_error("Failed to parse '%s' into a bool value\n",
            (char const *)event->data.scalar.value);
        return -1;
    }
    switch (handle->status) {
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_ARCHIVE:
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_CHECKOUT: {
        struct wanted_base *restrict wanted_object =
            yamlconf_get_last_wanted_object(config, handle->wanted_type);
        if (wanted_object == NULL) {
            pr_error("Failed to find wanted object\n");
            return -1;
        }
        switch (handle->status) {
        case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_ARCHIVE:
            wanted_object->archive = bool_value;
            break;
        case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_CHECKOUT:
            wanted_object->checkout = bool_value;
            break;
        default: goto impossible_status;
        }
        break;
    }
    case YAMLCONF_PARSING_STATUS_DAEMON:
        config->daemon = bool_value;
        break;
    case YAMLCONF_PARSING_STATUS_CLEAN_REPOS:
        config->clean_repos = bool_value;
        break;
    case YAMLCONF_PARSING_STATUS_CLEAN_ARCHIVES:
        config->clean_archives = bool_value;
        break;
    case YAMLCONF_PARSING_STATUS_CLEAN_CHECKOUTS:
        config->clean_checkouts = bool_value;
        break;
    case YAMLCONF_PARSING_STATUS_ARCHIVE_GHPREFIX:
        config->archive_gh_prefix = bool_value;
        break;
    default: goto impossible_status;
    }
    switch (handle->status) {
    case YAMLCONF_PARSING_STATUS_DAEMON:
        handle->status =
            YAMLCONF_PARSING_STATUS_SECTION;
        break;
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_ARCHIVE:
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_CHECKOUT:
        handle->status =
            YAMLCONF_PARSING_STATUS_WANTED_OBJECT_SECTION;
        break;
    case YAMLCONF_PARSING_STATUS_CLEAN_REPOS:
    case YAMLCONF_PARSING_STATUS_CLEAN_ARCHIVES:
    case YAMLCONF_PARSING_STATUS_CLEAN_CHECKOUTS:
        handle->status =
            YAMLCONF_PARSING_STATUS_CLEAN_SECTION;
        break;
    case YAMLCONF_PARSING_STATUS_ARCHIVE_GHPREFIX:
        handle->status = YAMLCONF_PARSING_STATUS_ARCHIVE_SECTION;
        break;
    default: goto impossible_status;
    }
    return 0;
impossible_status:
    pr_error("Impossible status %d (%s)\n", handle->status,
        yamlconf_parsing_status_strings[handle->status]);
    return -1;
}

#define YAMLCONF_EVENT_TO_STATUS(EVENT_NAME, STATUS_NAME) \
    case YAML_##EVENT_NAME##_EVENT:\
        handle->status = YAMLCONF_PARSING_STATUS_##STATUS_NAME; \
        return 0

int config_update_from_yaml_event(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    struct yamlconf_parsing_handle *const restrict handle
) {
    switch (handle->status) {
    case YAMLCONF_PARSING_STATUS_NONE:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(STREAM_START, STREAM);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_STREAM:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(DOCUMENT_START, DOCUMENT);
        YAMLCONF_EVENT_TO_STATUS(STREAM_END, NONE);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_DOCUMENT:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(MAPPING_START, SECTION);
        YAMLCONF_EVENT_TO_STATUS(DOCUMENT_END, STREAM);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_section(event, handle);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_END, DOCUMENT);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_PROXY:
    case YAMLCONF_PARSING_STATUS_DIR_REPOS:
    case YAMLCONF_PARSING_STATUS_DIR_ARCHIVES:
    case YAMLCONF_PARSING_STATUS_DIR_CHECKOUTS:
    case YAMLCONF_PARSING_STATUS_ARCHIVE_SUFFIX:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_string(config, event, handle);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_ARCHIVE:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(MAPPING_START, ARCHIVE_SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_ARCHIVE_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_archive_section(event, handle);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_END, SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_ARCHIVE_PIPE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_archive_pipe(config, event, handle);
        case YAML_SEQUENCE_START_EVENT:
            config->archive_pipe_args_count = 0;
            handle->status = YAMLCONF_PARSING_STATUS_ARCHIVE_PIPE_LIST;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_ARCHIVE_PIPE_LIST:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_archive_pipe_list(config, event);
        YAMLCONF_EVENT_TO_STATUS(SEQUENCE_END, ARCHIVE_SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_CLEAN:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(MAPPING_START, CLEAN_SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_CLEAN_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_clean_section(event, handle);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_END, SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_WANTED:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(MAPPING_START, WANTED_SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_WANTED_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_wanted_section(event, handle);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_END, SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_WANTED_SECTION_START:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(SEQUENCE_START, WANTED_LIST);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_WANTED_LIST:
        switch (event->type) {
        case YAML_SCALAR_EVENT: // Simple wanted object with only name
            return yamlconf_parse_wanted_list(config, event, handle);
        case YAML_SEQUENCE_END_EVENT:
            return yamlconf_parse_wanted_list_end(handle);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_START, WANTED_OBJECT);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT:
        switch (event->type) {
        case YAML_SCALAR_EVENT: // Complex wanted object
            return yamlconf_parse_wanted_object(config, event, handle);
        case YAML_MAPPING_END_EVENT:
            return yamlconf_parse_wanted_object_end(config, handle);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_START:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(MAPPING_START, WANTED_OBJECT_SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_wanted_object_section(event, handle);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_END, WANTED_OBJECT);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_TYPE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_wanted_object_type(config, event, handle);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_DAEMON_INTERVAL:
    case YAMLCONF_PARSING_STATUS_PROXY_AFTER:
    case YAMLCONF_PARSING_STATUS_CONNECT_TIMEOUT:
    case YAMLCONF_PARSING_STATUS_EXPORT_THREADS:
    case YAMLCONF_PARSING_STATUS_CONNECTIONS_PER_SERVER:
    case YAMLCONF_PARSING_STATUS_CLEAN_LINKS_PASS:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_unsigned_integer(config, event, handle);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_REPOS:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(SEQUENCE_START, REPOS_LIST);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_REPOS_LIST:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_repos_list_add(config, event);
        YAMLCONF_EVENT_TO_STATUS(SEQUENCE_END, SECTION);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_START, REPO_URL);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_REPO_URL:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_repo_url(config, event, handle);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_END, REPOS_LIST);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_REPO_AFTER_URL:
        switch (event->type) {
        YAMLCONF_EVENT_TO_STATUS(MAPPING_START, REPO_SECTION);
        default: goto unexpected_event_type;
        }
        break;
    case YAMLCONF_PARSING_STATUS_REPO_SECTION:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_repo_section(event, handle);
        YAMLCONF_EVENT_TO_STATUS(MAPPING_END, REPO_URL);
        default: goto unexpected_event_type;
        }
        break;
    // Boolean common
    case YAMLCONF_PARSING_STATUS_DAEMON:
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_ARCHIVE:
    case YAMLCONF_PARSING_STATUS_WANTED_OBJECT_CHECKOUT:
    case YAMLCONF_PARSING_STATUS_CLEAN_REPOS:
    case YAMLCONF_PARSING_STATUS_CLEAN_ARCHIVES:
    case YAMLCONF_PARSING_STATUS_CLEAN_CHECKOUTS:
    case YAMLCONF_PARSING_STATUS_ARCHIVE_GHPREFIX:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            return yamlconf_parse_boolean(config, event, handle);
        default: goto unexpected_event_type;
        }
        break;
    }
    return 0;
unexpected_event_type:
    pr_error(
        "Unexpected YAML event type %d (%s) for current status %d (%s)\n",
        event->type, yamlconf_event_type_strings[event->type],
        handle->status, yamlconf_parsing_status_strings[handle->status]);
    return -1;
}

int config_from_yaml(
    struct config *const restrict config,
    unsigned char const *const restrict buffer,
    size_t size
){
    yaml_parser_t parser;
    yaml_event_t event;
    yaml_event_type_t event_type;

    struct yamlconf_parsing_handle handle = {0};
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, buffer, size);
    int r = -1;

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            pr_error("Failed to parse: %s\n", parser.problem);
            goto delete_parser;
        }
        if (config_update_from_yaml_event(
            config, &event, &handle)) {
            pr_error("Failed to update config from yaml event"
#ifdef DEBUGGING
            ", current read config:\n");
            config_print(config);
#else
            "\n");
#endif
            goto delete_parser;
        }
        event_type = event.type;
        yaml_event_delete(&event);
    } while (event_type != YAML_STREAM_END_EVENT);

    if (handle.status != YAMLCONF_PARSING_STATUS_NONE ||
        handle.wanted_type != YAMLCONF_WANTED_UNKNOWN) {
        pr_error("Config parsing unclean\n");
        goto delete_parser;
    }

    r = 0;
delete_parser:
    yaml_parser_delete(&parser);
    return r;
}


int repo_config_finish(
    struct repo_config *const restrict repo,
    struct config *const restrict config
) {
    if (!repo->wanted_objects_count &&
        config->empty_wanted_objects_count
    ) {
        pr_info("Repo '%s' does not have wanted objects defined, adding global "
                "wanted objects (when empty) to it as wanted\n",
                config_get_string(repo->url));
        if (repo->wanted_objects) {
            pr_warn("Wanted objects already allocated? "
                    "This should not happen\n");
            free(repo->wanted_objects);
        }
        size_t const size =
            sizeof *repo->wanted_objects * config->empty_wanted_objects_count;
        if (!(repo->wanted_objects = malloc(size))) {
            pr_error("Failed to allocate memory\n");
            return -1;
        }
        memcpy(repo->wanted_objects, config->empty_wanted_objects, size);
        repo->wanted_objects_count = config->empty_wanted_objects_count;
        repo->wanted_objects_allocated = config->empty_wanted_objects_count;
    }
    if (config->always_wanted_objects_count) {
        pr_info("Add always wanted objects to repo '%s'\n",
                    config_get_string(repo->url));
        unsigned long const new_wanted_objects_count =
            repo->wanted_objects_count + config->always_wanted_objects_count;
        if (new_wanted_objects_count > repo->wanted_objects_allocated) {
            struct wanted_base *wanted_objects_new =
                realloc(repo->wanted_objects,
                    sizeof *wanted_objects_new * new_wanted_objects_count);
            if (wanted_objects_new == NULL) {
                pr_error("Failed to allocate more memory\n");
                return -1;
            }
            repo->wanted_objects = wanted_objects_new;
            repo->wanted_objects_allocated = new_wanted_objects_count;
        }
        memcpy(repo->wanted_objects + repo->wanted_objects_count,
                config->always_wanted_objects,
                sizeof *repo->wanted_objects *
                    config->always_wanted_objects_count);
        repo->wanted_objects_count = new_wanted_objects_count;
    }
    return 0;
}

#define config_set_default_dir(LOWERNAME, UPPERNAME) \
    if (!config->len_dir_##LOWERNAME##s) { \
        config->dir_##LOWERNAME##s_offset = config->string_buffer.used; \
        if (string_buffer_add(&config->string_buffer, \
            DIR_##UPPERNAME##S_DEFAULT, \
            config->len_dir_##LOWERNAME##s = \
                sizeof DIR_##UPPERNAME##S_DEFAULT - 1) \
        ) { \
            pr_error("Failed to set default dir for "#LOWERNAME"s\n"); \
            return -1; \
        } \
    }

int config_finish(
    struct config *const restrict config
) {
    config_set_default_dir(repo, REPO);
    config_set_default_dir(archive, ARCHIVE);
    config_set_default_dir(checkout, CHECKOUT);
    if (!config->archive_suffix_offset) {
        config->archive_suffix_offset = config->string_buffer.used;
        if (string_buffer_add(&config->string_buffer, ARCHIVE_SUFFIX_DEFAULT, 
            config->len_archive_suffix = (sizeof ARCHIVE_SUFFIX_DEFAULT - 1))) 
        {
            pr_error("Failed to add default archive suffix to config\n");
            return -1;
        }
    }
    if (!config->len_proxy_url && config->proxy_after) {
        pr_warn(
            "You've set proxy_after but not set proxy, "
            "fixing proxy_after to 0\n");
        config->proxy_after = 0;
    }
    if (config->empty_wanted_objects == NULL) {
        pr_warn("Global wanted objects (when empty) not defined, adding 'HEAD' "
            "as default\n");
        if ((config->empty_wanted_objects =
            malloc(sizeof *config->empty_wanted_objects)) == NULL) {
            pr_error(
                "Failed to allocate memory for global wanted objects "
                "(when empty)\n");
            return -1;
        }
        config->empty_wanted_objects_count = 1;
        config->empty_wanted_objects_allocated = 1;
        *config->empty_wanted_objects = WANTED_BASE_HEAD_INIT;
    }
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (repo_config_finish(
            config->repos + i, config)) {
            pr_error("Failed to finish repo\n");
            return -1;
        }
    }
    return 0;
}

static inline
int repo_config_partial_free(
    struct repo_config *const restrict repo
) {
    return dynamic_array_partial_free_to(repo->wanted_objects);
}

// Free the parts not needed anymore
static inline
int config_partial_free(
    struct config *const restrict config
) {
    if (config->repos) {
        for (unsigned long i = 0; i < config->repos_count; ++i) {
            if (repo_config_partial_free(config->repos + i)) {
                pr_error("Failed to release memory used by repo\n");
                return -1;
            }
        }
        if (dynamic_array_partial_free_to(config->repos)) {
            pr_error("Failed to release memory used by repos\n");
            return -1;
        }
    }
    if (dynamic_array_partial_free_to(config->always_wanted_objects)) {
        pr_error("Failed to relaese memory used by always wanted objects\n");
        return -1;
    }
    if (dynamic_array_partial_free_to(config->empty_wanted_objects)) {
        pr_error("Failed to relaese memory used by empty wanted objects\n");
        return -1;
    }
    if (dynamic_array_partial_free_to(config->archive_pipe_args)) {
        pr_error("Failed to relaese memory used by archive pipe args\n");
        return -1;
    }
    if (string_buffer_partial_free(&config->string_buffer)) {
        pr_error("Failed to release memory used by string buffer\n");
        return -1;
    }
    return 0;
}

int config_read(
    struct config *const restrict config,
    char const *const restrict config_path
) {
    int config_fd = STDIN_FILENO;
    if (config_path && strcmp(config_path, "-")) {
        pr_info("Using '%s' as config file\n", config_path);
        if ((config_fd = open(config_path, O_RDONLY | O_CLOEXEC)) < 0) {
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
    size_t config_size = buffer_read_from_fd(&config_buffer, config_fd);
    int r = -1;
    if (config_size == (size_t)-1) {
        pr_error("Failed to read config into buffer\n");
        goto close_config_fd;
    }
    *config = CONFIG_INIT;
    if (config_from_yaml(config, config_buffer, config_size)) {
        pr_error("Failed to read config from YAML\n");
        goto free_config_buffer;
    }
    if (config_finish(config)) {
        pr_error("Failed to finish config\n");
        goto free_config_buffer;
    }
    if (config_partial_free(config)) {
        pr_error("Failed to free memory allocated but not used by config\n");
        goto free_config_buffer;
    }
    r = 0;
free_config_buffer:
    free_if_allocated(config_buffer);
close_config_fd:
    if (config_fd != STDIN_FILENO) close (config_fd);
    return r;
}

void config_free(
    struct config *const restrict config
) {
    free_if_allocated(config->string_buffer.buffer);
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        free_if_allocated(config->repos[i].wanted_objects);
    }
    free_if_allocated(config->repos);
    free_if_allocated(config->empty_wanted_objects);
    free_if_allocated(config->always_wanted_objects);
    free_if_allocated(config->archive_pipe_args);
    *config = CONFIG_INIT;
}


void config_print_repo_wanted(
    struct config const *const restrict config,
    struct repo_config const *const restrict repo
) {
    for (unsigned long i = 0; i < repo->wanted_objects_count; ++i) {
        struct wanted_base const *const restrict wanted_object
            = repo->wanted_objects + i;
        printf(
            "|        - %s:\n"
            "|            type: %d (%s)\n"
            "|            archive: %s\n"
            "|            checkout: %s\n",
            wanted_object->len_name ?
                config_get_string(wanted_object->name) : "(unnamed)",
            wanted_object->type,
            wanted_type_strings[wanted_object->type],
            wanted_object->archive ? "yes" : "no",
            wanted_object->checkout ? "yes" : "no"
        );
    }
}

void config_print_repo(
    struct config const *const restrict config,
    struct repo_config const *const restrict repo
) {
    printf(
        "|  - %s:\n"
        "|      hash: %016lx\n"
        "|      long_name: %s (depth %hu)\n"
        "|      short_name: %s\n"
        "|      domain: %016lx\n",
        config_get_string(repo->url),
        repo->hash_url,
        config_get_string(repo->long_name),
        repo->depth_long_name,
        config_get_string(repo->short_name),
        repo->hash_domain);
    if (repo->wanted_objects_count) {
        printf(
        "|      wanted (%lu):\n",
            repo->wanted_objects_count);
        config_print_repo_wanted(config, repo);
    }
}

void config_print(
    struct config const *const restrict config
) {
    printf(
        "| proxy: %s\n"
        "| proxy_after: %hu\n"
        "| dir_repos: %s\n"
        "| dir_archives: %s\n"
        "| dir_checkouts: %s\n",
        config_get_string(config->proxy_url),
        config->proxy_after,
        config_get_string(config->dir_repos),
        config_get_string(config->dir_archives),
        config_get_string(config->dir_checkouts));
    if (config->repos_count) {
        printf("| repos (%lu): \n", config->repos_count);
        for (unsigned long i = 0; i < config->repos_count; ++i) {
            config_print_repo(config, config->repos + i);
        }
    }
}

static inline
int mkdir_allow_existing(
    char *const restrict path
) {
    if (mkdir(path, 0755)) {
        if (errno == EEXIST) {
            struct stat stat_buffer;
            if (lstat(path, &stat_buffer)) {
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

static inline
int mkdir_allow_existing_at(
    int const dir_fd,
    char *const restrict path
) {
    if (mkdirat(dir_fd, path, 0755)) {
        if (errno == EEXIST) {
            struct stat stat_buffer;
            if (fstatat(dir_fd, path, &stat_buffer, AT_SYMLINK_NOFOLLOW)) {
                pr_error_with_errno("Failed to stat '%s' at %d", path, dir_fd);
                return -1;
            }
            if ((stat_buffer.st_mode & S_IFMT) == S_IFDIR) {
                return 0;
            } else {
                pr_error("Exisitng '%s' at %d is not a folder\n", path, dir_fd);
                return -1;
            }
        } else {
            pr_error_with_errno("Failed to mkdir '%s' at %d", path, dir_fd);
            return -1;
        }
    }
    return 0;
}

int mkdir_recursively(
    char const *const restrict path,
    unsigned short const len_path
) {
    if (path && len_path);
    else {
        pr_error("Internal: caller passed NULL pointer or 0-length path\n");
        return -1;
    }
    struct lazy_alloc_string path_buffer;
    if (lazy_alloc_string_init_with(&path_buffer, path, len_path)) {
        pr_error("Failed to prepare path buffer\n");
        return -1;
    }
    unsigned short from_left = 0;
    int r;
    /* Go from right to reduce mkdir calls */
    /* In the worst case this takes double the time than from left */
    /* but in the most cases parents should exist and this should */
    /* skip redundant mkdir syscalls */
    for (unsigned short i = len_path; i; --i) {
        bool revert_slash = false;
        switch (path_buffer.string[i]) {
        case '/':
            path_buffer.string[i] = '\0';
            revert_slash = true;
            __attribute__((fallthrough));
        case '\0':
            r = mkdir_allow_existing(path_buffer.string);
            if (revert_slash) path_buffer.string[i] = '/';
            if (!r) {
                if (!revert_slash) return 0;
                from_left = i + 1;
                goto from_left;
            }
            break;
        }
    }
from_left:
    for (unsigned short i = from_left; i < len_path + 1; ++i) {
        bool revert_slash = false;
        switch (path_buffer.string[i]) {
        case '/':
            path_buffer.string[i] = '\0';
            revert_slash = true;
            __attribute__((fallthrough));
        case '\0':
            r = mkdir_allow_existing(path_buffer.string);
            if (revert_slash) path_buffer.string[i] = '/';
            if (r) {
                pr_error("Failed to mkdir '%s'\n", path_buffer.string);
                r = -1;
                goto free_path_buffer;
            }
            break;
        }
    }
    r = 0;
free_path_buffer:
    lazy_alloc_string_free(&path_buffer);
    return r;
}

int mkdir_recursively_at(
    int const dir_fd,
    char const *const restrict path,
    unsigned short const len_path
) {
    if (path && len_path && dir_fd >= 0);
    else {
        pr_error("Internal: caller passed NULL pointer or 0-length path\n");
        return -1;
    }
    struct lazy_alloc_string path_buffer;
    if (lazy_alloc_string_init_with(&path_buffer, path, len_path)) {
        pr_error("Failed to prepare path buffer\n");
        return -1;
    }
    unsigned short from_left = 0;
    int r;
    /* Go from right to reduce mkdir calls */
    /* In the worst case this takes double the time than from left */
    /* but in the most cases parents should exist and this should */
    /* skip redundant mkdir syscalls */
    for (unsigned short i = len_path; i; --i) {
        bool revert_slash = false;
        switch (path_buffer.string[i]) {
        case '/':
            path_buffer.string[i] = '\0';
            revert_slash = true;
            __attribute__((fallthrough));
        case '\0':
            r = mkdir_allow_existing_at(dir_fd, path_buffer.string);
            if (revert_slash) path_buffer.string[i] = '/';
            if (!r) {
                if (!revert_slash) return 0;
                from_left = i + 1;
                goto from_left;
            }
            break;
        }
    }
from_left:
    for (unsigned short i = from_left; i < len_path + 1; ++i) {
        bool revert_slash = false;
        switch (path_buffer.string[i]) {
        case '/':
            path_buffer.string[i] = '\0';
            revert_slash = true;
            __attribute__((fallthrough));
        case '\0':
            r = mkdir_allow_existing_at(dir_fd, path_buffer.string);
            if (revert_slash) path_buffer.string[i] = '/';
            if (r) {
                pr_error("Failed to mkdir '%s'\n", path_buffer.string);
                r = -1;
                goto free_path_buffer;
            }
            break;
        }
    }
    r = 0;
free_path_buffer:
    lazy_alloc_string_free(&path_buffer);
    return r;
}

int open_or_create_dir_recursively(
    char const *const restrict path,
    unsigned short const len_path
) {
    int dir_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        switch (errno) {
        case ENOENT:
            if (mkdir_recursively(path, len_path)) {
                pr_error("Failed to create folder '%s'\n", path);
                return -1;
            }
            if ((dir_fd =
                open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
                pr_error_with_errno("Still failed to open '%s' as directory",
                                    path);
                return -1;
            }
            break;
        default:
            pr_error_with_errno("Failed to open '%s' as directory", path);
            return -1;
        }
    }
    return dir_fd;
}

int open_or_create_dir_recursively_at(
    int const atfd,
    char const *const restrict path,
    unsigned short const len_path
) {
    int dir_fd = openat(atfd, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        switch (errno) {
        case ENOENT:
            if (mkdir_recursively_at(atfd, path, len_path)) {
                pr_error("Failed to create folder '%s'\n", path);
                return -1;
            }
            if ((dir_fd =
                openat(atfd, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
                pr_error_with_errno("Still failed to open '%s' as directory",
                                    path);
                return -1;
            }
            break;
        default:
            pr_error_with_errno("Failed to open '%s' as directory", path);
            return -1;
        }
    }
    return dir_fd;
}

int open_or_create_subdir(
    int const atfd,
    char const *const restrict path
) {
    int fd = openat(atfd, path,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        switch (errno) {
        case ENOENT:
            if (mkdirat(atfd, path, 0755) < 0) {
                pr_error_with_errno(
                    "Failed to create links subdir under '%s'", path);
                return -1;
            }
            if ((fd = openat(atfd, path,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
                pr_error_with_errno(
                    "Failed to open links subdir under '%s' as directory after "
                    "creating it", path);
                return -1;
            }
            break;
        default:
            pr_error_with_errno(
                "Failed to open links subdir under '%s' as directory", path);
            return -1;
        }
    }
    return fd;
}

int work_directory_init_from_path(
    struct work_directory *const restrict workdir,
    struct string_buffer *const restrict sbuffer,
    char const *const restrict path,
    unsigned short const len_path
) {
    workdir->path_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, path, len_path)) {
        pr_error("Failed to add path '%s' to string buffer\n", path);
        return -1;
    }
    workdir->len_path = len_path;

    int dir_fd = open_or_create_dir_recursively(path, len_path);
    if (dir_fd < 0) {
        pr_error("Failed to create work dir '%s' recursively\n", path);
        return -1;
    }
    if ((workdir->datafd = open_or_create_subdir(dir_fd, DIR_DATA)) < 0) {
        pr_error("Failed to open data subdir for '%s'\n", path);
        goto close_dirfd;
    }
    if ((workdir->linkfd = open_or_create_subdir(dir_fd, DIR_LINKS)) < 0) {
        pr_error("Failed to open link subdir for '%s'\n", path);
        goto close_datafd;
    }
    if (close(dir_fd)) {
        pr_error("Failed to close workdir fd when finishing '%s'\n", path);
        goto close_linkfd;
    }
    workdir->keeps = NULL;
    workdir->keeps_allocated = 0;
    workdir->keeps_count = 0;
    return 0;
close_linkfd:
    if (close(workdir->linkfd))
        pr_error_with_errno("Failed to close links fd for work directory");
close_datafd:
    if (close(workdir->datafd))
        pr_error_with_errno("Failed to close data fd for work directory");
close_dirfd:
    if (close(dir_fd))
        pr_error_with_errno("Failed to close dir fd for work directory");
    return -1;
}

static inline
void work_directory_free(
    struct work_directory *const restrict workdir
) {
    if (workdir->datafd > 0) {
        if (close(workdir->datafd)) {
            pr_error_with_errno("Failed to close data dirfd for workdir");
        }
        workdir->datafd = -1;
    }
    if (workdir->linkfd > 0) {
        if (close(workdir->linkfd)) {
            pr_error_with_errno("Failed to close links dirfd for workdir");
        }
        workdir->linkfd = -1;
    }
    free_if_allocated_to_null(workdir->keeps);
}

#define work_directory_init_from_handle(NAME) \
    work_directory_init_from_path( \
        &work_handle->dir_##NAME##s,  \
        &work_handle->string_buffer, \
        work_handle_get_string(work_handle->dir_##NAME##s), \
        work_handle->len_dir_##NAME##s)

static inline
int work_handle_work_directories_init(
    struct work_handle *const restrict work_handle
) {
    if (work_handle->clean_repos ||
        work_handle->clean_archives ||
        work_handle->clean_checkouts)
    {
        if (string_buffer_add(
                &work_handle->string_buffer,
                DIR_LINKS,
                sizeof DIR_LINKS - 1))
        {
            pr_error("Failed to add links to string buffer\n");
            return -1;
        }
    }
    if (work_directory_init_from_handle(repo)) {
        pr_error("Failed to open work directory '%s' for repos\n",
            work_handle_get_string(work_handle->dir_repos));
        return -1;
    }
    if (work_directory_init_from_handle(archive)) {
        pr_error("Failed to open work directory '%s' for archives\n",
                work_handle_get_string(work_handle->dir_archives));
        goto free_workdir_repos;
    }
    if (work_directory_init_from_handle(checkout)) {
        pr_error("Failed to open work directory '%s' for checkouts\n",
                work_handle_get_string(work_handle->dir_checkouts));
        goto free_workdir_archives;
    }
    return 0;
free_workdir_archives:
    work_directory_free(&work_handle->dir_archives);
free_workdir_repos:
    work_directory_free(&work_handle->dir_repos);
    return -1;
}


static inline
void work_handle_work_directories_free(
    struct work_handle *const restrict work_handle
) {
    work_directory_free(&work_handle->dir_repos);
    work_directory_free(&work_handle->dir_archives);
    work_directory_free(&work_handle->dir_checkouts);
}

static inline
int format_oid_to_string_buffer(
    git_oid const *const restrict oid,
    struct string_buffer *const restrict sbuffer
) {
    char oid_hex[GIT_OID_HEXSZ];
    if (git_oid_fmt(oid_hex, oid)) {
        pr_error("Failed to format git oid hex string\n");
        return -1;
    }
    if (string_buffer_add(sbuffer, oid_hex, GIT_OID_HEXSZ)) {
        pr_error("Failed to add git oid hex string to buffer\n");
        return -1;
    }
    return 0;
}

static inline
int wanted_object_complete_from_base(
    struct wanted_object *const restrict wanted_object,
    struct string_buffer *const restrict sbuffer
) {
    char const *const restrict name =
        buffer_get_string(sbuffer, wanted_object->name);
    if (!wanted_object->type &&
        !(wanted_object->type =
            wanted_type_guess_from_name(
                name, wanted_object->len_name))) {
        pr_error("Failed to guess type of wanted object\n");
        return -1;
    }
    wanted_object->commit_parsed = false;
    wanted_object->parsed_commit_id = (unsigned long) -1;
    if (wanted_object->type != WANTED_TYPE_COMMIT) {
        memset(&wanted_object->oid, 0, sizeof wanted_object->oid);
        wanted_object->oid_hex_offset = 0;
        return 0;
    }
    if (git_oid_fromstr(&wanted_object->oid, name)) {
        pr_error("Failed to convert '%s' to a git oid\n", name);
        return -1;
    }
    wanted_object->oid_hex_offset = sbuffer->used;
    if (format_oid_to_string_buffer(&wanted_object->oid, sbuffer)) {
        pr_error("Failed to format git oid hex string to buffer\n");
        return -1;
    }
    return 0;
}

static inline
int wanted_object_work_from_config(
    struct wanted_object *const restrict wanted_work,
    struct wanted_base const *const restrict wanted_config,
    struct string_buffer *const restrict sbuffer
) {
    wanted_work->base = *wanted_config;
    return wanted_object_complete_from_base(wanted_work, sbuffer);
}


/* Non-common attribute that's not set:  wanted_objects{,_count,_allocated},
  from_config, wanted_dynamic */
static inline
void repo_work_finish_bare(
    struct repo_work *restrict repo_work
) {
    repo_work->wanted_objects_count_original = repo_work->wanted_objects_count;
    repo_work->commits = NULL;
    repo_work->commits_count = 0;
    repo_work->commits_allocated = 0;
    repo_work->git_repository = NULL;
    repo_work->need_update = repo_work->wanted_dynamic;
    repo_work->updated = false;
}

static inline
int repo_work_from_config(
    struct repo_work *restrict repo_work,
    struct repo_config const *const restrict repo_config,
    struct string_buffer *const restrict sbuffer
) {
    repo_work->wanted_dynamic = false;
    if (repo_config->wanted_objects_count) {
        if (!repo_config->wanted_objects) {
            pr_error("Repo does not have wanted objects allocated but "
                    "marked it has\n");
            return -1;
        }
        if (!(repo_work->wanted_objects = malloc(
                sizeof *repo_work->wanted_objects *
                    (repo_work->wanted_objects_allocated =
                        repo_config->wanted_objects_count))))
        {
            pr_error("Failed to allocate memory for wanted obejcts\n");;
            return -1;
        }
        for (unsigned long i = 0;
            i < repo_config->wanted_objects_count;
            ++i) {
            if (wanted_object_work_from_config(
                repo_work->wanted_objects + i,
                repo_config->wanted_objects + i,
                sbuffer)) {
                pr_error("Failed to create work wanted object from config\n");
                return -1;
            }
            if ((repo_work->wanted_objects + i)->type != WANTED_TYPE_COMMIT)
                repo_work->wanted_dynamic = true;
        }
        repo_work->wanted_objects_count = repo_config->wanted_objects_count;
    } else {
        pr_warn("No wanted object defined\n");
        repo_work->wanted_objects = NULL;
        repo_work->wanted_objects_allocated = 0;
        repo_work->wanted_objects_count = 0;
    }
    repo_work->common = repo_config->common;
    repo_work->from_config = true;
    repo_work_finish_bare(repo_work);
    return 0;
}

static inline
int work_handle_repos_init_from_config(
    struct work_handle *const restrict work_handle,
    struct config const *const restrict config
) {
    if (!config->repos_count) {
        pr_warn("No repos defined");
        work_handle->repos = NULL;
        work_handle->repos_allocated = 0;
        work_handle->repos_count = 0;
        return 0;
    }
    if (!config->repos) {
        pr_error("Internal: config repos is NULL pointer\n");
        return -1;
    }
    work_handle->repos_allocated =
        (config->repos_count + ALLOC_BASE - 1) / ALLOC_BASE * ALLOC_BASE;
    if (!(work_handle->repos = malloc(
            sizeof *work_handle->repos *
                work_handle->repos_allocated)))
    {
        pr_error("Failed to allocate memory for work repos\n");
        return -1;
    }
    work_handle->repos_count = 0;
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (repo_work_from_config(work_handle->repos + i, config->repos+ i,
                                &work_handle->string_buffer)) {
            pr_error("Failed to create work repo from config\n");
            goto free_objects;
        }
        ++work_handle->repos_count;
    }
    return 0;
free_objects:
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        free_if_allocated_to_null(work_handle->repos[i].wanted_objects);
    }
    free_if_allocated_to_null(work_handle->repos);
    return -1;
}

static inline
int work_handle_cwd_open_or_dup(
    struct work_handle *const restrict work_handle,
    int const cwd
) {
    if (cwd < 0) {
        work_handle->cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } else {
        work_handle->cwd = dup(cwd);
    }
    if (work_handle->cwd < 0) {
        pr_error_with_errno("Failed to open/dup cwd");
        return -1;
    }
    return 0;
}

static inline
bool console_trylock() { // true locked, false not
    int pr = pthread_mutex_trylock(&console_mutex);
    switch (pr) {
        case 0:
            printf("\33[2K\r");
            return true;
        case EBUSY:
            break;
        default:
            pr_error_with_pthread_error("Failed to try lock console");
            break;
    }
    return false;
}

static inline
bool console_lock() { // true locked, false not
    int pr = pthread_mutex_lock(&console_mutex);
    switch (pr) {
        case 0:
            printf("\33[2K\r");
            return true;
        default:
            pr_error_with_pthread_error("Failed to try lock console");
            break;
    }
    return false;
}

static inline
void console_unlock() {
    pthread_mutex_unlock(&console_mutex);
}

static inline
int gcb_sideband_progress_headless(
    char const *string, int len, void *payload
) {
    (void)string;
    (void)len;
    *((struct gmr_payload *)payload)->last_transfer = time(NULL);
	return 0;
}

int gcb_sideband_progress(char const *string, int len, void *payload) {
    gcb_sideband_progress_headless(string, len, payload);
    // if (!console_trylock()) {
    //     return 0;
    // }
    pr_info("Repo '%s': Remote: %.*s",
        ((struct gmr_payload *)payload)->url, len, string);
    // console_unlock();
	return 0;
}

#define declare_func_size_to_human_readable_type(TYPE, SUFFIX) \
static inline \
TYPE size_to_human_readable_##SUFFIX(TYPE size, char *const suffix) { \
    char const suffixes[] = "BKMGTPEZY"; \
    unsigned short suffix_id = 0; \
    while (size >= 1024) { \
        ++suffix_id; \
        size /= 1024; \
    } \
    *suffix = suffixes[suffix_id]; \
    return size; \
}

declare_func_size_to_human_readable_type(size_t, size_t)
declare_func_size_to_human_readable_type(unsigned int, uint)
declare_func_size_to_human_readable_type(double, double)

static inline void gcb_print_progress(
    git_indexer_progress const *const restrict stats,
    struct gmr_payload const *const restrict payload
) {
    // if (!console_trylock()) {
    //     return;
    // }
	if (stats->total_objects &&
		stats->received_objects == stats->total_objects) {
		pr_info("Repo '%s': Resolving deltas %u%% (%u/%u)\r",
                payload->url,
                stats->total_deltas > 0 ?
                    100 * stats->indexed_deltas / stats->total_deltas :
                    0,
                stats->indexed_deltas,
                stats->total_deltas);
	} else {
        char suffix_total, suffix_speed;
        unsigned int size_total_human_readable = size_to_human_readable_uint(
            stats->received_bytes, &suffix_total);
        double speed_human_readable;
        time_t time_elasped = time(NULL) - payload->first_transfer;
        if (time_elasped > 0) {
            speed_human_readable = size_to_human_readable_double(
                stats->received_bytes / time_elasped, &suffix_speed);
        } else {
            speed_human_readable = 0;
            suffix_speed = 'B';
        }
		pr_info("Repo '%s': "
            "Receiving objects %u%% (%u%c, %.2lf%c/s %u); "
            "Indexing objects %u%% (%u); "
            "Total objects %u.\r",
            payload->url,
            stats->total_objects > 0 ?
                100 * stats->received_objects / stats->total_objects :
                0,
            size_total_human_readable, suffix_total,
            speed_human_readable, suffix_speed,
            stats->received_objects,
            stats->total_objects > 0 ?
                100 * stats->indexed_objects/ stats->total_objects :
                0,
            stats->indexed_objects,
            stats->total_objects);
	}
    // console_unlock();
}

static inline
int gcb_fetch_progress_headless(
    git_indexer_progress const *stats, void *payload
) {
    (void)stats;
    *((struct gmr_payload *)payload)->last_transfer = time(NULL);
	return 0;
}

int gcb_fetch_progress(git_indexer_progress const *stats, void *payload) {
    gcb_fetch_progress_headless(stats, payload);
	gcb_print_progress(stats, (struct gmr_payload *)payload);
	return 0;
}

int work_handle_init_from_config(
    struct work_handle *const restrict work_handle,
    struct config const *const restrict config,
    int const cwd
) {
    if (work_handle_cwd_open_or_dup(work_handle, cwd)) {
        pr_error("Failed to open/dup cwd\n");
        return -1;
    }
    if (string_buffer_clone(
            &work_handle->string_buffer,
            &config->string_buffer)) {
        pr_error("Failed to clone string buffer from config\n");
        goto free_cwd;
    }
    if (config->archive_pipe_args_count) {
        work_handle->archive_pipe_args = malloc(
            sizeof *work_handle->archive_pipe_args * 
                config->archive_pipe_args_count);
        if (!work_handle->archive_pipe_args) {
            pr_error("Failed to allocate memory for archive pipe args\n");
            goto free_string_buffer;
        }
        memcpy(work_handle->archive_pipe_args, config->archive_pipe_args, 
            sizeof *work_handle->archive_pipe_args * 
                config->archive_pipe_args_count);
        work_handle->archive_pipe_args_count = config->archive_pipe_args_count;
        work_handle->archive_pipe_args_allocated = 
            config->archive_pipe_args_count;
    } else {
        work_handle->archive_pipe_args = NULL;
        work_handle->archive_pipe_args_allocated = 0;
        work_handle->archive_pipe_args_count = 0;
    }
    work_handle->_static = config->_static;
    if (work_handle_repos_init_from_config(work_handle, config)) {
        pr_error("Failed to init repos\n");
        goto free_pipe_args;
    }
    if (work_handle_work_directories_init(work_handle)) {
        pr_error("Failed to init work directories\n");
        goto free_repos;
    }
    if (isatty(STDOUT_FILENO)) {
        work_handle->cb_sideband = gcb_sideband_progress;
        work_handle->cb_fetch = gcb_fetch_progress;
    } else {
        work_handle->cb_sideband = gcb_sideband_progress_headless;
        work_handle->cb_fetch = gcb_fetch_progress_headless;
    }
    return 0;
free_repos:
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        free_if_allocated(work_handle->repos[i].wanted_objects);
    }
    free_if_allocated_to_null(work_handle->repos);
free_pipe_args:
    dynamic_array_free(work_handle->archive_pipe_args);
free_string_buffer:
    free_if_allocated_to_null(work_handle->string_buffer.buffer);
free_cwd:
    if (close(work_handle->cwd))
        pr_error_with_errno("Failed to clsoe opened/duped cwd");
    return -1;
}

void commit_free(
    struct commit *const restrict commit
) {
    git_commit_free_if_allocated_to_null(commit->git_commit);
    dynamic_array_free(commit->submodules);
}

void repo_work_free(
    struct repo_work *const restrict repo
) {
    for (unsigned long i = 0; i < repo->commits_count; ++i) {
        commit_free(repo->commits + i);
    }
    dynamic_array_free(repo->commits);
    dynamic_array_free(repo->wanted_objects);
    git_repository_free_if_allocated_to_null(repo->git_repository);
}

void work_handle_free(
    struct work_handle *const restrict work_handle
) {
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        repo_work_free(work_handle->repos + i);
    }
    dynamic_array_free(work_handle->repos);
    string_buffer_free(&work_handle->string_buffer);
    free_if_allocated(work_handle->archive_pipe_args);
    if (close(work_handle->cwd))
        pr_error_with_errno("Failed to clsoe opened/duped cwd");
}

// 0 existing and opened, 1 does not exist but created, -1 error
int repo_open_or_create(
    git_repository **const restrict repo,
    char const *const restrict url,
    char const *const restrict name
) {
    int r;
    switch ((r = git_repository_open_bare(repo, name))) {
    case GIT_OK:
        return 0;
    case GIT_ENOTFOUND:
        if ((r = git_repository_init(repo, name, 1))) {
            pr_error_with_libgit_error(
                "Failed to create repo '%s' at '%s'", url, name);
            return -1;
        }
        git_remote *remote;
        if ((r = git_remote_create_with_fetchspec(
                &remote, *repo, GMR_REMOTE, url, GMR_FETCHSPEC))) {
            pr_error_with_libgit_error(
                "Failed to create remote '"GMR_REMOTE"' with url '%s'", url);
            goto free_repo;
        }
        git_remote_free(remote);
        /*
          The following part is optional, the remote.*.mirror config
          is only for note and reference by users, it does not define
          the actual mirroing behaviour for either us, libgit, or git.
        */
#ifndef SKIP_MIRROR_CONFIG
        git_config *config;
        if ((r = git_repository_config(&config, *repo))) {
            pr_error_with_libgit_error(
                "Failed to open config for repo '%s' at '%s'", url, name);
            goto free_repo;
        }
        r = git_config_set_bool(config, GMR_CONFIG, true);
        git_config_free(config);
        if (r) {
            pr_error_with_libgit_error(
                "Failed to set config '"GMR_CONFIG"' to true "
                "for repo '%s' at '%s'",
                    url, name);
            goto free_repo;
        }
#endif
        return 1;
    default:
        pr_error_with_libgit_error(
            "Failed to open repo '%s' at '%s'", url, name);
        return -1;
    }

free_repo:
    git_repository_free(*repo);
    return -1;
}

int repo_work_open_common(
    struct repo_work *const restrict repo_work,
    char const *const url,
    char const *const name
) {
    int r;
    switch ((r = repo_open_or_create(&repo_work->git_repository, url, name))) {
    case 1:
        repo_work->need_update = true;
        return 0;
    case 0:
        switch ((r = git_repository_head_unborn(repo_work->git_repository))) {
        case 1:
            repo_work->need_update = true;
        case 0:
            break;
        default:
            pr_error_with_libgit_error(
                "Failed to check if repo '%s' at '%s's HEAD is unborn",
                url, name);
            return -1;
        }
        return 0;
    case -1:
        pr_error("Failed to open or create repo '%s' at '%s'\n", url, name);
        return -1;
    default:
        pr_error("Impossible return %d\n", r);
        return -1;
    }
}


int repo_work_open_one(
    struct repo_work *const restrict repo_work,
    char const *const restrict sbuffer,
    int const fd_repos,
    int const fd_cwd
) {
    char const *const url = sbuffer + repo_work->url_offset;
    char const *const name = repo_work->hash_url_string;
    if (repo_work->git_repository) {
        pr_error("Repo '%s' already opened\n", url);
        return -1;
    }
    if (fchdir(fd_repos)) {
        pr_error_with_errno("Failed to chdir to repos");
        return -1;
    }
    int r;
    if (repo_work_open_common(repo_work, url, name)) {
        pr_error("Failed to open repo '%s' at '%s'\n", url, name);
        r = -1;
        goto return_cwd;
    }
    r = 0;
return_cwd:
    if (fchdir(fd_cwd)) {
        pr_error_with_errno("Failed to chdir back to cwd");
        r = -1;
    }
    return r;
}

/* Expecting a list of repo pointers, ended with NULL */
int repo_work_open_many_scatter(
    struct repo_work **const restrict repos,
    char const *const restrict sbuffer,
    int const fd_repos,
    int const fd_cwd
) {
    if (fchdir(fd_repos)) {
        pr_error_with_errno("Failed to chdir to repos");
        return -1;
    }
    int r;
    unsigned short free_count = 0;
    for (unsigned short i = 0; ; ++i) {
        struct repo_work *const restrict repo_work = repos[i];
        if (!repo_work) break;
        if (repo_work->git_repository) {
            pr_error("Repo already opened\n");
            free_count = i + 1;
            r = -1;
            goto free_repos;
        }
        char const *const url = sbuffer + repo_work->url_offset;
        char const *const name = repo_work->hash_url_string;
        if (repo_work_open_common(repo_work, url, name)) {
            pr_error("Failed to open repo '%s' at '%s'\n", url, name);
            free_count = i;
            r = -1;
            goto free_repos;
        }
    }
    r = 0;
free_repos:
    for (unsigned short i = 0; i < free_count; ++i) {
        git_repository_free(repos[i]->git_repository);
        repos[i]->git_repository = NULL;
    }
    if (fchdir(fd_cwd)) {
        pr_error_with_errno("Failed to chdir back to cwd");
        r = -1;
    }
    return r;
}

/* Expecting continous repo structures */
int repo_work_open_many_serial(
    struct repo_work *const restrict repos,
    unsigned long repos_count,
    char const *const restrict sbuffer,
    int const fd_repos,
    int const fd_cwd
) {
    if (fchdir(fd_repos)) {
        pr_error_with_errno("Failed to chdir to repos");
        return -1;
    }
    int r;
    unsigned long free_count = 0;
    for (unsigned long i = 0; i < repos_count; ++i) {
        struct repo_work *const restrict repo_work = repos + i;
        if (repo_work->git_repository) {
            pr_error("Repo already opened\n");
            free_count = i + 1;
            r = -1;
            goto free_repos;
        }
        char const *const url = sbuffer + repo_work->url_offset;
        char const *const name = repo_work->hash_url_string;
        if (repo_work_open_common(repo_work, url, name)) {
            pr_error("Failed to open repo '%s' at '%s'\n", url, name);
            free_count = i;
            r = -1;
            goto free_repos;
        }
    }
    r = 0;
free_repos:
    for (unsigned short i = 0; i < free_count; ++i) {
        git_repository_free((repos + i)->git_repository);
        (repos + i)->git_repository = NULL;
    }
    if (fchdir(fd_cwd)) {
        pr_error_with_errno("Failed to chdir back to cwd");
        r = -1;
    }
    return r;
}

int work_handle_open_all_repos(
    struct work_handle const *const restrict work_handle
) {
#ifdef WORK_HANDLE_OPEN_ALL_REPOS_USE_SCATTER_VARAINT
    struct repo_work **repos_heap = NULL;
    struct repo_work *repos_stack[0x100 / sizeof *repos_heap];
    struct repo_work **repos = NULL;
    if (work_handle->repos_count > 0x100 / sizeof *repos_heap - 1) {
        if (!(repos_heap = malloc(
                sizeof *repos_heap * (work_handle->repos_count + 1)))) {
            pr_error_with_errno(
                "Failed to allocate memory for repos' pointers");
            return -1;
        }
        repos = repos_heap;
    } else {
        repos = repos_stack;
    }
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        repos[i] = work_handle->repos + i;
    }
    repos[work_handle->repos_count] = NULL;
    int r = repo_work_open_many(repos,
                work_handle->string_buffer.buffer,
                work_handle->dir_repos.datafd,
                work_handle->cwd);
    free_if_allocated(repos_heap);
    return r;
#else
    switch (work_handle->repos_count) {
    case 0:
        pr_error("No repos defined\n");
        return -1;
    case 1:
        return repo_work_open_one(
                    work_handle->repos,
                    work_handle->string_buffer.buffer,
                    work_handle->dir_repos.datafd,
                    work_handle->cwd);
    default:
        return repo_work_open_many_serial(
            work_handle->repos,
            work_handle->repos_count,
            work_handle->string_buffer.buffer,
            work_handle->dir_repos.datafd,
            work_handle->cwd);
    }
#endif
}

/* 0 link exists and OK, 1 link does not exist, or removed, -1 error */
int check_symlink_at(
    int const links_dirfd,
    char const *const restrict symlink_path,
    char const *const restrict symlink_target
) {
    char actual_target_stack[0x100];
    char *actual_target_heap = NULL;
    char *actual_target = actual_target_stack;
    ssize_t buffer_size = 0x100;
    ssize_t len;
    int r;
    while ((len = readlinkat(links_dirfd, symlink_path, 
                    actual_target, buffer_size)) >= buffer_size) {
        /* Just in case target is too long */
        buffer_size *= ALLOC_MULTIPLIER;
        if (actual_target_heap) free(actual_target_heap);
        if (!(actual_target_heap = malloc(buffer_size))) {
            pr_error_with_errno("Failed to allocate path buffer on heap");
            return -1;
        }
        actual_target = actual_target_heap;
    }
    if (len < 0) {
        if (errno == ENOENT) {
            r = 1;
            goto free_actual_target_heap;
        } else {
            pr_error_with_errno("Failed to read link at '%s'", symlink_path);
            r = -1;
            goto free_actual_target_heap;
        }
    } else if (len == 0) {
        pr_error("Symlink target is 0, impossible\n");
        r = -1;
        goto free_actual_target_heap;
    } else {
        actual_target[len] = '\0';
        if (strcmp(actual_target, symlink_target)) {
            pr_warn("Symlink at '%s' points to '%s' instead of '%s', "
            "if you see this message for too many times, you've probably set "
            "too many repos with same path but different schemes.\n",
            symlink_path, actual_target, symlink_target);
            if (unlinkat(links_dirfd, symlink_path, 0) < 0) {
                pr_error_with_errno("Faild to unlink '%s'", symlink_path);
                r = -1;
                goto free_actual_target_heap;
            }
            r = 1;
            goto free_actual_target_heap;
        }
    }
    r = 0;
free_actual_target_heap:
    free_if_allocated(actual_target_heap);
    return r;

}

int ensure_parent_dir(
    char const *const restrict path,
    unsigned short const len_path
) {
    for (unsigned short i = len_path; i > 0; --i) {
        if (path[i - 1] == '/') {
            return mkdir_recursively(path, i - 1);
        }
    }
    pr_error("Path '%s' does not have parent\n", path);
    return -1;
}

int ensure_parent_dir_at(
    int const dir_fd,
    char const *const restrict path,
    unsigned short const len_path
) {
    for (unsigned short i = len_path; i > 0; --i) {
        if (path[i - 1] == '/') {
            return mkdir_recursively_at(dir_fd, path, i - 1);
        }
    }
    pr_error("Path '%s' does not have parent\n", path);
    return -1;
}

int ensure_symlink_at (
    int const links_dirfd,
    char const *const restrict symlink_path,
    size_t const len_symlink_path,
    char const *const restrict symlink_target
) {
    switch (check_symlink_at(links_dirfd, symlink_path, symlink_target)) {
    case 0: /* Exists and OK */
        return 0;
    case 1: /* Does not exist, or invalid but removed */
        break;
    default: /* Error */
        return -1;
    }
    if (symlinkat(symlink_target, links_dirfd, symlink_path) < 0) {
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
        pr_debug("Created symlink '%s' -> '%s'\n",
            symlink_path, symlink_target);
        return 0;
    }
    // After above routine, the only possiblity is missing dirs
    if (ensure_parent_dir_at(links_dirfd, symlink_path, len_symlink_path)) {
        pr_error("Failed to ensure parent dir for '%s'\n", symlink_path);
        return -1;
    }
    if (symlinkat(symlink_target, links_dirfd, symlink_path) < 0) {
        pr_error_with_errno(
            "Failed to create symlink '%s' -> '%s'",
            symlink_path, symlink_target);
        return -1;
    }
    pr_debug("Created symlink '%s' -> '%s'\n",
        symlink_path, symlink_target);
    return 0;
}

struct link_target {
    char target_stack[0x100];
    char *target_heap;
    size_t target_heap_allocated;
    char *target;
};

static inline
void link_target_init(
    struct link_target *const restrict link_target
) {
    link_target->target_stack[0] = '\0';
    link_target->target_heap = NULL;
    link_target->target_heap_allocated = 0;
    link_target->target = NULL;
}

static inline
void link_target_free(
    struct link_target *const restrict link_target
) {
    free_if_allocated(link_target->target_heap);
}

static inline
int link_target_format(
    struct link_target *const restrict link_target,
    unsigned short const depth_link,
    char const *const restrict target_suffix,
    unsigned short const len_target_suffix
) {
    // E.g. links/A -> ../data/B
    size_t const len = depth_link * 3 + 5 + len_target_suffix;
    if (len + 1 >= 0x100) {
        if (len + 1 >= link_target->target_heap_allocated) {
            free_if_allocated(link_target->target_heap);
            if (!(link_target->target_heap = malloc(
                    (link_target->target_heap_allocated = 
                        (len + 2) / 0x1000 * 0x1000)))) {
                pr_error_with_errno("Failed to allocate memory");
                return -1;
            }
        }
        link_target->target = link_target->target_heap;
    } else {
        link_target->target = link_target->target_stack;
    }
    char *current = link_target->target;
    for (unsigned short i = 0; i < depth_link; ++i) {
        memcpy(current, "../", 3);
        current += 3;
    }
    memcpy(current, "data/", 5);
    current += 5;
    memcpy(current, target_suffix, len_target_suffix);
    link_target->target[len] = '\0';
    return 0;
}

struct link_handle {
    int dirfd_links;
    bool need;
    bool link_branches_dir;
    bool link_tags_dir;
};

static inline
int work_handle_link_repo_wanted_object(
    struct work_handle const *const restrict work_handle,
    struct repo_work const *const restrict repo,
    struct wanted_object const *const restrict wanted_object,
    struct link_handle *const restrict archive_handle,
    struct link_handle *const restrict checkout_handle,
    struct link_target *const restrict link_target
) {
    /* links/[sanitized url]/[commit hash](archive suffix)
                            /named/[name](a.s.)
                            /tags -> refs/tags
                            /branches -> refs/heads
     undetermimed layers -> /refs/[ref name](a.s.)
                            /HEAD(a.s.)
    */
    bool    link_tags_dir = false,
            link_branches_dir = false;
    char const *dir_link = "";
    // E.g.
    //  archive: archives/abcdef.tar.gz
    //  link: archives/links/github.com/user/repo/abcdeg.tar.gz
    //  target: ../../../../abcdef.tar.gz
    //   github.com/user/repo has 3 parts, depth is 4
    char const *const restrict name = 
        work_handle_get_string(wanted_object->name);
    unsigned short link_depth = repo->depth_long_name + 1;
    switch (wanted_object->type) {
        case WANTED_TYPE_UNKNOWN:
            pr_error("Wanted type unknown for '%s'\n", name);
            return -1;
        case WANTED_TYPE_ALL_BRANCHES:
        case WANTED_TYPE_ALL_TAGS:
            return 0;
        case WANTED_TYPE_BRANCH:
            link_branches_dir = true;
            dir_link = "refs/heads/";
            link_depth += 2;
            break;
        case WANTED_TYPE_TAG:
            link_tags_dir = true;
            dir_link = "refs/tags/";
            link_depth += 2;
            break;
        case WANTED_TYPE_REFERENCE:
            if (!strncmp(name, "refs/", 5)) {
                char const *const ref_kind = name + 5;
                if (!strncmp(ref_kind, "heads/", 6))
                    link_branches_dir = true;
                else if (!strncmp(ref_kind, "tags/", 5))
                    link_tags_dir = true;
            }
            break;
        case WANTED_TYPE_COMMIT:
        case WANTED_TYPE_HEAD:
            break;
    }
    if (link_branches_dir) {
        if (wanted_object->archive) archive_handle->link_branches_dir = true;
        if (wanted_object->checkout) checkout_handle->link_branches_dir = true;
    }
    if (link_tags_dir) {
        if (wanted_object->archive) archive_handle->link_tags_dir = true;
        if (wanted_object->checkout) checkout_handle->link_tags_dir = true;
    }
    for (unsigned short i = 0; i < wanted_object->len_name; ++i) {
        switch (name[i]) {
        case '/':
            ++link_depth;
            break;
        case '\0':
            pr_error("Name '%s' ends pre-maturely\n", name);
            return -1;
        }
    }
    
    if (wanted_object->archive) {
        if (archive_handle->dirfd_links < 0 &&
            (archive_handle->dirfd_links = open_or_create_dir_recursively_at(
                work_handle->dir_archives.linkfd, 
                work_handle_get_string(repo->long_name),
                repo->len_long_name)) < 0) 
        {
            pr_error("Failed to open archive repo links dir\n");
            return -1;
        }
    }
    if (wanted_object->checkout) {
        if (checkout_handle->dirfd_links < 0 &&
        (checkout_handle->dirfd_links = open_or_create_dir_recursively_at(
            work_handle->dir_checkouts.linkfd, 
            work_handle_get_string(repo->long_name),
            repo->len_long_name)) < 0) 
        {
            pr_error("Failed to open checkout repo links dir\n");
            return -1;
        }
    }
    int r = -1;
    // The commit hash one
    // char symlink_path[PATH_MAX] = "";
    // char *symlink_path_current =
    //     stpcpy(symlink_path, wanted_object->hex_string);
    // // unsigned short len_symlink_path = HASH_STRING_LEN;
    // char symlink_target[PATH_MAX] = "";
    // char *symlink_target_current = symlink_target;
    // for (unsigned short i = 0; i < repo->url_no_scheme_sanitized_parts+1; ++i) {
    //     symlink_target_current = stpcpy(symlink_target_current, "../");
    // }
    // symlink_target_current = stpcpy(symlink_target_current,
    //                                 wanted_object->hex_string);
    // if (checkout && guarantee_symlink_at(
    //     checkouts_repo_links_dirfd,
    //     symlink_path, HASH_STRING_LEN,
    //     symlink_target)) {
    //     goto close_checkouts_repo_links_dirfd;
    // }
    // if (archive) {
    //     if (archive_suffix[0] == '\0' && guarantee_symlink_at(
    //         archives_repo_links_dirfd,
    //         symlink_path, HASH_STRING_LEN,
    //         symlink_target)) {
    //         goto close_checkouts_repo_links_dirfd;
    //     } else {
    //         strcpy(symlink_path_current, archive_suffix);
    //         strcpy(symlink_target_current, archive_suffix);
    //         if (guarantee_symlink_at(
    //             archives_repo_links_dirfd,
    //             symlink_path, HASH_STRING_LEN + len_archive_suffix,
    //             symlink_target)) {
    //             goto close_checkouts_repo_links_dirfd;
    //         }
    //     }
    // }

    // // The named one
    // if (wanted_object->type != WANTED_TYPE_COMMIT) {
    //     char *symlink_path_current = stpcpy(symlink_path, dir_link);
    //     symlink_path_current =
    //         stpcpy(symlink_path_current, wanted_object->name);
    //     unsigned short len_symlink_path = symlink_path_current - symlink_path;
    //     char *symlink_target_current = symlink_target;
    //     for (unsigned short i = 0; i < link_depth; ++i) {
    //         symlink_target_current = stpcpy(symlink_target_current, "../");
    //     }
    //     symlink_target_current = stpcpy(
    //         symlink_target_current,
    //         wanted_object->hex_string);
    //     if (checkout && guarantee_symlink_at(
    //         checkouts_repo_links_dirfd,
    //         symlink_path, len_symlink_path,
    //         symlink_target)) {
    //         goto close_checkouts_repo_links_dirfd;
    //     }
    //     if (archive) {
    //         if (archive_suffix[0] == '\0' && guarantee_symlink_at(
    //             archives_repo_links_dirfd,
    //             symlink_path, len_symlink_path,
    //             symlink_target)) {
    //             goto close_checkouts_repo_links_dirfd;
    //         } else {
    //             strcpy(symlink_path_current, archive_suffix);
    //             strcpy(symlink_target_current, archive_suffix);
    //             if (guarantee_symlink_at(
    //                 archives_repo_links_dirfd,
    //                 symlink_path, wanted_object->len_name + len_archive_suffix,
    //                 symlink_target)) {
    //                 goto close_checkouts_repo_links_dirfd;
    //             }
    //         }
    //     }
    // }
    r = 0;
    return r;
}

static inline
int work_handle_link_repo(
    struct work_handle const *const restrict work_handle,
    struct repo_work const *const restrict repo,
    struct link_target *const restrict link_target
) {
    int r = 0;
    if (link_target_format(link_target, repo->depth_long_name,
        repo->hash_url_string, HASH_STRING_LEN)) r = -1;
    else if (ensure_symlink_at(work_handle->dir_repos.linkfd, 
        work_handle_get_string(repo->long_name),
        repo->len_long_name, link_target->target)) r = -1;
    struct link_handle archive_handle = {.dirfd_links = -1};
    struct link_handle checkout_handle = {.dirfd_links = -1};
    for (unsigned long i = 0; i < repo->wanted_objects_count; ++i) {
        if (work_handle_link_repo_wanted_object(work_handle, repo, 
            repo->wanted_objects + i, &archive_handle, &checkout_handle, 
            link_target)) r = -1;
    }
    if (archive_handle.dirfd_links >= 0 && close(archive_handle.dirfd_links)) {
        pr_error_with_errno("Failed to close archive links fd");
        r = -1;
    }
    if (checkout_handle.dirfd_links >= 0 && close(checkout_handle.dirfd_links)){
        pr_error_with_errno("Failed to close checkout links fd");
        r = -1;
    }
    return r;
}

int work_handle_link_all_repos(
    struct work_handle const *const restrict work_handle
) {
    if (!work_handle->repos_count) {
        pr_error("No repos defined\n");
        return -1;
    }
    struct link_target link_target;
    link_target_init(&link_target);
    int r = 0;
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        if (work_handle_link_repo(
            work_handle, work_handle->repos + i, &link_target)) 
            r = -1;
    }
    link_target_free(&link_target);
    return r;
}

// check if non-dynamic wanted objects are OK
static inline
void work_handle_set_need_update_all_repos(
    struct work_handle *const restrict work_handle
) {
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        struct repo_work *const restrict repo = work_handle->repos + i;
        if (repo->need_update) continue;
        for (unsigned long j = 0; j < repo->wanted_objects_count; ++j) {
            struct wanted_object const *const restrict wanted_object
                = repo->wanted_objects + j;
            if (wanted_object->type != WANTED_TYPE_COMMIT) continue;
            struct wanted_commit const *const wanted_commit
                = (struct wanted_commit *)wanted_object;
            git_commit *commit;
            int r = git_commit_lookup(&commit, 
                repo->git_repository, &wanted_commit->oid);
            if (r) {
                pr_error_with_libgit_error(
                    "Failed to lookup commit '%s' from repo '%s', need update",
                    work_handle_get_string(wanted_commit->oid_hex), 
                    work_handle_get_string(repo->url));
                repo->need_update = true;
            } else {
                git_commit_free(commit);
            }
        }
    }
}

static inline 
int gmr_remote_update(
    git_remote *const restrict remote,
    git_fetch_options const *const restrict fetch_opts
) {
    char const *const url = git_remote_url(remote);
    struct gmr_payload *payload = fetch_opts->callbacks.payload;
    int r;
    *payload->last_transfer = time(NULL);
    if ((r = git_remote_connect(remote, GIT_DIRECTION_FETCH,
        &fetch_opts->callbacks, &fetch_opts->proxy_opts, NULL))) {
        pr_error_with_libgit_error("Failed to connect to remote '%s'", url);
        return -1;
    }
    payload->first_transfer = time(NULL);
    *payload->last_transfer = time(NULL);
    if ((r = git_remote_download(remote, &gmr_refspecs, fetch_opts))) {
        pr_error_with_libgit_error("Failed to download from remote '%s'", url);
    }
    int r2;
    *payload->last_transfer = time(NULL);
    if ((r2 = git_remote_disconnect(remote))) {
        pr_error_with_libgit_error(
            "Failed to disconnect from remote '%s'", url);
    }
    if (r || r2) return -1;
    *payload->last_transfer = time(NULL);
    if ((r = git_remote_update_tips(remote, &fetch_opts->callbacks, 0,
                        GIT_REMOTE_DOWNLOAD_TAGS_AUTO, NULL))) {
        pr_error_with_libgit_error(
            "Failed to update tips from remote '%s'", url);
        return -1;
    }
    *payload->last_transfer = time(NULL);
    if ((r = git_remote_prune(remote, &fetch_opts->callbacks))) {
        pr_error("Failed to prune remote '%s'", url);
        return -1;
    }
    return 0;
}

static inline
int gmr_repo_sync_head_to_remote(
    git_repository *const restrict repo,
    git_remote *const restrict remote
) {
    git_remote_head const **heads;
    size_t heads_count;
    if (git_remote_ls(&heads, &heads_count, remote)) {
        pr_error("Failed to ls remote\n");
        return -1;
    }
    char const *head_ref = NULL;
    for (size_t i = 0; i < heads_count; ++i) {
        git_remote_head const *const head = heads[i];
        if (!strcmp(head->name, "HEAD")) {
            head_ref = head->symref_target;
            break;
        }
    }
    if (!head_ref) {
        pr_warn("Remote does not have HEAD or HEAD does not point to any "
                "branch, keeping local\n");
        return 0;
    }
    int r;
    /* Always set head, as reading local HEAD first takes more time than 
       just writing*/
    if ((r = git_repository_set_head(repo, head_ref))) {
        pr_error_with_libgit_error(
            "Failed to update repo HEAD to '%s'\n", head_ref);
        return -1;
    }
    return 0;
}

int gmr_repo_update(
    git_repository *const restrict repo,
    char const *const restrict url,
    git_fetch_options const *const restrict fetch_opts_orig,
    unsigned short const proxy_after,
    time_t *last_transfer
) {
    pr_info("Updating repo '%s'\n", url);
    git_remote *remote;
    int r = git_remote_create_anonymous(&remote, repo, url);
    if (r) {
        pr_error_with_libgit_error(
            "Failed to create anonymous remote for '%s'", url);
        return -1;
    }
    unsigned short max_try = proxy_after + 3;
    git_fetch_options fetch_opts = *fetch_opts_orig;
    struct gmr_payload payload = {
        .url = url,
        .last_transfer = last_transfer,
    };
    fetch_opts.callbacks.payload = (void *)&payload;
    for (unsigned short try = 0; try < max_try; ++try) {
        if (try == proxy_after) {
            if (try)
                pr_warn(
                    "Failed to fetch from '%s' for %hu times, use proxy\n",
                    url, proxy_after);
            fetch_opts.proxy_opts.type = GIT_PROXY_SPECIFIED;
        }
        if (!(r = gmr_remote_update(remote, &fetch_opts))) break;
    }
    if (r) {
        pr_error("Failed to update repo '%s' after %hu tries, "
                "considered failure\n", url, max_try);
        r = -1;
        goto free_remote;
    }
    if (gmr_repo_sync_head_to_remote(repo, remote)) {
        r = -1;
        goto free_remote;
    }
    pr_info("Updated repo '%s'\n", url);
    r = 0;
free_remote:
    git_remote_free(remote);
    return r;
}

struct gmr_repo_update_thread_arg {
    git_repository *restrict repo;
    char const *restrict url;
    git_fetch_options const *restrict fetch_opts_orig;
    unsigned short proxy_after;
    int r;
    bool finished;
    time_t last_transfer;
};

void *gmr_repo_update_thread(void *arg) {
    struct gmr_repo_update_thread_arg *const restrict parg = arg;
    parg->r = gmr_repo_update(
        parg->repo, parg->url, parg->fetch_opts_orig, 
        parg->proxy_after, &parg->last_transfer);
    parg->finished = true;
    return NULL;
}

static inline
git_fetch_options gmr_fetch_options_init(
    git_transport_message_cb cb_sideband,
    git_indexer_progress_cb cb_fetch,
    char const *const restrict proxy,
    unsigned short const proxy_after
) {
    git_fetch_options fetch_opts = {
        .version = GIT_FETCH_OPTIONS_VERSION,
        .callbacks = {
            .version = GIT_REMOTE_CALLBACKS_VERSION,
            .sideband_progress = cb_sideband,
            .transfer_progress = cb_fetch,
        },
        .prune = GIT_FETCH_PRUNE,
        .update_fetchhead = true,
        .download_tags = GIT_REMOTE_DOWNLOAD_TAGS_ALL,
        .proxy_opts = {
            .version = GIT_PROXY_OPTIONS_VERSION,
            .type = (proxy && !proxy_after) ?
                        GIT_PROXY_SPECIFIED : GIT_PROXY_NONE,
            .url = proxy,
        },
        .depth = GIT_FETCH_DEPTH_FULL,
        .follow_redirects = GIT_REMOTE_REDIRECT_INITIAL,
    };
    return fetch_opts;
}

void repo_domain_map_free(
    struct repo_domain_map *const restrict map
) {
    if (map->groups) {
        for (unsigned long i = 0; i < map->groups_count; ++i) {
            struct repo_domain_group *group = map->groups + i;
            free_if_allocated(group->repos);
        }
        free(map->groups);
    }
}

int repo_domain_map_init(
    struct repo_domain_map *const restrict map,
    struct repo_work *const restrict repos,
    unsigned long const repos_count
) {
    map->groups = NULL;
    map->groups_allocated = 0;
    map->groups_count = 0;
    for (unsigned long i = 0; i < repos_count; ++i) {
        struct repo_work *const repo = repos + i;
        if (!repo->need_update) continue;
        struct repo_domain_group *group = NULL;
        for (unsigned long j = 0; j < map->groups_count; ++j) {
            if (map->groups[j].domain == repo->hash_domain) {
                group = map->groups + j;
                break;
            }
        }
        if (!group) {
            if (dynamic_array_add_to(map->groups)) {
                pr_error("Failed to add domain group to map\n");
                goto free_map;
            }
            group = get_last(map->groups);
            group->domain = repo->hash_domain;
            group->repos = NULL;
            group->repos_allocated = 0;
            group->repos_count = 0;
        }
        if (dynamic_array_add_to(group->repos)) {
            pr_error("Failed to add repo to domain group\n");
            goto free_map;
        }
        *(get_last(group->repos)) = repo;
    }
    for (unsigned long i = 0; i < map->groups_count; ++i) {
        struct repo_domain_group *group = map->groups + i;
        if (dynamic_array_partial_free_to(group->repos)) {
            pr_error("Failed to partially free group repos\n");
            goto free_map;
        }
    }
    if (dynamic_array_partial_free_to(map->groups)) {
        pr_error("Failed to partially free map groups\n");
        goto free_map;
    }
    return 0;
free_map:
    repo_domain_map_free(map);
    return -1;
}

static inline
void repo_domain_group_print(
    struct repo_domain_group const *const restrict group,
    char const *const restrict sbuffer
) {
    printf("| Domain %016lx:\n", group->domain);
    for (unsigned long j = 0; j < group->repos_count; ++j) {
        printf("|  - Repo %s\n", sbuffer + group->repos[j]->url_offset);
    }
}


static inline
void repo_domain_map_print(
    struct repo_domain_map const *const restrict map,
    char const *const restrict sbuffer
) {
    pr_info("Domain-repo map:\n");
    for (unsigned long i = 0; i < map->groups_count; ++i) {
        repo_domain_group_print(map->groups + i, sbuffer);
    }
}

/* Warning: passed-in map would be exhausted, but still need to be freed */
static inline
int repo_domain_map_update(
    struct repo_domain_map *const restrict map,
    unsigned short const max_connections,
    struct gmr_repo_update_thread_arg *thread_arg_init,
    char const *const restrict sbuffer
) {
    struct thread_helper {
        bool used;
        pthread_t thread;
        struct repo_work *repo;
        struct gmr_repo_update_thread_arg arg;
    };
    struct thread_helper *thread_helpers;
    unsigned short *threads_count;
    /* Basically a fixed-dynamic array */
    size_t const chunk_size = sizeof *threads_count + 
            max_connections * sizeof *thread_helpers;
    void *const restrict chunks = malloc(chunk_size * map->groups_count);
    if (!chunks) {
        pr_error_with_errno("Failed to allocate memory for thread chunks");
        return -1;
    }
    for (unsigned long i = 0; i < map->groups_count; ++i) {
        void *const chunk = chunks + chunk_size * i;
        *(unsigned short *)chunk = 0;
        thread_helpers = chunk + sizeof *threads_count;
        for (unsigned long j = 0; j < max_connections; ++j) {
            thread_helpers[j].used = false;
            thread_helpers[j].arg = *thread_arg_init;
        }
    }
    int r, pr;
    bool bad_ret = false;
    void *chunks_actual = chunks;
    struct repo_domain_group* groups_actual = map->groups;
    unsigned short active_threads_last = 0;
    for (;;) {
        time_t time_current = time(NULL);
        unsigned short active_threads = 0;
        for (unsigned long i = 0; i < map->groups_count; ++i) {
            void *const chunk = chunks_actual + chunk_size * i;
            threads_count = chunk;
            thread_helpers = chunk + sizeof *threads_count;
            if (*threads_count) { // Check finished threads
                for (unsigned short j = 0; j < max_connections; ++j) {
                    struct thread_helper *thread_helper = thread_helpers + j;
                    if (!thread_helper->used) continue;
                    if (thread_helper->arg.finished) {
                        if (thread_helper->arg.r) {
                            pr_error(
                                "Repo updater %lu for '%s' returned with %d\n",
                                thread_helper->thread,
                                thread_helper->arg.url, 
                                thread_helper->arg.r);
                            bad_ret = true;
                        } else {
                            thread_helper->repo->updated = true;
                        }
                        if ((pr = pthread_join(thread_helper->thread, NULL))) {
                            pr_error_with_pthread_error(
                                "Failed to join supposed finished thread %ld",
                                thread_helper->thread);
                            r = -1;
                            goto wait_threads;
                        }
                        --*threads_count;
                        thread_helper->used = false;
                    } else if (time_current - 
                                thread_helper->arg.last_transfer > 600) {
                        pr_warn(
                            "Repo updater for '%s' took too long without "
                            "transfter, restarting it\n", 
                            thread_helper->arg.url);
                        if ((pr = pthread_cancel(thread_helper->thread))) {
                            pr_error_with_pthread_error(
                                "Failed to cancel updater %lu for '%s'", 
                                thread_helper->thread,  thread_helper->arg.url);
                            r = -1;
                            goto wait_threads;
                        }
                        if ((pr = pthread_join(thread_helper->thread, NULL))) {
                            pr_error_with_pthread_error(
                                "Failed to join cancelled thread %ld", 
                                thread_helper->thread);
                            r = -1;
                            goto wait_threads;
                        }
                        thread_helper->arg.finished = false;
                        thread_helper->arg.last_transfer = time_current;
                        if ((pr = pthread_create(&thread_helper->thread, NULL, 
                            gmr_repo_update_thread, &thread_helper->arg))) {
                            pr_error_with_pthread_error(
                                "Failed to create thread");
                            thread_helper->used = false;
                            r = -1;
                            goto wait_threads;
                        }
                    }
                }
            }
            struct repo_domain_group* const restrict group = groups_actual + i;
            while (*threads_count < max_connections && group->repos_count) {
                struct repo_work *repo = group->repos[--group->repos_count];
                struct thread_helper *thread_helper = NULL;
                for (unsigned short j = 0; j < max_connections; ++j) {
                    if (!thread_helpers[j].used) {
                        thread_helper = thread_helpers + j;
                        break;
                    }
                }
                if (!thread_helper) {
                    pr_error("FATAL: failed to find free thread slot\n");
                    r = -1;
                    goto wait_threads;
                }
                thread_helper->arg.finished = false;
                thread_helper->arg.repo = repo->git_repository;
                thread_helper->arg.url = sbuffer + repo->url_offset;
                thread_helper->arg.last_transfer = time_current;
                thread_helper->repo = repo;
                thread_helper->used = true;
                if ((pr = pthread_create(&thread_helper->thread, NULL, 
                    gmr_repo_update_thread, &thread_helper->arg))) {
                    pr_error_with_pthread_error("Failed to create thread");
                    thread_helper->used = false;
                    r = -1;
                    goto wait_threads;
                }
                ++*threads_count;
            }
            active_threads += *threads_count;
            if (*threads_count + group->repos_count) {
                // Group not exhausted
            } else if (i == 0) {
                // Group exhausted at head
                chunks_actual += chunk_size;
                groups_actual += 1;
                --map->groups_count;
                --i;
            } else if (i == map->groups_count - 1) {
                // Group exhausted at end
                --map->groups_count;
            } else {
                // Group exhuasted in the middle
            }
        }
        if (active_threads != active_threads_last) {
            active_threads_last = active_threads;
            // bool locked = console_lock();
            pr_info("%hu updaters running...\n", active_threads);
            // if (locked) {
            //     console_unlock();
            // }
        }
        if (active_threads == 0) {
            break;
        } else if (active_threads <= max_connections) {
            usleep(100000);
        } else {
            sleep(1);
        }
    }
    if (bad_ret) {
        r = -1;
    } else {
        r = 0;
    }
wait_threads:
    if (active_threads_last) {
        pr_info("Waiting for %hu remaining updaters...\n", active_threads_last);
    }
    for (unsigned long i = 0; i < map->groups_count; ++i) {
        void *const chunk = chunks + chunk_size * i;
        if (!*(unsigned short *)chunk) continue;
        thread_helpers = chunk + sizeof *threads_count;
        for (unsigned long j = 0; j < max_connections; ++j) {
            struct thread_helper *const restrict thread_helper
                = thread_helpers + j;
            if (!thread_helper->used) continue;
            pr_info("Waiting for updater for '%s'...\n", 
                    thread_helper->arg.url);
            time_t time_current = time(NULL);
            while (!thread_helper->arg.finished && 
                time_current - thread_helper->arg.last_transfer < 600) 
            {
                time_current = time(NULL);
                usleep(100000);
            }
            if (thread_helper->arg.finished) {
                if (thread_helper->arg.r) {
                    pr_error("Updater for '%s' bad return %d...\n", 
                        thread_helper->arg.url, thread_helper->arg.r);
                    r = -1;
                } else {
                    thread_helper->repo->updated = true;
                }
            } else {
                pr_warn(
                    "Repo updater for '%s' took too long without "
                    "transfter, cancelling it\n", thread_helper->arg.url);
                if ((pr = pthread_cancel(thread_helper->thread))) {
                    pr_error_with_pthread_error("Failed to cancel thread");
                    r = -1;
                }
            }
            if ((pr = pthread_join(thread_helper->thread, NULL))) {
                pr_error_with_pthread_error(
                    "Failed to join supposed finished thread %ld", 
                    thread_helper->thread);
                r = -1;
            }
        }
    }
    free(chunks);
    return r;
}

static inline
unsigned short repo_domain_map_get_max_repos(
    struct repo_domain_map const *const restrict map
) {
    unsigned short max_domain_repos = 0;
    for (unsigned long i = 0; i < map->groups_count; ++i) {
        if (map->groups[i].repos_count > max_domain_repos) {
            max_domain_repos = map->groups[i].repos_count;
        }
    }
    return max_domain_repos;
}

int work_handle_update_all_repos(
    struct work_handle *const restrict work_handle
) {
    if (!work_handle->repos_count) {
        pr_error("No repos defined\n");
        return -1;
    }
    work_handle_set_need_update_all_repos(work_handle);
    struct repo_domain_map map;
    if (repo_domain_map_init(&map, work_handle->repos, 
                            work_handle->repos_count)) 
    {
        pr_error("Failed to map repos by domain");
        return -1;
    }
    int r;
    if (!map.groups_count) {
        pr_warn("Repos map is empty\n");
        r = 0;
        goto free_map;
    }
    repo_domain_map_print(&map, work_handle->string_buffer.buffer);
    unsigned short max_connections = 
        work_handle->connections_per_server > 1 ? 
            work_handle->connections_per_server: 1;
    unsigned short const max_domain_repos = repo_domain_map_get_max_repos(&map);
    if (max_connections > max_domain_repos) {
        max_connections = max_domain_repos;
    }
    pr_info("Connections per domain group: %hu\n", max_connections);
    char const *restrict proxy_url;
    if (work_handle->len_proxy_url) {
        proxy_url =
            work_handle->string_buffer.buffer + work_handle->proxy_url_offset;
    } else {
        proxy_url = NULL;
    }
    git_fetch_options fetch_opts = gmr_fetch_options_init(
        work_handle->cb_sideband, work_handle->cb_fetch,
        proxy_url, work_handle->proxy_after);
    struct gmr_repo_update_thread_arg thread_arg_init = {
        .fetch_opts_orig = &fetch_opts,
        .finished = false,
        .proxy_after = work_handle->proxy_after,
        .r = 0,
        .repo = NULL,
        .url = NULL,
        .last_transfer = 0,
    };
    if (repo_domain_map_update(&map, max_connections, &thread_arg_init, 
            work_handle->string_buffer.buffer)) {
        pr_error("Failed to update all repos with domain map\n");
        r = -1;
        goto free_map;
    }
    r = 0;
free_map:
    repo_domain_map_free(&map);
    return r;
}

int repo_work_add_wanted_reference_common(
    struct repo_work *const restrict repo,
    struct string_buffer *const restrict sbuffer,
    enum wanted_type const type,
    char const *const restrict name,
    unsigned short const len_name,
    bool const archive,
    bool const checkout
) {
    unsigned short const name_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, name, len_name)) {
        pr_error("Failed to append reference name '%s' to string buffer\n",
                    name);
        return -1;
    }
    if (dynamic_array_add_to(repo->wanted_objects)) {
        pr_error("Failed to allocate new wanted object\n");
        return -1;
    }
    struct wanted_reference *wanted_reference = 
        (struct wanted_reference *)(get_last(repo->wanted_objects));
    wanted_reference->type = type;
    wanted_reference->commit_parsed = false;
    wanted_reference->archive = archive;
    wanted_reference->checkout = checkout;
    wanted_reference->type = type;
    wanted_reference->name_offset = name_offset;
    wanted_reference->len_name = len_name;
    return 0;
}

static inline
int repo_work_add_wanted_reference(
    struct repo_work *const restrict repo,
    struct string_buffer *const restrict sbuffer,
    char const *const restrict name,
    unsigned short const len_name,
    bool const archive,
    bool const checkout
) {
    return repo_work_add_wanted_reference_common(
        repo, sbuffer, WANTED_TYPE_REFERENCE, 
        name, len_name, archive, checkout);
}

static inline
int repo_work_add_wanted_branch(
    struct repo_work *const restrict repo,
    struct string_buffer *const restrict sbuffer,
    char const *const restrict name,
    unsigned short const len_name,
    bool const archive,
    bool const checkout
) {
    return repo_work_add_wanted_reference_common(
        repo, sbuffer, WANTED_TYPE_BRANCH, 
        name, len_name, archive, checkout);
}

static inline
int repo_work_add_wanted_tag(
    struct repo_work *const restrict repo,
    struct string_buffer *const restrict sbuffer,
    char const *const restrict name,
    unsigned short const len_name,
    bool const archive,
    bool const checkout
) {
    return repo_work_add_wanted_reference_common(
        repo, sbuffer, WANTED_TYPE_TAG, 
        name, len_name, archive, checkout);
}

int repo_work_parse_wanted_all_branches(
    struct repo_work *const restrict repo,
    struct wanted_base *const restrict wanted_all_branches,
    struct string_buffer *const restrict sbuffer
) {
    char const *const restrict url = buffer_get_string(sbuffer, repo->url);
    git_branch_iterator *branch_iterator;
    int r = git_branch_iterator_new(
        &branch_iterator, repo->git_repository, GIT_BRANCH_LOCAL);
    if (r) {
        pr_error_with_libgit_error(
            "Failed to create branch iterator for repo '%s'", url);
        return -1;
    }
    git_reference *reference = NULL;
    git_branch_t branch_t;
    pr_info("Iterating through all branches of repo '%s' to create "
            "individual wanted branches\n", url);
    unsigned long i = repo->wanted_objects_count;
    bool bad_branch = false;
    while ((r = git_branch_next(
        &reference, &branch_t, branch_iterator)) == GIT_OK) {
        char const *reference_name = git_reference_name(reference);
        if (branch_t != GIT_BRANCH_LOCAL) {
            pr_error("Found branch '%s' is not local\n", reference_name);
            bad_branch = true;
            continue;
        }
        if (strncmp(reference_name, "refs/heads/", 11)) {
            pr_error("Reference '%s' does not start with 'refs/heads/'\n",
                    reference_name);
            bad_branch = true;
            continue;
        }
        reference_name += 11;
        size_t const len_name = strlen(reference_name);
        if (repo_work_add_wanted_branch(
            repo, sbuffer, reference_name, len_name,
            wanted_all_branches->archive, wanted_all_branches->checkout)) 
        {
            pr_error("Failed to add branch '%s' as wannted to "
                    "repo '%s'\n", reference_name, url);
            bad_branch = true;
            continue;
        }
        git_reference_free(reference);
    }
    git_branch_iterator_free(branch_iterator);
    pr_info("All branches:");
    for (; i < repo->wanted_objects_count; ++i) {
        printf(" '%s'", buffer_get_string(
                            sbuffer, repo->wanted_objects[i].name));
    }
    putc('\n', stdout);
    switch (r) {
    case GIT_OK:
        pr_error("Got GIT_OK at the end, this shouldn't happen\n");
        return -1;
    case GIT_ITEROVER:
        break;
    default:
        pr_error_with_libgit_error("Failed to iterate through all banches");
        return -1;
    }
    if (bad_branch) return -1;
    return 0;
}

int repo_work_parse_wanted_all_tags(
    struct repo_work *const restrict repo,
    struct wanted_base *const restrict wanted_all_tags,
    struct string_buffer *const restrict sbuffer
) {
    char const *const restrict url = buffer_get_string(sbuffer, repo->url);
    git_strarray tag_names;
    int r = git_tag_list(&tag_names, repo->git_repository);
    if (r) {
        pr_error_with_libgit_error("Failed to list tags for repo '%s'", url);
        return -1;
    }
    r = 0;
    pr_info("Iterating through all tags of repo '%s' to create "
            "individual wanted tags\n", url);
    // The tags do not have refs/tags prefix, but just simply tag names
    unsigned long i = repo->wanted_objects_count;
    for (size_t j = 0; j < tag_names.count; ++j) {
        char const *const restrict tag_name  = tag_names.strings[j];
        if (repo_work_add_wanted_tag(
            repo, sbuffer, tag_name, strlen(tag_name),
            wanted_all_tags->archive, wanted_all_tags->checkout)) 
        {
            pr_error("Failed to add tag '%s' as wannted to "
                    "repo '%s'\n", tag_name, url);
            r = -1;
        }
    }
    git_strarray_free(&tag_names);
    pr_info("All tags:");
    for (; i < repo->wanted_objects_count; ++i) {
        printf(" '%s'", buffer_get_string(sbuffer, 
                        repo->wanted_objects[i].name));
    }
    putc('\n', stdout);
    return r;
}

int repo_work_add_commit(
    struct repo_work *const restrict repo,
    git_oid const *const restrict oid,
    unsigned int oid_hex_offset,
    struct string_buffer *const restrict sbuffer
) {
    if (dynamic_array_add((void **)&repo->commits,
                        sizeof *repo->commits,
                        &repo->commits_count,
                        &repo->commits_allocated))
    {
        pr_error("Failed to allocate new parsed commit\n");
        return -1;
    }
    struct commit *commit = get_last(repo->commits);
    memset(commit, 0, sizeof *commit);
    if (!oid_hex_offset) {
        oid_hex_offset = sbuffer->used;
        if (format_oid_to_string_buffer(oid, sbuffer)) {
            pr_error("Failed to format git oid string to buffer\n");
            return -1;
        }
    }
    commit->oid = *oid;
    commit->oid_hex_offset = oid_hex_offset;
    return 0;
}

// May re-allocate repo->parsed_commits
int repo_work_parse_wanted_commit(
    struct repo_work *const restrict repo,
    struct wanted_commit *const restrict wanted_commit,
    struct string_buffer *const restrict sbuffer
) {
    for (unsigned long i = 0; i < repo->commits_count; ++i) {
        if (!git_oid_cmp(&repo->commits[i].oid, &wanted_commit->oid)) {
            wanted_commit->parsed_commit_id = i;
            goto sync_export_setting;
        }
    }
    if (repo_work_add_commit(repo, &wanted_commit->oid, 
            wanted_commit->oid_hex_offset, sbuffer)) 
    {
        pr_error("Failed to add parsed commit\n");
        return -1;
    }
    wanted_commit->parsed_commit_id = repo->commits_count - 1;
sync_export_setting:
    struct commit *commit =
        repo->commits + wanted_commit->parsed_commit_id;
    if (wanted_commit->archive) commit->archive = true;
    if (wanted_commit->checkout) commit->checkout = true;
    return 0;
}


// May re-allocate repo->parsed_commits
int repo_work_parse_wanted_reference_common(
    struct repo_work *const restrict repo,
    struct wanted_reference *const restrict wanted_reference,
    git_reference *reference,
    struct string_buffer *const restrict sbuffer
) {
    git_object *object;
    int r = git_reference_peel(&object, reference, GIT_OBJECT_COMMIT);
    if (r) {
        pr_error_with_libgit_error(
            "Failed to peel reference '%s' into a commit object",
            git_reference_name(reference));
        repo->need_update = true;
        return -1;
    }
    git_commit *commit = (git_commit *)object;
    wanted_reference->oid = *git_commit_id(commit);
    git_object_free(object);
    wanted_reference->commit_parsed = true;
    wanted_reference->oid_hex_offset = sbuffer->used;
    if (format_oid_to_string_buffer(&wanted_reference->oid, sbuffer)) {
        pr_error("Failed to format git oid string to buffer\n");
        return -1;
    }
    pr_info("Repo '%s' reference parsed: '%s' => %s\n", 
        buffer_get_string(sbuffer, repo->url),
        git_reference_name(reference),
        buffer_get_string(sbuffer, wanted_reference->oid_hex));
    return repo_work_parse_wanted_commit(repo,
            (struct wanted_commit *)wanted_reference, sbuffer);
}

static inline
int repo_work_parse_wanted_reference_looked_up(
    struct repo_work *const restrict repo,
    struct wanted_reference *const restrict wanted_reference,
    git_reference *reference,
    struct string_buffer *const restrict sbuffer,
    char const *const restrict reftype,
    char const *const restrict refname,
    int r
) {
    char const *const url = buffer_get_string(sbuffer, repo->url);
    switch (r) {
        case 0:
            r = repo_work_parse_wanted_reference_common(
                repo, wanted_reference, reference, sbuffer);
            git_reference_free(reference);
            return r;
        case GIT_ENOTFOUND:
            pr_error("Failed to lookup %s '%s' from '%s': not found\n",
                        reftype, refname, url);
            repo->need_update = true;
            break;
        case GIT_EINVALID:
            pr_error("Failed to lookup %s '%s' from '%s': invalid ref\n",
                        reftype, refname, url);
            break;
        default:
            pr_error_with_libgit_error(
                "Failed to lookup %s '%s' from '%s'", reftype, refname, url);
            break;
    }
    return -1;
}

int repo_work_parse_wanted_reference(
    struct repo_work *const restrict repo,
    struct wanted_reference *const restrict wanted_reference,
    struct string_buffer *const restrict sbuffer
) {
    char const *const refname = buffer_get_string(
        sbuffer, wanted_reference->name);
    git_reference *reference;
    int r = git_reference_lookup(&reference, repo->git_repository, refname);
    return repo_work_parse_wanted_reference_looked_up(
        repo, wanted_reference, reference, sbuffer, "reference", refname, r);
}

int repo_work_parse_wanted_branch(
    struct repo_work *const restrict repo,
    struct wanted_reference *const restrict wanted_branch,
    struct string_buffer *const restrict sbuffer
) {
    char const *const branch = buffer_get_string(
        sbuffer, wanted_branch->name);
    git_reference *reference;
    int r = git_branch_lookup(&reference, repo->git_repository, branch, 
                            GIT_BRANCH_LOCAL);
    return repo_work_parse_wanted_reference_looked_up(
        repo, wanted_branch, reference, sbuffer, "branch", branch, r);
}


int repo_work_parse_wanted_tag(
    struct repo_work *const restrict repo,
    struct wanted_reference *const restrict wanted_tag,
    struct string_buffer *const restrict sbuffer
) {
    char const *const tag = buffer_get_string(sbuffer, wanted_tag->name);
    char refname_stack[0x100];
    char *refname_heap = NULL;
    char *refname = refname_stack;
    unsigned short const len_refname = wanted_tag->len_name + 10; // refs/tags/
    if (len_refname >= 0x100) {
        if (!(refname_heap = malloc(len_refname))) {
            pr_error_with_errno("Failed to allocate name for long tag '%s'",
                                tag);
            return -1;
        }
        refname = refname_heap;
    }
    memcpy(refname, "refs/tags/", 10);
    memcpy(refname + 10, tag, wanted_tag->len_name);
    refname[len_refname] = '\0';
    git_reference *reference;
    int r = git_reference_lookup(&reference, repo->git_repository, refname);
    r = repo_work_parse_wanted_reference_looked_up(
        repo, wanted_tag, reference, sbuffer, "tag", tag, r);
    free_if_allocated(refname_heap);
    return r;
}

// May re-allocate repo->parsed_commits
int repo_work_parse_wanted_head(
    struct repo_work *const restrict repo,
    struct wanted_reference *const restrict wanted_head,
    struct string_buffer *const restrict sbuffer
) {
    char const *const url = buffer_get_string(sbuffer, repo->url);
    git_reference *head;
    int r = git_repository_head(&head, repo->git_repository);
    switch (r) {
        case 0:
            pr_info("Repo '%s' HEAD parsed: '%s'\n", url, 
                git_reference_name(head));
            r = repo_work_parse_wanted_reference_common(
                repo, wanted_head, head, sbuffer);
            git_reference_free(head);
            return r;
        case GIT_EUNBORNBRANCH:
            pr_error("Failed to lookup HEAD from '%s': unborn\n", url);
            repo->need_update = true;
            break;
        case GIT_ENOTFOUND:
            pr_error("Failed to lookup HEAD from '%s': not found\n", url);
            repo->need_update = true;
            break;
        default:
            pr_error_with_libgit_error("Failed to lookup HEAD from '%s'", url);
            break;
    }
    return -1;
}

int commit_add_submodule_in_tree(
    struct commit *const restrict commit,
    git_tree const *const restrict tree,
    char const *const restrict path,
    unsigned short const len_path,
    char const *const restrict url,
    unsigned short const len_url,
    struct string_buffer *const restrict sbuffer
) {
    for (unsigned long i = 0; i < commit->submodules_count; ++i) {
        if (!strcmp(buffer_get_string(sbuffer, commit->submodules[i].path),
                     path)) 
        {
            pr_error("Already defined a submodule at path '%s' for commit %s\n",
                    path, buffer_get_string(sbuffer, commit->oid_hex));
            return -1;
        }
    }
    unsigned path_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, path, len_path)) {
        pr_error("Failed to add path to string buffer");
        return -1;
    }
    unsigned url_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, url, len_url)) {
        pr_error("Failed to add url to string buffer");
        return -1;
    }
    if (dynamic_array_add_to(commit->submodules)) {
        pr_error("Failed to allocate new submodule\n");
        return -1;
    }
    struct submodule *const restrict submodule = get_last(commit->submodules);
    git_tree_entry *entry;
    int r;
    if (git_tree_entry_bypath(&entry, tree, path)) {
        pr_error("Path '%s' of submodule does not exist in tree\n", path);
        r = -1;
        goto reduce_count;
    }
    if (git_tree_entry_type(entry) != GIT_OBJECT_COMMIT) {
        pr_error("Object at path '%s' in tree is not a commit\n", path);
        r = -1;
        goto free_entry;
    }
    submodule->oid = *git_tree_entry_id(entry);
    submodule->oid_hex_offset = sbuffer->used;
    if (format_oid_to_string_buffer(&submodule->oid, sbuffer)) {
        pr_error("Failed to format submdoule ID to string buffer\n");
        r = -1;
        goto free_entry;
    }
    submodule->target_commit_id = -1;
    submodule->target_repo_id = -1;
    submodule->hash_url = hash_calculate(url, len_url);
    submodule->path_offset = path_offset;
    submodule->url_offset = url_offset;
    submodule->len_path = len_path;
    submodule->len_url = len_url;
    pr_info("Submodule added: '%s' <= '%s': %s\n",
            buffer_get_string(sbuffer, submodule->path),
            buffer_get_string(sbuffer, submodule->url),
            buffer_get_string(sbuffer, submodule->oid_hex));
    r = 0;
free_entry:
    git_tree_entry_free(entry);
reduce_count:
    if (r) {
        sbuffer->used = path_offset;
        --commit->submodules_count;
    }
    return r;
}

int work_handle_add_repo_bare(
    struct work_handle *const restrict work_handle,
    char const *const restrict url,
    unsigned short const len_url
) {
    if (dynamic_array_add_to(work_handle->repos)) {
        pr_error("Failed to allocate memory for new repo");
        return -1;
    }
    struct repo_work *const restrict repo = get_last(work_handle->repos);
    int r;
    if (repo_common_init_from_url(&repo->common, &work_handle->string_buffer, 
        url, len_url)) 
    {
        pr_error("Failed to init common part of new repo\n");
        r = -1;
        goto reduce_count;
    }
    repo->wanted_objects = NULL;
    repo->wanted_objects_allocated = 0;
    repo->wanted_objects_count = 0;
    repo->from_config = false;
    repo->wanted_dynamic = false;
    repo->git_repository = NULL;
    repo_work_finish_bare(repo);
    r = 0;
reduce_count:
    if (r) --work_handle->repos_count;
    return r;
}

int work_handle_parse_repo_commit(
    struct work_handle *const restrict work_handle,
    unsigned long const repo_id,
    unsigned long const commit_id
);

// // May re-allocate config->repos
int work_handle_parse_repo_commit_submodule_in_tree(
    struct work_handle *const restrict work_handle,
    unsigned long const repo_id,
    unsigned long const commit_id,
    git_tree const *const restrict tree,
    char const *const restrict path,
    unsigned short const len_path,
    char const *const restrict url,
    unsigned short const len_url
) {
    struct repo_work const *repo = work_handle->repos + repo_id;
    struct commit *commit = repo->commits + commit_id;
    if (commit_add_submodule_in_tree(commit, tree, path, len_path, url, len_url,
         &work_handle->string_buffer)) 
    {
        pr_error("Failed to add submodule from commit tree\n");
        return -1;
    }
    struct submodule *const restrict submodule = get_last(commit->submodules);
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        struct repo_work *const repo_cmp = work_handle->repos + i;
        if (repo_cmp->hash_url == submodule->hash_url) {
            submodule->target_repo_id = i;
            for (unsigned long j = 0; j < repo_cmp->commits_count; ++j) {
                if (git_oid_cmp(&submodule->oid, &repo_cmp->commits[j].oid)) 
                    continue;
                submodule->target_commit_id = j;
                return 0;
            }
            break;
        }
    }
    int r;
    if (submodule->target_repo_id == (unsigned long) -1) {
        pr_warn("Repo '%s' was not seen before, need to add it\n", url);
        if (work_handle_add_repo_bare(work_handle, url, len_url)) {
            pr_error("Failed to add repo\n");
            r = -1;
            goto reduce_count;
        }
        if (repo_work_open_one(get_last(work_handle->repos), 
            work_handle->string_buffer.buffer, work_handle->dir_repos.datafd, 
            work_handle->cwd)) 
        {
            pr_error("Failed to open added repo");
            r = -1;
            goto reduce_count;
        }
        repo = work_handle->repos + repo_id;
        submodule->target_repo_id = work_handle->repos_count - 1;
    }
    if (submodule->target_repo_id == (unsigned long) -1) {
        pr_error("Submodule '%s' with url '%s' for commmit %s of repo '%s' "
        "still missing target repo id, refuse to continue\n",
            path, url, work_handle_get_string(submodule->oid_hex), 
            work_handle_get_string(repo->url));
        r = -1;
        goto reduce_count;
    }
    if (submodule->target_commit_id != (unsigned long) -1) return 0;
    struct repo_work *repo_target =
        work_handle->repos + submodule->target_repo_id;
    // The repo is either completely new, or we found it but not found commit
    // There is no need to check for commit duplication here
    if (repo_work_add_commit(repo_target, &submodule->oid, 
        submodule->oid_hex_offset, &work_handle->string_buffer)) 
    {
        pr_error("Failed to add parsed commit to repo\n");
        r = -1;
        goto reduce_count;
    }
    submodule->target_commit_id = repo_target->commits_count - 1;
    if (submodule->target_repo_id >= repo_id) {
        return 0;
    }
    pr_warn("Added commit %s as wanted to parsaed repo '%s', need to go back "
            "to handle that specific commit\n",
            work_handle_get_string(submodule->oid_hex),
            work_handle_get_string(repo_target->url));
    if (work_handle_parse_repo_commit(work_handle, submodule->target_repo_id, 
        submodule->target_commit_id)) 
    {
        pr_error("Failed to go back to parse commit in a parsed repo\n");
        r = -1;
        goto reduce_count;
    }
    r = 0;
reduce_count:
    if (r) {
        --commit->submodules_count;
    }
    return 0;
}


// May re-allocate the config->repos array, must re-assign repo after calling
int work_handle_parse_repo_commit_blob_gitmodules(
    struct work_handle *const restrict work_handle,
    unsigned long const repo_id,
    unsigned long const commit_id,
    git_tree const *const restrict tree,
    git_blob *const restrict blob
) {
    struct repo_work const *const restrict repo = work_handle->repos + repo_id;
    struct commit const *const restrict commit = repo->commits + commit_id;
    pr_info("Parsing submodule of repo '%s' commit %s\n", 
            work_handle_get_string(repo->url), 
            work_handle_get_string(commit->oid_hex));
    char const *buffer_all = git_blob_rawcontent(blob);
    if (!buffer_all) {
        pr_error("Failed to get a ro buffer for gitmodules\n");
        return -1;
    }
    git_object_size_t len_all = git_blob_rawsize(blob);
    if (!len_all) {
        pr_error("Tree entry .gitmodules blob size is 0\n");
        return -1;
    }
    char name_stack[0x100],
         path_stack[0x100],
         url_stack[0x100],
         *name_heap = NULL,
         *path_heap = NULL,
         *url_heap = NULL,
         *name = name_stack,
         *path = path_stack,
         *url = url_stack;
    unsigned short  len_path = 0,
                    len_url = 0,
                    name_allocated = 0x100,
                    path_allocated = 0x100,
                    url_allocated = 0x100;
    name[0] = '\0';
    path[0] = '\0';
    url[0] = '\0';
    int r;
    for (git_object_size_t start = 0; start < len_all; ) {
        switch (buffer_all[start]) {
        case '\0':
        case '\b':
        case '\n':
        case '\r':
            ++start;
            continue;
        }
        unsigned short len_line = 0;
        git_object_size_t end = start + 1;
        for (; end < len_all && len_line == 0;) {
            switch (buffer_all[end]) {
            case '\0':
            case '\n':
                len_line = end - start;
                break;
            default:
                ++end;
                break;
            }
        }
        if (len_line <= 7) {
            start = end + 1;
            continue;
        }
        char const *line = buffer_all + start;
        char const *line_end = buffer_all + end;
        switch (buffer_all[start]) {
        case '[':
            if (!strncmp(line + 1, "submodule \"", 11)) {
                if (name[0]) {
                    pr_error("Incomplete submodule definition for '%s'\n",name);
                    r = -1;
                    goto free_heap;
                }
                char const *name_start = line + 12;
                char const *right_quote = name_start;
                for (;
                    *right_quote != '"' && right_quote < line_end;
                    ++right_quote);
                unsigned short len_name = 
                    right_quote - name_start;
                if (len_name >= name_allocated) {
                    name_allocated = (len_name + 2) / 0x1000  * 0x1000;
                    if (name_heap) free(name_heap);
                    if (!(name_heap = malloc(name_allocated))) {
                        pr_error_with_errno("Failed to allocate memory for long"
                            " submodule name");
                        r = -1;
                        goto free_heap;
                    }
                    name = name_heap;
                }
                memcpy(name, name_start, len_name);
                name[len_name] = '\0';
            }
            break;
        case '\t':
            char const *parsing_value = NULL;
            char **value = NULL;
            char **value_heap = NULL;
            unsigned short *len_value = NULL;
            unsigned short *value_allocated = NULL;
            if (!strncmp(line + 1, "path = ", 7)) {
                parsing_value = line + 8;
                value = &path;
                value_heap = &path_heap;
                len_value = &len_path;
                value_allocated = &path_allocated;
            } else if (!strncmp(line + 1, "url = ", 6)) {
                parsing_value = line + 7;
                value = &url;
                value_heap = &url_heap;
                len_value = &len_url;
                value_allocated = &url_allocated;
            }
            if (!value) {
                break;
            }
            if (!name[0]) {
                pr_error("Submodule definition begins before the submodule "
                          "name\n");
                r = -1;
                goto free_heap;
            }
            if ((*value)[0]) {
                pr_error("Duplicated value definition for submodule '%s'\n", 
                        name);
                r = -1;
                goto free_heap;
            }
            *len_value = line_end - parsing_value;
            if (*len_value >= *value_allocated) {
                *value_allocated = (*len_value + 2) / 0x1000  * 0x1000;
                if (*value_heap) free(*value_heap);
                if (!(*value_heap = malloc(*value_allocated))) {
                    pr_error_with_errno("Failed to allocate memory for long"
                        " submodule value");
                    r = -1;
                    goto free_heap;
                }
                *value = *value_heap;
            }
            memcpy(*value, parsing_value, *len_value);
            (*value)[*len_value] = '\0';
            if (path[0] && url[0]); else break;
            if (!memcmp(url + len_url - 4, ".git", 4)) {
                len_url -= 4;
                url[len_url] = '\0';
            }
            pr_info("Submodule '%s', path '%s', url '%s'\n", name, path, url);
            if (work_handle_parse_repo_commit_submodule_in_tree(work_handle, 
                repo_id, commit_id, tree, path, len_path, url, len_url)) 
            {
                pr_error("Failed to add parse commit submodule in tree");
                r = -1;
                goto free_heap;
            }
            name[0] = '\0';
            path[0] = '\0';
            url[0] = '\0';
            break;
        default:
            break;
        }
        start = end + 1;
    }
    r = 0;
free_heap:
    free_if_allocated(name_heap);
    free_if_allocated(path_heap);
    free_if_allocated(url_heap);
    return r;
}

int work_repo_parse_wanted_objects(
    struct repo_work *const restrict repo,
    struct string_buffer *const restrict sbuffer
) {
    char const *const restrict url = buffer_get_string(sbuffer, repo->url);
    int r = 0;
    for (unsigned long i = 0; i < repo->wanted_objects_count; ++i) {
        struct wanted_object *const restrict wanted_object
            = repo->wanted_objects + i;
        switch (wanted_object->type) {
        case WANTED_TYPE_ALL_BRANCHES:
            if (repo_work_parse_wanted_all_branches(repo, 
                (struct wanted_base *)wanted_object, sbuffer)) 
            {
                pr_error("Failed to parse wanted all branches for repo '%s'\n",
                        url);
                r = -1;
            }
            break;
        case WANTED_TYPE_ALL_TAGS:
            if (repo_work_parse_wanted_all_tags(repo,
                (struct wanted_base *)wanted_object, sbuffer)) 
            {
                pr_error("Failed to parse wanted all tags for repo '%s'\n",url);
                r = -1;
            }
            break;
        case WANTED_TYPE_REFERENCE:
            if (repo_work_parse_wanted_reference(repo,
                (struct wanted_reference *)wanted_object, sbuffer)) 
            {
                pr_error(
                    "Failed to parsed wanted reference '%s'  for repo '%s'\n",
                    buffer_get_string(sbuffer, wanted_object->name), url);
                return -1;
            }
            break;
        case WANTED_TYPE_BRANCH:
            if (repo_work_parse_wanted_branch(repo,
                (struct wanted_reference *)wanted_object, sbuffer)) 
            {
                pr_error(
                    "Failed to parsed wanted branch '%s'  for repo '%s'\n",
                    buffer_get_string(sbuffer, wanted_object->name), url);
                return -1;
            }
            break;
        case WANTED_TYPE_TAG:
            if (repo_work_parse_wanted_tag(repo,
                (struct wanted_reference *)wanted_object, sbuffer)) 
            {
                pr_error(
                    "Failed to parsed wanted tag '%s'  for repo '%s'\n",
                    buffer_get_string(sbuffer, wanted_object->name), url);
                return -1;
            }
            break;
        case WANTED_TYPE_HEAD:
            if (repo_work_parse_wanted_head(repo,
                (struct wanted_reference *)wanted_object, sbuffer)) 
            {
                pr_error("Failed to parsed wanted HEAD for repo '%s'\n", url);
                return -1;
            }
            break;
        case WANTED_TYPE_COMMIT:
            if (repo_work_parse_wanted_commit(repo,
                (struct wanted_commit *)wanted_object, sbuffer)) 
            {
                pr_error(
                    "Failed to parse wanted commit %s for repo '%s'\n",
                    buffer_get_string(sbuffer, wanted_object->oid_hex), url);
                return -1;
            }
            break;
        case WANTED_TYPE_UNKNOWN:
        default:
            pr_error("Impossible wanted type unknown for wanted object '%s' "
                    "for repo '%s'\n",
                    buffer_get_string(sbuffer, wanted_object->name), 
                    url);
            r = -1;
        }
    }
    return r;
}

int work_handle_parse_repo_commit(
    struct work_handle *const restrict work_handle,
    unsigned long const repo_id,
    unsigned long const commit_id
) {
    struct repo_work *restrict repo = work_handle->repos + repo_id;
    struct commit *restrict commit = repo->commits + commit_id;
    char const *restrict oid_hex = work_handle_get_string(commit->oid_hex);
    char const *restrict url = work_handle_get_string(repo->url);
    if (commit->git_commit) return 0; // Already looked up, skip
    int r = git_commit_lookup(&commit->git_commit, repo->git_repository, 
                                &commit->oid);
    if (r) {
        pr_error_with_libgit_error("Failed to lookup commit %s in repo '%s'",
            oid_hex, url);
        repo->need_update = true;
        return -1;
    }
    // Submodules:
    git_tree *tree;
    if ((r = git_commit_tree(&tree, commit->git_commit))) {
        pr_error_with_libgit_error("Failed to get the commit tree pointed by "
            "commit %s in repo '%s'", oid_hex, url);
        r = -1;
        goto free_commit;
    }
    git_tree_entry const *const entry =
        git_tree_entry_byname(tree, ".gitmodules");
    if (!entry) {
        r = 0;
        goto free_tree;
    }
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        pr_error("Tree entry .gitmodules in commit %s for repo '%s' "
                "is not a blob\n", oid_hex, url);
        r = -1;
        goto free_tree;
    }
    git_object *object;
    if ((r = git_tree_entry_to_object(&object, repo->git_repository, entry))) {
        pr_error_with_libgit_error(
            "Failed to convert tree entry for gitmodules to object");
        r = -1;
        goto free_object;
    }
    r = work_handle_parse_repo_commit_blob_gitmodules(
        work_handle, repo_id, commit_id, tree, (git_blob *)object);
    if (r) {
        pr_error("Failed to parse .gitmodules blob in tree");
    }
free_object:
    git_object_free(object);
free_tree:
    git_tree_free(tree);
free_commit:
    if (r) { git_commit_free_to_null(commit->git_commit); }
    else {
        repo = work_handle->repos + repo_id;
        commit = repo->commits + commit_id;
        oid_hex = work_handle_get_string(commit->oid_hex);
        url = work_handle_get_string(repo->url);
        pr_info("Repo '%s' commit robust: %s\n", url, oid_hex);
    }
    return r;
}

static inline
void work_handle_unset_need_update_all_repos(
    struct work_handle *const restrict work_handle
) {
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        struct repo_work *const restrict repo = work_handle->repos + i;
        repo->need_update = false;
        repo->updated = false;
    }
}

static inline
void repo_work_deparse(
    struct repo_work *const restrict repo
) {
    if (repo->git_repository) {
        git_repository_free(repo->git_repository);
        repo->git_repository = NULL;
    }
    repo->wanted_objects_count = repo->wanted_objects_count_original;
    repo->commits_count = 0;
    repo->need_update = false;
    repo->updated = false;
}

static inline
void work_handle_deparse_all_repos(
    struct work_handle *const restrict work_handle,
    unsigned long const repos_count_original,
    unsigned const sbuffer_used_original
) {
    for (unsigned long i = repos_count_original; 
        i < work_handle->repos_count; ++i) 
    {
        repo_work_free(work_handle->repos + i);
    }
    work_handle->repos_count = repos_count_original;
    work_handle->string_buffer.used = sbuffer_used_original;
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        struct repo_work *const restrict repo = work_handle->repos + i;
        repo->wanted_objects_count = repo->wanted_objects_count_original;
        repo->commits_count = 0;
    }
}

static inline
bool work_handle_need_update(
    struct work_handle *const restrict work_handle
) {
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        if (work_handle->repos[i].need_update) return true;
    }
    return false;
}

static inline
int work_handle_parse_all_repos_simple(
    struct work_handle *const restrict work_handle
) {
    int r = 0;
    for (unsigned long i = 0; i < work_handle->repos_count; ++i)
        if (work_repo_parse_wanted_objects(work_handle->repos + i, 
                            &work_handle->string_buffer)) 
            r = -1;
    for (unsigned long i = 0; i < work_handle->repos_count; ++i)
        for (unsigned long j = 0; j < work_handle->repos[i].commits_count; ++j)
            if (work_handle_parse_repo_commit(work_handle, i, j)) r = 1;
    return r;
}

int work_handle_hash_need_update(
    struct work_handle *const restrict work_handle,
    hash_type *hash
) {
    bool flags_stack[0x100];
    bool *flags_heap = NULL;
    bool *flags;
    if (work_handle->repos_count > 0x100) {
        if (!(flags_heap = malloc(work_handle->repos_count))) {
            pr_error_with_errno("Failed to allocate memory for flags on heap");
            return -1;
        }
        flags = flags_heap;
    } else {
        flags = flags_stack;
    }
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        flags[i] = work_handle->repos[i].need_update;
    }
    *hash = hash_calculate(flags, work_handle->repos_count);
    free_if_allocated(flags_heap);
    return 0;
}

int work_handle_parse_all_repos(
    struct work_handle *const restrict work_handle
) {
    work_handle_unset_need_update_all_repos(work_handle);
    unsigned long const repos_count_original = work_handle->repos_count;
    unsigned const sbuffer_used_original = work_handle->string_buffer.used;
    hash_type hash_need_update_last = 0, hash_need_update;
    int r;
    for (unsigned short i = 0; i < 100; ++i) {
        r = work_handle_parse_all_repos_simple(work_handle);
        if (!work_handle_need_update(work_handle)) return r;
        pr_warn("Some repos are not robust and some need to be updated, "
            "re-update the repos before we re-check the rebostness\n");
        if (work_handle_hash_need_update(work_handle, &hash_need_update)) {
            pr_error("Failed to hash need-update flags\n");
            return -1;
        }
        if (i) {
            if (hash_need_update == hash_need_update_last) {
                pr_error("Hash of need-update flags same as last, giving up\n");
                return -1;
            }
        }
        hash_need_update_last = hash_need_update;
        if (work_handle_update_all_repos(work_handle)) {
            pr_error("Failed to re-udpate all repos");
            return -1;
        };
        work_handle_deparse_all_repos(work_handle, repos_count_original, 
            sbuffer_used_original);
    }
    pr_error("Too many iterations, giving up\n");
    return -1;
}

// int work_directory_add_keep(
//     struct work_directory *const restrict work_directory,
//     char const *const restrict keep,
//     unsigned short const len_keep
// ) {
//     if (work_directory_add_keep_no_init(work_directory)) {
//         pr_error("Failed to add keep to work directory\n");
//         return -1;
//     }
//     if (len_keep >= sizeof *work_directory->keeps) {
//         pr_error("Length of keep item '%s' too long\n", keep);
//         return -1;
//     }
//     char *keep_last = (char *)(get_last(work_directory->keeps));
//     memcpy(keep_last, keep, len_keep);
//     keep_last[len_keep] = '\0';
//     return 0;
// }

// static inline
// void keep_list_swap_item(
//     char (*keeps)[NAME_MAX + 1],
//     unsigned long const i,
//     unsigned long const j,
//     unsigned short const memlen // including terminating \0
// ) {
//     if (i == j) return;
//     char buffer[NAME_MAX + 1];
//     // keeps[i] and keeps + i points to the same memory address
//     // Type: keeps[i]  : char[256], collapsing to char *
//     //       keeps + i : char (*)[256], won't collapse
//     // Use memcpy instead of strcpy to save strlen call
//     memcpy(buffer, keeps + i, memlen);
//     memcpy(keeps + i, keeps + j, memlen);
//     memcpy(keeps + j, buffer, memlen);
// }

// static inline
// unsigned long keep_list_partition(
//     char (*keeps)[NAME_MAX + 1],
//     unsigned long const low,
//     unsigned long const high,
//     unsigned short const memlen
// ) {
//     char *pivot = keeps[high];
//     unsigned long i = low - 1;
//     for (unsigned long j = low; j < high; ++j) {
//         pr_debug("Comparing '%s' vs '%s'\n", keeps[j], pivot);
//         if (strcmp(keeps[j], pivot) < 0) {
//             keep_list_swap_item(keeps, ++i, j, memlen);
//         }
//     }
//     keep_list_swap_item(keeps, ++i, high, memlen);
//     return i;
// }

// void keep_list_quick_sort(
//     char (*keeps)[NAME_MAX + 1],
//     unsigned long const low,
//     unsigned long const high,
//     unsigned short const memlen
// ) {
//     pr_debug("Soring %lu to %lu\n", low, high);
//     if (low < high) {
//         pr_debug("Into %lu to %lu\n", low, high);
//         unsigned long const pivot = keep_list_partition(
//                                 keeps, low, high, memlen);
//          // if pivot is 0, that will make the new high (ulong) -1
//         if (pivot) keep_list_quick_sort(keeps, low, pivot - 1, memlen);
//         keep_list_quick_sort(keeps, pivot + 1, high, memlen);
//     }
//     pr_debug("Ended sorting %lu to %lu\n", low, high);
// }

// // 1 dir empty (now), 0 dir non empty, -1 error
// int remove_dead_symlinks_recursively_at(
//     int const dir_fd,
//     unsigned short const pass
// ) {
//     if (pass == 0) return 0;
//     int dirfd_dup = dup(dir_fd);
//     if (dirfd_dup < 0) {
//         pr_error_with_errno("Failed to duplicate fd");
//         return -1;
//     }
//     DIR *dir_p = fdopendir(dirfd_dup);
//     if (dir_p == NULL) {
//         if (close(dirfd_dup)) {
//             pr_error_with_errno("Failed to close uplicated fd");
//         }
//         return -1;
//     }
//     struct dirent *entry;
//     errno = 0;
//     int r = -1;
//     for (unsigned short i = 0; i < pass; ++i) {
//         while ((entry = readdir(dir_p)) != NULL) {
//             switch (entry->d_name[0]) {
//             case '\0':
//                 continue;
//             case '.':
//                 switch (entry->d_name[1]) {
//                 case '\0':
//                     continue;
//                 case '.':
//                     if (entry->d_name[2] == '\0')
//                         continue;
//                     break;
//                 }
//                 break;
//             }
//             switch (entry->d_type) {
//             case DT_DIR: {
//                 int const link_fd = openat(
//                     dir_fd, entry->d_name, O_RDONLY | O_DIRECTORY);
//                 if (link_fd < 0) {
//                     pr_error_with_errno("Failed to open subdir '%s'",
//                                         entry->d_name);
//                     r = -1;
//                     goto close_dir;
//                 }
//                 r = remove_dead_symlinks_recursively_at(link_fd, pass);
//                 if (close(link_fd)) {
//                     pr_error_with_errno("Failed to close subdir '%s'",
//                         entry->d_name);
//                     r = -1;
//                 }
//                 if (r < 0) {
//                     pr_error(
//                         "Failed to remove dead symlinks recursively at '%s'\n",
//                                 entry->d_name);
//                     r = -1;
//                     goto close_dir;
//                 }
//                 if (r > 0) {
//                     if (unlinkat(dir_fd, entry->d_name, AT_REMOVEDIR)) {
//                         pr_error_with_errno(
//                             "Failed to remove empty folder '%s'",
//                                 entry->d_name);
//                         r = -1;
//                         goto close_dir;
//                     }
//                 }
//                 break;
//             }
//             case DT_LNK: {
//                 char path[PATH_MAX];
//                 ssize_t len_path = readlinkat(
//                         dir_fd, entry->d_name, path, PATH_MAX);
//                 if (len_path < 0) {
//                     pr_error_with_errno(
//                         "Failed to readlink '%s'", entry->d_name);
//                     r = -1;
//                     goto close_dir;
//                 }
//                 path[len_path] = '\0';
//                 struct stat stat_buffer;
//                 if (fstatat(dir_fd, path, &stat_buffer,
//                     AT_SYMLINK_NOFOLLOW) == 0) break;
//                 errno = 0;
//                 if (unlinkat(dir_fd, entry->d_name, 0)) {
//                     pr_error_with_errno(
//                         "Failed to remove dead link '%s'", path);
//                     r = -1;
//                     goto close_dir;
//                 }
//                 pr_debug("Removed dead link '%s'\n", path);
//                 break;
//             }
//             default: continue;
//             }
//         }
//         if (errno) {
//             pr_error_with_errno("Failed to read dir");
//             r = -1;
//             goto close_dir;
//         }
//         rewinddir(dir_p);
//     }
//     errno = 0;
//     unsigned short entries_count = 0;
//     while ((entry = readdir(dir_p)) != NULL) {
//         if (++entries_count > 2) break;
//     }
//     if (entries_count < 2) {
//         pr_error("Directory entry count smaller than 2, which is impossible\n");
//         r = -1;
//         goto close_dir;
//     }
//     if (entries_count == 2) r = 1;
//     else r = 0;
// close_dir:
//     if (closedir(dir_p)) {
//         pr_error_with_errno("Failed to close dir");
//     }
//     return r;
// }

// int work_directory_clean(
//     struct work_directory *const restrict workdir,
//     unsigned short clean_links_pass,
//     unsigned short const keep_memlen // including the terminating \0
// ) {
//     pr_info("Cleaning '%s'\n", workdir->path);
//     int fd_dup = dup(workdir->dirfd);
//     if (fd_dup < 0) {
//         pr_error_with_errno("Failed to duplicate fd for '%s'", workdir->path);
//         return -1;
//     }
//     DIR *dir_p = fdopendir(fd_dup);
//     if (dir_p == NULL) {
//         pr_error("Failed to opendir '%s'\n", workdir->path);
//         if (close(fd_dup)) {
//             pr_error_with_errno("Failed to close duplicated fd for '%s'",
//                                 workdir->path);
//         }
//         return -1;
//     }
//     // Quick sort the keeps list
// #ifdef DEBUGGING
//     for (unsigned long i = 0; i < workdir->keeps_count; ++i) {
//         pr_debug("[Before] Keeping '%s'\n", workdir->keeps[i]);
//     }
// #endif
//     keep_list_quick_sort(workdir->keeps, 0, workdir->keeps_count - 1,
//         keep_memlen > NAME_MAX + 1 ? NAME_MAX + 1 : keep_memlen);
// #ifdef DEBUGGING
//     for (unsigned long i = 0; i < workdir->keeps_count; ++i) {
//         pr_debug("[After] Keeping '%s'\n", workdir->keeps[i]);
//     }
// #endif
//     // Iterate over the folder to remove things not in kept list
//     // unsigned long keeps_count = workdir->keeps_count;
//     struct dirent *entry;
//     errno = 0;
//     int r = -1;
//     // Condition at outer level to reduce comparison
//     if (workdir->keeps_count) {
//         while ((entry = readdir(dir_p)) != NULL) {
//             switch (entry->d_name[0]) {
//             case '\0':
//                 continue;
//             case '.':
//                 switch (entry->d_name[1]) {
//                 case '\0':
//                     continue;
//                 case '.':
//                     if (entry->d_name[2] == '\0')
//                         continue;
//                     break;
//                 }
//                 break;
//             }
//             switch (entry->d_type) {
//             case DT_REG:
//             case DT_DIR:
//             case DT_LNK:
//                 break;
//             default: continue;
//             }
//             bool keep = false;
//             unsigned long low = 0;
//             unsigned long high = workdir->keeps_count - 1;
//             while (low <= high) {
//                 unsigned long mid = (low + high) / 2;
//                 pr_debug("Low @ %lu: %s, High @ %lu: %s, Mid @ %lu: %s"
//                 "\n", low, workdir->keeps[low], high, workdir->keeps[high], mid,
//                 workdir->keeps[mid]);
//                 r = strcmp(entry->d_name, workdir->keeps[mid]);
//                 if (r > 0) {
//                     low = mid + 1;
//                 } else if (r < 0) {
//                     if (mid) high = mid - 1;
//                     else break;
//                 } else {
//                     keep = true;
//                     break;
//                 }
//             }
//             if (!keep && ensure_path_non_exist_at(
//                     workdir->dirfd, entry->d_name)) {
//                 pr_error("Failed to remove '%s' which is not needed under work "
//                     "folder'%s'\n", entry->d_name, workdir->path);
//                 goto close_dir;
//             }
//         }
//     } else {
//         while ((entry = readdir(dir_p)) != NULL) {
//             switch (entry->d_name[0]) {
//             case '\0':
//                 continue;
//             case '.':
//                 switch (entry->d_name[1]) {
//                 case '\0':
//                     continue;
//                 case '.':
//                     if (entry->d_name[2] == '\0')
//                         continue;
//                     break;
//                 }
//                 break;
//             }
//             switch (entry->d_type) {
//             case DT_REG:
//             case DT_DIR:
//             case DT_LNK:
//                 break;
//             default: continue;
//             }
//             if (ensure_path_non_exist_at(workdir->dirfd, entry->d_name)) {
//                 pr_error("Failed to remove '%s' which is not needed under work "
//                     "folder'%s'\n", entry->d_name, workdir->path);
//                 goto close_dir;
//             }
//         }
//     }
//     if (errno) {
//         pr_error_with_errno("Failed to read dir\n");
//         goto close_dir;
//     }
//     r = 0;
// close_dir:
//     if (closedir(dir_p)) {
//         pr_error_with_errno("Failed to close dir");
//     }
//     if (clean_links_pass &&
//             remove_dead_symlinks_recursively_at(
//                 workdir->links_dirfd, clean_links_pass) < 0)  {
//         pr_error("Failed to remove dead links under '%s'\n", workdir->path);
//     }
//     return r;
// }

static inline unsigned int
    tar_header_checksum(struct tar_header *header) {
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

int tar_header_checksum_self(struct tar_header *header) {
    if (snprintf(header->chksum, sizeof header->chksum - 1, "%06o",
        tar_header_checksum(header)) < 0) {
        pr_error_with_errno("Failed to format header checksum");
        return -1;
    }
    header->chksum[sizeof header->chksum - 1] = ' ';
    return 0;
}

int tar_write_and_pad_to_512_block(
    int const tar_fd,
    void const *const restrict data,
    size_t const size
) {
#ifdef TAR_WRITE_CHECK_OFFSET
    if (lseek(tar_fd, 0, SEEK_CUR) % 512) {
        pr_error("Tar not at 512 offset\n");
        return -1;
    }
#endif
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
#ifdef TAR_WRITE_CHECK_OFFSET
    if (lseek(tar_fd, 0, SEEK_CUR) % 512) {
        pr_error("Tar not at 512 offset\n");
        return -1;
    }
#endif
    return 0;
}

int tar_add_global_header(
    int const tar_fd,
    char const *const restrict mtime,
    void const *const restrict content,
    unsigned short const len_content
) {
    struct tar_header global_header =
        TAR_HEADER_PAX_GLOBAL_HEADER_INIT;
    if (snprintf(global_header.size, sizeof global_header.size,
                    "%011o", len_content) < 0) {
        pr_error("Failed to format global header size\n");
        return -1;
    }
    memcpy(global_header.mtime, mtime, sizeof global_header.mtime);
    if (tar_header_checksum_self(&global_header)) {
        pr_error("Failed to calculate header checksum\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(
        tar_fd, &global_header, sizeof global_header)) {
        pr_error("Failed to write pax global header to tar\n");
        return -1;
    }
    if (tar_write_and_pad_to_512_block(tar_fd, content, len_content)) {
        pr_error("Failed to write file data to tar\n");
        return -1;
    }
    return 0;
}

int tar_append_longlink_optional(
    int const tar_fd,
    char const *const restrict link,
    unsigned short const len_link
) {
    struct tar_header longlink_header;
    if (len_link < sizeof longlink_header.linkname) return 0;
    longlink_header = TAR_HEADER_GNU_LONGLINK_INIT;
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
    struct tar_header longname_header;
    if (len_name < sizeof longname_header.name) return 0;
    longname_header = TAR_HEADER_GNU_LONGNAME_INIT;
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
    struct tar_header symlink_header =
        TAR_HEADER_SYMLINK_INIT;
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
    struct tar_header regular_file_header;
    switch (mode) {
    case 0644:
        regular_file_header = TAR_HEADER_FILE_REG_INIT;
        break;
    case 0755:
        regular_file_header = TAR_HEADER_FILE_EXE_INIT;
        break;
    default:
        pr_warn("%03o mode is not expected, but we accept it for now\n", mode);
        regular_file_header = TAR_HEADER_FILE_REG_INIT;
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
    struct tar_header folder_header = TAR_HEADER_FOLDER_INIT;
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

static inline
bool work_handle_all_looked_up(
    struct work_handle const *const restrict work_handle
) {
    pr_info("Checking if all repos and commits are looked up\n");
    bool looked_up = true;
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        struct repo_work *repo = work_handle->repos + i;
        if (!repo->git_repository) {
            pr_error("Repo '%s' not opened yet\n", 
                work_handle_get_string(repo->url));
            looked_up = false;
        }
        for (unsigned long j = 0; j < repo->commits_count; ++j) {
            struct commit *commit = repo->commits + j;
            if (!commit->git_commit) {
                pr_error("Repo '%s' commit %s not looked up yet\n",
                    work_handle_get_string(repo->url),
                    work_handle_get_string(commit->oid_hex));
                looked_up = false;
            }
        }
    }
    return looked_up;
}

static inline
unsigned long work_handle_commits_count(
    struct work_handle const *const restrict work_handle
) {
    unsigned long count = 0;
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        struct repo_work *repo = work_handle->repos + i;
        for (unsigned long j = 0; j < repo->commits_count; ++j) {
            ++count;
        }
    }
    return count;
}

static inline
void work_handle_fill_repo_commit_pairs(
    struct work_handle const *const restrict work_handle,
    struct repo_commit_pair *const restrict pairs
) {
    unsigned long count = 0;
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        struct repo_work *repo = work_handle->repos + i;
        for (unsigned long j = 0; j < repo->commits_count; ++j) {
            struct repo_commit_pair *element = pairs + count++;
            element->repo = repo;
            element->commit = repo->commits + j;
        }
    }
}

static inline
void repo_commit_pairs_swap_item(
    struct repo_commit_pair *pairs,
    unsigned long const i,
    unsigned long const j
) {
    if (i ==j) return;
    struct repo_commit_pair temp = pairs[i];
    pairs[i] = pairs[j];
    pairs[j] = temp;
}

static inline
unsigned long repo_commit_pairs_partition(
    struct repo_commit_pair *pairs,
    unsigned long const low,
    unsigned long const high
) {
    struct repo_commit_pair pivot = pairs[high];
    unsigned long i = low - 1;
    for (unsigned long j = low; j < high; ++j) {
        if (git_oid_cmp(&pairs[j].commit->oid, &pivot.commit->oid) < 0) {
            repo_commit_pairs_swap_item(pairs, ++i, j);
        }
    }
    repo_commit_pairs_swap_item(pairs, ++i, high);
    return i;
}

void repo_commit_pairs_quick_sort(
    struct repo_commit_pair *pairs,
    unsigned long const low,
    unsigned long const high
) {
    if (low >= high) return;
    unsigned long const pivot = repo_commit_pairs_partition(pairs, low, high);
    if (pivot) repo_commit_pairs_quick_sort(pairs, low, pivot - 1);
    repo_commit_pairs_quick_sort(pairs, pivot + 1, high);
}

static inline
int repo_commit_pairs_dedup(
    struct repo_commit_pair *restrict pairs,
    unsigned long *restrict count
) {
    unsigned long id_unique = 0;
    struct commit *commit_unique = pairs[0].commit;
    git_oid *oid_unique = &commit_unique->oid;
    for (unsigned long id_duplicatable = 1;
        id_duplicatable < *count; 
        ++id_duplicatable
    ) {
        struct commit *commit_duplicatable = pairs[id_duplicatable].commit;
        int diff = git_oid_cmp(&commit_duplicatable->oid, 
                                oid_unique);
        if (diff > 0) {
            ++id_unique;
            if (id_unique < id_duplicatable) {
              pairs[id_unique] = pairs[id_duplicatable];
            } else if (id_unique > id_duplicatable) {
                pr_error("Deduped pairs ID pre-stepped\n");
                return -1;
            } // else, do nothing (self)
            commit_unique = pairs[id_unique].commit;
            oid_unique = &commit_unique->oid;
        } else if (diff < 0) {
            pr_error("Repo commit pairs wrongly sorted\n");
            return -1;
        } else {
            if (commit_duplicatable->archive)
                commit_unique->archive = true;
            if (commit_duplicatable->checkout)
                commit_unique->checkout = true;
        }
    }
    *count = id_unique + 1;
    return 0;
}

static inline
int repo_commit_pairs_shrink(
    struct repo_commit_pair **const restrict pairs,
    unsigned long const count,
    unsigned long *const restrict allocated
) {
    struct repo_commit_pair *new_pairs = realloc(*pairs, 
        sizeof *new_pairs * (*allocated = count));
    if (!new_pairs) {
        pr_error_with_errno("Failed to shrink memory allocated for pairs");
        return -1;
    }
    *pairs = new_pairs;
    return 0;
}

int remove_dir_recursively(
    DIR * const restrict dir_p
) {
    struct dirent *entry;
    int dir_fd = dirfd(dir_p);
    errno = 0;
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
        case DT_LNK:
            if (unlinkat(dir_fd, entry->d_name, 0)) {
                pr_error_with_errno(
                    "Failed to delete '%s' recursively", entry->d_name);
                return -1;
            }
            break;
        case DT_DIR: {
            int dir_fd_r = openat(dir_fd, entry->d_name, O_RDONLY | O_CLOEXEC);
            if (dir_fd_r < 0) {
                pr_error_with_errno(
                    "Failed to open dir entry '%s'", entry->d_name);
                return -1;
            }
            DIR *dir_p_r = fdopendir(dir_fd_r);
            if (dir_p_r == NULL) {
                pr_error_with_errno(
                    "Failed to open '%s' as subdir", entry->d_name);
                if (close(dir_fd_r)) {
                    pr_error_with_errno("Failed to close fd for recursive dir");
                }
                return -1;
            }
            int r = remove_dir_recursively(dir_p_r);
            if (closedir(dir_p_r)) {
                pr_error_with_errno("Faild to close dir");
            }
            if (r) {
                pr_error("Failed to remove dir '%s' recursively\n",
                    entry->d_name);
                return -1;
            }
            if (unlinkat(dir_fd, entry->d_name, AT_REMOVEDIR)) {
                pr_error_with_errno(
                    "Failed to rmdir '%s' recursively", entry->d_name);
                return -1;
            }
            break;
        }
        default:
            pr_error("Unsupported file type %d for '%s'\n",
                entry->d_type, entry->d_name);
            return -1;
        }
    }
    if (errno) {
        pr_error_with_errno("Failed to read dir\n");
        return -1;
    }
    return 0;
}

int remove_at_with_format(
    int const atfd,
    char const *const restrict path,
    mode_t fmt
) {
    
    if (fmt == S_IFDIR) {
        int fd = openat(atfd, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
            pr_error_with_errno("Failed to open '%s'", path);
            return -1;
        }
        DIR* dir = fdopendir(fd);
        if (!dir) {
            pr_error_with_errno("Failed to fdopendir '%s'", path);
            if (close(fd)) {
                pr_error_with_errno("Failed to close '%s'", path);
            }
            return -1;
        }
        int r = remove_dir_recursively(dir);
        if (closedir(dir)) {
            pr_error_with_errno("Failed to closedir '%s'", path);
        }
        if (r) {
            pr_error_with_errno("Failed to remove dir '%s' recursively", path);
            return -1;
        }
        if (unlinkat(atfd, path, AT_REMOVEDIR)) {
            pr_error_with_errno("Failed to rmdir '%s'", path);
            return -1;
        }
    } else {
        if (unlinkat(atfd, path, 0)) {
            pr_error_with_errno("Failed to unlink '%s'", path);
            return -1;
        }
    }
    return 0;
}

int remove_at(
    int const atfd,
    char const *const restrict path
) {
    struct stat stat_buffer;
    if (fstatat(atfd, path, &stat_buffer, AT_SYMLINK_NOFOLLOW)) {
        pr_error_with_errno("Failed to stat '%s'", path);
        return -1;
    }
    return remove_at_with_format(atfd, path, stat_buffer.st_mode & S_IFMT);
}

// 1 path did not exist, or existed but we removed it,
// 0 exists and is of type, -1 error
int ensure_path_is_type_at(
    int atfd,
    char const *const restrict path,
    mode_t type
) {
    struct stat stat_buffer;
    if (fstatat(atfd, path, &stat_buffer, AT_SYMLINK_NOFOLLOW)) {
        switch (errno) {
        case ENOENT:
            return 1;
        default:
            pr_error_with_errno(
                "Failed to check stat of existing '%s'", path);
            return -1;
        }
    } else {
        mode_t fmt = stat_buffer.st_mode & S_IFMT;
        if (fmt == type) {
            pr_debug("'%s' is of expected type %u\n", path, type);
            return 0;
        } else {
            if (remove_at_with_format(atfd, path, fmt)) {
                pr_error_with_errno(
                    "Failed to remove existing '%s' whose type is not %u",
                    path, type);
                return -1;
            }
            return 1;
        }
    }
}

static inline
int repo_commit_pairs_filter_need_export(
    struct repo_commit_pair *const restrict pairs,
    unsigned long *restrict count,
    int const dirfd_archive,
    int const dirfd_checkout,
    char const *const restrict sbuffer,
    char const *const restrict archive_suffix,
    unsigned short const len_archive_suffix
) {
    char name_archive_stack[0x100];
    char *name_archive_heap = NULL;
    char *name_archive;
    unsigned short len_name_archive = GIT_OID_HEXSZ + len_archive_suffix;
    if (len_name_archive >= 0x100) {
        if (!(name_archive_heap = malloc(len_name_archive + 1))) {
            pr_error_with_errno("Failed to allocate memory for archive name");
            return -1;
        }
    } else {
        name_archive = name_archive_stack;
    }
    memcpy(name_archive + GIT_OID_HEXSZ, archive_suffix, len_archive_suffix);
    name_archive[len_name_archive] = '\0';
    unsigned long id_need_export = -1;
    int r;
    for (unsigned long i = 0; i < *count; ++i) {
        struct commit *commit = (pairs + i)->commit;
        if (!commit->archive && !commit->checkout) continue;
        char const *const oid_hex = sbuffer + commit->oid_hex_offset;
        if (commit->archive) {
            memcpy(name_archive, oid_hex, GIT_OID_HEXSZ);
            int r2 = ensure_path_is_type_at(dirfd_archive, name_archive, 
                                                                S_IFREG);
            if (r2 < 0) {
                r = -1;
                goto free_heap;
            } else if (r2 == 0) {
                commit->archive = false;
            }
            
        }
        if (commit->checkout) {
            int r2 = ensure_path_is_type_at(dirfd_checkout, oid_hex, S_IFDIR);
            if (r2 < 0) {
                r = -1;
                goto free_heap;
            } else if (r2 == 0) {
                commit->checkout = false;
            }
        }
        if (!commit->archive && !commit->checkout) continue;
        ++id_need_export;
        if (id_need_export < i) {
            pairs[id_need_export] = pairs[i];
        } else if (id_need_export > i) {
            pr_error("Need export pairs ID pre-stepped\n");
            r = -1;
            goto free_heap;
        } // else, do nothing
    }
    *count = id_need_export + 1;
    r = 0;
free_heap:
    free_if_allocated(name_archive_heap);
    return r;
}

struct export_path_handle {
    char path[PATH_MAX];
    unsigned short len;
    unsigned short entry_offset;
    unsigned short module_offset;
};

// Seperate functions instead of IFs, to speed up
int blob_export_archive(
    git_blob *const restrict blob,
    git_filemode_t const mode,
    struct export_path_handle *path_handle,
    char const *const restrict mtime,
    int const fd_archive
) {
    switch (mode) {
    case GIT_FILEMODE_BLOB:
        return tar_append_regular_file(fd_archive, git_blob_rawcontent(blob), 
            git_blob_rawsize(blob), mtime, path_handle->path, path_handle->len, 
            0644);
    case GIT_FILEMODE_BLOB_EXECUTABLE:
        return tar_append_regular_file(fd_archive, git_blob_rawcontent(blob), 
            git_blob_rawsize(blob), mtime, path_handle->path, path_handle->len, 
            0755);
    case GIT_FILEMODE_LINK:
        return tar_append_symlink(fd_archive, mtime, path_handle->path, 
            path_handle->len, git_blob_rawcontent(blob), 
            git_blob_rawsize(blob));
    default:
        pr_error("Impossible tree entry filemode %d\n", mode);
        return -1;
    }
}

int create_and_write_at(
    int const atfd,
    char const *const restrict name,
    mode_t const mode,
    void const *const restrict content,
    git_object_size_t size
) {
    int const fd = openat(atfd, name, O_WRONLY | O_TRUNC | O_CREAT, mode);
    if (fd < 0) {
        pr_error_with_errno("Failed to create file '%s' with mode 0%o", 
            name, mode);
        return -1;
    }
    int r;
    if (size) {
        git_object_size_t size_written = 0;
        while (size_written < size) {
            ssize_t size_written_this = write(
                fd, content + size_written, size - size_written);
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
                        size - size_written, name);
                    r = -1;
                    goto close;
                }
            } else {
                size_written += size_written_this;
            }
        }
    }
    r = 0;
close:
    if (close(fd)) {
        pr_error_with_errno("Failed to close fd");
    }
    return r;
}

int blob_export_checkout(
    git_blob *const restrict blob,
    git_filemode_t const git_mode,
    char const *const restrict name,
    int const fd_checkout
) {
    mode_t mode;
    switch (git_mode) {
    case GIT_FILEMODE_BLOB:
        mode = 0644;
        break;
    case GIT_FILEMODE_BLOB_EXECUTABLE:
        mode = 0755;
        break;
    case GIT_FILEMODE_LINK:
        if (symlinkat(git_blob_rawcontent(blob), fd_checkout, name)) {
            pr_error_with_errno("Failed to symlink");
            return -1;
        }
        return 0;
    default:
        pr_error("Impossible tree entry filemode 0x%x\n", git_mode);
        return -1;
    }
    return create_and_write_at(fd_checkout, name, mode, 
        git_blob_rawcontent(blob), git_blob_rawsize(blob));
}

static inline
int blob_export_archive_checkout(
    git_blob *const restrict blob,
    git_filemode_t const git_mode,
    char const *const restrict name,
    struct export_path_handle *path_handle,
    char const *const restrict mtime,
    int const fd_archive,
    int const fd_checkout
) {
    int r = 0;
    if (blob_export_archive(blob, git_mode, path_handle, mtime, fd_archive)) {
        r = -1;
    }
    if (blob_export_checkout(blob, git_mode, name, fd_checkout)) {
        r = -1;
    }
    return r;
}

static inline
bool tree_entry_type_illegal(
    git_object_t const type
) {
    switch (type) {
    case GIT_OBJECT_BLOB:
    case GIT_OBJECT_TREE:
    case GIT_OBJECT_COMMIT:
        break;
    default:
        pr_error("Unexpected tree entry type %i in tree\n", type);
        return true;
    }
    return false;
}

#define tree_export_prepare_entry \
    git_tree_entry const *const entry = git_tree_entry_byindex(tree, i); \
    if (!entry) { \
        pr_error("Failed to get tree entry by index\n"); \
        return -1; \
    } \
    git_object_t const type = git_tree_entry_type(entry); \
    if (tree_entry_type_illegal(type)) return -1; \
    git_object *object; \
    int r; \
    if (type != GIT_OBJECT_COMMIT) \
    if ((r = git_tree_entry_to_object(&object, repo->git_repository, entry))){ \
        pr_error_with_libgit_error("Failed to convert tree entry to object"); \
        return -1; \
    } \
    char const *const restrict name = git_tree_entry_name(entry); \
    unsigned short const len_name = strnlen(name, USHRT_MAX); \
    if (path_handle->entry_offset + len_name >= PATH_MAX) { \
        pr_error("Path would exceed max length with entry '%s' name added", \
                    name); \
        return -1; \
    } \
    path_handle->len = path_handle->entry_offset + len_name; \
    memcpy(path_handle->path + path_handle->entry_offset, name, len_name); \
    path_handle->path[path_handle->len] = '\0';

#define export_path_handle_backup \
    unsigned short const entry_offset = path_handle->entry_offset; \
    unsigned short const module_offset = path_handle->module_offset

#define export_path_handle_prepare_tree \
    path_handle->path[path_handle->len] = '/'; \
    path_handle->entry_offset = path_handle->len + 1

#define export_path_handle_finish_tree \
    path_handle->entry_offset = entry_offset; \
    path_handle->module_offset = module_offset

#define export_path_handle_prepare_commit \
    export_path_handle_prepare_tree; \
    path_handle->module_offset = path_handle->len + 1

int commit_get_target_repo_commit_tree(
    struct commit const *const restrict commit,
    char const *const restrict module_path,
    struct repo_work *const restrict repos,
    struct repo_work **const restrict target_repo,
    struct commit **const restrict target_commit,
    git_tree **const restrict target_tree,
    char const *const restrict sbuffer
) {
    struct submodule *module = NULL;
    for (unsigned long j = 0; j < commit->submodules_count; ++j) {
        if (!strcmp(sbuffer + commit->submodules[j].path_offset, module_path)) {
            module = commit->submodules + j;
            break;
        }
    }
    if (!module) {
        pr_error("Failed to find submodule '%s'\n", module_path);
        return -1;
    }
    *target_repo = repos + module->target_repo_id;
    *target_commit = (*target_repo)->commits + module->target_commit_id;
    int r = git_commit_tree(target_tree, (*target_commit)->git_commit);
    if (r) {
        pr_error_with_libgit_error("Failed to get submodule commit tree");
        return -1;
    }
    return 0;
}

#define tree_export_submodule_prepeare \
    struct repo_work *target_repo; \
    struct commit *target_commit; \
    git_tree *target_tree; \
    if (commit_get_target_repo_commit_tree(commit, \
        path_handle->path + module_offset, repos, &target_repo, \
        &target_commit, &target_tree, sbuffer) \
    ) { \
        pr_error("Failed to get submodule tree"); \
        r = -1; \
        break; \
    }

#define tree_export_end_entry \
    if (type != GIT_OBJECT_COMMIT) git_object_free(object); \
    if (r) return -1

// Use our own implementation instead of git_tree_walk() for optimization
int tree_export_archive(
    git_tree *const restrict tree,
    struct commit const *const restrict commit,
    struct repo_work const *const restrict repo,
    struct repo_work *const restrict repos,
    struct export_path_handle *path_handle,
    char const *const restrict mtime,
    int const fd_archive,
    char const *const restrict sbuffer
) {
    size_t const count = git_tree_entrycount(tree);
    export_path_handle_backup;
    for (size_t i = 0; i < count; ++i) {
        tree_export_prepare_entry;
        switch (type) {
        case GIT_OBJECT_BLOB: 
            r = blob_export_archive((git_blob *)object, 
                git_tree_entry_filemode(entry), path_handle, mtime, fd_archive);
            break;
        case GIT_OBJECT_TREE:
            export_path_handle_prepare_tree;
            r = tree_export_archive((git_tree *)object, commit, repo, repos,
                path_handle, mtime, fd_archive, sbuffer);
            export_path_handle_finish_tree;
            break;
        case GIT_OBJECT_COMMIT:
            tree_export_submodule_prepeare;
            export_path_handle_prepare_commit;
            r = tree_export_archive(target_tree, target_commit, target_repo, 
                repos, path_handle, mtime, fd_archive, sbuffer); 
            git_tree_free(target_tree);
            export_path_handle_finish_tree;
            break;
        default:
            pr_error("Unexpected routine\n");
            r = -1;
        }
        tree_export_end_entry;
    }
    return 0;
}

int create_and_open_dir_at(
    int const atfd,
    char const *const restrict name
) {
    if (mkdirat(atfd, name, 0755)) {
        if (errno == EEXIST) {
            if (remove_at(atfd, name)) {
                return -1;
            }
        } else {
            pr_error_with_errno("Failed to mkdir '%s'", name);
            return -1;
        }
    }
    int fd = openat(atfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        pr_error_with_errno("Failed to open created dir '%s'", name);
        if (unlinkat(atfd, name, AT_REMOVEDIR)) {
            pr_error_with_errno("Failed to remove created dir '%s'", name);
        }
        return -1;
    }
    return fd;
}

#define tree_export_checkout_prepare_subdir \
    if ((subdir_fd = create_and_open_dir_at(fd_checkout, name)) < 0) { \
        pr_error_with_errno("Failed to create and open subdir"); \
        r = -1; \
        break; \
    }

#define tree_export_checkout_close_subdir \
    if (close(subdir_fd)) { \
        pr_error_with_errno("Failed to close subdir"); \
        r = -1; \
    }

// Use our own implementation instead of git_tree_walk() for optimization
int tree_export_checkout(
    git_tree *const restrict tree,
    struct commit const *const restrict commit,
    struct repo_work const *const restrict repo,
    struct repo_work *const restrict repos,
    struct export_path_handle *path_handle,
    int const fd_checkout,
    char const *const restrict sbuffer
) {
    size_t const count = git_tree_entrycount(tree);
    export_path_handle_backup;
    int subdir_fd;
    for (size_t i = 0; i < count; ++i) {
        tree_export_prepare_entry;
        switch (type) {
        case GIT_OBJECT_BLOB: 
            r = blob_export_checkout((git_blob *)object, 
                git_tree_entry_filemode(entry), name, fd_checkout);
            break;
        case GIT_OBJECT_TREE:
            tree_export_checkout_prepare_subdir;
            export_path_handle_prepare_tree;
            r = tree_export_checkout((git_tree *)object, commit, repo, repos,
                path_handle, subdir_fd, sbuffer);
            tree_export_checkout_close_subdir;
            export_path_handle_finish_tree;
            break;
        case GIT_OBJECT_COMMIT:
            tree_export_checkout_prepare_subdir;
            tree_export_submodule_prepeare;
            export_path_handle_prepare_commit;
            r = tree_export_checkout(target_tree, target_commit,  target_repo, 
                repos, path_handle, subdir_fd, sbuffer); 
            tree_export_checkout_close_subdir;
            git_tree_free(target_tree);
            export_path_handle_finish_tree;
            break;
        default:
            pr_error("Unexpected routine\n");
            r = -1;
        }
        tree_export_end_entry;
    }
    return 0;
}

int tree_export_archive_checkout(
    git_tree *const restrict tree,
    struct commit const *const restrict commit,
    struct repo_work const *const restrict repo,
    struct repo_work *const restrict repos,
    struct export_path_handle *path_handle,
    char const *const restrict mtime,
    int const fd_archive,
    int const fd_checkout,
    char const *const restrict sbuffer
) {
    size_t const count = git_tree_entrycount(tree);
    export_path_handle_backup;
    int subdir_fd;
    for (size_t i = 0; i < count; ++i) {
        tree_export_prepare_entry;
        switch (type) {
        case GIT_OBJECT_BLOB: 
            r = blob_export_archive_checkout((git_blob *)object, 
                git_tree_entry_filemode(entry), name, path_handle, mtime, 
                fd_archive, fd_checkout);
            break;
        case GIT_OBJECT_TREE:
            tree_export_checkout_prepare_subdir;
            export_path_handle_prepare_tree;
            r = tree_export_archive_checkout((git_tree *)object, commit, repo, 
                repos, path_handle, mtime, fd_archive, subdir_fd, sbuffer);
            tree_export_checkout_close_subdir;
            export_path_handle_finish_tree;
            break;
        case GIT_OBJECT_COMMIT:
            tree_export_checkout_prepare_subdir;
            tree_export_submodule_prepeare;
            export_path_handle_prepare_commit;
            r = tree_export_archive_checkout(target_tree, target_commit, 
                target_repo, repos, path_handle, mtime, fd_archive, subdir_fd, 
                sbuffer); 
            tree_export_checkout_close_subdir;
            git_tree_free(target_tree);
            export_path_handle_finish_tree;
            break;
        default:
            pr_error("Unexpected routine\n");
            r = -1;
        }
        tree_export_end_entry;
    }
    return 0;
}

unsigned short get_unsigned_short_decimal_width(unsigned short number) {
    unsigned short width = 0;
    if (!number) return 1;
    while (number) {
        number /= 10;
        ++width;
    }
    return width;
}

int commit_export_add_global_comment_to_tar(
    int tar_fd,
    char const *const restrict repo,
    char const *const restrict commit,
    char const *const restrict mtime
) {
    char comment[4096];
    int r = snprintf(comment, 4096, "Archive of repo '%s' commit '%s', "
                                    "all recursive submodules includeded, "
                                    "created with git-mirrorer by "
                                    "Guoxin \"7Ji\" Pu (c) 2023-present",
                                    repo, commit);
    if (r < 0) {
        pr_error("Failed to format comment\n");
        return -1;
    }
    if (r >= 4000) {
        pr_error("Comment too long: '%s'\n", comment);
        return -1;
    }
    unsigned short const len_comment = r;
    unsigned short width_length = get_unsigned_short_decimal_width(len_comment);
     // 1 between length and comment=
     // 8 for comment=
     // 1 for ending \n new line
    unsigned short width_all = width_length + len_comment + 10;
    for (;;) {
        width_length = get_unsigned_short_decimal_width(width_all);
        unsigned const width_all_new = width_length + len_comment + 10;
        if (width_all_new == width_all) break;
        width_all = width_all_new;
    }
    char content[4096];
    r = snprintf(content, 4096, "%hu comment=%s\n", width_all, comment);
    if (r < 0) {
        pr_error_with_errno("Failed to format content");
        return -1;
    }
    if (tar_add_global_header(tar_fd, mtime, content, r)) {
        pr_error("Failed to add global header to tar\n");
        return -1;
    }
    return 0;
}

static inline
int commit_export_tree(
    struct commit const *const restrict commit,
    struct repo_work const *const restrict repo,
    struct repo_work *const restrict repos,
    int const fd_archive,
    int const fd_checkout,
    char const *const restrict sbuffer
) {
    git_tree *tree;
    int r = git_commit_tree(&tree, commit->git_commit);
    if (r) {
        pr_error("Failed to get tree pointed by commit\n");
        return -1;
    }
    struct export_path_handle path_handle = {
        .len = 0,
        .entry_offset = 0,
        .module_offset = 0,
    };
    if (commit->archive) {
        char mtime[TAR_HEADER_MTIME_LEN] = "";
        if (snprintf(mtime, TAR_HEADER_MTIME_LEN, "%011lo", 
            git_commit_time(commit->git_commit)) < 0) 
        {
            pr_error("Failed to format mtime\n");
            r = -1;
            goto free_tree;
        }
        if (commit_export_add_global_comment_to_tar(fd_archive, 
            sbuffer + repo->url_offset, sbuffer + commit->oid_hex_offset, 
            mtime)) 
        {
            pr_error("Failed to add global comment to tar\n");
            r = -1;
            goto free_tree;
        }
        if (commit->checkout) {
            r = tree_export_archive_checkout(tree, commit, repo, repos, 
                &path_handle, mtime, fd_archive, fd_checkout, sbuffer);
        } else {
            r = tree_export_archive(tree, commit, repo, repos, &path_handle, 
                mtime, fd_archive, sbuffer);
        }
    } else if (commit->checkout) {
        r = tree_export_checkout(tree, commit, repo, repos, &path_handle,
            fd_checkout, sbuffer);
    } else {
        pr_error("Commit should neither be archived nor checked-out\n");
        r = -1;
    }
    if (r) {
        path_handle.path[PATH_MAX - 1] = '\0';
        pr_warn("Last path handleded: '%s'\n", path_handle.path);
    }
free_tree:
    git_tree_free(tree);
    return r;
}

int commit_export(
    struct commit const *const restrict commit,
    struct repo_work const *const restrict repo,
    struct repo_work *const restrict repos,
    char *const *const restrict pipe_args,
    char *const restrict name_archive,
    char *const restrict name_archive_temp,
    int const datafd_archive,
    int const datafd_checkout,
    char const *const restrict sbuffer
) {
    int r;
    char name_checkout_temp[GIT_OID_HEXSZ + 6];
    int fd_archive = -1;
    int fd_checkout = -1;
    pid_t child_pipe = -1;
    if (commit->checkout) {
        memcpy(name_checkout_temp, sbuffer + commit->oid_hex_offset, 
                GIT_OID_HEXSZ);
        memcpy(name_checkout_temp + GIT_OID_HEXSZ, ".temp", 5);
        name_checkout_temp[GIT_OID_HEXSZ + 5] = '\0';
        if ((fd_checkout = create_and_open_dir_at(
            datafd_checkout, name_checkout_temp)) < 0) 
        {
            pr_error("Failed to create and open checkout dir '%s'\n", 
                name_checkout_temp);
            return -1;
        }
    }
    if (commit->archive) {
        memcpy(name_archive, sbuffer + commit->oid_hex_offset, GIT_OID_HEXSZ);
        memcpy(name_archive_temp, sbuffer + commit->oid_hex_offset, 
            GIT_OID_HEXSZ);
        if ((fd_archive = openat(datafd_archive, name_archive_temp, 
                            O_WRONLY | O_CREAT, 0644)) < 0) {
            pr_error("Failed to archive fd\n");
            r = -1;
            goto close;
        }
        if (pipe_args) {
            int fd_pipes[2];
            if (pipe2(fd_pipes, O_CLOEXEC)) {
                pr_error_with_errno("Failed to create pipe");
                r = -1;
                goto close;
            }
            if (!(child_pipe = fork())) { // Child
                if (dup2(fd_archive, STDOUT_FILENO) < 0) {
                    fpr_error_with_errno(stderr,
                        "[Child %ld] Failed to dup archive fd to stdout",
                        pthread_self());
                    exit(EXIT_FAILURE);
                }
                if (dup2(fd_pipes[0], STDIN_FILENO) < 0) {
                    fpr_error_with_errno(stderr,
                        "[Child %ld] Failed to dup pipe read end to stdin",
                        pthread_self());
                    exit(EXIT_FAILURE);
                }
                if (execvp(pipe_args[0], pipe_args)) {
                    fpr_error_with_errno(
                        stderr, "[Child %ld] Failed to execute piper",
                                pthread_self());
                    exit(EXIT_FAILURE);
                }
                fpr_error(stderr, "[Child %ld] We should not be here\n",
                    pthread_self());
                exit(EXIT_FAILURE);
            }
            if (close(fd_pipes[0])) {
                pr_error_with_errno("Failed to close the read-end of pipe");
            }
            if (close(fd_archive)) {
                pr_error_with_errno("Failed to close the original archive fd");
            }
            fd_archive = fd_pipes[1];
            if (child_pipe < 0) {
                pr_error_with_errno("Failed to fork");
                r = -1;
                goto close;
            }
        }
    }
    r = commit_export_tree(commit, repo, repos, fd_archive, fd_checkout,
                            sbuffer);
close:
    // git_tree_free(tree);
    if (fd_archive >= 0) {
        if (close(fd_archive)) {
            pr_error_with_errno("Failed to close archive fd");
        }
        if (child_pipe > 0) {
            int status;
            pid_t waited = waitpid(child_pipe, &status, 0);
            if (waited != child_pipe) {
                pr_error("Waited pipe child different %i != %i\n", waited, 
                        child_pipe);
                r = -1;
            }
            if (status) {
                pr_error("Piper child bad return %i\n", status);
                r = -1;
            }
        }
        if (r) {
            remove_at_with_format(datafd_archive, name_archive_temp, S_IFREG);
        } else if (renameat(datafd_archive, name_archive_temp, datafd_archive, 
                name_archive)) 
        {
            pr_error_with_errno("Failed to rename finished archive");
            r = -1;
        }
    }
    if (fd_checkout >= 0) {
        if (close(fd_checkout)) {
            pr_error_with_errno("Failed to close checkout fd");
            // r = -1;
        }
        if (r) {
            remove_at_with_format(datafd_checkout, name_checkout_temp, S_IFDIR);
        } else if (renameat(datafd_checkout, name_checkout_temp, 
            datafd_checkout, sbuffer + commit->oid_hex_offset)) 
        {
            pr_error_with_errno("Failed to rename finished checkout");
            r = -1;
        }
    }
    if (r) {
        pr_error("Failed to export commit %s\n", 
                sbuffer + commit->oid_hex_offset);
    } else {
        pr_info("Exported commit %s\n", sbuffer + commit->oid_hex_offset);
    }
    return r;
}

static inline
bool repo_commit_pairs_need_archive(
    struct repo_commit_pair const *const restrict pairs,
    unsigned long const pairs_count
) {
    for (unsigned long i = 0; i < pairs_count; ++i) {
        if (pairs[i].commit->archive) return true;
    }
    return false;
}

struct work_handle_export_repo_commit_pairs_some_arg {
    struct work_handle const *work_handle;
    struct repo_commit_pair const *pairs;
    unsigned long pairs_count;
    char *const *pipe_args;
    pthread_t thread;
    bool active;
};

int work_handle_export_repo_commit_pairs_some(
    struct work_handle const *const restrict work_handle,
    struct repo_commit_pair const *const restrict pairs,
    unsigned long const pairs_count,
    char *const *const restrict pipe_args
) { 
    char name_archive_temp_stack[0x100];
    char *name_archive_temp_heap = NULL;
    char *name_archive_temp = NULL;
    char name_archive_stack[0x100];
    char *name_archive_heap = NULL;
    char *name_archive = NULL;
    if (repo_commit_pairs_need_archive(pairs, pairs_count)) {
        unsigned short len_name_archive = GIT_OID_HEXSZ + 
            work_handle->len_archive_suffix;
        // Non-temp name
        if (len_name_archive >= 0x100) {
            if (!(name_archive_heap = malloc(len_name_archive + 1))) {
                pr_error_with_errno(
                    "Failed to allocate memory for archive name");
                return -1;
            }
            name_archive = name_archive_heap;
        } else name_archive = name_archive_stack;
        if (work_handle->len_archive_suffix) 
            memcpy(name_archive + GIT_OID_HEXSZ, 
                work_handle_get_string(work_handle->archive_suffix), 
                    work_handle->len_archive_suffix);
        name_archive[len_name_archive] = '\0';
        // Temp name
        len_name_archive += 5;
        if (len_name_archive >= 0x100) {
            if (!(name_archive_temp_heap = malloc(len_name_archive + 1))) {
                pr_error_with_errno(
                    "Failed to allocate memory for archive name");
                return -1;
            }
            name_archive_temp = name_archive_temp_heap;
        } else name_archive_temp = name_archive_temp_stack;
        if (work_handle->len_archive_suffix) 
            memcpy(name_archive_temp + GIT_OID_HEXSZ, 
                work_handle_get_string(work_handle->archive_suffix), 
                    work_handle->len_archive_suffix);
        memcpy(name_archive_temp + GIT_OID_HEXSZ + 
                    work_handle->len_archive_suffix, ".temp", 5);
        name_archive_temp[len_name_archive] = '\0';
    }
    int r = 0;
    for (unsigned long i = 0; i < pairs_count; ++i) {
        if (commit_export(pairs[i].commit, pairs[i].repo, work_handle->repos, 
                pipe_args, name_archive, name_archive_temp, 
                work_handle->dir_archives.datafd, 
                work_handle->dir_checkouts.datafd, 
                work_handle->string_buffer.buffer))
        {
            pr_error("Failed to export commit %s of repo '%s'\n",
                work_handle_get_string(pairs[i].commit->oid_hex),
                work_handle_get_string(pairs[i].repo->url));
            r = -1;
        }
    }
    free_if_allocated(name_archive_heap);
    free_if_allocated(name_archive_temp_heap);
    return r;
}

void *work_handle_export_repo_commit_pairs_some_thread(void *parg) {
    struct work_handle_export_repo_commit_pairs_some_arg *arg = 
        (struct work_handle_export_repo_commit_pairs_some_arg *)parg;
    return (void *)(long)work_handle_export_repo_commit_pairs_some(
        arg->work_handle, arg->pairs, arg->pairs_count, arg->pipe_args);
}

static inline
int work_handle_export_repo_commit_pairs_single_threaded(
    struct work_handle const *const restrict work_handle,
    struct repo_commit_pair const *const restrict pairs,
    unsigned long const pairs_count,
    char *const *const restrict pipe_args
) {
    return work_handle_export_repo_commit_pairs_some(work_handle, pairs, 
        pairs_count, pipe_args);
}

static inline
int work_handle_export_repo_commit_pairs_multi_threaded(
    struct work_handle const *const restrict work_handle,
    struct repo_commit_pair const *const restrict pairs,
    unsigned long const pairs_count,
    unsigned short const threads_count,
    unsigned short const jobs_per_thread,
    char *const *const restrict pipe_args
) {
    struct work_handle_export_repo_commit_pairs_some_arg args_stack[10];
    struct work_handle_export_repo_commit_pairs_some_arg *args_heap = NULL;
    struct work_handle_export_repo_commit_pairs_some_arg *args;
    if (threads_count > 10) {
        if (!(args_heap = malloc(sizeof *args_heap * threads_count))) {
            pr_error_with_errno("Failed to allocate memory for thread args");
            return -1;
        }
        args = args_heap;
    } else {
        args = args_stack;
    }
    unsigned long pairs_offset = 0;
    unsigned long pairs_remaining = pairs_count;
    int r = 0, pr;
    for (unsigned short i = 0; i < threads_count; ++i) {
        struct work_handle_export_repo_commit_pairs_some_arg *arg = args + i;
        unsigned long pairs_this;
        if (pairs_remaining > jobs_per_thread) {
            pairs_this = jobs_per_thread;
        } else {
            pairs_this = pairs_remaining;
        }
        arg->work_handle = work_handle;
        arg->pairs = pairs + pairs_offset;
        arg->pairs_count = pairs_this;
        arg->pipe_args = pipe_args;
        if ((pr = pthread_create(&arg->thread, NULL, 
            work_handle_export_repo_commit_pairs_some_thread, arg))) 
        {
            pr_error_with_pthread_error("Failed to create thread");
            r = -1;
            arg->active = false;
        } else {
            arg->active = true;
        }
        pairs_offset += pairs_this;
        pairs_remaining -= pairs_this;
    }
    for (unsigned short i = 0; i < threads_count; ++i) {
        if (!args[i].active) continue;
        long ret;
        if ((pr = pthread_join(args[i].thread, (void **)&ret))) {
            pr_error_with_pthread_error("Failed to join thread");
            r = -1;
            continue;
        }
        if (ret) {
            pr_error("Thread bad return %ld\n", ret);
            r = -1;
        }
    }
    free_if_allocated(args_heap);
    return r;
}

static inline
int work_handle_export_repo_commit_pairs(
    struct work_handle const *const restrict work_handle,
    struct repo_commit_pair const *const restrict pairs,
    unsigned long const pairs_count
) {
    char const *archive_pipe_args_stack[0x20];
    char const **archive_pipe_args_heap = NULL;
    char const **archive_pipe_args = NULL;
    if (work_handle->archive_pipe_args_count && 
        repo_commit_pairs_need_archive(pairs, pairs_count)) 
    {
        if (work_handle->archive_pipe_args_count >= 0x20) {
            archive_pipe_args_heap = malloc(
                sizeof *archive_pipe_args_heap * 
                    (work_handle->archive_pipe_args_count + 1));
            if (!archive_pipe_args_heap) {
                pr_error_with_errno(
                    "Failed to allocate memory for pipe args\n");
                return -1;
            }
            archive_pipe_args = archive_pipe_args_heap;
        } else {
            archive_pipe_args = archive_pipe_args_stack;
        }
        for (unsigned long i = 0; i < work_handle->archive_pipe_args_count; ++i) 
        {
            archive_pipe_args[i] = work_handle->string_buffer.buffer + 
                work_handle->archive_pipe_args[i].offset;
        }
        archive_pipe_args[work_handle->archive_pipe_args_count] = NULL;
    } else {
        pr_info("Not creating archive pipe args\n");
    }
    unsigned short jobs_per_thread = pairs_count / work_handle->export_threads;
    if (pairs_count % work_handle->export_threads) {
        ++jobs_per_thread;
    }
    unsigned short export_threads = work_handle->export_threads;
    while (export_threads * jobs_per_thread > pairs_count) --export_threads;
    if (export_threads * jobs_per_thread < pairs_count) ++export_threads;
    pr_info("Exporting with %hu threads, %hu jobs per thread\n", 
            export_threads, jobs_per_thread);
    int r;
    if (export_threads <= 1) {
        r = work_handle_export_repo_commit_pairs_single_threaded(
                work_handle, pairs, pairs_count, 
                (char *const *)archive_pipe_args);
    } else {
        r = work_handle_export_repo_commit_pairs_multi_threaded(
                work_handle, pairs, pairs_count, export_threads, 
                jobs_per_thread, (char *const *)archive_pipe_args);
    }
    free_if_allocated(archive_pipe_args_heap);
    return r;
}

int work_handle_export_all_repos(
    struct work_handle const *const restrict work_handle
) {
    if (!work_handle_all_looked_up(work_handle)) {
        pr_error("Refuse to export, as there's repos/commits not looked up\n");
        return -1;
    }
    pr_info("ALl repos and commits looked up, exporting now\n");
    DYNAMIC_ARRAY_DECLARE(struct repo_commit_pair, pair);
    if (!(pairs_count = work_handle_commits_count(work_handle))) {
        pr_error("No commits parsed for all repos");
        return -1;
    }
    if (!(pairs = malloc(sizeof *pairs * (
                    pairs_allocated = pairs_count)))) 
    {
        pr_error_with_errno("Failed to allocate memory for commits\n");
        return -1;
    }
    work_handle_fill_repo_commit_pairs(work_handle, pairs);
    repo_commit_pairs_quick_sort(pairs, 0, 
                                pairs_count - 1);
    int r;
    if (repo_commit_pairs_dedup(pairs, &pairs_count)) {
        pr_error("Failed to dedup repo commit pairs\n");
        r = -1;
        goto free_pairs;
    }
    if (!pairs_count) {
        pr_error("No commit could be exported\n");
        r = -1;
        goto free_pairs;
    }
    if (repo_commit_pairs_filter_need_export(pairs, &pairs_count, 
        work_handle->dir_archives.datafd, work_handle->dir_checkouts.datafd, 
        work_handle->string_buffer.buffer, 
        work_handle_get_string(work_handle->archive_suffix), 
        work_handle->len_archive_suffix)) 
    {
        pr_error("Failed to filter commit pairs to only keep need export\n");
        r = -1;
        goto free_pairs;
    }
    if (!pairs_count) {
        pr_info("No commit need be exported\n");
        r = 0;
        goto free_pairs;
    }
    if (pairs_allocated > pairs_count) {
        if (repo_commit_pairs_shrink(&pairs, pairs_count, &pairs_allocated)) {
            pr_error("Failed to shrink pairs list after dedup and filter\n");
            r = -1;
            goto free_pairs;
        }
    }
    for (unsigned long i = 0; i < pairs_count; ++i) {
        struct repo_commit_pair *pair = pairs + i;
        pr_info("Need to export commit %s from repo '%s'\n", 
            work_handle_get_string(pair->commit->oid_hex), 
            work_handle_get_string(pair->repo->url));
    }
    if (work_handle_export_repo_commit_pairs(work_handle, pairs, pairs_count)) {
        pr_error("Failed to export commits\n");
        r = -1;
        goto free_pairs;
    }
    r = 0;
free_pairs:
    free(pairs);
    return r;
}

// int raise_nofile_limit() {
//     struct rlimit rlimit;
//     if (getrlimit(RLIMIT_NOFILE, &rlimit)) {
//         pr_error_with_errno("Failed to get limit of opened files");
//         return -1;
//     }
//     if (rlimit.rlim_cur <= 1024) {
//         pr_warn(
//             "Current nofile limit too small (%lu), this may result in "
//             "unexpeceted behaviours as git-mirrorer caches all repos "
//             "with all of their fds kept open during the whole run. "
//             "~10 fds are needed per repo.\n",
//             rlimit.rlim_cur);
//     }
//     if (rlimit.rlim_cur == rlimit.rlim_max) return 0;
//     rlimit.rlim_cur = rlimit.rlim_max > 16384 ? 16384 : rlimit.rlim_max;
//     if (setrlimit(RLIMIT_NOFILE, &rlimit)) {
//         pr_error_with_errno("Failed to raise limit of opened files");
//         return -1;
//     }
//     pr_info("Raised limit of opened file descriptors to %lu\n",
//             rlimit.rlim_cur);
//     return 0;
// }

// int clean_all_dirs(
//     struct work_directory *const restrict workdir_repos,
//     struct work_directory *const restrict workdir_archives,
//     struct work_directory *const restrict workdir_checkouts,
//     struct config const *const restrict config
// ) {
//     int r = 0;
//     if (config->clean_repos && work_directory_clean(
//             workdir_repos, config->clean_links_pass,
//             HASH_STRING_LEN > 5 ? HASH_STRING_LEN + 1 : 6)) {
//         pr_error("Failed to clean repos workdir '%s'\n", workdir_repos->path);
//         r = -1;
//     }
//     if (config->clean_archives && work_directory_clean(
//             workdir_archives, config->clean_links_pass,
//             config->len_archive_suffix + (
//                 GIT_OID_MAX_HEXSIZE > 5 ? GIT_OID_MAX_HEXSIZE + 1 : 6))) {
//         pr_error("Failed to clean archives workdir '%s'\n",
//                 workdir_archives->path);
//         r = -1;
//     }
//     if (config->clean_checkouts && work_directory_clean(
//             workdir_checkouts, config->clean_links_pass,
//             GIT_OID_MAX_HEXSIZE > 5 ? GIT_OID_MAX_HEXSIZE + 1 : 6)) {
//         pr_error("Failed to clean checkouts workdir '%s'\n",
//                 workdir_repos->path);
//         r = -1;
//     }
//     return r;
// }

// int work_oneshot(
//     struct config *const restrict config,
//     struct work_directory *const restrict workdir_repos,
//     struct work_directory *const restrict workdir_archives,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     if (mirror_all_repos(
//             config, workdir_repos, config->clean_repos)) {
//         pr_error("Failed to mirro all repos\n");
//         return -1;
//     }
//     if (export_all_repos(
//             config, workdir_archives, workdir_checkouts)) {
//         pr_error("Failed to export all repos (archives and checkouts)\n");
//         return -1;
//     }
//     if (clean_all_dirs(
//         workdir_repos, workdir_archives, workdir_checkouts, config)) {
//         pr_error("Failed to clean up all folders\n");
//         return -1;
//     }
//     return 0;
// }

// int work_daemon(
//     struct config *const restrict config,
//     char const *const restrict config_path,
//     struct work_directory *const restrict workdir_repos,
//     struct work_directory *const restrict workdir_archives,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     bool watch_config = false;
//     struct stat stat_buffer = {0};
//     struct timespec config_mtime = {0};
//     if (config_path && strcmp(config_path, "-")) {
//         if (stat(config_path, &stat_buffer)) {
//             pr_warn("Failed to stat config '%s' to get its mtime, won't "
//                 "watch config\n", config_path);
//         } else {
//             config_mtime = stat_buffer.st_mtim;
//             pr_info("Started watching config '%s'\n", config_path);
//             watch_config = true;
//         }
//     }
//     for (;;) {
//         if (mirror_all_repos(
//                 config, workdir_repos, config->clean_repos)) {
//             pr_error("Failed to mirro all repos\n");
//             return -1;
//         }
//         if (export_all_repos(
//                 config, workdir_archives, workdir_checkouts)) {
//             pr_error("Failed to export all repos (archives and checkouts)\n");
//             return -1;
//         }
//         if (clean_all_dirs(
//             workdir_repos, workdir_archives, workdir_checkouts, config)) {
//             pr_error("Failed to clean up all folders\n");
//             return -1;
//         }
//         // Cleanup
//         // Free all repos not in config
//         for (unsigned long i = config->repos_count_original;
//             i < config->repos_count; ++i) {
//             repo_free(config->repos + i);
//         }
//         config->repos_count = config->repos_count_original;
//         // Free some memory
//         if (config->repos_allocated - config->repos_count > ALLOC_BASE) {
//             config->repos_allocated =
//                 (config->repos_count / ALLOC_BASE + 1) * ALLOC_BASE;
//             struct repo *const restrict repos_new =
//                 realloc(config->repos,
//                     sizeof *config->repos * config->repos_allocated);
//             if (repos_new == NULL) {
//                 pr_error_with_errno("Failed to shrink memory used on repos");
//                 return -1;
//             }
//             config->repos = repos_new;
//         }
//         for (unsigned long i = 0; i < config->repos_count; ++i) {
//             struct repo *const restrict repo = config->repos + i;
//             if (repo->parsed_commits_allocated - repo->parsed_commits_count
//                  > ALLOC_BASE) {
//                 repo->parsed_commits_allocated =
//                     (repo->parsed_commits_count / ALLOC_BASE + 1) * ALLOC_BASE;
//                 struct parsed_commit *const restrict parsed_commits_new =
//                     realloc(repo->parsed_commits,
//                         sizeof *repo->parsed_commits *
//                             repo->parsed_commits_allocated);
//                 if (parsed_commits_new == NULL) {
//                     pr_error_with_errno(
//                         "Failed to shrink memory used on parsed commits");
//                     return -1;
//                 }
//                 repo->parsed_commits = parsed_commits_new;
//             }
//             for (unsigned long j = 0; j < repo->parsed_commits_count; ++j) {
//                 parsed_commit_free(repo->parsed_commits + j);
//             }
//             repo->parsed_commits_count = 0;
//             repo->wanted_objects_count = repo->wanted_objects_count_original;
//             if (repo->wanted_objects_allocated - repo->wanted_objects_count
//                 > ALLOC_BASE) {
//                 repo->wanted_objects_allocated =
//                     (repo->wanted_objects_count / ALLOC_BASE + 1) * ALLOC_BASE;
//                 struct wanted_object *const restrict wanted_objects_new =
//                     realloc(repo->wanted_objects,
//                         sizeof *repo->wanted_objects *
//                             repo->wanted_objects_allocated);
//                 if (wanted_objects_new == NULL) {
//                     pr_error_with_errno(
//                         "Failed to shrink memory used on wanted objects");
//                     return -1;
//                 }
//                 repo->wanted_objects = wanted_objects_new;
//             }
//             repo->wanted_dynamic = false;
//             for (unsigned long j = 0; j < repo->wanted_objects_count; ++j) {
//                 struct wanted_object *const restrict wanted_object =
//                     repo->wanted_objects + j;
//                 switch (wanted_object->type) {
//                 case WANTED_TYPE_BRANCH:
//                 case WANTED_TYPE_TAG:
//                 case WANTED_TYPE_REFERENCE:
//                 case WANTED_TYPE_HEAD:
//                     wanted_object->commit_parsed = false;
//                     wanted_object->parsed_commit_id = (unsigned long) -1;
//                     wanted_object->hex_string[0] = '\0';
//                     memset(&wanted_object->oid, 0, sizeof wanted_object->oid);
//                     __attribute__((fallthrough));
//                 case WANTED_TYPE_ALL_BRANCHES:
//                 case WANTED_TYPE_ALL_TAGS:
//                     repo->wanted_dynamic = true;
//                     break;
//                 case WANTED_TYPE_COMMIT:
//                     break;
//                 case WANTED_TYPE_UNKNOWN:
//                     pr_error("Wanted object '%s' type still unknown?!",
//                         wanted_object->name);
//                     return -1;
//                 }
//                 wanted_object->parsed_commit_id = (unsigned long) -1;
//             }
//             repo->updated = false;
//         }
//         if (config->clean_repos) {
//             workdir_repos->keeps_count = 1;
//             memcpy(workdir_repos->keeps, "links", 6);
//         }
//         if (config->clean_archives) {
//             workdir_archives->keeps_count = 1;
//             memcpy(workdir_archives->keeps, "links", 6);
//         }
//         if (config->clean_checkouts) {
//             workdir_checkouts->keeps_count = 1;
//             memcpy(workdir_checkouts->keeps, "links", 6);
//         }
//         if (watch_config) {
//             if (stat(config_path, &stat_buffer)) {
//                 pr_warn("Failed to stat config '%s' to get its mtime, won't "
//                 "update config\n", config_path);
//             } else if (
//                 (stat_buffer.st_mode & S_IFMT) == S_IFREG &&
//                 ((stat_buffer.st_mtim.tv_nsec != config_mtime.tv_nsec) ||
//                 (stat_buffer.st_mtim.tv_sec != config_mtime.tv_sec))) {

//                 config_mtime = stat_buffer.st_mtim;
//                 pr_warn("Config '%s' updated, re-reading config\n",
//                         config_path);
//                 struct config config_new = CONFIG_INIT;
//                 struct work_directory workdir_repos_new, workdir_archives_new,
//                                         workdir_checkouts_new;
//                 if (config_read(&config_new, config_path)) {
//                     pr_warn("Failed to read new config, "
//                             "keep using the old one\n");
//                     config_free(&config_new);
//                 } else if (config_new.repos_count == 0) {
//                     pr_warn("New config has no repos defined, keep using the "
//                             "old one\n");
//                     config_free(&config_new);
//                 } else if (work_directories_from_config(
//                     &workdir_repos_new, &workdir_archives_new,
//                     &workdir_checkouts_new, &config_new
//                 )) {
//                     pr_warn("Failed to open work directories for new config, "
//                             "keep using the old one\n");
//                     config_free(&config_new);
//                 } else {
//                     if (git_libgit2_opts(GIT_OPT_SET_SERVER_CONNECT_TIMEOUT,
//                         config_new.timeout_connect)) {
//                         pr_warn("Failed to update connect timeout config, "
//                         "error: %d (%s)\n",
//                             git_error_last()->klass, git_error_last()->message);
//                     }
//                     work_directories_free(
//                     workdir_repos, workdir_archives, workdir_checkouts);
//                     config_free(config);
//                     *config = config_new;
//                     *workdir_repos = workdir_repos_new;
//                     *workdir_archives = workdir_archives_new;
//                     *workdir_checkouts = workdir_checkouts_new;

//                     pr_info("Starting using new config\n");

//                 }
//             }
//         }
//         sleep(config->daemon_interval);
//     }
//     return -1;
// }

static inline
int gmr_set_timeout(int const timeout) {
    if (timeout && git_libgit2_opts(
        GIT_OPT_SET_SERVER_CONNECT_TIMEOUT, timeout)) {
        pr_error("Failed to set timeout, %d (%s)\n",
            git_error_last()->klass, git_error_last()->message);
        return -1;
    }
    return 0;
}

static inline
int gmr_work(char const *const restrict config_path) {
    int r = setvbuf(stdout, NULL, _IOLBF, 0);
    if (r) {
        pr_error_with_errno(
            "Failed to set stdout to line-buffered, return %d", r);
        return -1;
    }
    struct config config;
    if (config_read(&config, config_path)) {
        pr_error("Failed to read config\n");
        return -1;
    }
    config_print(&config);
    if (config.repos_count == 0) {
        pr_warn("No repos defined, early quit\n");
        r = 0;
        goto free_config;
    }
    struct work_handle work_handle;
    if (work_handle_init_from_config(&work_handle, &config, -1)) {
        r = -1;
        goto free_config;
    }
    if (!work_handle.repos_count) {
        pr_error("No repos after parsing config to work handle\n");
        r = -1;
        goto free_work_handle;
    }
    pr_info("Initializing libgit2\n");
    if ((r = git_libgit2_init()) != 1) {
        pr_error_with_libgit_error("Failed to init libgit2");
        if (r > 0) {
            r = -1;
            goto shutdown;
        }
        goto free_work_handle;
    }
    if (gmr_set_timeout(config.timeout_connect) ||
        work_handle_open_all_repos(&work_handle) || 
        work_handle_update_all_repos(&work_handle) ||
        work_handle_parse_all_repos(&work_handle) ||
        work_handle_export_all_repos(&work_handle) ||
        work_handle_link_all_repos(&work_handle)) {
        r = -1;
        goto shutdown;
    }
    r = 0;
shutdown:
    pr_info("Shutting down libgit2\n");
    git_libgit2_shutdown();
free_work_handle:
    work_handle_free(&work_handle);
free_config:
    config_free(&config);
    return r;
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
    return gmr_work(config_path);
}