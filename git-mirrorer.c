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
I know you would want to say: "Hold the fk up, why is this program written in a
single .c file? Don't you know you could write it in multiple .c files and com-
pile them into individual object files then linking them together? Not to say
it's several thousands LOC! How could you even get a comprehensive understanding
of how the program works by yourself?"

Look, I've written a lot of programs with the multiple source files: ampart,
eemount, YAopenVFD, nvrust, etc. Keeping the source splited and decoupled is
good, but burnt me out as an invidual develeoper: all these programs were com-
pletely written by myself, and then turnt out each to be several thousands LOC,
which made it harder and harder to jump back and forward among all those diffe-
rent source files.

As such, the whole program was written in a single .c file as an experiment at
first, but then at the point where I would split it up I decided to keep it as
a whole this time: splitting the source is not a cure but really an excuse to
pile a lot of boilerplate codes and the source of the evilness of overly abstra-
ction. I want to keep this always as a single file, but much easier than those
multi-source programs to go through and get an idea of what is done.
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

/* Commit */

#define COMMIT_ID_DECLARE { \
    git_oid oid; \
    char hex_string[GIT_OID_MAX_HEXSIZE + 1]; \
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
    XXH64_hash_t url_hash;
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
    bool    submodules_parsed,
            archive,
            checkout;
};

struct commit const COMMIT_INIT = {0};


/* Wanted objects */

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

char const *wanted_type_strings[] = {
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
    bool commit_resolved; \
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
    git_repository *git_repository;
    bool from_config, wanted_dynamic, need_update, updated;
};

struct repo_domain_group {
    hash_type domain;
    DYNAMIC_ARRAY_DECLARE(struct repo_work *, repo);
};

struct repo_domain_map {
    DYNAMIC_ARRAY_DECLARE(struct repo_domain_group, group);
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
    DYNAMIC_ARRAY_DECLARE_SAME(archive_pipe_arg);
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
    char args_buffer_stack[0x100];
    char *args_buffer_heap = NULL;
    char *args_buffer;
    if (args_length >= 0x100) {
        if (!(args_buffer_heap = malloc(
                sizeof *args_buffer * (args_length + 1)))) {
            pr_error("Failed to allocate memory for buffer\n");
            return -1;
        }
        args_buffer = args_buffer_heap;
    } else {
        args_buffer = args_buffer_stack;
    }
    memcpy(args_buffer, event->data.scalar.value, args_length);
    args_buffer[args_length] = '\0';
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
    free_if_allocated(args_buffer_heap);
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

static inline
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
    char long_name_stack[0x100];
    char *long_name_heap = NULL;
    char *long_name;
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
#else
    if (len_url + 4 < 0x100) {
        long_name = long_name_stack;
    } else {
        if (!(long_name_heap = malloc(len_url + 5))) {
            pr_error("Failed to allocate memory for long name\n");
            return -1;
        }
        long_name = long_name_heap;
    }
#endif
    long_name[0] = '\0';
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
        long_name[repo->len_long_name++] = url[i];
    }
    if (!has_domain) {
        pr_error("Url '%s' does not have domain\n",
                    sbuffer->buffer + repo->url_offset);
        r = -1;
        goto free_long_name_heap;
    }
    if (!repo->len_long_name) {
        pr_error("Long name for url '%s' is empty\n",
                    sbuffer->buffer + repo->url_offset);
        r = -1;
        goto free_long_name_heap;
    }
#ifndef TREAT_DOTGIT_AS_DIFFERENT_REPO
    memcpy(long_name + repo->len_long_name, ".git", 4);
    repo->len_long_name += 4;
#endif
    repo->long_name_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, long_name, repo->len_long_name)) {
        long_name[repo->len_long_name] = '\0';
        pr_error("Failed to add long name '%s' to string buffer\n",
                    long_name);
        r = -1;
        goto free_long_name_heap;
    }
    repo->hash_long_name = hash_calculate(long_name, repo->len_long_name);


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
        goto free_long_name_heap;
    }
    char const *const short_name = url + short_name_offset;
    repo->short_name_offset = sbuffer->used;
    if (string_buffer_add(sbuffer, short_name, repo->len_short_name)) {
        pr_error("Failed to add short name '%s' to string buffer\n",
                url + short_name_offset);
        r = -1;
        goto free_long_name_heap;
    }
    repo->hash_short_name = hash_calculate(short_name, repo->len_short_name);
    r = 0;
free_long_name_heap:
    free_if_allocated(long_name_heap);
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
            print_config(config);
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
    char const *const restrict path,
    unsigned short const len_path
) {
    if (path && len_path);
    else {
        pr_error("Internal: caller passed NULL pointer or 0-length path\n");
        return -1;
    }
    char path_stack[0x100]; // 256 is long enough for normal paths
    char *path_heap = NULL;
    char *path_dup;
    if (len_path >= sizeof path_stack) {
        if (!(path_heap = malloc(len_path + 1))) {
            pr_error_with_errno("Failed to allocate memory");
            return -1;
        }
        path_dup = path_heap;
    } else {
        path_dup = path_stack;
    }
    memcpy(path_dup, path, len_path);
    path_dup[len_path] = '\0';
    unsigned short from_left = 0;
    int r;
    /* Go from right to reduce mkdir calls */
    /* In the worst case this takes double the time than from left */
    /* but in the most cases parents should exist and this should */
    /* skip redundant mkdir syscalls */
    for (unsigned short i = len_path; i; --i) {
        bool revert_slash = false;
        switch (path_dup[i]) {
        case '/':
            path_dup[i] = '\0';
            revert_slash = true;
            __attribute__((fallthrough));
        case '\0':
            r = mkdir_allow_existing(path_dup);
            if (revert_slash) path_dup[i] = '/';
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
        switch (path_dup[i]) {
        case '/':
            path_dup[i] = '\0';
            revert_slash = true;
            __attribute__((fallthrough));
        case '\0':
            r = mkdir_allow_existing(path_dup);
            if (revert_slash) path_dup[i] = '/';
            if (r) {
                pr_error("Failed to mkdir '%s'\n", path_dup);
                r = -1;
                goto free_path_heap;
            }
            break;
        }
    }
    r = 0;
free_path_heap:
    free_if_allocated(path_heap);
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
    char path_stack[0x100]; // 256 is long enough for normal paths
    char *path_heap = NULL;
    char *path_dup;
    if (len_path >= sizeof path_stack) {
        if (!(path_heap = malloc(len_path + 1))) {
            pr_error_with_errno("Failed to allocate memory");
            return -1;
        }
        path_dup = path_heap;
    } else {
        path_dup = path_stack;
    }
    memcpy(path_dup, path, len_path);
    path_dup[len_path] = '\0';
    unsigned short from_left = 0;
    int r;
    /* Go from right to reduce mkdir calls */
    /* In the worst case this takes double the time than from left */
    /* but in the most cases parents should exist and this should */
    /* skip redundant mkdir syscalls */
    for (unsigned short i = len_path; i; --i) {
        bool revert_slash = false;
        switch (path_dup[i]) {
        case '/':
            path_dup[i] = '\0';
            revert_slash = true;
            __attribute__((fallthrough));
        case '\0':
            r = mkdir_allow_existing_at(dir_fd, path_dup);
            if (revert_slash) path_dup[i] = '/';
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
        switch (path_dup[i]) {
        case '/':
            path_dup[i] = '\0';
            revert_slash = true;
            __attribute__((fallthrough));
        case '\0':
            r = mkdir_allow_existing_at(dir_fd, path_dup);
            if (revert_slash) path_dup[i] = '/';
            if (r) {
                pr_error("Failed to mkdir '%s'\n", path_dup);
                r = -1;
                goto free_path_heap;
            }
            break;
        }
    }
    r = 0;
free_path_heap:
    free_if_allocated(path_heap);
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
int wanted_object_complete_from_base(
    struct wanted_object *const restrict wanted_object,
    struct string_buffer const *const restrict sbuffer
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
    wanted_object->commit_resolved = false;
    wanted_object->parsed_commit_id = (unsigned long) -1;
    if (wanted_object->type != WANTED_TYPE_COMMIT) {
        memset(&wanted_object->oid, 0, sizeof wanted_object->oid);
        wanted_object->hex_string[0] = '\0';
        return 0;
    }
    if (git_oid_fromstr(&wanted_object->oid, name)) {
        pr_error("Failed to convert '%s' to a git oid\n", name);
        return -1;
    }
    if (git_oid_fmt(
            wanted_object->hex_string,
            &wanted_object->oid)) {
        pr_error("Failed to format git oid hex string\n");
        return -1;
    }
    wanted_object->hex_string[sizeof wanted_object->hex_string - 1] = '\0';
    return 0;
}

static inline
int wanted_object_work_from_config(
    struct wanted_object *const restrict wanted_work,
    struct wanted_base const *const restrict wanted_config,
    struct string_buffer const *const restrict sbuffer
) {
    wanted_work->base = *wanted_config;
    return wanted_object_complete_from_base(wanted_work, sbuffer);
}

static inline
int repo_work_from_config(
    struct repo_work *restrict repo_work,
    struct repo_config const *const restrict repo_config,
    struct string_buffer const *const restrict sbuffer
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
    repo_work->commits = NULL;
    repo_work->commits_count = 0;
    repo_work->commits_allocated = 0;
    repo_work->git_repository = NULL;
    repo_work->need_update = repo_work->wanted_dynamic;
    repo_work->updated = false;
    repo_work->common = repo_config->common;
    repo_work->from_config = true;
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

int gcb_sideband_progress(char const *string, int len, void *payload) {
    pr_info("Repo '%s': Remote: %.*s",
        (char const *)payload, len, string);
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

static inline void gcb_print_progress(
    git_indexer_progress const *const restrict stats,
    char const *const restrict repo
) {
	if (stats->total_objects &&
		stats->received_objects == stats->total_objects) {
		pr_info("Repo '%s': Resolving deltas %u%% (%u/%u)\r",
                repo,
                stats->total_deltas > 0 ?
                    100 * stats->indexed_deltas / stats->total_deltas :
                    0,
                stats->indexed_deltas,
                stats->total_deltas);
	} else {
        char suffix;
        unsigned int size_human_readable = size_to_human_readable_uint(
            stats->received_bytes, &suffix);
		pr_info(
            "Repo '%s': Receiving objects %u%% (%u%c, %u); "
            "Indexing objects %u%% (%u); "
            "Total objects %u.\r",
            repo,
            stats->total_objects > 0 ?
                100 * stats->received_objects / stats->total_objects :
                0,
            size_human_readable, suffix,
            stats->received_objects,
            stats->total_objects > 0 ?
                100 * stats->indexed_objects/ stats->total_objects :
                0,
            stats->indexed_objects,
            stats->total_objects);
	}
}

int gcb_fetch_progress(git_indexer_progress const *stats, void *payload) {
	gcb_print_progress(stats, (char const *)payload);
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
    work_handle->_static = config->_static;
    if (work_handle_repos_init_from_config(work_handle, config)) {
        pr_error("Failed to init repos\n");
        goto free_string_buffer;
    }
    if (work_handle_work_directories_init(work_handle)) {
        pr_error("Failed to init work directories\n");
        goto free_repos;
    }
    if (isatty(STDOUT_FILENO)) {
        work_handle->cb_sideband = gcb_sideband_progress;
        work_handle->cb_fetch = gcb_fetch_progress;
    } else {
        work_handle->cb_sideband = NULL;
        work_handle->cb_fetch = NULL;
    }
    return 0;
free_repos:
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        free_if_allocated(work_handle->repos[i].wanted_objects);
    }
    free_if_allocated_to_null(work_handle->repos);
free_string_buffer:
    free_if_allocated_to_null(work_handle->string_buffer.buffer);
free_cwd:
    if (close(work_handle->cwd))
        pr_error_with_errno("Failed to clsoe opened/duped cwd");
    return -1;
}

static inline
void repo_work_free(
    struct repo_work *const restrict repo_work
) {
    free_if_allocated_to_null(repo_work->commits);
    free_if_allocated_to_null(repo_work->wanted_objects);
    if (repo_work->git_repository) {
        git_repository_free(repo_work->git_repository);
        repo_work->git_repository = NULL;
    }
}

void work_handle_free(
    struct work_handle *const restrict work_handle
) {
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        repo_work_free(work_handle->repos + i);
    }
    free_if_allocated_to_null(work_handle->repos);
    free_if_allocated_to_null(work_handle->string_buffer.buffer);
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

static inline
int format_link_target(
    char **const target,
    char *const restrict target_stack,
    char **const restrict target_heap,
    size_t *target_heap_allocated,
    unsigned short const depth_link,
    char const *const restrict target_suffix,
    unsigned short const len_target_suffix
) {
    // E.g. links/A -> ../data/B
    size_t const len = depth_link * 3 + 5 + len_target_suffix;
    if (len + 1 >= 0x100) {
        if (len + 1 >= *target_heap_allocated) {
            free_if_allocated(*target_heap);
            if (!(*target_heap = malloc((*target_heap_allocated = 
                    (len + 2) / 0x1000 * 0x1000)))) {
                pr_error_with_errno("Failed to allocate memory");
                return -1;
            }
        }
        *target = *target_heap;
    } else {
        *target = target_stack;
    }
    char *current = *target;
    for (unsigned short i = 0; i < depth_link; ++i) {
        memcpy(current, "../", 3);
        current += 3;
    }
    memcpy(current, "data/", 5);
    current += 5;
    memcpy(current, target_suffix, len_target_suffix);
    (*target)[len] = '\0';
    return 0;
}

int work_handle_link_all_repos(
    struct work_handle const *const restrict work_handle
) {
    if (!work_handle->repos_count) {
        pr_error("No repos defined\n");
        return -1;
    }
    char target_stack[0x100];
    char *target_heap = NULL;
    size_t target_heap_allocated = 0;
    char *target;
    int r;
    for (unsigned long i = 0; i < work_handle->repos_count; ++i) {
        struct repo_work const *const restrict repo_work = 
            work_handle->repos + i;
        if (format_link_target(&target, target_stack, &target_heap, 
                                &target_heap_allocated, 
                                repo_work->depth_long_name,
                                repo_work->hash_url_string,
                                HASH_STRING_LEN)) {
            r = -1;
            goto free_target_heap;   
        }
        if (ensure_symlink_at(work_handle->dir_repos.linkfd, 
                            work_handle_get_string(repo_work->long_name),
                            repo_work->len_long_name, target)) {
            r = -1;
            goto free_target_heap;
        }
    }
    r = 0;
free_target_heap:
    free_if_allocated(target_heap);
    return r;
}

static inline 
int gmr_remote_update(
    git_remote *const restrict remote,
    git_fetch_options const *const restrict fetch_opts
) {
    int r;
    if ((r = git_remote_connect(remote, GIT_DIRECTION_FETCH,
        &fetch_opts->callbacks, &fetch_opts->proxy_opts, NULL))) {
        pr_error_with_libgit_error("Failed to connect");
        return -1;
    }
    if ((r = git_remote_download(remote, &gmr_refspecs, fetch_opts))) {
        pr_error_with_libgit_error("Failed to download from remote");
    }
    int r2;
    if ((r2 = git_remote_disconnect(remote))) {
        pr_error_with_libgit_error("Failed to disconnect from remote");
    }
    if (r || r2) return -1;
    if ((r = git_remote_update_tips(remote, &fetch_opts->callbacks, 0,
                        GIT_REMOTE_DOWNLOAD_TAGS_AUTO, NULL))) {
        pr_error_with_libgit_error("Failed to update tips");
        return -1;
    }
    if ((r = git_remote_prune(remote, &fetch_opts->callbacks))) {
        pr_error("Failed to prune remote");
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
    unsigned short const proxy_after
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
    fetch_opts.callbacks.payload = (void *)url;
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
};

void *gmr_repo_update_thread(void *arg) {
    struct gmr_repo_update_thread_arg *const restrict parg = arg;
    parg->r = gmr_repo_update(
        parg->repo, parg->url, parg->fetch_opts_orig, parg->proxy_after);
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

static inline
int repo_domain_map_update(
    struct repo_domain_map const *const restrict map,
    unsigned short const max_connections,
    struct gmr_repo_update_thread_arg *thread_arg_init,
    char const *const restrict sbuffer
) {
    struct thread_helper {
        bool used;
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
        threads_count = chunk;
        *threads_count = 0;
        thread_helpers = chunk + sizeof *threads_count;
        for (unsigned long j = 0; j < max_connections; ++j) {
            struct thread_helper *const restrict thread_helper = 
                thread_helpers + j;
            thread_helper->used = false;
            thread_helper->arg = *thread_arg_init;
        }
    }
    pthread_attr_t thread_attr;
    int r;
    if ((r = pthread_attr_init(&thread_attr))) {
        pr_error("Failed to init pthread attr, pthread return %d\n", r);
        r = -1;
        goto free_chunks;
    }
    if ((r = pthread_attr_setdetachstate(
            &thread_attr, PTHREAD_CREATE_DETACHED))) {
        r = -1;
        goto destroy_attr;
    }
    unsigned short active_threads;
    bool bad_ret = false;
    for (;;) {
        active_threads = 0;
        for (unsigned long i = 0; i < map->groups_count; ++i) {
            void *const chunk = chunks + chunk_size * i;
            threads_count = chunk;
            thread_helpers = chunk + sizeof *threads_count;
            if (*threads_count) {
                for (unsigned short j = 0; j < max_connections; ++j) {
                    struct thread_helper *thread_helper = thread_helpers + j;
                    if (thread_helper->used && thread_helper->arg.finished);
                    else continue;
                    --*threads_count;
                    if (thread_helper->arg.r) {
                        pr_error("Repo updater for '%s' returned with %d\n",
                            thread_helper->arg.url, thread_helper->arg.r);
                        bad_ret = true;
                    }
                    thread_helper->used = false;
                }
            }
            struct repo_domain_group* const restrict group = map->groups + i;
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
                thread_helper->used = true;
                pthread_t thread;
                if ((r = pthread_create(&thread, &thread_attr, 
                    gmr_repo_update_thread, &thread_helper->arg))) {
                    pr_error(
                        "Failed to create thread, pthread return %d\n", r);
                    thread_helper->used = false;
                    r = -1;
                    goto wait_threads;
                }
                ++*threads_count;
            }
            active_threads += *threads_count;
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
    for (unsigned long i = 0; i < map->groups_count; ++i) {
        void *const chunk = chunks + chunk_size * i;
        threads_count = chunk;
        if (!*threads_count) continue;
        thread_helpers = chunk + sizeof *threads_count;
        for (unsigned long j = 0; j < max_connections; ++j) {
            struct thread_helper *const restrict thread_helper
                = thread_helpers + j;
            if (thread_helper->used) {
                pr_info("Waiting for updater for '%s'...\n", 
                        thread_helper->arg.url);
                while (!thread_helper->arg.finished) {
                    usleep(100000);
                }
                if (thread_helper->arg.r) {
                    pr_error("Updater for '%s' bad return %d...\n", 
                        thread_helper->arg.url, thread_helper->arg.r);
                    r = -1;
                }
            }
        }
    }
destroy_attr:
    pthread_attr_destroy(&thread_attr);
free_chunks:
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
    struct repo_domain_map map;
    if (repo_domain_map_init(&map, work_handle->repos, 
                            work_handle->repos_count)) 
    {
        pr_error("Failed to map repos by domain");
        return -1;
    }
    int r;
    if (!map.groups_count) {
        pr_error("Repos map is empty");
        r = -1;
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
// int mkdir_allow_existing_at(
//     int const dirfd,
//     char *const restrict path
// ) {
//     if (mkdirat(dirfd, path, 0755)) {
//         if (errno == EEXIST) {
//             struct stat stat_buffer;
//             if (fstatat(dirfd, path, &stat_buffer, AT_SYMLINK_NOFOLLOW)) {
//                 pr_error_with_errno("Failed to stat '%s'", path);
//                 return -1;
//             }
//             if ((stat_buffer.st_mode & S_IFMT) == S_IFDIR) {
//                 return 0;
//             } else {
//                 pr_error("Exisitng '%s' is not a folder\n", path);
//                 return -1;
//             }
//         } else {
//             pr_error_with_errno("Failed to mkdir '%s'", path);
//             return -1;
//         }
//     }
//     return 0;
// }

// int mkdir_recursively_at(
//     int const dirfd,
//     char *const restrict path
// ) {
//     for (char *c = path; ; ++c) {
//         switch (*c) {
//         case '\0':
//             return mkdir_allow_existing_at(dirfd, path);
//         case '/':
//             *c = '\0';
//             int r = mkdir_allow_existing_at(dirfd, path);
//             *c = '/';
//             if (r) {
//                 pr_error("Failed to mkdir recursively '%s'\n", path);
//                 return -1;
//             }
//             break;
//         default:
//             break;
//         }
//     }
// }

// int remove_dir_recursively(
//     DIR * const restrict dir_p
// ) {
//     struct dirent *entry;
//     errno = 0;
//     int dir_fd = dirfd(dir_p);
//     while ((entry = readdir(dir_p)) != NULL) {
//         if (entry->d_name[0] == '.') {
//             switch (entry->d_name[1]) {
//             case '\0':
//                 continue;
//             case '.':
//                 if (entry->d_name[2] == '\0') continue;
//                 break;
//             }
//         }
//         switch (entry->d_type) {
//         case DT_REG:
//         case DT_LNK:
//             if (unlinkat(dir_fd, entry->d_name, 0)) {
//                 pr_error_with_errno(
//                     "Failed to delete '%s' recursively", entry->d_name);
//                 return -1;
//             }
//             break;
//         case DT_DIR: {
//             int dir_fd_r = openat(dir_fd, entry->d_name, O_RDONLY);
//             if (dir_fd_r < 0) {
//                 pr_error_with_errno(
//                     "Failed to open dir entry '%s'", entry->d_name);
//                 return -1;
//             }
//             DIR *dir_p_r = fdopendir(dir_fd_r);
//             if (dir_p_r == NULL) {
//                 pr_error_with_errno(
//                     "Failed to open '%s' as subdir", entry->d_name);
//                 if (close(dir_fd_r)) {
//                     pr_error_with_errno("Failed to close fd for recursive dir");
//                 }
//                 return -1;
//             }
//             int r = remove_dir_recursively(dir_p_r);
//             if (closedir(dir_p_r)) {
//                 pr_error_with_errno("Faild to close dir");
//             }
//             if (r) {
//                 pr_error("Failed to remove dir '%s' recursively\n",
//                     entry->d_name);
//                 return -1;
//             }
//             if (unlinkat(dir_fd, entry->d_name, AT_REMOVEDIR)) {
//                 pr_error_with_errno(
//                     "Failed to rmdir '%s' recursively", entry->d_name);
//                 return -1;
//             }
//             break;
//         }
//         default:
//             pr_error("Unsupported file type %d for '%s'\n",
//                 entry->d_type, entry->d_name);
//             return -1;
//         }

//     }
//     if (errno) {
//         pr_error_with_errno("Failed to read dir\n");
//         return -1;
//     }
//     return 0;
// }

// int ensure_path_non_exist( // essentially rm -rf
//     char const *const restrict path
// ) {
//     struct stat stat_buffer;
//     if (stat(path, &stat_buffer)) {
//         switch(errno) {
//         case ENOENT:
//             return 0;
//         default:
//             pr_error_with_errno("Failed to get stat of path '%s'", path);
//             return -1;
//         }
//     }
//     mode_t mode = stat_buffer.st_mode & S_IFMT;
//     switch (mode) {
//     case S_IFDIR: {
//         DIR *const restrict dir_p = opendir(path);
//         if (dir_p == NULL) {
//             pr_error_with_errno("Failed to opendir '%s'", path);
//             return -1;
//         }
//         int r = remove_dir_recursively(dir_p);
//         if (closedir(dir_p)) {
//             pr_error_with_errno("Failed to close dir");
//         }
//         if (r) {
//             pr_error("Failed to remove '%s' recursively\n", path);
//             return -1;
//         }
//         if (rmdir(path)) {
//             pr_error_with_errno("Failed to rmdir '%s'", path);
//             return -1;
//         }
//         break;
//     }
//     case S_IFREG:
//         if (unlink(path)) {
//             pr_error_with_errno("Failed to remove regular file '%s'", path);
//             return -1;
//         }
//         break;
//     default:
//         pr_error("Cannot remove existing '%s' with type %d\n", path, mode);
//         return -1;
//     }
//     return 0;
// }

// int ensure_path_non_exist_at( // essentially rm -rf
//     int const dir_fd,
//     char const *const restrict path
// ) {
//     struct stat stat_buffer;
//     if (fstatat(dir_fd, path, &stat_buffer, AT_SYMLINK_NOFOLLOW)) {
//         switch(errno) {
//         case ENOENT:
//             return 0;
//         default:
//             pr_error_with_errno("Failed to get stat of path '%s'", path);
//             return -1;
//         }
//     }
//     mode_t mode = stat_buffer.st_mode & S_IFMT;
//     switch (mode) {
//     case S_IFDIR: {
//         int const subdir_fd = openat(dir_fd, path, O_RDONLY | O_DIRECTORY);
//         // DIR *const restrict dir_p = opendir;
//         if (subdir_fd < 0) {
//             pr_error_with_errno("Failed to open subdir '%s'", path);
//             return -1;
//         }
//         DIR *const restrict dir_p = fdopendir(subdir_fd);
//         if (dir_p == NULL) {
//             pr_error_with_errno("Failed to opendir '%s'", path);
//             if (close(subdir_fd)) {
//                 pr_error_with_errno("Failed to close fd for subdir");
//             }
//             return -1;
//         }
//         int r = remove_dir_recursively(dir_p);
//         if (closedir(dir_p)) {
//             pr_error_with_errno("Failed to close dir");
//         }
//         if (r) {
//             pr_error("Failed to remove '%s' recursively\n", path);
//             return -1;
//         }
//         if (unlinkat(dir_fd, path, AT_REMOVEDIR)) {
//             pr_error_with_errno("Failed to rmdir '%s'", path);
//             return -1;
//         }
//         break;
//     }
//     case S_IFREG:
//     case S_IFLNK:
//         if (unlinkat(dir_fd, path, 0)) {
//             pr_error_with_errno("Failed to remove regular file '%s'", path);
//             return -1;
//         }
//         break;
//     default:
//         pr_error("Cannot remove existing '%s' with type %d\n", path, mode);
//         return -1;
//     }
//     return 0;
// }

// unsigned short get_unsigned_short_decimal_width(unsigned short number) {
//     unsigned short width = 0;
//     if (!number) return 1;
//     while (number) {
//         number /= 10;
//         ++width;
//     }
//     return width;
// }

// // Read from fd until EOF,
// // return the size being read, or -1 if failed,
// // the pointer should be free'd by caller


// // May re-allocate config->repos
// // int config_add_repo_and_init_with_url(
// //     struct config *const restrict config,
// //     char const *const restrict url,
// //     unsigned short const len_url,
// //     enum repo_added_from added_from
// // ) {
// //     if (config == NULL || url == NULL || len_url == 0) {
// //         pr_error("Internal: invalid argument\n");
// //         return -1;
// //     }

// // }

// int opendir_create_if_non_exist_at(
//     int const dir_fd,
//     char const *const restrict path,
//     unsigned short const len_path
// ) {
//     int subdir_fd = openat(
//             dir_fd, path,
//             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
//     if (subdir_fd < 0) {
//         switch (errno) {
//         case ENOENT:
//             char path_dup[PATH_MAX];
//             memcpy(path_dup, path, len_path + 1);
//             if (mkdir_recursively_at(dir_fd, path_dup)) {
//                 pr_error("Failed to create dir '%s'\n", path);
//                 return -1;
//             }
//             if ((subdir_fd = openat(
//                 dir_fd, path,
//                 O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
//                 pr_error_with_errno("Failed to open dir '%s'", path);
//                 return -1;
//             }
//             break;
//         default:
//             pr_error_with_errno("Failed to open dir '%s'", path);
//             return -1;
//         }
//     }
//     return subdir_fd;
// }


// int wanted_object_guarantee_symlinks(
//     struct wanted_object const *const restrict wanted_object,
//     struct repo const *const restrict repo,
//     char const *const restrict archive_suffix,
//     unsigned short const len_archive_suffix,
//     int const archives_links_dirfd,
//     int const checkouts_links_dirfd
// ) {
//     /* links/[sanitized url]/[commit hash](archive suffix)
//                             /named/[name](a.s.)
//                             /tags -> refs/tags
//                             /branches -> refs/heads
//      undetermimed layers -> /refs/[ref name](a.s.)
//                             /HEAD(a.s.)
//     */
//     bool    link_tags_to_dir_refs_tags = false,
//             link_branches_to_dir_refs_heads = false;
//     bool const  archive = wanted_object->archive,
//                 checkout = wanted_object->checkout;
//     char const *dir_link = "";
//     // E.g.
//     //  archive: archives/abcdef.tar.gz
//     //  link: archives/links/github.com/user/repo/abcdeg.tar.gz
//     //  target: ../../../../abcdef.tar.gz
//     //   github.com/user/repo has 3 parts, depth is 4
//     unsigned short link_depth = repo->url_no_scheme_sanitized_parts + 1;
//     switch (wanted_object->type) {
//         case WANTED_TYPE_UNKNOWN:
//             pr_error("Wanted type unknown for '%s'\n", wanted_object->name);
//             return -1;
//         case WANTED_TYPE_ALL_BRANCHES:
//         case WANTED_TYPE_ALL_TAGS:
//             return 0;
//         case WANTED_TYPE_BRANCH:
//             link_branches_to_dir_refs_heads = true;
//             dir_link = "refs/heads/";
//             link_depth += 2;
//             break;
//         case WANTED_TYPE_TAG:
//             link_tags_to_dir_refs_tags = true;
//             dir_link = "refs/tags/";
//             link_depth += 2;
//             break;
//         case WANTED_TYPE_REFERENCE:
//             if (!strncmp(wanted_object->name, "refs/", 5)) {
//                 char const *const ref_kind = wanted_object->name + 5;
//                 if (!strncmp(ref_kind, "heads/", 6))
//                     link_branches_to_dir_refs_heads = true;
//                 else if (!strncmp(ref_kind, "tags/", 5))
//                     link_tags_to_dir_refs_tags = true;
//             }
//             break;
//         case WANTED_TYPE_COMMIT:
//         case WANTED_TYPE_HEAD:
//             break;
//     }
//     switch (wanted_object->type) {
//     case WANTED_TYPE_BRANCH:
//     case WANTED_TYPE_TAG:
//     case WANTED_TYPE_REFERENCE:
//         if (!wanted_object->commit_resolved) {
// #ifdef ALL_REFERENCES_MUST_BE_RESOLVED
//             pr_error(
// #else
//             pr_warn(
// #endif
//                 "Commit not resolved for wanted object '%s' yet\n",
//                     wanted_object->name);
// #ifdef ALL_REFERENCES_MUST_BE_RESOLVED
//             return -1;
// #else
//             return 0;
// #endif
//         }
//         break;
//     default:
//         break;
//     }
//     for (unsigned short i = 0; i < wanted_object->len_name; ++i) {
//         switch (wanted_object->name[i]) {
//         case '/':
//             ++link_depth;
//             break;
//         case '\0':
//             pr_error("Name '%s' ends pre-maturely\n", wanted_object->name);
//             return -1;
//         }
//     }
//     int archives_repo_links_dirfd = -1;
//     if (archive) {
//         if ((archives_repo_links_dirfd = opendir_create_if_non_exist_at(
//             archives_links_dirfd, repo->url_no_scheme_sanitized,
//             repo->len_url_no_scheme_sanitized)) < 0) {
//             pr_error("Failed to open archive repos links dir\n");
//             return -1;
//         }
//     }
//     int checkouts_repo_links_dirfd = -1;
//     int r = -1;
//     if (checkout) {
//         if ((checkouts_repo_links_dirfd = opendir_create_if_non_exist_at(
//             checkouts_links_dirfd, repo->url_no_scheme_sanitized,
//             repo->len_url_no_scheme_sanitized)) < 0) {
//             pr_error("Failed to open Checkout repos links dir\n");
//             goto close_archives_repo_links_dirfd;
//         }
//     }
//     if (link_branches_to_dir_refs_heads) {
//         if (archive && guarantee_symlink_at(
//             archives_repo_links_dirfd, "branches", 8, "refs/heads")) {
//             goto close_checkouts_repo_links_dirfd;
//         }
//         if (checkout && guarantee_symlink_at(
//             checkouts_repo_links_dirfd, "branches", 8, "refs/heads")) {
//             goto close_checkouts_repo_links_dirfd;
//         }
//     }
//     if (link_tags_to_dir_refs_tags) {
//         if (archive && guarantee_symlink_at(
//             archives_repo_links_dirfd, "tags", 4, "refs/tags")) {
//             goto close_checkouts_repo_links_dirfd;
//         }
//         if (checkout && guarantee_symlink_at(
//             checkouts_repo_links_dirfd, "tags", 4, "refs/tags")) {
//             goto close_checkouts_repo_links_dirfd;
//         }
//     }
//     // The commit hash one
//     char symlink_path[PATH_MAX] = "";
//     char *symlink_path_current =
//         stpcpy(symlink_path, wanted_object->hex_string);
//     // unsigned short len_symlink_path = HASH_STRING_LEN;
//     char symlink_target[PATH_MAX] = "";
//     char *symlink_target_current = symlink_target;
//     for (unsigned short i = 0; i < repo->url_no_scheme_sanitized_parts+1; ++i) {
//         symlink_target_current = stpcpy(symlink_target_current, "../");
//     }
//     symlink_target_current = stpcpy(symlink_target_current,
//                                     wanted_object->hex_string);
//     if (checkout && guarantee_symlink_at(
//         checkouts_repo_links_dirfd,
//         symlink_path, HASH_STRING_LEN,
//         symlink_target)) {
//         goto close_checkouts_repo_links_dirfd;
//     }
//     if (archive) {
//         if (archive_suffix[0] == '\0' && guarantee_symlink_at(
//             archives_repo_links_dirfd,
//             symlink_path, HASH_STRING_LEN,
//             symlink_target)) {
//             goto close_checkouts_repo_links_dirfd;
//         } else {
//             strcpy(symlink_path_current, archive_suffix);
//             strcpy(symlink_target_current, archive_suffix);
//             if (guarantee_symlink_at(
//                 archives_repo_links_dirfd,
//                 symlink_path, HASH_STRING_LEN + len_archive_suffix,
//                 symlink_target)) {
//                 goto close_checkouts_repo_links_dirfd;
//             }
//         }
//     }

//     // The named one
//     if (wanted_object->type != WANTED_TYPE_COMMIT) {
//         char *symlink_path_current = stpcpy(symlink_path, dir_link);
//         symlink_path_current =
//             stpcpy(symlink_path_current, wanted_object->name);
//         unsigned short len_symlink_path = symlink_path_current - symlink_path;
//         char *symlink_target_current = symlink_target;
//         for (unsigned short i = 0; i < link_depth; ++i) {
//             symlink_target_current = stpcpy(symlink_target_current, "../");
//         }
//         symlink_target_current = stpcpy(
//             symlink_target_current,
//             wanted_object->hex_string);
//         if (checkout && guarantee_symlink_at(
//             checkouts_repo_links_dirfd,
//             symlink_path, len_symlink_path,
//             symlink_target)) {
//             goto close_checkouts_repo_links_dirfd;
//         }
//         if (archive) {
//             if (archive_suffix[0] == '\0' && guarantee_symlink_at(
//                 archives_repo_links_dirfd,
//                 symlink_path, len_symlink_path,
//                 symlink_target)) {
//                 goto close_checkouts_repo_links_dirfd;
//             } else {
//                 strcpy(symlink_path_current, archive_suffix);
//                 strcpy(symlink_target_current, archive_suffix);
//                 if (guarantee_symlink_at(
//                     archives_repo_links_dirfd,
//                     symlink_path, wanted_object->len_name + len_archive_suffix,
//                     symlink_target)) {
//                     goto close_checkouts_repo_links_dirfd;
//                 }
//             }
//         }
//     }

//     r = 0;

// close_checkouts_repo_links_dirfd:
//     if (checkout) {
//         if (close(checkouts_repo_links_dirfd)) {
//             pr_error_with_errno(
//                 "Failed to close file descriptor for checkouts/repo/links dir");
//         }
//     }
// close_archives_repo_links_dirfd:
//     if (archive) {
//         if (close(archives_repo_links_dirfd)) {
//             pr_error_with_errno(
//                 "Failed to close file descriptor for archives/repo/links dir");
//         }
//     }
//     return r;
// }


// struct wanted_object *config_get_last_wanted_object_of_last_repo(
//     struct config *const restrict config
// ) {
//     struct repo *const restrict repo = get_last(config->repos);
//     return get_last(repo->wanted_objects);
// }

// struct wanted_object *config_get_last_wanted_object_of_type(
//     struct config *const restrict config,
//     enum yaml_wanted_type type
// ) {
//     switch (type) {
//     case YAML_WANTED_UNKNOWN:
//         pr_error("Wanted type unknown\n");
//         return NULL;
//     case YAML_WANTED_GLOBAL_EMPTY:
//         return get_last(config->empty_wanted_objects);
//     case YAML_WANTED_GLOBAL_ALWAYS:
//         return get_last(config->always_wanted_objects);
//         break;
//     case YAML_WANTED_REPO:
//         return config_get_last_wanted_object_of_last_repo(config);
//     }
//     return NULL;
// }





// int guarantee_symlink (
//     char const *const restrict symlink_path,
//     unsigned short const len_symlink_path,
//     char const *const restrict symlink_target
// ) {
//     if (len_symlink_path >= PATH_MAX) {
//         pr_error("Symlink path too long\n");
//         return -1;
//     }
//     char path[PATH_MAX];
//     ssize_t len = readlink(symlink_path, path, PATH_MAX);
//     if (len < 0) {
//         switch (errno) {
//         case ENOENT:
//             break;
//         default:
//             pr_error_with_errno("Failed to read link at '%s'", symlink_path);
//             return -1;
//         }
//     } else {
//         path[len] = '\0';
//         if (strcmp(path, symlink_target)) {
//             pr_warn("Symlink at '%s' points to '%s' instead of '%s', "
//             "if you see this message for too many times, you've probably set "
//             "too many repos with same path but different schemes.\n",
//             symlink_path, path, symlink_target);
//             if (unlink(symlink_path) < 0) {
//                 pr_error_with_errno("Faild to unlink '%s'", symlink_path);
//                 return -1;
//             }
//         } else {
//             pr_debug("Symlink '%s' -> '%s' already existing\n",
//                 symlink_path, symlink_target);
//             return 0;
//         }
//     }
//     if (symlink(symlink_target, symlink_path) < 0) {
//         switch (errno) {
//         case ENOENT:
//             break;
//         default:
//             pr_error_with_errno(
//                 "Failed to create symlink '%s' -> '%s'",
//                 symlink_path, symlink_target);
//             return -1;
//         }
//     } else {
//         pr_debug("Created symlink '%s' -> '%s'\n",
//             symlink_path, symlink_target);
//         return 0;
//     }
//     char symlink_path_dup[PATH_MAX];
//     memcpy(symlink_path_dup, symlink_path, len_symlink_path);
//     symlink_path_dup[len_symlink_path] = '\0';
//     unsigned short last_sep = 0;
//     for (unsigned short i = len_symlink_path; i > 0; --i) {
//         char *c = symlink_path_dup + i;
//         if (*c == '/') {
//             if (!last_sep) {
//                 last_sep = i;
//             }
//             *c = '\0';
//             if (mkdir(symlink_path_dup, 0755)) {
//                 if (errno != ENOENT) {
//                     pr_error_with_errno(
//                         "Failed to create folder '%s' as parent of symlink "
//                         "'%s' -> '%s'",
//                         symlink_path_dup, symlink_path, symlink_target);
//                     return -1;
//                 }
//             } else {
//                 for (unsigned short j = i; j < last_sep; ++j) {
//                     c = symlink_path_dup + j;
//                     if (*c == '\0') {
//                         *c = '/';
//                         if (mkdir(symlink_path_dup, 0755)) {
//                             pr_error_with_errno(
//                                 "Failed to create folder '%s' as parent of "
//                                 "symlink '%s' -> '%s'",
//                                 symlink_path_dup, symlink_path, symlink_target);
//                             return -1;
//                         }
//                     }
//                 }
//                 break;
//             }
//         }
//     }
//     if (symlink(symlink_target, symlink_path) < 0) {
//         pr_error_with_errno(
//             "Failed to create symlink '%s' -> '%s'",
//             symlink_path, symlink_target);
//         return -1;
//     }
//     pr_debug("Created symlink '%s' -> '%s'\n",
//         symlink_path, symlink_target);
//     return 0;
// }

// int repo_guarantee_symlink(
//     struct repo *const restrict repo,
//     int const links_dirfd
// ) {
//     if (repo->url_no_scheme_sanitized_parts * 3 + HASH_STRING_LEN + 1
//              >= PATH_MAX) {
//         pr_error("Link target would be too long");
//         return -1;
//     }
//     char symlink_target[PATH_MAX] = "";
//     char *symlink_target_current = symlink_target;
//     for (unsigned short i = 0; i < repo->url_no_scheme_sanitized_parts; ++i) {
//         symlink_target_current = stpcpy(symlink_target_current, "../");
//     }
//     symlink_target_current = stpcpy(symlink_target_current, repo->hash_name);
//     if (guarantee_symlink_at(links_dirfd, repo->url_no_scheme_sanitized,
//         repo->len_url_no_scheme_sanitized, symlink_target)) {
//         pr_error("Failed to guarantee a symlink at '%s' pointing to '%s'\n",
//             repo->url_no_scheme_sanitized, symlink_target);
//         return -1;
//     }
//     return 0;
// }

// int repo_finish_bare(
//     struct repo *const restrict repo,
//     char const *const restrict dir_repos,
//     unsigned short len_dir_repos
// ) {
//     if (repo == NULL || dir_repos == NULL || len_dir_repos == 0 ||
//         repo->wanted_objects_count > 0) {
//         pr_error("Internal: invalid arguments\n");
//         return -1;
//     }
//     repo->len_dir_path = len_dir_repos + HASH_STRING_LEN + 1;
//     if (snprintf(repo->dir_path, repo->len_dir_path + 1, "%s/"HASH_FORMAT,
//         dir_repos, repo->url_hash) < 0) {
//         pr_error_with_errno(
//             "Failed to format dir path of repo '%s'\n",
//             repo->url);
//         return -1;
//     }
//     pr_debug("Repo '%s' will be stored at '%s'\n", repo->url, repo->dir_path);
//     return 0;
// }

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

// // static inline
// // void work_directories_free(
// //     struct work_directory *const restrict workdir_repos,
// //     struct work_directory *const restrict workdir_archives,
// //     struct work_directory *const restrict workdir_checkouts
// // ) {
// //     work_directory_free(workdir_repos);
// //     work_directory_free(workdir_archives);
// //     work_directory_free(workdir_checkouts);
// // }

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

// void *repo_update_thread(void *arg) {
//     struct repo_update_thread_arg *private_arg =
//         (struct repo_update_thread_arg *)arg;
//     pr_debug("Thread called for repo '%s'\n", private_arg->repo->url);
//     return (void *)(long)repo_update(private_arg->repo,
//         &private_arg->fetch_options, private_arg->proxy_after);
// }

// // Will also create symlink
// int repo_prepare_open_or_create_if_needed(
//     struct repo *const restrict repo,
//     int const links_dirfd,
//     git_fetch_options *const restrict fetch_options,
//     unsigned short const proxy_after,
//     bool const delay_update
// ) {
//     if (repo->repository != NULL) return 0;
//     if (repo_guarantee_symlink(repo, links_dirfd)) {
//         pr_error("Failed to create symlink\n");
//         return -1;
//     }
//     switch (repo_open_or_init_bare(repo)) {
//     case -1:
//         pr_error("Failed to open or init bare repo for '%s'\n", repo->url);
//         return -1;
//     case 0:
//         break;
//     case 1:
//         pr_warn(
//             "Repo '%s' just created locally, need to update\n", repo->url);
//         if (delay_update) repo->wanted_dynamic = true;
//         else if (repo_update(repo, fetch_options, proxy_after)) {
//             pr_error(
//                 "Failed to update freshly created repo '%s'\n", repo->url);
//             return -1;
//         }
//         break;
//     }
//     return 0;
// }

// void parsed_commit_free(
//     struct parsed_commit *const restrict parsed_commit
// ) {
//     if (parsed_commit->submodules) {
//         free(parsed_commit->submodules);
//     }
//     if (parsed_commit->commit) {
//         git_commit_free(parsed_commit->commit);
//     }
//     *parsed_commit = PARSED_COMMIT_INIT;
// }

// void repo_free(
//     struct repo *const restrict repo
// ) {
//     if (repo->parsed_commits) {
//         for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
//             parsed_commit_free(repo->parsed_commits + i);
//         }
//         free (repo->parsed_commits);
//     }
//     if (repo->wanted_objects) {
//         free (repo->wanted_objects);
//     }
//     if (repo->repository) {
//         git_repository_free(repo->repository);
//     }
//     *repo = REPO_INIT;
// }

// int parsed_commit_add_submodule_and_init_with_path_and_url(
//     struct parsed_commit *const restrict parsed_commit,
//     char const *const restrict path,
//     unsigned short len_path,
//     char const *const restrict url,
//     unsigned short len_url
// ) {
//     if (parsed_commit_add_submodule_no_init(parsed_commit)) {
//         pr_error("Failed to add submodule to commit\n");
//         return -1;
//     }
//     struct parsed_commit_submodule *const restrict submodule =
//         parsed_commit->submodules + parsed_commit->submodules_count -1;
//     *submodule = PARSED_COMMIT_SUBMODULE_INIT;
//     memcpy(submodule->path, path, len_path + 1);
//     memcpy(submodule->url, url, len_url + 1);
//     submodule->len_path = len_path;
//     submodule->len_url = len_url;
//     submodule->url_hash = hash_calculate(submodule->url, submodule->len_url);
//     return 0;
// }

// // May re-allocate the config->repos array, must re-assign repo after calling

// int parsed_commit_add_submodule_from_commit_tree(
//     struct parsed_commit *const restrict parsed_commit,
//     git_tree const *const restrict tree,
//     char const *const restrict path,
//     unsigned short const len_path,
//     char const *const restrict url,
//     unsigned short const len_url
// ) {
//     for (unsigned long i = 0; i < parsed_commit->submodules_count; ++i) {
//         if (!strcmp(parsed_commit->submodules[i].path, path)) {
//             pr_warn(
//                 "Already defined a submodule at path '%s' for commit %s\n",
//                 path, parsed_commit->id_hex_string);
//             return -1;
//         }
//     }
//     if (parsed_commit_add_submodule_and_init_with_path_and_url(
//         parsed_commit, path, len_path, url, len_url)) {
//         pr_error("Failed to init submodule for commit %s with path "
//                 "'%s' and url '%s'\n",
//                 parsed_commit->id_hex_string, path, url);
//         return -1;
//     }
//     struct parsed_commit_submodule *const restrict submodule =
//         get_last(parsed_commit->submodules);
//     git_tree_entry *entry;
//     if (git_tree_entry_bypath(&entry, tree, path)) {
//         pr_error("Path '%s' of submodule does not exist in tree\n", path);
//         return -1;
//     }
//     int r = -1;
//     if (git_tree_entry_type(entry) != GIT_OBJECT_COMMIT) {
//         pr_error("Object at path '%s' in tree is not a commit\n", path);
//         goto free_entry;
//     }
//     submodule->id = *git_tree_entry_id(entry);
//     if (git_oid_tostr(
//             submodule->id_hex_string,
//             sizeof submodule->id_hex_string,
//             &submodule->id
//         )[0] == '\0') {
//         pr_error("Failed to format commit id into hex string\n");
//         goto free_entry;
//     }
//     pr_info(
//         "Submodule needed: '%s' <= '%s': %s\n",
//         path, url, submodule->id_hex_string);
//     r = 0;
// free_entry:
//     git_tree_entry_free(entry);
//     return r;
// }

// // May re-allocate repo->parsed_commits
// int repo_add_parsed_commit(
//     struct repo *const restrict repo,
//     git_oid const *const restrict oid
// ) {
//     if (repo_add_parsed_commit_no_init(repo)) {
//         pr_error("Failed to add parsed commit without init\n");
//         return -1;
//     }
//     struct parsed_commit *const restrict parsed_commit =
//         get_last(repo->parsed_commits);
//     *parsed_commit = PARSED_COMMIT_INIT;
//     parsed_commit->id = *oid;
//     if (git_oid_tostr(
//             parsed_commit->id_hex_string,
//             sizeof parsed_commit->id_hex_string,
//             &parsed_commit->id
//         )[0] == '\0') {
//         pr_error("Failed to format commit id into hex string\n");
//         return -1;
//     }
//     return 0;
// }

// // May re-allocate config->repos
// int repo_parse_commit_submodule_in_tree(
//     struct config *const restrict config,
//     unsigned long const repo_id,
//     unsigned long const commit_id,
//     git_tree const *const restrict tree,
//     char const *const restrict path,
//     unsigned short const len_path,
//     char const *const restrict url,
//     unsigned short const len_url
// ) {
//     struct repo const *repo = config->repos + repo_id;
//     struct parsed_commit *parsed_commit =
//         repo->parsed_commits + commit_id;
//     if (parsed_commit_add_submodule_from_commit_tree(
//         parsed_commit, tree, path, len_path, url, len_url)) {
//         pr_error("Failed to add submodule from commit tree\n");
//         return -1;
//     }
//     struct parsed_commit_submodule *const restrict submodule =
//         get_last(parsed_commit->submodules);

//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         struct repo *const repo_cmp = config->repos + i;
//         if (repo_cmp->url_hash == submodule->url_hash) {
//             submodule->target_repo_id = i;
//             for (unsigned long j = 0; j < repo_cmp->parsed_commits_count; ++j) {
//                 if (git_oid_cmp(
//                     &submodule->id,
//                     &repo_cmp->parsed_commits[j].id)) continue;
//                 pr_debug(
//                     "Already added commit %s to repo '%s', skipped\n",
//                     submodule->id_hex_string, repo_cmp->url);
//                 submodule->target_commit_id = j;
//                 return 0;
//             }
//             break;
//         }
//     }
//     if (submodule->target_repo_id == (unsigned long) -1) {
//         pr_warn("Repo '%s' was not seen before, need to add it\n", url);
//         if (config_add_repo_and_init_with_url(config, url, len_url,
//             REPO_ADDED_FROM_SUBMODULE)) {
//             pr_error("Failed to add repo '%s'\n", url);
//             return -1;
//         }
//         repo = config->repos + repo_id;
//         submodule->target_repo_id = config->repos_count - 1;
//         if (repo_finish_bare(
//             get_last(config->repos), config->dir_repos, config->len_dir_repos)){
//             pr_error("Failed to finish bare repo\n");
//             return -1;
//         }
//     }
//     if (submodule->target_repo_id == (unsigned long) -1) {
//         pr_error("Submodule '%s' with url '%s' for commmit %s of repo '%s' "
//         "still missing target repo id, refuse to continue\n",
//             path, url, submodule->id_hex_string, repo->url);
//         return -1;
//     }
//     if (submodule->target_commit_id != (unsigned long) -1) return 0;
//     struct repo *repo_target =
//         config->repos + submodule->target_repo_id;
//     // The repo is either completely new, or we found it but not found commit
//     // There is no need to check for commit duplication here
//     int r = repo_add_parsed_commit(repo_target, &submodule->id);
//     // The above function may re-allocate repo_target, the re-assign here
//     // is in case repo == repo_target
//     parsed_commit = repo->parsed_commits + commit_id;
//     if (r) {
//         pr_error("Failed to add parsed commit to repo\n");
//         return -1;
//     }
//     submodule->target_commit_id = repo_target->parsed_commits_count - 1;
//     if (submodule->target_repo_id >= repo_id) {
//         pr_debug("Added commit %s as wanted to repo '%s', will handle "
//             "that repo later\n", submodule->id_hex_string, repo_target->url);
//         return 0;
//     }
//     pr_warn("Added commit %s as wanted to parsaed repo '%s', need to go back "
//             "to handle that specific commit\n",
//             submodule->id_hex_string, repo_target->url);
//     r = repo_ensure_parsed_commit(config, submodule->target_repo_id,
//                                     submodule->target_commit_id);
//     repo = config->repos + repo_id;
//     parsed_commit = repo->parsed_commits + commit_id;
//     if (r) {
//         pr_error("Failed to ensure repo '%s' commit %s 's submodule at '%s' "
//                 "from '%s' commit %s in target repo\n",
//                 repo->url, parsed_commit->id_hex_string, path, url,
//                 submodule->id_hex_string);
//         return 1;
//     };
//     return 0;
// }


// // May re-allocate the config->repos array, must re-assign repo after calling
// int repo_parse_commit_blob_gitmodules(
//     struct config *const restrict config,
//     unsigned long const repo_id,
//     unsigned long const commit_id,
//     git_tree const *const tree,
//     git_blob *const restrict blob_gitmodules
// ) {
//     char const *blob_gitmodules_ro_buffer =
//         git_blob_rawcontent(blob_gitmodules);
//     if (blob_gitmodules_ro_buffer == NULL) {
//         pr_error("Failed to get a ro buffer for gitmodules\n");
//         return -1;
//     }
//     git_object_size_t blob_gitmodules_size =
//         git_blob_rawsize(blob_gitmodules);
//     if (blob_gitmodules_size == 0) {
//         pr_error("Tree entry .gitmodules blob size is 0\n");
//         return -1;
//     }
//     char    submodule_name[NAME_MAX] = "",
//             submodule_path[PATH_MAX] = "",
//             submodule_url[PATH_MAX] = "";
//     unsigned short  len_submodule_name = 0,
//                     len_submodule_path = 0,
//                     len_submodule_url = 0;
//     for (git_object_size_t id_start = 0; id_start < blob_gitmodules_size; ) {
//         switch (blob_gitmodules_ro_buffer[id_start]) {
//         case '\0':
//         case '\n':
//         case '\r':
//         case '\b':
//             ++id_start;
//             continue;
//         }
//         unsigned short len_line = 0;
//         git_object_size_t id_end = id_start + 1;
//         for (; id_end < blob_gitmodules_size && len_line == 0;) {
//             switch (blob_gitmodules_ro_buffer[id_end]) {
//             case '\0':
//             case '\n':
//                 len_line = id_end - id_start;
//                 break;
//             default:
//                 ++id_end;
//                 break;
//             }
//         }
//         if (len_line > 7) { // The shortest, "\turl = "
//             char const *line = blob_gitmodules_ro_buffer + id_start;
//             char const *line_end = blob_gitmodules_ro_buffer + id_end;
//             switch (blob_gitmodules_ro_buffer[id_start]) {
//             case '[':
//                 if (!strncmp(line + 1, "submodule \"", 11)) {
//                     if (submodule_name[0]) {
//                         pr_error(
//                             "Incomplete submodule definition for '%s'\n",
//                             submodule_name);
//                         return -1;
//                     }
//                     char const *submodule_name_start = line + 12;
//                     char const *right_quote = submodule_name_start;
//                     for (;
//                         *right_quote != '"' && right_quote < line_end;
//                         ++right_quote);
//                     len_submodule_name = right_quote - submodule_name_start;
//                     strncpy(
//                         submodule_name,
//                         submodule_name_start,
//                         len_submodule_name);
//                     submodule_name[len_submodule_name] = '\0';
//                 }
//                 break;
//             case '\t':
//                 char const *value = NULL;
//                 char *submodule_value = NULL;
//                 unsigned short *len_submodule_value = NULL;
//                 if (!strncmp(line + 1, "path = ", 7)) {
//                     value = line + 8;
//                     submodule_value = submodule_path;
//                     len_submodule_value = &len_submodule_path;
//                 } else if (!strncmp(line + 1, "url = ", 6)) {
//                     value = line + 7;
//                     submodule_value = submodule_url;
//                     len_submodule_value = &len_submodule_url;
//                 }
//                 if (value) {
//                     if (submodule_name[0] == '\0') {
//                         pr_error(
//                             "Submodule definition begins before "
//                             "the submodule name\n");
//                         return -1;
//                     }
//                     if (submodule_value[0] != '\0') {
//                         pr_error("Duplicated value definition for "
//                             "submodule '%s'\n", submodule_name);
//                         return -1;
//                     }
//                     *len_submodule_value = line_end - value;
//                     strncpy(submodule_value, value, *len_submodule_value);
//                     submodule_value[*len_submodule_value] = '\0';
//                     if (submodule_path[0] != '\0' &&
//                         submodule_url[0] != '\0') {
//                         pr_debug(
//                             "Submodule '%s', path '%s', url '%s'\n",
//                             submodule_name, submodule_path, submodule_url);
//                         if (repo_parse_commit_submodule_in_tree(
//                             config, repo_id, commit_id, tree,
//                                     submodule_path, len_submodule_path,
//                                     submodule_url, len_submodule_url)) {
//                             pr_error(
//                                 "Failed to recursively clone or update "
//                                 "submodule '%s' (url '%s')\n",
//                                 submodule_name, submodule_url);
//                             return -1;
//                         }
//                         submodule_name[0] = '\0';
//                         submodule_path[0] = '\0';
//                         submodule_url[0] = '\0';
//                     }
//                 }
//                 break;
//             default:
//                 break;
//             }
//         }
//         id_start = id_end + 1;
//     }
//     return 0;
// }

// // May re-allocate the config->repos array, must re-assign repo after calling
// int repo_parse_commit_tree_entry_gitmodules(
//     struct config *const restrict config,
//     unsigned long const repo_id,
//     unsigned long const commit_id,
//     git_tree const *const tree,
//     git_tree_entry const *const entry_gitmodules
// ) {
//     struct repo const *restrict repo = config->repos + repo_id;
//     struct parsed_commit *restrict parsed_commit =
//         repo->parsed_commits + commit_id;
//     if (git_tree_entry_type(entry_gitmodules) != GIT_OBJECT_BLOB) {
//         pr_error(
//             "Tree entry .gitmodules in commit %s for repo '%s' "
//             "is not a blob\n",
//             parsed_commit->id_hex_string, repo->url);
//         return -1;
//     }
//     git_object *object_gitmodules;
//     int r = git_tree_entry_to_object(
//         &object_gitmodules, repo->repository, entry_gitmodules);
//     if (r) {
//         pr_error("Failed to convert tree entry for gitmodules to object\n");
//         return -1;
//     }
//     git_blob *blob_gitmodules = (git_blob *)object_gitmodules;
//     r = repo_parse_commit_blob_gitmodules(
//         config, repo_id, commit_id, tree, blob_gitmodules);
//     repo = config->repos + repo_id;
//     parsed_commit = repo->parsed_commits + commit_id;
//     if (r) {
//         pr_error("Failed to parse gitmodules blob\n");
//         r = -1;
//         goto free_object;
//     }
//     r = 0;
// free_object:
//     free(object_gitmodules);
//     return r;
// }

// // May re-allocate repo->parsed_commits
// int repo_parse_wanted_commit(
//     struct repo *const restrict repo,
//     struct wanted_commit *const restrict wanted_commit
// ) {
//     for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
//         if (!git_oid_cmp(&repo->parsed_commits[i].id, &wanted_commit->oid)) {
//             wanted_commit->parsed_commit_id = i;
//             goto sync_export_setting;
//         }
//     }
//     if (repo_add_parsed_commit(repo, &wanted_commit->oid)) {
//         pr_error("Failed to add parsed commit\n");
//         return -1;
//     }
//     wanted_commit->parsed_commit_id = repo->parsed_commits_count - 1;
// sync_export_setting:
//     struct parsed_commit *parsed_commit =
//         repo->parsed_commits + wanted_commit->parsed_commit_id;
//     if (wanted_commit->archive) parsed_commit->archive = true;
//     if (wanted_commit->checkout) parsed_commit->checkout = true;
//     return 0;
// }

// // May re-allocate repo->parsed_commits
// int repo_parse_wanted_reference_common(
//     struct repo *const restrict repo,
//     struct wanted_reference *const restrict wanted_reference,
//     git_reference *reference,
//     git_fetch_options *const restrict fetch_options,
//     unsigned short const proxy_after
// ) {
//     git_object *object;
//     int r;
//     if ((r = git_reference_peel(&object, reference, GIT_OBJECT_COMMIT))) {
//         if (repo->updated) {
//             pr_error(
//                 "Failed to peel reference '%s' into a commit object, "
//                 "libgit return %d\n",
//                 wanted_reference->name, r);
// #ifdef ALL_REFERENCES_MUST_BE_RESOLVED
//             return -1;
// #else
//             return 0;
// #endif
//         }
//         pr_warn("Failed to peel reference '%s' into a commit object, "
//                 "libgit return %d, but repo not updated yet, update to retry\n",
//                 wanted_reference->name, r);
//         if (repo_update(repo, fetch_options, proxy_after)) {
//             pr_error("Failed to update\n");
//             return -1;
//         }
//         if ((r = git_reference_peel(&object, reference, GIT_OBJECT_COMMIT))) {
//             pr_error("Failed to peel reference '%s' into commit object even "
//             "after updating, libgit return %d\n", wanted_reference->name, r);
//             return -1;
//         }
//     }
//     git_commit *commit = (git_commit *)object;
//     wanted_reference->commit_resolved = true;
//     wanted_reference->commit.oid = *git_commit_id(commit);
//     if (git_oid_tostr(
//             wanted_reference->commit.hex_string,
//             sizeof wanted_reference->commit.hex_string,
//             &wanted_reference->commit.oid
//         )[0] == '\0') {
//         pr_error("Failed to format git oid hex string\n");
//         git_object_free(object);
//         return -1;
//     }
//     git_object_free(object);
//     pr_info("Reference resolved: '%s': '%s' => %s\n",
//         repo->url, wanted_reference->name,
//         wanted_reference->commit.hex_string);
//     return repo_parse_wanted_commit(repo,
//                                 (struct wanted_commit *)wanted_reference);
// }

// void repo_parse_wanted_head_explain_libgit_return(int const r) {
//     switch (r) {
//     case GIT_EUNBORNBRANCH:
//         pr_error("Failed to find HEAD, HEAD points to a non-"
//             "existing branch\n");
//         break;
//     case GIT_ENOTFOUND:
//         pr_error("Failed to find HEAD, HEAD is missing\n");
//         break;
//     default:
//         pr_error("Failed to find HEAD, unhandled libgit return %d\n", r);
//         break;
//     }
// }

// // May re-allocate repo->parsed_commits
// int repo_parse_wanted_head(
//     struct repo *const restrict repo,
//     struct wanted_reference *const restrict wanted_head,
//     git_fetch_options *const restrict fetch_options,
//     unsigned short const proxy_after
// ) {
//     git_reference *head;
//     int r = git_repository_head(&head, repo->repository);
//     if (r) {
//         repo_parse_wanted_head_explain_libgit_return(r);
//         if (repo->updated) {
//             pr_error("Failed to find HEAD\n");
//             return -1;
//         }
//         pr_warn("Failed to find HEAD, but repo not updated yet, "
//                 "update to retry");
//         if (repo_update(repo, fetch_options, proxy_after)) {
//             pr_error("Failed to update\n");
//             return -1;
//         }
//         if ((r = git_repository_head(&head, repo->repository))) {
//             repo_parse_wanted_head_explain_libgit_return(r);
//             pr_error("Still failed to find HEAD after updating\n");
//             return -1;
//         }
//     }
//     r = repo_parse_wanted_reference_common(
//         repo, wanted_head, head, fetch_options, proxy_after);
//     git_reference_free(head);
//     return r;
// }

// void repo_parse_wanted_branch_explain_libgit_return(
//     int const r,
//     char const *const restrict branch,
//     char const *const restrict repo
// ) {
//     switch (r) {
//     case GIT_ENOTFOUND:
//         pr_error("Branch '%s' was not found in repo '%s'\n",
//             branch, repo);
//         break;
//     case GIT_EINVALIDSPEC:
//         pr_error("'%s' is an illegal branch spec\n", branch);
//         break;
//     default:
//         pr_error("Failed to find branch '%s', "
//             "unhandled libgit return %d\n",
//             branch, r);
//         break;
//     }
// }

// // May re-allocate the config->repos array, must re-assign repo after calling
// int repo_parse_wanted_branch(
//     struct repo *const restrict repo,
//     struct wanted_reference *const restrict wanted_branch,
//     git_fetch_options *const restrict fetch_options,
//     unsigned short const proxy_after
// ) {
//     git_reference *reference;
//     int r = git_branch_lookup(
//         &reference, repo->repository, wanted_branch->name, GIT_BRANCH_LOCAL);
//     if (r) {
//         repo_parse_wanted_branch_explain_libgit_return(
//             r, wanted_branch->name, repo->url);
//         if (repo->updated) {
//             pr_error("Failed to find branch\n");
//             return -1;
//         }
//         pr_warn(
//             "Failed to find branch, but repo not updated, update to retry\n");
//         if (repo_update(repo, fetch_options, proxy_after)) {
//             pr_error("Failed to update repo\n");
//             return -1;
//         }
//         if ((r = git_branch_lookup(
//             &reference, repo->repository, wanted_branch->name, GIT_BRANCH_LOCAL
//         ))) {
//             repo_parse_wanted_branch_explain_libgit_return(
//                 r, wanted_branch->name, repo->url);
//             pr_error("Still failed to lookup branch even after update\n");
//             return -1;
//         }
//     }
//     r = repo_parse_wanted_reference_common(
//         repo, wanted_branch, reference, fetch_options, proxy_after);
//     git_reference_free(reference);
//     return r;
// }

// void repo_parse_wanted_reference_explain_libgit_return(
//     int const r,
//     char const *const restrict reference,
//     char const *const restrict repo
// ) {
//     switch (r) {
//     case GIT_ENOTFOUND:
//         pr_error("Not found reference '%s' in repo '%s'\n", reference, repo);
//         break;
//     case GIT_EINVALIDSPEC:
//         pr_error("'%s' is not a valid reference spec\n", reference);
//         break;
//     default:
//         pr_error("Failed to lookup reference, unhandled libgit return %d\n", r);
//         break;
//     }
// }

// int repo_parse_wanted_reference_with_given_ref_name(
//     struct repo *const restrict repo,
//     struct wanted_reference *const restrict wanted_reference,
//     git_fetch_options *const restrict fetch_options,
//     unsigned short const proxy_after,
//     char const *const ref_name
// ) {
//     git_reference *reference;
//     int r = git_reference_lookup(&reference, repo->repository, ref_name);
//     if (r) {
//         repo_parse_wanted_reference_explain_libgit_return(
//             r, ref_name, repo->url);
//         if (repo->updated) {
//             pr_error("Failed to lookup reference\n");
//             return -1;
//         }
//         pr_warn("Failed to lookup reference, but repo not updated yet, "
//             "update to retry\n");
//         if (repo_update(repo, fetch_options, proxy_after)) {
//             pr_error("Failed to update\n");
//             return -1;
//         }
//         if ((r = git_reference_lookup(
//             &reference, repo->repository, ref_name))) {
//             repo_parse_wanted_reference_explain_libgit_return(
//                 r, ref_name, repo->url);
//             pr_error("Failed to lookup reference even after update\n");
//             return -1;
//         }
//     }
//     r = repo_parse_wanted_reference_common(
//         repo, wanted_reference, reference, fetch_options, proxy_after);
//     git_reference_free(reference);
//     return r;
// }


// int repo_parse_wanted_tag(
//     struct repo *const restrict repo,
//     struct wanted_reference *const restrict wanted_tag,
//     git_fetch_options *const restrict fetch_options,
//     unsigned short const proxy_after
// ) {
//     char ref_name[NAME_MAX];
//     char const *const tag_name = wanted_tag->commit.base.name;
//     if (snprintf(ref_name, sizeof ref_name, "refs/tags/%s", tag_name) < 0) {
//         pr_error_with_errno(
//             "Failed to generate full ref name of tag '%s' for repo '%s'",
//             tag_name, repo->url);
//         return -1;
//     }
//     return repo_parse_wanted_reference_with_given_ref_name(
//         repo, wanted_tag, fetch_options, proxy_after, ref_name);
// }

// int repo_parse_wanted_reference(
//     struct repo *const restrict repo,
//     struct wanted_reference *const restrict wanted_reference,
//     git_fetch_options *const restrict fetch_options,
//     unsigned short const proxy_after
// ) {
//     return repo_parse_wanted_reference_with_given_ref_name(
//         repo, wanted_reference, fetch_options, proxy_after,
//         wanted_reference->name);
// }

// int repo_add_wanted_reference(
//     struct repo *const restrict repo,
//     char const *const restrict reference_name,
//     bool const archive,
//     bool const checkout
// ) {
//     if (strncmp(reference_name, "refs/", 5)) {
//         pr_error("Reference does not start with 'refs/'\n");
//         return -1;
//     }
//     if (repo_add_wanted_object_and_init_with_name_no_complete(
//         repo, reference_name, strlen(reference_name))) {
//         pr_error("Failed to add reference '%s' to repo '%s'\n",
//             reference_name, repo->url);
//         return -1;
//     }
//     struct wanted_object *const restrict wanted_reference =
//         get_last(repo->wanted_objects);
//     wanted_reference->archive = archive;
//     wanted_reference->checkout = checkout;
//     wanted_reference->type = WANTED_TYPE_REFERENCE;
//     pr_debug("Added wanted reference '%s' to repo '%s'\n",
//         wanted_reference->commit.base.name, repo->url);
//     return 0;
// }

// int repo_parse_wanted_all_branches(
//     struct repo *const restrict repo,
//     struct wanted_base *const restrict wanted_all_branches
// ) {
//     git_branch_iterator *branch_iterator;
//     int r = git_branch_iterator_new(
//         &branch_iterator, repo->repository, GIT_BRANCH_LOCAL);
//     if (r) {
//         pr_error("Failed to create branch iterator for repo '%s', "
//         "libgit return %d\n", repo->url, r);
//         return -1;
//     }
//     git_reference *reference = NULL;
//     git_branch_t branch_t;
//     pr_info(
//         "Looping through all branches to create "
//         "individual wanted references\n");
//     pr_info("All branches:");
//     while ((r = git_branch_next(
//         &reference, &branch_t, branch_iterator)) == GIT_OK) {
//         char const *const reference_name = git_reference_name(reference);
//         printf(" '%s'", reference_name);
//         if (branch_t != GIT_BRANCH_LOCAL) {
//             pr_error("\nFound branch is not a local branch\n");
//             r = -1;
//             goto free_reference;
//         }
//         if (strncmp(reference_name, "refs/", 5)) {
//             pr_error("\nReference does not start with 'refs/'\n");
//             r = -1;
//             goto free_reference;
//         }
//         if (repo_add_wanted_reference(repo, reference_name,
//             wanted_all_branches->archive, wanted_all_branches->checkout)) {
//             pr_error("\nFailed to add branch reference '%s' as wannted to "
//             "repo '%s'\n", reference_name, repo->url);
//             r = -1;
//             goto free_reference;
//         }
//         git_reference_free(reference);
//     }
//     printf("\n");
//     reference = NULL;
//     switch (r) {
//     case GIT_OK:
//         pr_error("Got GIT_OK at the end, this shouldn't happen\n");
//         r = -1;
//         goto free_iterator;
//     case GIT_ITEROVER:
//         break;
//     default:
//         pr_error(
//             "Failed to iterate through all banches, libgit return %d\n", r);
//         r = -1;
//         goto free_iterator;
//     }
//     r = 0;
// free_reference:
//     if (reference) git_reference_free(reference);
// free_iterator:
//     git_branch_iterator_free(branch_iterator);
//     return r;
// }

// struct repo_parse_wanted_all_tags_foreach_payload {
//     struct repo *const restrict repo;
//     bool const archive;
//     bool const checkout;
// };

// int repo_parse_wanted_all_tags_foreach_callback(
//     char const *name, git_oid *oid, void *payload
// ) {
//     (void) oid;
//     struct repo_parse_wanted_all_tags_foreach_payload
//         *const restrict private_payload =
//         (struct repo_parse_wanted_all_tags_foreach_payload *
//             const restrict) payload;
//     if (repo_add_wanted_reference(private_payload->repo, name,
//         private_payload->archive, private_payload->checkout)) {
//         pr_error("Failed to add tag reference '%s' as wannted to "
//         "repo '%s'\n", name, private_payload->repo->url);
//         return -1;
//     }
//     return 0;
// }

// int repo_parse_wanted_all_tags(
//     struct repo *const restrict repo,
//     struct wanted_base *const restrict wanted_all_tags
// ) {
//     unsigned long i = repo->wanted_objects_count;
//     struct repo_parse_wanted_all_tags_foreach_payload
//         const private_payload = {
//             .repo = repo,
//             .archive = wanted_all_tags->archive,
//             .checkout = wanted_all_tags->checkout,
//         };
//     pr_debug(
//         "Looping through all tags to create individual wanted references\n");
//     int r = git_tag_foreach(
//         repo->repository, repo_parse_wanted_all_tags_foreach_callback,
//         (void *)&private_payload);
//     if (r) {
//         pr_error("Failed git_tag_foreach callback, libgit return %d\n", r);
//         return -1;
//     }
//     pr_info("All tags:");
//     for (; i < repo->wanted_objects_count; ++i) {
//         printf(" '%s'", repo->wanted_objects[i].name);
//     }
//     printf("\n");
//     return 0;
// }

// // May re-allocate config->repos, and repo->parsed_commits
// int repo_lookup_commit_and_update_if_failed(
//     git_commit **const restrict commit,
//     struct config *const restrict config,
//     unsigned long const repo_id,
//     unsigned long const commit_id
// ) {
//     struct repo *restrict repo = config->repos + repo_id;
//     struct parsed_commit *restrict parsed_commit =
//         repo->parsed_commits + commit_id;
//     int r = git_commit_lookup(commit, repo->repository, &parsed_commit->id);
//     if (r) {
//         if (repo->updated) {
//             pr_error(
//                 "Failed to lookup commit %s in repo '%s' "
//                 "even it's up-to-date, "
//                 "libgit return %d, consider failure\n",
//                 parsed_commit->id_hex_string, repo->url, r);
//             return -1;
//         }
//         pr_warn(
//             "Commit %s does not exist in repo '%s' (libgit return %d), "
//             "but the repo is not updated yet, "
//             "trying to update the repo before looking up the commit again\n",
//             parsed_commit->id_hex_string, repo->url, r);
//         if (repo_update(repo, &config->fetch_options, config->proxy_after)) {
//             pr_error("Failed to update repo\n");
//             return -1;
//         }
//         pr_warn(
//             "Repo '%s' updated, go back to ensure old parsed commits are "
//             "still robust\n", repo->url);
//         r = repo_ensure_first_parsed_commits(config, repo_id, commit_id);
//         repo = config->repos + repo_id;
//         parsed_commit = repo->parsed_commits + commit_id;
//         if (r) {
//             pr_error("Updated repo '%s' breaks robustness of old parsed commit "
//             "%s", repo->url, parsed_commit->id_hex_string);
//             return -1;
//         }
//         if ((r = git_commit_lookup(
//             commit, repo->repository, &parsed_commit->id))) {
//             pr_error(
//                 "Failed to lookup commit %s in repo '%s' "
//                 "even after updating the repo, libgit return %d, "
//                 "consider failure\n",
//                 parsed_commit->id_hex_string, repo->url, r);
//             return -1;
//         }
//     }
//     return 0;
// }

// // May re-allocate config->repos, and repo->parsed_commits
// int repo_ensure_parsed_commit_submodules (
//     struct config *const restrict config,
//     unsigned long const repo_id,
//     unsigned long const commit_id,
//     git_commit *commit
// ) {
//     struct repo *restrict repo = config->repos + repo_id;
//     struct parsed_commit *restrict parsed_commit =
//         repo->parsed_commits + commit_id;
//     if (parsed_commit->submodules_parsed) return 0;
//     git_tree *tree;
//     int r = git_commit_tree(&tree, commit);
//     if (r) {
//         pr_error(
//             "Failed to get the commit tree pointed by commit %s "
//             "in repo '%s', libgit return %d\n",
//             parsed_commit->id_hex_string, repo->url, r);
//         return -1;
//     }
//     git_tree_entry const *const entry_gitmodules =
//         git_tree_entry_byname(tree, ".gitmodules");
//     if (entry_gitmodules != NULL) {
//         pr_debug(
//             "Found .gitmodules in commit tree of %s for repo '%s', "
//             "parsing submodules\n", parsed_commit->id_hex_string, repo->url);
//         r = repo_parse_commit_tree_entry_gitmodules(
//             config, repo_id, commit_id, tree, entry_gitmodules);
//         repo = config->repos + repo_id;
//         parsed_commit = repo->parsed_commits + commit_id;
//         if (r) {
//             pr_error(
//                 "Failed to parse submodules in commit tree of %s "
//                 "for repo '%s'\n",
//                 parsed_commit->id_hex_string, repo->url);
//             return -1;
//         }
//     }
//     parsed_commit->submodules_parsed = true;
//     return 0;
// }

// // May re-allocate config->repos, and repo->parsed_commits
// int repo_ensure_parsed_commit(
//     struct config *const restrict config,
//     unsigned long const repo_id,
//     unsigned long const commit_id
// ) {
//     git_commit *commit;
//     int r = repo_lookup_commit_and_update_if_failed(
//                 &commit, config, repo_id, commit_id);

//     struct repo *restrict repo = config->repos + repo_id;
//     struct parsed_commit *restrict parsed_commit =
//         repo->parsed_commits + commit_id;
//     if (r) {
//         pr_error("Failed to lookup commit %s in repo '%s'\n",
//             parsed_commit->id_hex_string, repo->url);
//         return -1;
//     }
//     if (!parsed_commit->submodules_parsed) {
//         r = (repo_ensure_parsed_commit_submodules(
//             config, repo_id, commit_id, commit));
//         repo = config->repos + repo_id;
//         parsed_commit = repo->parsed_commits + commit_id;
//         if (r) {
//             pr_error("Failed to parse repo '%s' commit %s submodules\n",
//                 repo->url, parsed_commit->id_hex_string);
//             r = -1;
//             goto free_commit;
//         }
//     }
//     pr_info("Commit robust: '%s': %s\n",
//         repo->url, parsed_commit->id_hex_string);
//     r = 0;
// free_commit:
//     git_commit_free(commit);
//     return r;
// }

// // May re-allocate config->repos, and repo->parsed_commits
// int repo_ensure_first_parsed_commits(
//     struct config *const restrict config,
//     unsigned long const repo_id,
//     unsigned long const stop_before_commit_id
// ) {
//     struct repo *restrict repo = config->repos + repo_id;
//     for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
//         if (i == stop_before_commit_id) break;
//         if (repo_ensure_parsed_commit(config, repo_id, i)) {
//             repo = config->repos + repo_id;
//             pr_error(
//                 "Failed to ensure robustness of commit %s of repo '%s'\n",
//                 repo->parsed_commits[i].id_hex_string, repo->url);
//             return -1;
//         }
//         repo = config->repos + repo_id;
//     }
//     return 0;
// }

// // May re-allocate config->repos, and repo->parsed_commits
// int repo_ensure_all_parsed_commits(
//     struct config *const restrict config,
//     unsigned long const repo_id
// ) {
//     struct repo *restrict repo = config->repos + repo_id;
//     pr_debug("Ensursing all parsed commit for repo '%s', count %lu\n",
//         repo->url, repo->parsed_commits_count);
//     for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
//         if (repo_ensure_parsed_commit(config, repo_id, i)) {
//             repo = config->repos + repo_id;
//             pr_error(
//                 "Failed to ensure robustness of commit %s of repo '%s'\n",
//                 repo->parsed_commits[i].id_hex_string, repo->url);
//             return -1;
//         }
//         repo = config->repos + repo_id;
//     }
//     return 0;
// }

// int mirror_repo(
//     struct config *const restrict config,
//     unsigned long const repo_id,
//     int const links_dirfd
// ) {
//     int r = repo_prepare_open_or_create_if_needed(
//         config->repos + repo_id, links_dirfd,
//         &config->fetch_options, config->proxy_after, false);
//     struct repo *restrict repo = config->repos + repo_id;
//     if (r) {
//         pr_error("Failed to ensure repo '%s' is opened\n", repo->url);
//         return -1;
//     }
//     pr_info("Mirroring repo '%s'\n", repo->url);
//     if (repo->wanted_dynamic && !repo->updated) {
//         pr_warn(
//             "Dynamic wanted objects set for repo '%s', need to update\n",
//             repo->url);
//         if (repo_update(
//             repo, &config->fetch_options, config->proxy_after)) {
//             pr_error(
//                 "Failed to update repo '%s' to prepare for "
//                 "dynamic wanted objects\n",
//                 repo->url);
//             return -1;
//         }
//     }
//     git_fetch_options *const fetch_options = &config->fetch_options;
//     unsigned short const proxy_after = config->proxy_after;

//     bool updated = repo->updated;
//     for (;;) {
//         for (unsigned i = 0; i < repo->wanted_objects_count;) {
//             struct wanted_object *wanted_object = repo->wanted_objects + i;
//             switch (wanted_object->type) {
//             case WANTED_TYPE_COMMIT:
//                 if (repo_parse_wanted_commit(repo,
//                     (struct wanted_commit *)wanted_object)) {
//                     pr_error(
//                         "Failed to parse wanted commit %s for repo '%s'\n",
//                         wanted_object->hex_string, repo->url);
//                     return -1;
//                 }
//                 break;
//             case WANTED_TYPE_ALL_TAGS:
//                 if (repo_parse_wanted_all_tags(repo,
//                     (struct wanted_base *)wanted_object)) {
//                     pr_error(
//                         "Failed to parse wanted all branches for repo '%s'\n",
//                         repo->url);
//                     return -1;
//                 }
//                 break;
//             case WANTED_TYPE_ALL_BRANCHES:
//                 if (repo_parse_wanted_all_branches(repo,
//                     (struct wanted_base *)wanted_object)) {
//                     pr_error("Failed to parse wanted all tags for repo '%s'\n",
//                         repo->url);
//                     return -1;
//                 }
//                 break;
//             case WANTED_TYPE_BRANCH:
//                 if (repo_parse_wanted_branch(repo,
//                     (struct wanted_reference *)wanted_object,
//                     fetch_options, proxy_after)) {
//                     pr_error(
//                         "Failed to parsed wanted branch '%s'  for repo '%s'\n",
//                         wanted_object->name, repo->url);
//                     return -1;
//                 }
//                 break;
//             case WANTED_TYPE_TAG:
//                 if (repo_parse_wanted_tag(repo,
//                     (struct wanted_reference *)wanted_object,
//                     fetch_options, proxy_after)) {
//                     pr_error(
//                         "Failed to parsed wanted tag '%s'  for repo '%s'\n",
//                         wanted_object->name, repo->url);
//                     return -1;
//                 }
//                 break;
//             case WANTED_TYPE_REFERENCE:
//                 if (repo_parse_wanted_reference(repo,
//                     (struct wanted_reference *)wanted_object,
//                     fetch_options, proxy_after)) {
//                     pr_error(
//                         "Failed to parsed wanted reference '%s'  for "
//                         "repo '%s'\n",
//                         wanted_object->name, repo->url);
//                     return -1;
//                 }
//                 break;
//             case WANTED_TYPE_HEAD:
//                 if (repo_parse_wanted_head(repo,
//                     (struct wanted_reference *)wanted_object,
//                     fetch_options, proxy_after)) {
//                     pr_error("Failed to parsed wanted HEAD for repo '%s'\n",
//                     repo->url);
//                     return -1;
//                 }
//                 break;
//             case WANTED_TYPE_UNKNOWN:
//             default:
//                 pr_error(
//                     "Impossible wanted type unknown for wanted object '%s' "
//                     "for repo '%s'\n",
//                     wanted_object->name, repo->url);
//                 return -1;
//             }
//             if (repo->updated && !updated) {
//                 pr_warn(
//                     "Silent update happended during run, need to reset loop\n");
//                 // Drop all wanted objects added later
//                 updated = true;
//                 repo->wanted_objects_count =
//                     repo->wanted_objects_count_original;
//                 i = 0;
//                 pr_warn("Repo updated, go back to first wanted object\n");
//                 continue;
//             }
//             ++i;
//         }
//         if (repo_ensure_all_parsed_commits(config, repo_id)) {
//             pr_error("Failed to ensure robustness of all parsed commits\n");
//             return -1;
//         }
//         repo = config->repos + repo_id;
//         if (updated == repo->updated) {
//             break;
//         } else {
//             pr_warn("Silent update happened during run, need to reset loop\n");
//             updated = repo->updated;
//         }
//     }
//     pr_info("Repo mirrored and robust: '%s'\n", repo->url);
//     return 0;
// }

// int update_status_add_server_and_init_with_hash_optional(
//     struct update_status *const restrict update_status,
//     hash_type const server_hash
// ) {
//     for (unsigned long i = 0; i < update_status->servers_count; ++i) {
//         if (server_hash == update_status->servers[i].server_hash)
//             return 0;
//     }
//     if (update_status_add_server_no_init(update_status)) {
//         pr_error("Failed to add server\n");
//         return -1;
//     }
//     struct update_server_repo_activity *const server =
//         get_last(update_status->servers);
//     server->server_hash = server_hash;
//     server->repos_updating_count = 0;
//     return 0;
// }


// int open_and_update_all_dynamic_repos_threaded_optional(
//     struct config *const restrict config,
//     int const links_dirfd
// ) {
//     git_fetch_options *const fetch_options = &config->fetch_options;
//     unsigned short const proxy_after = config->proxy_after;
//     struct update_status update_status = {0};
//     int r = -1;
//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         struct repo *const restrict repo = config->repos + i;
//         if (repo_prepare_open_or_create_if_needed(
//             repo, links_dirfd, fetch_options, proxy_after, true)) {
//             pr_error("Failed to prepare repo\n");
//             goto free_servers_and_ids_maybe;
//         }
//         if (!repo->wanted_dynamic) continue;
//         if (update_status_add_server_and_init_with_hash_optional(
//             &update_status, repo->server_hash)) {
//             pr_error("Failed to add server\n");
//             goto free_servers_and_ids_maybe;
//         }
//         if (update_status_add_repo_id_no_init(&update_status)) {
//             pr_error("Failed to add repo id\n");
//             goto free_servers_and_ids_maybe;
//         }
//         *(get_last(update_status.repo_ids)) = i;
//     }
//     // If there's only 1 thread needed, going this routine just wastes time
//     if (update_status.repo_ids_count <= 1) {
//         r = 0;
//         goto free_servers_and_ids_maybe;
//     }
//     // We only allow 10 concurrent connections to a server
//     // Here we allocate the most possibly used memory to avoid future
//     // realloc calls
//     unsigned long const max_possible_connections =
//         update_status.servers_count * config->connections_per_server;
//     if (max_possible_connections <= 1) {
//         r = 0;
//         goto free_servers_and_ids_maybe;
//     }
//     update_status.thread_handles_allocated =
//         max_possible_connections > update_status.repo_ids_count ?
//             update_status.repo_ids_count :
//             max_possible_connections;
//     update_status.thread_handles = calloc(
//         update_status.thread_handles_allocated,
//         sizeof *update_status.thread_handles);
//     if (update_status.thread_handles == NULL) {
//         pr_error_with_errno("Failed to allocate memory for thread ids");
//         goto free_thread_handles;
//     }
//     for (unsigned i = 0; i < update_status.thread_handles_allocated; ++i) {
//         struct repo_update_thread_arg *arg =
//             &update_status.thread_handles[i].arg;
//         arg->fetch_options = *fetch_options;
//         arg->proxy_after = proxy_after;
//     }
//     pr_info("Updating repos with %hu connections per server...\n",
//             config->connections_per_server);
//     while (update_status.repo_ids_count || update_status.threads_active_count) {
//         update_status.changed = false;
//         for (unsigned long i = 0; i < update_status.repo_ids_count; ++i) {
//             struct repo *const restrict repo =
//                 config->repos + update_status.repo_ids[i];
//             unsigned long server_id = (unsigned long) -1;
//             for (unsigned long j = 0; j < update_status.servers_count; ++j) {
//                 if (repo->server_hash == update_status.servers[j].server_hash) {
//                     server_id = j;
//                     break;
//                 }
//             }
//             if (server_id == (unsigned long) -1) {
//                 pr_error("Failed to find server hash\n");
//                 goto wait_threads;
//             }
//             // Already at max concurrent connection
//             if (update_status.servers[server_id].repos_updating_count >=
//                 config->connections_per_server) {
//                 continue;
//             }
//             ++update_status.servers[server_id].repos_updating_count;
//             if (++update_status.threads_active_count >
//                     update_status.thread_handles_allocated) {
//                 pr_error(
//                     "Allocated memory for threads not enough %lu / %lu\n",
//                     update_status.threads_active_count,
//                     update_status.thread_handles_allocated);
//                 goto wait_threads;
//             }
//             struct update_thread_handle *handle = NULL;
//             for (unsigned long j = 0;
//                 j < update_status.thread_handles_allocated;
//                 ++j) {
//                 if (!update_status.thread_handles[j].active) {
//                     handle = update_status.thread_handles + j;
//                     break;
//                 }
//             }
//             if (handle == NULL) {
//                 pr_error("Failed to find empty handle\n");
//                 goto wait_threads;
//             }
//             handle->arg.repo = repo;
//             r = pthread_create(&handle->thread,
//                             NULL, repo_update_thread, &handle->arg);
//             if (r) {
//                 pr_error("Failed to create thread, pthread return %d\n", r);
//                 --update_status.threads_active_count;
//                 r = -1;
//                 goto wait_threads;
//             }
//             handle->server_id = server_id;
//             handle->active = true;
//             handle->checked = 0;
//             update_status.repo_ids[i] =
//                 update_status.repo_ids[--update_status.repo_ids_count];
//             update_status.changed = true;
//         }
//         // Here there must be at least one active, no need to check
//         for (unsigned long i = 0;
//             i < update_status.thread_handles_allocated;
//             ++i) {
//             struct update_thread_handle *handle =
//                 update_status.thread_handles + i;;
//             if (!handle->active) continue;
//             long thread_ret;
//             r = pthread_tryjoin_np(handle->thread, (void **)&thread_ret);
//             switch (r) {
//             case 0:
//                 handle->active = false;
//                 --update_status.threads_active_count;
//                 --update_status.servers[handle->server_id].repos_updating_count;
//                 if (thread_ret) {
//                     pr_error(
//                         "Repo update thread bad return %ld\n", thread_ret);
//                     r = -1;
//                     goto wait_threads;
//                 }
//                 update_status.changed = true;
//                 break;
//             case EBUSY:
//                 if (++handle->checked % 100 == 0)  {
//                     pr_warn("Repo '%s' takes too long to update, "
//                         "%lu cycles after started it\n",
//                         handle->arg.repo->url,
//                         handle->checked);
//                 }
//                 break;
//             default:
//                 pr_error("Failed to join thread, pthread return %d\n", r);
//                 r = -1;
//                 goto wait_threads;
//             }
//         }
//         if (update_status.changed) {
//             if (update_status.threads_active_count) {
//                 if (update_status.repo_ids_count) {
//                     pr_info("Updating %lu repos, "
//                         "%lu more repos "
//                         "needs to be updated...\n",
//                         update_status.threads_active_count,
//                         update_status.repo_ids_count);
//                 } else {
//                     pr_info("Updating %lu repos...\n",
//                         update_status.threads_active_count);
//                 }
//             }
//         } else {
//             sleep(1);
//         }
//     }
//     r = 0;
// wait_threads:
//     if (r) pr_warn("Waiting for all update threads to end...\n");
//     for (unsigned long i = 0;
//         i < update_status.thread_handles_allocated; ++i) {
//         struct update_thread_handle *handle = update_status.thread_handles + i;
//         if (handle->active) {
//             long thread_ret;
//             int r2 = pthread_join(handle->thread, (void **)&thread_ret);
//             if (r2) {
//                 pr_error("Faiiled to join updating thread %ld for repo '%s', "
//                     "pthread return %d\n",
//                     handle->thread, handle->arg.repo->url, r2);
//                 r = -1;
//             }
//             handle->active = false;
//             if (thread_ret) {
//                 pr_error(
//                     "Thread %ld for updating repo '%s' returned with %ld\n",
//                     handle->thread, handle->arg.repo->url, thread_ret);
//                 r = -1;
//             }
//         }
//     }
//     pr_info("All update threads ended\n");
// free_thread_handles:
//     free(update_status.thread_handles);
// // free_servers_and_ids:
//     free(update_status.servers);
//     free(update_status.repo_ids);
//     return r;
// free_servers_and_ids_maybe:
//     if (update_status.servers) free(update_status.servers);
//     if (update_status.repo_ids) free(update_status.repo_ids);
//     return r;
// }

// int mirror_all_repos(
//     struct config *const restrict config,
//     struct work_directory *const restrict workdir_repos,
//     bool const clean
// ) {
//     if (open_and_update_all_dynamic_repos_threaded_optional(
//         config, workdir_repos->links_dirfd)) {
//         pr_error("Failed to pre-update repos\n");
//         return -1;
//     }
//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         if (clean) {
//             struct repo const *const restrict repo = config->repos + i;
//             if (work_directory_add_keep(
//                 workdir_repos, repo->hash_name, HASH_STRING_LEN)) {
//                 pr_error("Failed to add '%s' to keep items\n", repo->hash_name);
//                 return -1;
//             }
//         }
//         if (mirror_repo(config, i, workdir_repos->links_dirfd)) {
//             pr_error("Failed to mirror all repos\n");
//             return -1;
//         }
//     }
//     pr_debug("Finished mirroring all repos\n");
//     return 0;
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

// int export_commit_tree_entry_blob_file_regular_to_archive(
//     void const *const restrict ro_buffer,
//     git_object_size_t size,
//     char const *const restrict path,
//     unsigned short const len_path,
//     char const *const restrict mtime,
//     int const fd_archive,
//     mode_t mode
// ){
//     if (tar_append_regular_file(
//         fd_archive, ro_buffer, size, mtime, path, len_path, mode)) {
//         pr_error("Failed to append regular file '%s' to archive\n", path);
//         return -1;
//     }
//     return 0;
// }

// int export_commit_tree_entry_blob_file_regular_to_checkout(
//     void const *const restrict ro_buffer,
//     git_object_size_t size,
//     char const *const restrict path,
//     int const dirfd_checkout,
//     mode_t mode
// ){
//     int blob_fd = openat(dirfd_checkout, path, O_WRONLY | O_CREAT, mode);
//     if (blob_fd < 0) {
//         pr_error("Failed to create file '%s' with mode 0o%o\n",
//             path, mode);
//         return -1;
//     }
//     int r = -1;
//     if (size) {
//         git_object_size_t size_written = 0;
//         while (size_written < size) {
//             ssize_t size_written_this =
//                 write(blob_fd,
//                     ro_buffer + size_written,
//                     size - size_written);
//             if (size_written_this < 0) {
//                 switch (errno) {
//                 case EAGAIN:
// #if (EAGAIN != EWOULDBLOCK)
//                 case EWOULDBLOCK:
// #endif
//                 case EINTR:
//                     break;
//                 default:
//                     pr_error_with_errno(
//                         "Failed to write %lu bytes to file '%s'",
//                         size - size_written,
//                         path);
//                     goto close_blob_fd;
//                 }
//             } else {
//                 size_written += size_written_this;
//             }
//         }
//     }
//     r = 0;
// close_blob_fd:
//     if (close(blob_fd)) {
//         pr_error_with_errno("Failed to close fd for blob");
//     }
//     return r;
// }

// int export_commit_tree_entry_blob_file_regular(
//     void const *const restrict ro_buffer,
//     git_object_size_t size,
//     bool const archive,
//     char const *const restrict mtime,
//     int const fd_archive,
//     char const *const restrict path_archive,
//     unsigned short const len_path_archive,
//     bool const checkout,
//     int const dirfd_checkout,
//     char const *const restrict path_checkout,
//     mode_t mode
// ) {
//     if (archive) {
//         if (export_commit_tree_entry_blob_file_regular_to_archive(
//             ro_buffer, size, path_archive, len_path_archive, mtime, fd_archive,
//             mode)) {
//             pr_error("Failed to archive commit tree entry blob regular file "
//                 "at '%s'\n", path_archive);
//             return -1;
//         }
//     }
//     if (checkout) {
//         if (export_commit_tree_entry_blob_file_regular_to_checkout(
//             ro_buffer, size, path_checkout, dirfd_checkout, mode)) {
//             pr_error("Failed to checkout commit tree entry blob regular file "
//                 "at '%s'\n", path_checkout);
//             return -1;
//         }
//     }
//     return 0;
// }

// int export_commit_tree_entry_blob_file_symlink_to_archive(
//     char const *const restrict ro_buffer,
//     char const *const restrict path,
//     unsigned short const len_path,
//     char const *const restrict mtime,
//     int const fd_archive
// ) {
//     char link[PATH_MAX];
//     unsigned short len_link =
//         stpncpy(link, ro_buffer, PATH_MAX - 1) - link;
//     link[len_link] = '\0';
//     if (tar_append_symlink(
//         fd_archive, mtime, path, len_path, link, len_link)) {
//         pr_error("Failed to append symlink to archive\n");
//         return -1;
//     }
//     return 0;
// }


// int export_commit_tree_entry_blob_file_symlink_to_checkout(
//     char const *const restrict ro_buffer,
//     char const *const restrict path,
//     int const dirfd_checkout
// ) {
//     if (symlinkat(ro_buffer, dirfd_checkout, path) < 0) {
//         pr_error_with_errno("Failed to create symlink '%s' -> '%s'",
//             path, ro_buffer);
//         return -1;
//     }
//     return 0;
// }

// int export_commit_tree_entry_blob_file_symlink(
//     char const *const restrict ro_buffer,
//     bool const archive,
//     char const *const restrict mtime,
//     int const fd_archive,
//     char const *const restrict path_archive,
//     unsigned short const len_path_archive,
//     bool const checkout,
//     int const dirfd_checkout,
//     char const *const restrict path_checkout
// ) {
//     if (archive) {
//         if (export_commit_tree_entry_blob_file_symlink_to_archive(
//             ro_buffer, path_archive, len_path_archive, mtime, fd_archive)) {
//             pr_error("Failed to archive commit tree entry blob file symlink "
//                 "at '%s'\n", path_archive);
//             return -1;
//         }
//     }
//     if (checkout) {
//         if (export_commit_tree_entry_blob_file_symlink_to_checkout(
//             ro_buffer, path_checkout, dirfd_checkout)) {
//             pr_error("Failed to checkout commit tree entry blob file symlink "
//                 "at '%s'\n", path_checkout);
//             return -1;
//         }
//     }
//     return 0;
// }

// int export_commit_tree_entry_blob(
//     git_tree_entry const *const restrict entry,
//     struct repo const *const restrict repo,
//     bool const archive,
//     char const *const restrict mtime,
//     int const fd_archive,
//     char const *const restrict path_archive,
//     unsigned short const len_path_archive,
//     bool const checkout,
//     int const dirfd_checkout,
//     char const *const restrict path_checkout
// ) {
//     git_object *object;
//     int r = git_tree_entry_to_object(
//         &object, repo->repository, entry);
//     if (r) {
//         pr_error(
//             "Failed to convert entry to object, libgit return %d\n",
//             r);
//         return -1;
//     }
//     void const *const restrict ro_buffer =
//         git_blob_rawcontent((git_blob *)object);
//     switch (git_tree_entry_filemode(entry)) {
//     case GIT_FILEMODE_BLOB:
//         r = export_commit_tree_entry_blob_file_regular(
//             ro_buffer,
//             git_blob_rawsize((git_blob *)object),
//             archive, mtime, fd_archive,
//             path_archive, len_path_archive,
//             checkout, dirfd_checkout,
//             path_checkout,
//             0644);
//         break;
//     case GIT_FILEMODE_BLOB_EXECUTABLE:
//         r = export_commit_tree_entry_blob_file_regular(
//             ro_buffer,
//             git_blob_rawsize((git_blob *)object),
//             archive, mtime, fd_archive,
//             path_archive, len_path_archive,
//             checkout, dirfd_checkout,
//             path_checkout,
//             0755);
//         break;
//     case GIT_FILEMODE_LINK:
//         r = export_commit_tree_entry_blob_file_symlink(
//             ro_buffer,
//             archive, mtime, fd_archive, path_archive, len_path_archive,
//             checkout, dirfd_checkout, path_checkout);
//         break;
//     default:
//         pr_error("Impossible tree entry filemode %d\n",
//                 git_tree_entry_filemode(entry));
//         r = -1;
//         break;
//     }
//     free(object);
//     return r;
// };

// int export_commit_tree_entry_tree_to_archive(
//     char const *const restrict path,
//     unsigned short const len_path,
//     char const *const restrict mtime,
//     int const fd_archive
// ) {
//     char path_with_slash[PATH_MAX];
//     memcpy(path_with_slash, path, len_path);
//     path_with_slash[len_path] = '/';
//     path_with_slash[len_path + 1] = '\0';
//     if (tar_append_folder(fd_archive, mtime, path_with_slash, len_path + 1)) {
//         pr_error("Failed to append folder '%s' to archive\n", path);
//         return -1;
//     }
//     return 0;
// }

// int export_commit_tree_entry_tree_to_checkout(
//     char const *const restrict path,
//     int const dirfd_checkout
// ) {
//     if (mkdirat(dirfd_checkout, path, 0755)) {
//         pr_error_with_errno("Failed to create folder '%s'",
//             path);
//         return -1;
//     }
//     return 0;
// }


// int export_commit_tree_entry_tree(
//     bool const archive,
//     char const *const restrict mtime,
//     int const fd_archive,
//     char const *const restrict path_archive,
//     unsigned short const len_path_archive,
//     bool const checkout,
//     int const dirfd_checkout,
//     char const *const restrict path_checkout
// ) {
//     if (archive) {
//         if (export_commit_tree_entry_tree_to_archive(
//             path_archive, len_path_archive, mtime, fd_archive)) {
//             pr_error("Failed to export '%s' to archive\n", path_archive);
//             return -1;
//         }
//     }
//     if (checkout) {
//         if (export_commit_tree_entry_tree_to_checkout(
//             path_checkout, dirfd_checkout)) {
//             pr_error("Failed to export '%s' to checkout\n", path_checkout);
//             return -1;
//         }
//     }
//     return 0;
// };

// int export_commit_tree_entry_commit(
// 	char const *const restrict root,
//     git_tree_entry const *const restrict entry,
//     struct config const *const restrict config,
//     struct parsed_commit const *const restrict parsed_commit,
//     char *const restrict submodule_path,
//     unsigned short const len_submodule_path,
//     bool const archive,
//     char const *const restrict mtime,
//     int const fd_archive,
//     char const *const restrict archive_prefix,
//     char const *const restrict path_archive,
//     unsigned short const len_path_archive,
//     bool const checkout,
//     int const dirfd_checkout,
//     char const *const restrict path_checkout
// ) {
//     // Export self as a tree (folder)
//     if (export_commit_tree_entry_tree(
//         archive, mtime, fd_archive, path_archive, len_path_archive,
//         checkout, dirfd_checkout, path_checkout)) {
//         pr_error("Failed to export submodule '%s' as a tree\n", path_archive);
//         return -1;
//     }

//     // Find which wanted submodule commit the entry is
//     git_oid const *const submodule_commit_id = git_tree_entry_id(entry);
//     struct parsed_commit_submodule *parsed_commit_submodule = NULL;
//     for (unsigned long i = 0; i < parsed_commit->submodules_count; ++i) {
//         pr_debug("Parsed submodule '%s' commit %s\n",
//         parsed_commit->submodules[i].path,
//         parsed_commit->submodules[i].id_hex_string);
//         if (!git_oid_cmp(
//             &parsed_commit->submodules[i].id, submodule_commit_id)) {
//             parsed_commit_submodule = parsed_commit->submodules + i;
//             break;
//         }
//     }
//     if (parsed_commit_submodule == NULL) {
//         char oid_buffer[GIT_OID_MAX_HEXSIZE + 1];
//         pr_error("Failed to find corresponding wanted commit submodule, "
//         "path: '%s', commit: %s\n", path_checkout,
//         git_oid_tostr(
//             oid_buffer, GIT_OID_MAX_HEXSIZE + 1, submodule_commit_id));
//         return -1;
//     }

//     // Find that wanted commit in target repo
//     struct repo const *const restrict target_repo =
//         config->repos + parsed_commit_submodule->target_repo_id;
//     struct parsed_commit const *restrict parsed_commit_in_target_repo =
//         target_repo->parsed_commits + parsed_commit_submodule->target_commit_id;
//     pr_debug("Submodule from target repo '%s', id %ld\n",
//         target_repo->url, parsed_commit_submodule->target_commit_id);

//     // Recursively export
//     char const *const restrict name = git_tree_entry_name(entry);
//     unsigned short len_submodule_path_r =
//         len_submodule_path + strlen(name) + strlen(root) + 1;
//     if (len_submodule_path_r >= PATH_MAX) {
//         pr_error("Path too long!\n");
//         return -1;
//     }
//     int r = -1;
//     if (sprintf(submodule_path + len_submodule_path,
//         "%s%s/", root, name) < 0) {
//         pr_error_with_errno("Failed to format name");
//         goto revert_submodule_path;
//     }

//     git_commit *commit;
//     if (git_commit_lookup(
//         &commit, target_repo->repository, submodule_commit_id)) {
//         pr_error("Failed to lookup commit\n");
//         goto revert_submodule_path;
//     }
//     git_tree *tree;
//     if (git_commit_tree(&tree, commit)) {
//         pr_error("Failed to get tree pointed by commit\n");
//         goto free_commit;
//     }
//     char mtime_r[TAR_HEADER_MTIME_LEN] = "";
//     if (snprintf(
//         mtime_r, TAR_HEADER_MTIME_LEN, "%011lo", git_commit_time(commit)
//     ) < 0) {
//         pr_error("Failed to format mtime\n");
//         goto free_commit;
//     }
//     struct export_commit_treewalk_payload submodule_payload = {
//         .config = config,
//         .repo = target_repo,
//         .parsed_commit = parsed_commit_in_target_repo,
//         .submodule_path = submodule_path,
//         .len_submodule_path = len_submodule_path_r,
//         .archive = archive,
//         .mtime = mtime_r,
//         .fd_archive = fd_archive,
//         .archive_prefix = archive_prefix,
//         .checkout = checkout,
//         .dirfd_checkout = dirfd_checkout,
//     };
//     if (git_tree_walk(
//         tree, GIT_TREEWALK_PRE, export_commit_treewalk_callback,
//             &submodule_payload)) {
//         pr_error("Failed to walk tree recursively\n");
//         goto free_commit;
//     }
//     r = 0;
// free_commit:
//     git_commit_free(commit);
// revert_submodule_path:
//     submodule_path[len_submodule_path] = '\0';
//     return r;
// };

// int export_commit_treewalk_callback(
// 	char const *const restrict root,
//     git_tree_entry const *const restrict entry,
//     void *payload
// ) {
//     struct export_commit_treewalk_payload *const restrict private_payload =
//         (struct export_commit_treewalk_payload *const restrict) payload;
//     bool const archive = private_payload->archive;
//     bool const checkout = private_payload->checkout;
//     if (archive || checkout);
//     else {
//         pr_error("Neither archive nor checkout needed\n");
//         return -1;
//     }
//     char path_checkout[PATH_MAX];
//     char const *const name = git_tree_entry_name(entry);
//     int r = snprintf(
//         path_checkout, PATH_MAX, "%s%s%s", private_payload->submodule_path,
//         root, name);
//     if (r < 0) {
//         pr_error("Failed to format entry path\n");
//         return -1;
//     }
//     unsigned short len_path_archive = r;
//     char path_archive[PATH_MAX];
//     char const *const restrict archive_prefix =
//         private_payload->archive_prefix;
//     if (archive_prefix && archive_prefix[0] != '\0') {
//         if ((r = snprintf(path_archive, PATH_MAX, "%s%s",
//                     archive_prefix, path_checkout)) < 0) {
//             pr_error("Failed to format entry path\n");
//             return -1;
//         }
//         len_path_archive = r;
//     } else {
//         memcpy(path_archive, path_checkout, len_path_archive + 1);
//     }
//     char const *const restrict mtime = private_payload->mtime;
//     int const fd_archive = private_payload->fd_archive;
//     int const dirfd_checkout = private_payload->dirfd_checkout;
//     switch (git_tree_entry_type(entry)) {
//     case GIT_OBJECT_BLOB:
//         return export_commit_tree_entry_blob(
//             entry, private_payload->repo,
//             archive, mtime, fd_archive, path_archive, len_path_archive,
//             checkout, dirfd_checkout, path_checkout);
//     case GIT_OBJECT_TREE:
//         return export_commit_tree_entry_tree(
//             archive, mtime, fd_archive, path_archive, len_path_archive,
//             checkout, dirfd_checkout, path_checkout);
//     case GIT_OBJECT_COMMIT:
//         return export_commit_tree_entry_commit(
//             root, entry, private_payload->config,
//             private_payload->parsed_commit, private_payload->submodule_path,
//             private_payload->len_submodule_path, archive, mtime, fd_archive,
//             archive_prefix, path_archive, len_path_archive,
//             checkout, dirfd_checkout, path_checkout);
//     default:
//         pr_error("Impossible tree entry type %d\n", git_tree_entry_type(entry));
//         return -1;
//     }
// }

// int export_commit_add_global_comment_to_tar(
//     int tar_fd,
//     char const *const restrict repo,
//     char const *const restrict commit,
//     char const *const restrict mtime
// ) {
//     char comment[4096];
//     int r = snprintf(comment, 4096, "Archive of repo '%s' commit '%s', "
//                                     "all recursive submodules includeded, "
//                                     "created with git-mirrorer by "
//                                     "Guoxin \"7Ji\" Pu (c) 2023-present",
//                                     repo, commit);
//     if (r < 0) {
//         pr_error("Failed to format comment\n");
//         return -1;
//     }
//     if (r >= 4000) {
//         pr_error("Comment too long: '%s'\n", comment);
//         return -1;
//     }
//     unsigned short const len_comment = r;
//     unsigned short width_length = get_unsigned_short_decimal_width(len_comment);
//      // 1 between length and comment=
//      // 8 for comment=
//      // 1 for ending \n new line
//     unsigned short width_all = width_length + len_comment + 10;
//     for (;;) {
//         width_length = get_unsigned_short_decimal_width(width_all);
//         unsigned const width_all_new = width_length + len_comment + 10;
//         if (width_all_new == width_all) break;
//         width_all = width_all_new;
//     }
//     char content[4096];
//     r = snprintf(content, 4096, "%hu comment=%s\n", width_all, comment);
//     if (r < 0) {
//         pr_error_with_errno("Failed to format content");
//         return -1;
//     }
//     if (tar_add_global_header(tar_fd, mtime, content, r)) {
//         pr_error("Failed to add global header to tar\n");
//         return -1;
//     }
//     return 0;
// }

// // 1 path did not exist, or existed but we removed it,
// // 0 exists and is of type, -1 error
// int ensure_path_is_type_at(
//     int dirfd,
//     char const *const restrict path,
//     mode_t type
// ) {
//     struct stat stat_buffer;
//     if (fstatat(dirfd, path, &stat_buffer, AT_SYMLINK_NOFOLLOW)) {
//         switch (errno) {
//         case ENOENT:
//             return 1;
//         default:
//             pr_error_with_errno(
//                 "Failed to check stat of existing '%s'", path);
//             return -1;
//         }
//     } else {
//         if ((stat_buffer.st_mode & S_IFMT) == type) {
//             pr_debug("'%s' is of expected type %u\n", path, type);
//             return 0;
//         } else {
//             if (ensure_path_non_exist_at(dirfd, path)) {
//                 pr_error_with_errno(
//                     "Failed to remove existing '%s' whose type is not %u",
//                     path, type);
//                 return -1;
//             }
//             return 1;
//         }
//     }
// }

// struct export_handle {
//     bool should_export;
//     char path[PATH_MAX],
//          path_work[PATH_MAX];
//     unsigned short  len_path,
//                     len_path_work;
//     int fd;
//     pid_t child;
// };

// int export_handle_init_common(
//     struct export_handle *restrict handle,
//     int const dir_fd,
//     char const commit_string[GIT_OID_MAX_HEXSIZE + 1],
//     char const *const restrict suffix,
//     unsigned short const len_suffix,
//     bool const is_dir
// ) {
//     handle->len_path = GIT_OID_MAX_HEXSIZE;
//     memcpy(handle->path, commit_string, GIT_OID_MAX_HEXSIZE);
//     if (suffix && suffix[0]) {
//         handle->len_path += len_suffix;
//         memcpy(handle->path + GIT_OID_MAX_HEXSIZE, suffix, len_suffix);
//     }
//     handle->path[handle->len_path] = '\0';
//     mode_t type, mode;
//     int flags;
//     if (is_dir) {
//         type = S_IFDIR;
//         mode = 0755;
//         flags = O_RDONLY | O_DIRECTORY;
//     } else {
//         type = S_IFREG;
//         mode = 0644;
//         flags = O_WRONLY | O_CREAT;
//     }
//     int r = ensure_path_is_type_at(dir_fd, handle->path, type);
//     if (r > 0) {
//         memcpy(handle->path_work, handle->path, handle->len_path);
//         memcpy(handle->path_work + handle->len_path, ".work", 6);
//         handle->len_path_work += 5;
//         if (ensure_path_non_exist_at(dir_fd, handle->path_work)) {
//             pr_error("Failed to ensure '%s' non-existing\n", handle->path_work);
//             r = -1;
//             goto set_no_export;
//         }
//         if (is_dir) {
//             if (mkdir_recursively_at(dir_fd, handle->path_work)) {
//                 pr_error("Failed to create work dir '%s'\n", handle->path_work);
//                 r = -1;
//                 goto set_no_export;
//             }
//         }
//         if ((handle->fd = openat(
//             dir_fd, handle->path_work, flags, mode)) < 0) {
//             pr_error_with_errno("Failed to open '%s'", handle->path_work);
//             r = -1;
//             goto set_no_export;
//         }
//         handle->should_export = true;
//     } else if (r < 0) {
//         pr_error("Failed to ensure '%s' non-existing or is type %d\n",
//                 handle->path, type);
//         r = -1;
//         goto set_no_export;
//     } else {
//         pr_debug("'%s' existing, no need to export\n", handle->path);
//         r = 0;
//         goto set_no_export;
//     }
//     return 0;
// set_no_export:
//     handle->should_export = false;
//     return r;
// }

// #define export_handle_init_checkout(handle, dir_fd, commit_string) \
//         export_handle_init_common(handle, dir_fd, commit_string, NULL, 0, true)

// int export_handle_init_archive(
//     struct export_handle *restrict handle,
//     int const dir_fd,
//     char const commit_string[GIT_OID_MAX_HEXSIZE + 1],
//     char const *const restrict suffix,
//     unsigned short const len_suffix,
//     char *const *const restrict pipe_args,
//     unsigned short const pipe_args_count
// ) {
//     if (export_handle_init_common(
//         handle, dir_fd, commit_string, suffix, len_suffix, false)) {
//         pr_error("Failed to init export handle for archive, common part\n");
//         return -1;
//     }
//     if (!handle->should_export) return 0;
//     if (pipe_args && pipe_args[0] && pipe_args_count) {
//         int fd_pipes[2];
//         if (pipe2(fd_pipes, O_CLOEXEC)) {
//             pr_error_with_errno("Failed to create pipe\n");
//             return -1;
//         }
//         switch ((handle->child = fork())) {
//         case 0: // Child
//             if (dup2(handle->fd, STDOUT_FILENO) < 0) {
//                 pr_error_with_errno_file(stderr,
//                     "[Child %ld] Failed to dup archive fd to stdout",
//                     pthread_self());
//                 exit(EXIT_FAILURE);
//             }
//             if (dup2(fd_pipes[0], STDIN_FILENO) < 0) {
//                 pr_error_with_errno_file(stderr,
//                     "[Child %ld] Failed to dup pipe read end to stdin",
//                     pthread_self());
//                 exit(EXIT_FAILURE);
//             }
//             // fd_pipes[0] (pipe read), fd_pipes[1] (pipe write)
//             // and fd_archive will all be closed as they've been
//             // opened/created with O_CLOEXEC
//             if (execvp(pipe_args[0],
//                 pipe_args)) {
//                 pr_error_with_errno_file(
//                     stderr, "[Child %ld] Failed to execute piper",
//                             pthread_self());
//                 exit(EXIT_FAILURE);
//             }
//             pr_error_file(stderr,
//                 "[Child %ld] We should not be here\n", pthread_self());
//             exit(EXIT_FAILURE);
//             break;
//         case -1:
//             pr_error_with_errno("Failed to fork");
//             goto close_fd;
//         default: // Parent
//             pr_debug("Forked piper to child %d\n", handle->child);
//             if (close(fd_pipes[0])) { // Close the read end
//                 pr_error_with_errno("Failed to close read end of the pipe");
//                 goto kill_child;
//             }
//             if (close(handle->fd)) { // Close the original archive fd
//                 pr_error_with_errno(
//                     "Failed to close the original archive fd");
//                 goto kill_child;
//             }
//             handle->fd = fd_pipes[1]; // write to pipe write end
//             break;
//         }
//     }
//     return 0;
// // These upper tags are only reachable from archive routines, no need to check
// kill_child:
//     kill(handle->child, SIGKILL);
// close_fd:
//     if (close(handle->fd)) {
//         pr_error_with_errno("Failed to close archive fd");
//     }
//     return -1;
// }

// int export_commit_prepare(
//     struct config const *const restrict config,
//     struct parsed_commit const *const restrict parsed_commit,
//     struct export_handle *archive_handle,
//     struct work_directory *const restrict workdir_archives,
//     struct export_handle *checkout_handle,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     if (archive_handle->should_export || checkout_handle->should_export);
//     else {
//         pr_error("Commit '%s' should neither be archived or checked out\n",
//                     parsed_commit->id_hex_string);
//         return -1;
//     }
//     if (checkout_handle->should_export) {
//         if (export_handle_init_checkout(
//             checkout_handle, workdir_checkouts->dirfd,
//             parsed_commit->id_hex_string)) {
//             pr_error("Failed to init export handle for checkout\n");
//             return -1;
//         }
//         if (config->clean_checkouts) {
//             if (work_directory_add_keep(workdir_checkouts,
//                 checkout_handle->path, checkout_handle->len_path)) {
//                 pr_error("Failed to add keep checkout '%s'\n",
//                     checkout_handle->path);
//                 goto close_checkout_fd;
//             }
//         }
//     }
//     if (archive_handle->should_export) {
//         if (export_handle_init_archive(
//             archive_handle, workdir_archives->dirfd,
//             parsed_commit->id_hex_string,
//             config->archive_suffix, config->len_archive_suffix,
//             config->archive_pipe_args, config->archive_pipe_args_count)) {
//             pr_error("Failed to init export handle for archive\n");
//             goto close_checkout_fd;
//         }
//         if (config->clean_archives) {
//             if (work_directory_add_keep(workdir_archives,
//                 archive_handle->path, archive_handle->len_path)) {
//                 pr_error("Failed to add keep archive '%s'\n",
//                     archive_handle->path);
//                 goto close_archive_fd;
//             }
//         }
//     }
//     return 0;
// close_archive_fd:
//     if (close(archive_handle->fd)) {
//         pr_error_with_errno("Failed to close archive dirfd");
//     }

// close_checkout_fd:
//     if (checkout_handle->should_export) {
//         if (close(checkout_handle->fd)) {
//             pr_error_with_errno("Failed to close checkout dirfd");
//         }
//     }
//     return -1;
// }

// /* This should be only be called AFTER the repo is updated */
// /* Updating the repo might break the commits */
// int repo_lookup_all_parsed_commits(
//     struct repo const *const restrict repo
// ) {
//     for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
//         struct parsed_commit *const restrict parsed_commit =
//             repo->parsed_commits + i;
//         if (parsed_commit->commit != NULL) {
//             pr_error("Commit '%s' already looked up, no commit should've been "
//                     "looked up when this func is called\n",
//                     parsed_commit->id_hex_string);
//             return -1;
//         }
//         int r = git_commit_lookup(
//             &parsed_commit->commit, repo->repository, &parsed_commit->id);
//         if (r) {
//             pr_error("Failed to lookup commit '%s' in repo '%s', libgit return "
//             "%d\n", parsed_commit->id_hex_string, repo->url, r);
//             for (unsigned long j = 0; j < i; ++j) {
//                 git_commit_free(repo->parsed_commits[j].commit);
//                 repo->parsed_commits[j].commit = NULL;
//             }
//             return -1;
//         }
//     }
//     return 0;
// }

// void *repo_lookup_all_parsed_commits_thread(void *arg) {
//     return (void *)(long)
//         repo_lookup_all_parsed_commits((struct repo const *)arg);
// }

// int repo_free_all_parsed_commits(
//     struct repo const *const restrict repo
// ) {
//     for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
//         struct parsed_commit *const restrict parsed_commit =
//             repo->parsed_commits + i;
//         if (parsed_commit->commit) {
//             git_commit_free(parsed_commit->commit);
//             parsed_commit->commit = NULL;
//         }
//     }
//     return 0;
// }

// int export_commit_write(
//     struct config const *const restrict config,
//     struct repo const *const restrict repo,
//     struct parsed_commit const *const restrict parsed_commit,
//     struct export_handle const *const restrict archive_handle,
//     struct export_handle const *const restrict checkout_handle
// ) {
//     git_commit *commit;
//     if (parsed_commit->commit) {
//         if (git_commit_dup(&commit, parsed_commit->commit)) {
//             pr_error("Failed to dup commit\n");
//             return -1;
//         }
//     } else {
//         if (git_commit_lookup(&commit, repo->repository, &parsed_commit->id)) {
//             pr_error("Failed to lookup commit\n");
//             return -1;
//         }
//     }
//     git_tree *tree;
//     if (git_commit_tree(&tree, commit)) {
//         pr_error("Failed to get the tree pointed by commit\n");
//         git_commit_free(commit);
//         return -1;
//     }
//     pr_info("Exporting: '%s': %s ...\n",
//         repo->url, parsed_commit->id_hex_string);
//     char submodule_path[PATH_MAX] = "";
//     unsigned short len_submodule_path = 0;
//     char archive_prefix[PATH_MAX] = "";
//     if (config->archive_gh_prefix) {
//         if (snprintf(archive_prefix, PATH_MAX, "%s-%s/", repo->short_name,
//         parsed_commit->id_hex_string) < 0) {
//             pr_error_with_errno("Failed to generate github-like prefix\n");
//             git_commit_free(commit);
//             return -1;
//         }
//         pr_debug("Will add github-like prefix '%s' to tar\n", archive_prefix);
//     }
//     char mtime[TAR_HEADER_MTIME_LEN] = "";
//     if (snprintf(
//         mtime, TAR_HEADER_MTIME_LEN, "%011lo", git_commit_time(commit)
//     ) < 0) {
//         pr_error("Failed to format mtime\n");
//         git_commit_free(commit);
//         return -1;
//     }
//     if (archive_handle->should_export) {
//         if (export_commit_add_global_comment_to_tar(archive_handle->fd,
//             repo->url, parsed_commit->id_hex_string, mtime)) {
//             pr_error("Failed to add pax global header comment\n");
//             git_commit_free(commit);
//             return -1;
//         }
//     }
//     struct export_commit_treewalk_payload export_commit_treewalk_payload = {
//         .config = config,
//         .repo = repo,
//         .parsed_commit = parsed_commit,
//         .submodule_path = submodule_path,
//         .len_submodule_path = len_submodule_path,
//         .archive = archive_handle->should_export,
//         .mtime = mtime, // second,
//         // there's also git_commit_time_offset(commit), one offset for a minute
//         .fd_archive = archive_handle->fd,
//         .archive_prefix = archive_prefix,
//         .checkout = checkout_handle->should_export,
//         .dirfd_checkout = checkout_handle->fd,
//     };
//     if (git_tree_walk(
//         tree, GIT_TREEWALK_PRE, export_commit_treewalk_callback,
//         (void *)&export_commit_treewalk_payload)) {
//         pr_error("Failed to walk through tree\n");
//         git_commit_free(commit);
//         return -1;
//     }
//     git_commit_free(commit);
//     pr_debug("Ended exporting repo '%s' commit %s\n",
//         repo->url, parsed_commit->id_hex_string);
//     return 0;
// }

// int export_commit_finish(
//     struct export_handle *archive_handle,
//     struct export_handle *checkout_handle,
//     int const dirfd_archives,
//     int const dirfd_checkouts,
//     bool const force
// ) {
//     int r = 0;
//     if (archive_handle->should_export) {
//         if (close(archive_handle->fd)) {
//             pr_error_with_errno("Failed to clsoe archive fd");
//             r = -1;
//         }
//         if (archive_handle->child > 0) {
//             int status = 0;
//             pid_t child_waited = waitpid(
//                 archive_handle->child, &status,
//                 force ? WNOHANG : 0);
//             bool waited = false;
//             switch (child_waited) {
//             case -1:
//                 pr_error("Failed to wait for child\n");
//                 break;
//             case 0:
//                 if (!force) {
//                     pr_warn("Waited child is 0 but we're not waiting nohang\n");
//                 }
//                 break;
//             default:
//                 if (child_waited == archive_handle->child) {
//                     waited = true;
//                 } else {
//                     pr_warn("Waited child %d is not what we expected %d\n",
//                             child_waited, archive_handle->child);
//                 }
//                 break;
//             }
//             if (!waited) {
//                 pr_warn("Child not properly ended (yet), force to kill it");
//                 if (kill(archive_handle->child, SIGKILL)) {
//                     pr_error_with_errno("Failed to force kill child %d",
//                         archive_handle->child);
//                 }
//                 r = -1;
//             }
//             if (status) {
//                 pr_error("Piper child returned with %d\n", status);
//                 r = -1;
//             }
//             archive_handle->child = -1;
//         }
//         if (!force &&
//             renameat(dirfd_archives, archive_handle->path_work,
//                     dirfd_archives, archive_handle->path)) {
//             pr_error_with_errno("Failed to move '%s' to '%s'",
//                 archive_handle->path_work, archive_handle->path);
//             r = -1;
//         }
//     }
//     if (checkout_handle->should_export) {
//         if (close(checkout_handle->fd)) {
//             pr_error_with_errno("Failed to close checkout dirfd");
//             r = -1;
//         }
//         if (!force &&
//             renameat(dirfd_checkouts, checkout_handle->path_work,
//                 dirfd_checkouts, checkout_handle->path)) {
//             pr_error_with_errno("Failed to move '%s' to '%s'",
//                 checkout_handle->path_work, checkout_handle->path);
//             r = -1;
//         }
//     }
//     return r;
// }

// int export_commit_finish_force(
//     struct export_handle *archive_handle,
//     struct export_handle *checkout_handle
// ) {
//     int r = 0;
//     if (archive_handle->should_export) {
//         if (close(archive_handle->fd)) {
//             pr_error_with_errno("Failed to clsoe archive fd");
//             r = -1;
//         }
//         if (archive_handle->child > 0) {
//             int status = 0;
//             pid_t child_waited = waitpid(archive_handle->child, &status, WNOHANG);
//             if (child_waited != archive_handle->child) {
//                 pr_error_with_errno("Waited child is not the same");
//                 r = -1;
//             }
//             if (status) {
//                 pr_error("Piper returned with %d\n", status);
//                 r = -1;
//             }
//         }
//         if (rename(archive_handle->path_work, archive_handle->path)) {
//             pr_error_with_errno("Failed to move '%s' to '%s'",
//                 archive_handle->path_work, archive_handle->path);
//             r = -1;
//         }
//     }
//     if (checkout_handle->should_export) {
//         if (close(checkout_handle->fd)) {
//             pr_error_with_errno("Failed to close checkout dirfd");
//             r = -1;
//         }
//         if (rename(checkout_handle->path_work, checkout_handle->path)) {
//             pr_error_with_errno("Failed to move '%s' to '%s'",
//                 checkout_handle->path_work, checkout_handle->path);
//             r = -1;
//         }
//     }
//     return r;
// }

// int export_commit_single_threaded(
//     struct config const *const restrict config,
//     struct repo const *const restrict repo,
//     struct parsed_commit const *const restrict parsed_commit,
//     bool const should_archive,
//     struct work_directory *const restrict workdir_archives,
//     bool const should_checkout,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     struct export_handle archive_handle = {.should_export = should_archive};
//     struct export_handle checkout_handle = {.should_export = should_checkout};
//     if (export_commit_prepare(
//             config, parsed_commit,
//             &archive_handle, workdir_archives,
//             &checkout_handle, workdir_checkouts)) {
//         pr_error("Failed to preapre to export commit '%s'\n",
//                         parsed_commit->id_hex_string);
//         return -1;
//     }
//     if (archive_handle.should_export || checkout_handle.should_export);
//     else {
//         return 0;
//     }
//     if (export_commit_write(config, repo, parsed_commit,
//                     &archive_handle, &checkout_handle)) {
//         pr_error("Failed to write export commit '%s'\n",
//                     parsed_commit->id_hex_string);
//         export_commit_finish(&archive_handle, &checkout_handle,
//             workdir_archives->dirfd, workdir_checkouts->dirfd, true);
//         return -1;
//     }
//     if (export_commit_finish(&archive_handle, &checkout_handle,
//             workdir_archives->dirfd, workdir_checkouts->dirfd, false)) {
//         pr_error("Failed to finish exporting of commit\n");
//         return -1;
//     }
//     pr_info("Exported: '%s': %s\n",
//         repo->url, parsed_commit->id_hex_string);
//     return 0;
// }


// // Called should've done export_commit_prepare
// int export_commit_write_and_finish(
//     struct config const *const restrict config,
//     struct repo const *const restrict repo,
//     struct parsed_commit const *const restrict parsed_commit,
//     struct export_handle *const restrict archive_handle,
//     int const dirfd_archives,
//     struct export_handle *const restrict checkout_handle,
//     int const dirfd_checkouts
// ) {
//     if (export_commit_write(config, repo, parsed_commit,
//                     archive_handle, checkout_handle)) {
//         pr_error("Failed to write export commit '%s'\n",
//                     parsed_commit->id_hex_string);
//         export_commit_finish(archive_handle, checkout_handle,
//             dirfd_archives, dirfd_checkouts, true);
//         return -1;
//     }
//     if (export_commit_finish(archive_handle, checkout_handle,
//             dirfd_archives, dirfd_checkouts, false)) {
//         pr_error("Failed to finish exporting of commit\n");
//         return -1;
//     }
//     pr_info("Exported: '%s': %s\n",
//         repo->url, parsed_commit->id_hex_string);
//     return 0;
// }

// struct export_commit_write_and_finish_arg {
//     struct config const *restrict config;
//     struct repo const *restrict repo;
//     struct parsed_commit const *restrict parsed_commit;
//     struct export_handle *restrict archive_handle;
//     int dirfd_archives;
//     struct export_handle *restrict checkout_handle;
//     int dirfd_checkouts;
// };

// void *export_commit_write_and_finish_thread(void *arg) {
//     struct export_commit_write_and_finish_arg *const restrict private_arg =
//         (struct export_commit_write_and_finish_arg *)arg;
//     return (void *)(long)export_commit_write_and_finish(
//         private_arg->config, private_arg->repo, private_arg->parsed_commit,
//         private_arg->archive_handle, private_arg->dirfd_archives,
//         private_arg->checkout_handle, private_arg->dirfd_checkouts
//     );
// }

// int export_wanted_object_with_symlinks_atomic_optional(
//     struct config const *const restrict config,
//     struct repo const *const restrict repo,
//     struct wanted_object const *const restrict wanted_object,
//     struct work_directory *const restrict workdir_archives,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     switch (wanted_object->type) {
//     case WANTED_TYPE_ALL_BRANCHES:
//     case WANTED_TYPE_ALL_TAGS:
//         return 0;
//     default:
//         break;
//     }
//     if (wanted_object->archive | wanted_object->checkout);
//     else return 0;
//     if (wanted_object_guarantee_symlinks(
//         wanted_object, repo,
//         config->archive_suffix, config->len_archive_suffix,
//         workdir_archives->links_dirfd,
//         workdir_checkouts->links_dirfd)) {
//         pr_error("Failed to guarantee symlinks for wanted object '%s' "
//             "of repo '%s'\n", wanted_object->name, repo->url);
//         return -1;
//     }
//     switch (wanted_object->type) {
//     case WANTED_TYPE_BRANCH:
//     case WANTED_TYPE_TAG:
//     case WANTED_TYPE_REFERENCE:
//         if (!((struct wanted_reference const *)wanted_object)
//             ->commit_resolved) {
//             pr_error("Reference '%s' is not resolved into commit\n",
//                     wanted_object->name);
//             return -1;
//         }
//         __attribute__((fallthrough));
//     case WANTED_TYPE_HEAD:
//         if (!((struct wanted_reference const *)wanted_object)
//             ->commit_resolved) {
//             pr_warn("Reference '%s' is not resolved into commit\n",
//                     wanted_object->name);
//             break;
//         }
//         __attribute__((fallthrough));
//     case WANTED_TYPE_COMMIT: {
//         if (wanted_object->parsed_commit_id == (unsigned long) -1) {
//             pr_error("Commit %s is not parsed yet\n",
//                 wanted_object->hex_string);
//             return -1;
//         }
//         if (export_commit_single_threaded(config, repo,
//             repo->parsed_commits + wanted_object->parsed_commit_id,
//             wanted_object->archive, workdir_archives,
//             wanted_object->checkout, workdir_checkouts)) {
//             pr_error("Failed to export commit %s of repo '%s'\n",
//                 wanted_object->hex_string, repo->url);
//             return -1;
//         }
//         break;
//     }
//     default:
//         pr_error("Impossible wanted type %d (%s)\n",
//             wanted_object->type, wanted_type_strings[wanted_object->type]);
//         return -1;
//     }
//     return 0;
// }

// int repo_guarantee_all_wanted_objects_symlinks(
//     struct repo const *const restrict repo,
//     char const *const restrict archive_suffix,
//     unsigned short const len_archive_suffix,
//     int const archives_links_dirfd,
//     int const checkouts_links_dirfd
// ) {
//     for (unsigned long i = 0; i < repo->wanted_objects_count; ++i) {
//         struct wanted_object const *const restrict wanted_object =
//             repo->wanted_objects + i;
//         if (wanted_object_guarantee_symlinks(
//             wanted_object, repo,
//             archive_suffix, len_archive_suffix,
//             archives_links_dirfd,
//             checkouts_links_dirfd)) {
//             pr_error("Failed to guarantee symlinks for wanted object '%s' "
//                 "of repo '%s'\n", wanted_object->name, repo->url);
//             return -1;
//         }
//     }
//     return 0;
// }

// int export_all_repos_single_threaded(
//     struct config const *const restrict config,
//     struct work_directory *const restrict workdir_archives,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     pr_debug("Exporting all repos (single-threaded)...\n");
//     int r = -1;
//     unsigned long repo_free_count = config->repos_count;
//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         if (repo_lookup_all_parsed_commits(config->repos + i)) {
//             repo_free_count = i;
//             goto free_commits;
//         }
//     }
//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         struct repo const *const restrict repo = config->repos + i;
//         for (unsigned long j = 0; j < repo->wanted_objects_count; ++j) {
//             struct wanted_object const *const restrict wanted_object =
//                 repo->wanted_objects + j;
//             if (export_wanted_object_with_symlinks_atomic_optional(
//                     config, repo, wanted_object,
//                     workdir_archives, workdir_checkouts)) {
//                 pr_error("Failed to export wanted object '%s'\n",
//                         wanted_object->name);
//                 goto free_commits;
//             }
//         }
//     }
//     pr_debug("Exported all repos\n");
//     r = 0;
// free_commits:
//     for (unsigned long i = 0; i < repo_free_count; ++i) {
//         repo_free_all_parsed_commits(config->repos + i);
//     }
//     return r;
// }

// int guanrantee_all_repos_wanted_objects_symlinks(
//     struct config const *const restrict config,
//     int const archives_links_dirfd,
//     int const checkouts_links_dirfd
// ) {
//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         struct repo const *const restrict repo = config->repos + i;
//         if (repo_guarantee_all_wanted_objects_symlinks(
//             repo, config->archive_suffix, config->len_archive_suffix,
//             archives_links_dirfd, checkouts_links_dirfd)) {
//             pr_error("Failed to guarantee symlinks for all wanted objects of "
//             "repo '%s'\n", repo->url);
//             return -1;
//         }
//     }
//     return 0;
// }
// struct guanrantee_all_repos_wanted_objects_symlinks_arg {
//     struct config const *restrict config;
//     int const archives_links_dirfd;
//     int const checkouts_links_dirfd;
// };

// void *guanrantee_all_repos_wanted_objects_symlinks_thread(void *arg) {
//     struct guanrantee_all_repos_wanted_objects_symlinks_arg *private_arg =
//         (struct guanrantee_all_repos_wanted_objects_symlinks_arg *)arg;
//     return (void *)(long)
//                 guanrantee_all_repos_wanted_objects_symlinks(
//                     private_arg->config,
//                     private_arg->archives_links_dirfd,
//                     private_arg->checkouts_links_dirfd);
// }

// int export_all_repos_multi_threaded_lookup(
//     struct config const *const restrict config
// ) {
//    struct prepare_thread_handle {
//         pthread_t thread;
//         struct repo const *repo;
//         bool active;
//     };
//     struct prepare_thread_handle *handles = calloc(
//         config->export_threads, sizeof *handles);
//     if (handles == NULL) {
//         pr_error("Failed to allocate memory for prepare threads\n");
//         return -1;
//     }
//     unsigned long repo_prepared_count = 0;
//     int r = -1;
//     long thread_ret;
//     for (; repo_prepared_count < config->repos_count;
//         ++repo_prepared_count) {
//         struct repo const *const restrict repo =
//             config->repos + repo_prepared_count;
//         bool thread_added = false;
//         for (;;) {
//             unsigned short threads_active_count = 0;
//             for (unsigned short i = 0; i < config->export_threads; ++i) {
//                 struct prepare_thread_handle *handle = handles + i;
//                 if (handle->active) {
//                     r = pthread_tryjoin_np(
//                         handle->thread, (void **)&thread_ret);
//                     switch (r) {
//                     case 0:
//                         handle->active = false;
//                         if (thread_ret) {
//                             pr_error("Thread %ld for preparing repo '%s' "
//                             "returned with %ld\n", handle->thread,
//                             handle->repo->url, thread_ret);
//                             r = -1;
//                             goto wait_threads;
//                         }
//                         break;
//                     case EBUSY:
//                         break;
//                     default:
//                         pr_error("Failed to nonblocking wait for thread %ld "
//                         "for preparing repo '%s', pthread return %d\n",
//                         handle->thread, handle->repo->url, r);
//                         r = -1;
//                         goto wait_threads;
//                     }
//                 }
//                 // If it's already running, ofc inc it;
//                 // If it's not, then we put a thread to it, also inc it
//                 ++threads_active_count;
//                 if (!handle->active) {
//                     handle->repo = repo;
//                     r = pthread_create(&handle->thread, NULL,
//                         repo_lookup_all_parsed_commits_thread, (void *)repo);
//                     if (r) {
//                         pr_error("Failed to create thread to prepare repo "
//                         "'%s', pthread return '%d'\n", repo->url, r);
//                         r = -1;
//                         goto wait_threads;
//                     }
//                     handle->active = true;
//                     thread_added = true;
//                     break;
//                 }
//             }
//             if (thread_added) break;
//             usleep(100);
//             if (threads_active_count == config->export_threads) {
//                 pr_debug("Active threads reached max\n");
//             }
//             pr_debug("%hu threads running for looking up commits\n",
//                             threads_active_count);
//         }
//     }
//     r = 0;
// wait_threads:
//     if (r) pr_warn("Waiting for all exporting preparation threads to end...\n");
//     for (unsigned short i = 0; i < config->export_threads; ++i) {
//         struct prepare_thread_handle *handle = handles + i;
//         if (handle->active) {
//             int r2 = pthread_join(handle->thread, (void **)&thread_ret);
//             if (r2) {
//                 pr_error("Failed to join thread %ld for preparing repo '%s', "
//                             "pthread return %d\n",
//                             handle->thread, handle->repo->url, r);
//                 r = -1;
//             }
//             handle->active = false;
//             if (thread_ret) {
//                 pr_error(
//                     "Thread %ld for preparing repo '%s' returned with %ld\n",
//                     handle->thread, handle->repo->url, thread_ret);
//                 r = -1;
//             }
//         }
//     }
//     free(handles);
//     if (r) {
//         for (unsigned long i = 0; i < repo_prepared_count; ++i) {
//             if (repo_free_all_parsed_commits(config->repos + i)) {
//                 pr_error("Failed to free all parsed commits in repo '%s'\n",
//                     config->repos[i].url);
//             }
//         }
//     }
//     return r;
// }
// struct commit_with_repo {
//     struct parsed_commit *commit;
//     struct repo *repo;
// };

// static inline
// void commit_with_repo_list_swap_item(
//     struct commit_with_repo *const restrict commits_with_repos,
//     unsigned long const i,
//     unsigned long const j
// ) {
//     struct commit_with_repo buffer = commits_with_repos[i];
//     commits_with_repos[i] = commits_with_repos[j];
//     commits_with_repos[j] = buffer;
// }

// static inline
// unsigned long commit_with_repo_list_partition(
//     struct commit_with_repo *const restrict commits_with_repos,
//     unsigned long const low,
//     unsigned long const high
// ) {
//     git_oid const *const restrict pivot =
//         &commits_with_repos[high].commit->id;
//     unsigned long i = low - 1;
//     for (unsigned long j = low; j < high; ++j) {
//         // pr_debug("Comparing %s @ %p vs %s @ %p \n",
//         //     commits[j]->id_hex_string, commits[j],
//         //     pivot->id_hex_string, pivot);
//         if (git_oid_cmp(&commits_with_repos[j].commit->id, pivot) < 0)
//             commit_with_repo_list_swap_item(commits_with_repos, ++i, j);
//     }
//     commit_with_repo_list_swap_item(commits_with_repos, ++i, high);
//     return i;
// }

// void commit_with_repo_list_quick_sort(
//     struct commit_with_repo *const restrict commits_with_repos,
//     unsigned long const low,
//     unsigned long const high
// ) {
//     if (low < high) {
//         unsigned long const pivot = commit_with_repo_list_partition(
//                                 commits_with_repos, low, high);
//          // if pivot is 0, that will make the new high (ulong) -1
//         if (pivot)
//             commit_with_repo_list_quick_sort(
//                     commits_with_repos, low, pivot - 1);
//         commit_with_repo_list_quick_sort(commits_with_repos, pivot + 1, high);
//     }
// }

// // To avoid race condition, i.e., same commit referenced by multiple
// // repos, which is usually caused by repos being clones/mirrors of each
// // other, we need to go through the whole repos and commits list first,
// // to create a sorted, non-duplicated list of all commits.
// // As a result of such iterating and sorting, single-thread exporting
// // could theoritically be better if we have too many commits
// long export_all_repos_get_unique_commits(
//     struct commit_with_repo **const restrict unique_commits,
//     struct config const *const restrict config
// ) {
//     unsigned long commits_allocated = 0;
//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         commits_allocated += config->repos[i].parsed_commits_count;
//     }
//     // No commits at all, this shouldn't happen, but silent return
//     if (commits_allocated == 0) return 0;
//     struct commit_with_repo *restrict commits_with_repos =
//         malloc(sizeof *commits_with_repos * commits_allocated);
//     if (commits_with_repos == NULL) {
//         pr_error("Failed to allocate memory for all commits\n");
//         return -1;
//     }
//     unsigned long commit_id = 0;
//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         struct repo *const restrict repo = config->repos + i;
//         for (unsigned long j = 0; j < repo->parsed_commits_count; ++j) {
//             struct parsed_commit *const restrict commit =
//                 repo->parsed_commits + j;
//             if (commit->archive || commit->checkout) {
//                 struct commit_with_repo *commit_with_repo =
//                     commits_with_repos + commit_id;
//                 commit_with_repo->commit = commit;
//                 commit_with_repo->repo = repo;
//                 // This shouldn't happen
//                 if (++commit_id > commits_allocated) {
//                     pr_error("Commits count overflow, %lu > %lu\n",
//                                 commit_id,  commits_allocated);
//                     goto free_commits;

//                 }
//             }
//         }
//     }
//     unsigned long commits_count = commit_id;
//     commit_with_repo_list_quick_sort(commits_with_repos, 0, commits_count - 1);
//     commit_id = 0;
//     git_oid *commit_oid_last_unique = &commits_with_repos[0].commit->id;
//     for (unsigned long i = 1; i < commits_count; ++i) {
//         int r = git_oid_cmp(commit_oid_last_unique,
//                         &commits_with_repos[i].commit->id);
//         if (r > 0) {
//             pr_error("Descending commits in commits list which should be "
//                         "ascending\n");
//             goto free_commits;
//         } else if (r < 0) {
//             if (++commit_id != i)
//                 commits_with_repos[commit_id] = commits_with_repos[i];
//             commit_oid_last_unique =
//                 &commits_with_repos[commit_id].commit->id;
//         } else { // Same, remove dup
//             struct parsed_commit *const restrict commit_unique =
//                 commits_with_repos[commit_id].commit;
//             struct parsed_commit *const restrict commit_duplicated =
//                 commits_with_repos[i].commit;
//             if (commit_duplicated->archive) commit_unique->archive = true;
//             if (commit_duplicated->checkout) commit_unique->checkout = true;
//         }
//     }
//     struct commit_with_repo *commits_with_repos_new =
//         realloc(commits_with_repos,
//                 sizeof *commits_with_repos_new * commits_count);
//     if (commits_with_repos_new) {
//         commits_with_repos = commits_with_repos_new;
//     } else {
//         pr_error("Failed to release memory occupied by duplicated commits\n");
//         goto free_commits;
//     }
//     // It's impossible to return 0 at this point
//     // No need to check and deallocate
//     commits_count = commit_id + 1;
//     *unique_commits = commits_with_repos;
//     return (long)commits_count;
// free_commits:
//     free(commits_with_repos);
//     *unique_commits = NULL;
//     return -1;
// }

// int export_all_unique_commits_multi_threaded(
//     struct commit_with_repo *const restrict commits,
//     unsigned long const commits_count,
//     struct config const *const restrict config,
//     struct work_directory *const restrict workdir_archives,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     if (!commits_count) return 0;
//     unsigned short const threads_count =
//         config->export_threads > 2 ? config->export_threads : 2;
//     struct thread_handle {
//         pthread_t thread;
//         struct export_handle archive_handle;
//         struct export_handle checkout_handle;
//         struct export_commit_write_and_finish_arg arg;
//         bool active;
//     };
//     struct thread_handle *handles = calloc(threads_count, sizeof *handles);
//     if (handles == NULL) {
//         pr_error_with_errno("Failed to allocate memory for handles");
//         return -1;
//     }
//     int r = -1;
//     long thread_ret;
//     for (unsigned short i = 0; i < threads_count; ++i) {
//         struct export_commit_write_and_finish_arg *arg = &(handles + i)->arg;
//         arg->config = config;
//         arg->dirfd_archives = workdir_archives->dirfd;
//         arg->dirfd_checkouts = workdir_checkouts->dirfd;
//         arg->archive_handle = &handles[i].archive_handle;
//         arg->checkout_handle = &handles[i].checkout_handle;
//     }
//     for (unsigned long i = 0; i < commits_count; ++i) {
//         struct parsed_commit const *const restrict parsed_commit =
//                                         commits[i].commit;
//         if (parsed_commit->archive || parsed_commit->checkout);
//         else continue;
//         struct export_handle archive_handle = {
//             .should_export = parsed_commit->archive};
//         struct export_handle checkout_handle = {
//             .should_export = parsed_commit->checkout};
//         if (export_commit_prepare(config, parsed_commit,
//                         &archive_handle, workdir_archives,
//                         &checkout_handle, workdir_checkouts)) {
//             pr_error("Failed to prepare to export commit '%s'\n",
//                         parsed_commit->id_hex_string);
//             goto wait_threads;
//         }
//         if (archive_handle.should_export || checkout_handle.should_export);
//         else continue;
//         bool thread_added = false;
//         for (;;) {
//             unsigned short threads_active_count = 0;
//             for (unsigned short k = 0; k < config->export_threads; ++k) {
//                 struct thread_handle *handle = handles + k;
//                 if (handle->active) {
//                     r = pthread_tryjoin_np(handle->thread, (
//                                             void **)&thread_ret);
//                     switch (r) {
//                     case 0:
//                         handle->active = false;
//                         if (thread_ret) {
//                             pr_error(
//                                 "Thread %ld for exporting commit %s return"
//                                 "with %ld", handle->thread,
//                                             parsed_commit->id_hex_string,
//                                             thread_ret);
//                             goto wait_threads;
//                         }
//                         break;
//                     case EBUSY:
//                         break;
//                     default:
//                         pr_error("Failed to nonblocking wait for thread %ld"
//                         " for exporting commit %s, pthread return %d\n",
//                         handle->thread, parsed_commit->id_hex_string, r);
//                         goto wait_threads;
//                     }
//                 }
//                 ++threads_active_count;
//                 if (!handle->active) {
//                     handle->archive_handle = archive_handle;
//                     handle->checkout_handle = checkout_handle;
//                     handle->arg.repo = commits[i].repo;
//                     handle->arg.parsed_commit = parsed_commit;
//                     r = pthread_create(&handle->thread, NULL,
//                             export_commit_write_and_finish_thread,
//                             &handle->arg);
//                     if (r) {
//                         pr_error("Failed to create thread to export commit "
//                                 "%s, pthread return %d\n",
//                                 parsed_commit->id_hex_string, r);
//                         goto wait_threads;
//                     }
//                     handle->active = true;
//                     thread_added = true;
//                     break;
//                 }
//             }
//             if (thread_added) break;
//             usleep(100);
//         }
//     }
//     r = 0;
// wait_threads:
//     if (r) pr_warn("Waiting for all exporting work threads to end...\n");
//     for (unsigned short i = 0; i < threads_count; ++i) {
//         struct thread_handle *handle = handles + i;
//         if (handle->active) {
//             int r2 = pthread_join(handle->thread, (void **)&thread_ret);
//             if (r2) {
//                 pr_error("Failed to join thread %ld for exporting commit %s , "
//                             "pthread return %d\n", handle->thread,
//                                 handle->arg.parsed_commit->id_hex_string, r);
//                 r = -1;
//             }
//             handle->active = false;
//             if (thread_ret) {
//                 pr_error(
//                     "Thread %ld for exporting commit %s returned with %ld\n",
//                     handle->thread, handle->arg.parsed_commit->id_hex_string,
//                     thread_ret);
//                 r = -1;
//             }
//         }
//     }
//     free(handles);
//     return r;
// }

// int export_all_repos_multi_threaded(
//     struct config const *const restrict config,
//     struct work_directory *const restrict workdir_archives,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     pr_debug("Exporting all repos (%hu threads + 1 for symlinks)\n",
//         config->export_threads);
//     struct guanrantee_all_repos_wanted_objects_symlinks_arg
//         symlinks_thread_arg = {
//             .config = config,
//             .archives_links_dirfd = workdir_archives->links_dirfd,
//             .checkouts_links_dirfd = workdir_checkouts->links_dirfd
//         };
//     pthread_t symlinks_thread;
//     int r = pthread_create(&symlinks_thread, NULL,
//                 guanrantee_all_repos_wanted_objects_symlinks_thread,
//                 &symlinks_thread_arg);
//     if (r) {
//         pr_error("Failed to create thread for generating symlinks, pthread "
//             "return %d\n", r);
//         return -1;
//     }
//     r = -1;
//     struct commit_with_repo *commits = NULL;
//     long commits_count = export_all_repos_get_unique_commits(
//                             &commits, config);
//     if (commits_count < 0) {
//         pr_error("Failed to get all unique commits\n");
//         goto free_commits;
//     } else if (commits_count == 0) {
//         pr_info("No commits to export\n");
//         r = 0;
//         goto free_commits;
//     } else {
//         r = export_all_unique_commits_multi_threaded(
//             commits, commits_count, config,
//             workdir_archives, workdir_checkouts);
//         free(commits);
//         commits = NULL;
//         if (r) {
//             pr_error("Failed to export repos (multi-threaded)\n");
//             goto free_commits;
//         }
//     }
//     r = 0;
// free_commits:
//     for (unsigned long i = 0; i < config->repos_count; ++i) {
//         repo_free_all_parsed_commits(config->repos + i);
//     }
// // wait_symlink_thread:
//     long thread_ret;
//     int r2 = pthread_join(symlinks_thread, (void **)&thread_ret);
//     if (r2) {
//         pr_error("Failed to join thread %ld for symlinks, pthread return %d\n",
//             symlinks_thread, r2);
//         r = -1;
//     }
//     if (thread_ret) {
//         pr_error("Thread %ld for guaranteeing symlinks returned with %ld\n",
//                 symlinks_thread, thread_ret);
//         r = -1;
//     }
//     if (r) {
//         pr_warn("Failed to export all repos, but commits already exported "
//             "should not be affected\n");
//     } else {
//         pr_debug("Exported all repos\n");
//     }
//     return r;
// }

// int export_all_repos(
//     struct config const *const restrict config,
//     struct work_directory *const restrict workdir_archives,
//     struct work_directory *const restrict workdir_checkouts
// ) {
//     if (config->export_threads <= 1) {
//         return export_all_repos_single_threaded(config,
//             workdir_archives, workdir_checkouts);
//     } else {
//         return export_all_repos_multi_threaded(config,
//             workdir_archives, workdir_checkouts);
//     }
// }

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
//                     wanted_object->commit_resolved = false;
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
    if ((r = gmr_set_timeout(config.timeout_connect))) {
        goto shutdown;
    }
    if ((r = work_handle_open_all_repos(&work_handle))) {
        goto shutdown;
    }
    if ((r = work_handle_link_all_repos(&work_handle))) {
        goto shutdown;
    }
    if ((r = work_handle_update_all_repos(&work_handle))) {
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