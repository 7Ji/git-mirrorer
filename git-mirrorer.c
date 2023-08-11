#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <linux/limits.h>

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

#define pr_error_file(file, format, arg...) \
    fprintf(file, "[ERROR] %s:%d: "format, __FUNCTION__, __LINE__, ##arg)

#define pr_error(format, arg...) \
    printf("[ERROR] %s:%d: "format, __FUNCTION__, __LINE__, ##arg)

#define pr_error_with_errno_file(file, format, arg...) \
    pr_error_file(file, format", errno: %d, error: %s\n", ##arg, errno, strerror(errno))

#define pr_error_with_errno(format, arg...) \
    pr_error(format", errno: %d, error: %s\n", ##arg, errno, strerror(errno))

#define pr_warn_file(file, format, arg...) \
    fprintf(file, "[WARN] "format, ##arg)

#define pr_warn(format, arg...) \
    printf("[WARN] "format, ##arg)

#define pr_info_file(file, format, arg...) \
    fprintf(file, "[INFO] "format, ##arg)

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

struct tar_posix_header const TAR_POSIX_HEADER_FILE_REG_INIT = 
    TAR_POSIX_INIT(644, TAR_REGTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_FILE_EXE_INIT = 
    TAR_POSIX_INIT(755, TAR_REGTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_SYMLINK_INIT = 
    TAR_POSIX_INIT(777, TAR_SYMTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_FOLDER_INIT = 
    TAR_POSIX_INIT(755, TAR_DIRTYPE);

struct tar_posix_header const TAR_POSIX_HEADER_GNU_LONGLINK_INIT = 
    TAR_INIT(GNUTAR_LONGLINK_NAME, 644, TAR_LONGLINK_TYPE);

struct tar_posix_header const TAR_POSIX_HEADER_GNU_LONGNAME_INIT = 
    TAR_INIT(GNUTAR_LONGLINK_NAME, 644, TAR_LONGNAME_TYPE);

struct tar_posix_header const TAR_POSIX_HEADER_PAX_GLOBAL_HEADER_INIT = 
    TAR_INIT(PAXTAR_GLOBAL_HEADER_NAME, 666, TAR_GLOBAL_HEADER_TYPE);

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
    char name[NAME_MAX + 1];\
    unsigned short len_name;\
    bool archive;\
    bool checkout;\
}

struct wanted_base WANTED_BASE_DECLARE;

struct wanted_base const WANTED_BASE_INIT = {0};

struct wanted_base const WANTED_ALL_BRANCHES_INIT = {
    .type = WANTED_TYPE_ALL_BRANCHES };

struct wanted_base const WANTED_ALL_TAGS_INIT = {
    .type = WANTED_TYPE_ALL_TAGS };

#define WANTED_COMMIT_DECLARE { \
    union { \
        struct wanted_base base; \
        struct WANTED_BASE_DECLARE; \
    }; \
    git_oid id; \
    char id_hex_string[GIT_OID_MAX_HEXSIZE + 1]; \
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
    .name = "HEAD",
    .len_name = 4,
    .parsed_commit_id = (unsigned long) -1};


struct parsed_commit_submodule {
    git_oid id;
    char    id_hex_string[GIT_OID_MAX_HEXSIZE + 1],
            path[PATH_MAX],
            url[PATH_MAX];
    unsigned short  len_path,
                    len_url;
    XXH64_hash_t url_hash;
    unsigned long   target_repo_id,
                    target_commit_id;
};

struct parsed_commit_submodule const PARSED_COMMIT_SUBMODULE_INIT = {
    .target_repo_id = (unsigned long) -1, 
    .target_commit_id = (unsigned long) -1};

struct parsed_commit {
    git_oid id;
    char id_hex_string[GIT_OID_MAX_HEXSIZE + 1];
    struct parsed_commit_submodule *submodules;
    unsigned long   submodules_count,
                    submodules_allocated;
    bool submodules_parsed;
};

struct parsed_commit const PARSED_COMMIT_INIT = {0};

enum repo_added_from {
    REPO_ADDED_FROM_CONFIG,
    REPO_ADDED_FROM_SUBMODULE,
};

#define hash_type   XXH64_hash_t
#define hash_calculate(data, size)  XXH3_64bits(data, size)
#define HASH_NAME   "64bit xxh3 hash"
#define HASH_FORMAT "%016lx"
#define HASH_STRING_LEN  16

struct repo {
    char    url[PATH_MAX],
            url_no_scheme_sanitized[PATH_MAX],
            dir_path[PATH_MAX],
            short_name[NAME_MAX + 1],
            hash_name[HASH_STRING_LEN + 1];
    unsigned short  len_url,
                    len_url_no_scheme_sanitized,
                    url_no_scheme_sanitized_parts,
                    len_dir_path,
                    len_short_name;
    hash_type   url_hash,
                url_no_scheme_sanitized_hash;
    git_repository *repository;
    struct wanted_object *wanted_objects;
    struct parsed_commit *parsed_commits;
    unsigned long   wanted_objects_count,
                    wanted_objects_allocated,
                    wanted_objects_count_original,
                    parsed_commits_count,
                    parsed_commits_allocated;
    enum repo_added_from added_from;
    bool wanted_dynamic;
    bool updated;
};

static const struct repo REPO_INIT = {0};

struct work_directory {
    char const *path;
    int dirfd;
    int links_dirfd;
    char (*keeps)[NAME_MAX + 1];
    unsigned long   keeps_count,
                    keeps_allocated;
};

#define ARCHIVE_PIPE_ARGS_MAX_COUNT 64

struct config {
    struct repo *repos;
    struct wanted_object    *empty_wanted_objects,
                            *always_wanted_objects;
    unsigned long   repos_count,
                    repos_allocated,
                    empty_wanted_objects_count,
                    empty_wanted_objects_allocated,
                    always_wanted_objects_count,
                    always_wanted_objects_allocated;
    git_fetch_options fetch_options;
    char    proxy_url[PATH_MAX],
            dir_repos[PATH_MAX],
            dir_archives[PATH_MAX],
            dir_checkouts[PATH_MAX],
             // I don't think some one will write arg that's actually ARG_MAX
            archive_pipe_args_buffer[PATH_MAX],
            archive_suffix[NAME_MAX + 1];
    char *archive_pipe_args[ARCHIVE_PIPE_ARGS_MAX_COUNT];
    unsigned short  len_archive_pipe_args_buffer,
                    proxy_after,
                    len_proxy_url,
                    len_dir_repos,
                    len_dir_archives,
                    len_dir_checkouts,
                    archive_pipe_args_count,
                    len_archive_suffix;
    bool    archive_gh_prefix,
            clean_repos,
            clean_archives,
            clean_checkouts,
            clean_links;
};

struct config const CONFIG_INIT = {
    .fetch_options = { 
        .version = GIT_FETCH_OPTIONS_VERSION, 
        .callbacks = {
            .version = GIT_REMOTE_CALLBACKS_VERSION,
        },
        .update_fetchhead = 1,
        .proxy_opts = GIT_PROXY_OPTIONS_INIT,
        0,
    },
    .archive_suffix = ".tar",
    .clean_links = true,
};

enum yaml_config_wanted_type {
    YAML_CONFIG_WANTED_UNKNOWN,
    YAML_CONFIG_WANTED_GLOBAL_EMPTY,
    YAML_CONFIG_WANTED_GLOBAL_ALWAYS,
    YAML_CONFIG_WANTED_REPO,
};

enum yaml_config_parsing_status {
    YAML_CONFIG_PARSING_STATUS_NONE,
    YAML_CONFIG_PARSING_STATUS_STREAM,
    YAML_CONFIG_PARSING_STATUS_DOCUMENT,
    YAML_CONFIG_PARSING_STATUS_SECTION,
    YAML_CONFIG_PARSING_STATUS_PROXY,
    YAML_CONFIG_PARSING_STATUS_PROXY_AFTER,
    YAML_CONFIG_PARSING_STATUS_DIR_REPOS,
    YAML_CONFIG_PARSING_STATUS_DIR_ARCHIVES,
    YAML_CONFIG_PARSING_STATUS_DIR_CHECKOUTS,
    YAML_CONFIG_PARSING_STATUS_ARCHIVE,
    YAML_CONFIG_PARSING_STATUS_ARCHIVE_SECTION,
    YAML_CONFIG_PARSING_STATUS_ARCHIVE_GHPREFIX,
    YAML_CONFIG_PARSING_STATUS_ARCHIVE_SUFFIX,
    YAML_CONFIG_PARSING_STATUS_ARCHIVE_PIPE,
    YAML_CONFIG_PARSING_STATUS_ARCHIVE_PIPE_LIST,
    YAML_CONFIG_PARSING_STATUS_CLEAN,
    YAML_CONFIG_PARSING_STATUS_CLEAN_SECTION,
    YAML_CONFIG_PARSING_STATUS_CLEAN_REPOS,
    YAML_CONFIG_PARSING_STATUS_CLEAN_ARCHIVES,
    YAML_CONFIG_PARSING_STATUS_CLEAN_CHECKOUTS,
    YAML_CONFIG_PARSING_STATUS_WANTED,
    YAML_CONFIG_PARSING_STATUS_WANTED_SECTION,
    YAML_CONFIG_PARSING_STATUS_WANTED_SECTION_START,
    YAML_CONFIG_PARSING_STATUS_WANTED_LIST,
    YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT,
    YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_START,
    YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_SECTION,
    YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_TYPE,
    YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_ARCHIVE,
    YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_CHECKOUT,
    YAML_CONFIG_PARSING_STATUS_REPOS,
    YAML_CONFIG_PARSING_STATUS_REPOS_LIST,
    YAML_CONFIG_PARSING_STATUS_REPO_URL,
    YAML_CONFIG_PARSING_STATUS_REPO_AFTER_URL,
    YAML_CONFIG_PARSING_STATUS_REPO_SECTION,
    
};

struct export_commit_treewalk_payload {
    struct config const *const restrict config;
    struct repo const *const restrict repo;
    struct parsed_commit const *const restrict parsed_commit;
    char *const restrict submodule_path;
    unsigned short const len_submodule_path;
    bool const archive;
    char const *const restrict mtime;
    int const fd_archive;
    char const *const restrict archive_prefix;
    bool const checkout;
    char const *const restrict dir_checkout;
};

int export_commit_treewalk_callback(
	char const *const restrict root, 
    git_tree_entry const *const restrict entry,
    void *payload
);

int repo_ensure_parsed_commit(
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const commit_id
);

int repo_ensure_first_parsed_commits(
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const stop_before_commit_id
);

#define get_last(x) x + x##_count - 1

#define declare_func_add_object_and_realloc_if_necessary_no_init_typed( \
        PARENT, CHILD, CHILDNEW) \
int PARENT##_add_##CHILD##_no_init( \
    struct PARENT *const restrict PARENT \
) { \
    if (PARENT->CHILD##s == NULL) { \
        if ((PARENT->CHILD##s = malloc( \
            sizeof *PARENT->CHILD##s * ALLOC_BASE)) == NULL) { \
            pr_error("Failed to allocate memory\n"); \
            return -1; \
        } \
        PARENT->CHILD##s_allocated = ALLOC_BASE; \
    } \
    if (++PARENT->CHILD##s_count > PARENT->CHILD##s_allocated) { \
        while (PARENT->CHILD##s_count > ( \
            PARENT->CHILD##s_allocated *= 2)) { \
            if (PARENT->CHILD##s_allocated == ULONG_MAX) { \
                pr_error( \
                    "Impossible to allocate more, how is this possible?\n"); \
                return -1; \
            } else if (PARENT->CHILD##s_allocated >= \
                    ULONG_MAX / ALLOC_MULTIPLY) { \
                PARENT->CHILD##s_allocated = ULONG_MAX; \
            } else { \
                PARENT->CHILD##s_allocated *= ALLOC_MULTIPLY; \
            } \
        } \
        CHILDNEW = realloc( \
            PARENT->CHILD##s, \
            sizeof *CHILD##s_new * PARENT->CHILD##s_allocated \
        ); \
        if (CHILD##s_new == NULL) { \
            pr_error("Failed to allocate memory\n"); \
            return -1; \
        } \
        PARENT->CHILD##s = CHILD##s_new; \
    } \
    return 0; \
}

#define declare_func_add_object_and_realloc_if_necessary_no_init( \
        PARENT, STRUCT_CHILD, CHILD) \
        declare_func_add_object_and_realloc_if_necessary_no_init_typed( \
        PARENT, CHILD, struct STRUCT_CHILD *CHILD##s_new)

declare_func_add_object_and_realloc_if_necessary_no_init(
    parsed_commit, parsed_commit_submodule, submodule)

declare_func_add_object_and_realloc_if_necessary_no_init(
    repo, wanted_object, wanted_object)

declare_func_add_object_and_realloc_if_necessary_no_init(
    repo, parsed_commit, parsed_commit)

declare_func_add_object_and_realloc_if_necessary_no_init(
    config, repo, repo)

declare_func_add_object_and_realloc_if_necessary_no_init(
    config, wanted_object, empty_wanted_object)

declare_func_add_object_and_realloc_if_necessary_no_init(
    config, wanted_object, always_wanted_object)

declare_func_add_object_and_realloc_if_necessary_no_init_typed(
    work_directory, keep, char (*keeps_new)[NAME_MAX + 1])

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

int mkdir_recursively(
    char *const restrict path
) {
    for (char *c = path; ; ++c) {
        switch (*c) {
        case '\0':
            return mkdir_allow_existing(path);
        case '/':
            *c = '\0';
            int r = mkdir_allow_existing(path);
            *c = '/';
            if (r) {
                pr_error("Failed to mkdir recursively '%s'\n", path);
                return -1;
            }
            break;
        default:
            break;
        }
    }
}

int mkdir_allow_existing_at(
    int const dirfd,
    char *const restrict path
) {
    if (mkdirat(dirfd, path, 0755)) {
        if (errno == EEXIST) {
            struct stat stat_buffer;
            if (fstatat(dirfd, path, &stat_buffer, AT_SYMLINK_NOFOLLOW)) {
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

int mkdir_recursively_at(
    int const dirfd,
    char *const restrict path
) {
    for (char *c = path; ; ++c) {
        switch (*c) {
        case '\0':
            return mkdir_allow_existing_at(dirfd, path);
        case '/':
            *c = '\0';
            int r = mkdir_allow_existing_at(dirfd, path);
            *c = '/';
            if (r) {
                pr_error("Failed to mkdir recursively '%s'\n", path);
                return -1;
            }
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

void config_clean_archive_pipe(struct config *const restrict config) {
    config->archive_pipe_args_count = 0;
    config->len_archive_pipe_args_buffer = 0;
    config->archive_pipe_args[0] = NULL;
    config->archive_pipe_args_buffer[0] = '\0';
}

// May re-allocate config->repos
int config_add_repo_and_init_with_url(
    struct config *const restrict config,
    char const *const restrict url,
    unsigned short const len_url,
    enum repo_added_from added_from
) {
    if (config == NULL || url == NULL || len_url == 0) {
        pr_error("Internal: invalid argument\n");
        return -1;
    }
    char url_no_scheme_sanitized[PATH_MAX];
    unsigned short  len_url_no_scheme_sanitized = 0,
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
    char const *short_name = url_no_scheme;
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
            short_name = c + 1;
        }
        url_no_scheme_sanitized[len_url_no_scheme_sanitized++] = *c;
    }
    if (len_url_no_scheme_sanitized == 0) {
        pr_error("Sanitized url for url '%s' is empty\n", url);
        return -1;
    }
    url_no_scheme_sanitized[len_url_no_scheme_sanitized] = '\0';
    unsigned short len_short_name = 0;
    for (char const *c = short_name; !len_short_name; ++c) {
        switch (*c) {
        case '.':
            if (strcmp(c + 1, "git")) break;
            __attribute__((fallthrough));
        case '\0':
            len_short_name = c - short_name;
            break;
        }
    }
    if (len_short_name == 0) {
        pr_error("Short name length is 0\n");
        return -1;
    }
    if (len_short_name > NAME_MAX) {
        pr_error("Short name '%s' too long\n", short_name);
        return -1;
    }
    hash_type url_hash = hash_calculate(url, len_url);
    hash_type url_no_scheme_sanitized_hash = hash_calculate(
        url_no_scheme_sanitized, len_url_no_scheme_sanitized);
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
        }
    }
    if (config_add_repo_no_init(config)) {
        pr_error("Failed to add repo");
        return -1;
    }
    struct repo *const restrict repo = get_last(config->repos);
    *repo = REPO_INIT;
    memcpy(repo->url, url, len_url + 1);
    repo->len_url = len_url;
    repo->url_hash = url_hash;
    memcpy(repo->url_no_scheme_sanitized, url_no_scheme_sanitized, 
        len_url_no_scheme_sanitized + 1);
    repo->len_url_no_scheme_sanitized = len_url_no_scheme_sanitized;
    repo->url_no_scheme_sanitized_hash = url_no_scheme_sanitized_hash;
    repo->url_no_scheme_sanitized_parts = url_no_scheme_sanitized_parts;
    memcpy(repo->short_name, short_name, len_short_name);
    repo->short_name[len_short_name] = '\0';
    repo->added_from = added_from;
    if (snprintf(repo->hash_name, sizeof repo->hash_name, HASH_FORMAT, 
        repo->url_hash) < 0) {
        pr_error_with_errno("Failed to format hash name of repo '%s'\n", 
                            repo->url);
        return -1;
    }
    pr_debug("Added repo '%s', "HASH_NAME" %s, "
            "no scheme sanitized url '%s', short name '%s'\n", 
            repo->url,
            repo->hash_name,
            repo->url_no_scheme_sanitized,
            repo->short_name);
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

int wanted_object_guess_type_self_optional(struct wanted_object *wanted_object) {
    if (wanted_object->type != WANTED_TYPE_UNKNOWN) return 0;
    if ((wanted_object->type = wanted_type_guess_from_name(
        wanted_object->name, wanted_object->len_name
    )) == WANTED_TYPE_UNKNOWN) {
        pr_error("Failed to guess type\n");
        return -1;
    }
    return 0;
}

int wanted_object_fill_type_from_string(
    struct wanted_object *wanted_object,
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

int wanted_object_complete_commit(
    struct wanted_commit *wanted_object
) {
    if (git_oid_fromstr(&wanted_object->id, wanted_object->name)) {
        pr_error("Failed to resolve '%s' to a git object id\n",
            wanted_object->name);
        return -1;
    }
    if (git_oid_tostr(
            wanted_object->id_hex_string,
            sizeof wanted_object->id_hex_string, 
            &wanted_object->id
        )[0] == '\0') {
        pr_error("Failed to format git oid hex string\n");
        return -1;
    }
    return 0;
}

int wanted_object_complete(
    struct wanted_object *wanted_object
) {
    if (wanted_object_guess_type_self_optional(wanted_object)) {
        pr_error("Failed to guess type of object with unknown type\n");
        return -1;
    }
    switch (wanted_object->type) {
    case WANTED_TYPE_UNKNOWN:
        pr_error("Impossible to complete an object with unknown type\n");
        return -1;
    case WANTED_TYPE_ALL_BRANCHES: // These two does not need to be upgraded
    case WANTED_TYPE_ALL_TAGS:
    case WANTED_TYPE_REFERENCE:
    case WANTED_TYPE_BRANCH:
    case WANTED_TYPE_TAG:
    case WANTED_TYPE_HEAD:
        return 0;
    case WANTED_TYPE_COMMIT:
        return wanted_object_complete_commit(
            (struct wanted_commit *)wanted_object);
    default:
        pr_error("Impossible routine\n");
        return -1;
    }
    return 0;
}

void wanted_object_init_with_name(
    struct wanted_object *wanted_object,
    char const *const restrict name,
    unsigned short const len_name
) {
    *wanted_object = WANTED_OBJECT_INIT;
    memcpy(wanted_object->name, name, len_name);
    wanted_object->name[len_name] = '\0';
    wanted_object->len_name = len_name;
}

int wanted_object_init_with_name_and_type_and_complete(
    struct wanted_object *wanted_object,
    char const *const restrict name,
    unsigned short const len_name,
    enum wanted_type const wanted_type
) {
    wanted_object_init_with_name(wanted_object, name, len_name);
    wanted_object->type = wanted_type;
    if (wanted_object_complete(wanted_object)) {
        pr_error("Failed to complete object\n");
        return -1;
    }
    return 0;
}

#define declare_func_add_wanted_object_and_init_with_name_no_complete(\
    PARENT, CHILDPREFIX...) \
int PARENT##_add_##CHILDPREFIX##wanted_object_and_init_with_name_no_complete( \
    struct PARENT *const restrict PARENT, \
    char const *const restrict name, \
    unsigned short len_name \
) { \
    if (PARENT##_add_##CHILDPREFIX##wanted_object_no_init(PARENT)) { \
        pr_error("Failed to add wanted object\n"); \
        return -1; \
    } \
    wanted_object_init_with_name(\
        get_last(PARENT->CHILDPREFIX##wanted_objects), \
        name, len_name); \
    return 0; \
}

#define declare_func_add_wanted_object_and_init_with_name_and_complete(\
    PARENT, CHILDPREFIX...) \
int PARENT##_add_##CHILDPREFIX##wanted_object_and_init_with_name_and_complete (\
    struct PARENT *const restrict PARENT, \
    char const *const restrict name, \
    unsigned short len_name \
) { \
    enum wanted_type wanted_type = wanted_type_guess_from_name(name, len_name);\
    if (wanted_type == WANTED_TYPE_UNKNOWN) { \
        pr_error("Failed to guess object type of '%s'\n", name); \
        return -1; \
    } \
    if (PARENT##_add_##CHILDPREFIX##wanted_object_no_init(PARENT)) { \
        pr_error("Failed to add wanted object\n"); \
        return -1; \
    } \
    if (wanted_object_init_with_name_and_type_and_complete( \
        get_last(PARENT->CHILDPREFIX##wanted_objects), \
        name, len_name, wanted_type)) { \
        pr_error("Failed to init object with name and complete\n"); \
        return -1; \
    } \
    return 0; \
}

#define declare_funcs_add_wanted_object_and_init(PARENT, CHILDPREFIX...) \
    declare_func_add_wanted_object_and_init_with_name_no_complete( \
        PARENT, CHILDPREFIX) \
    declare_func_add_wanted_object_and_init_with_name_and_complete( \
        PARENT, CHILDPREFIX)

declare_funcs_add_wanted_object_and_init(repo)
declare_funcs_add_wanted_object_and_init(config, empty_)
declare_funcs_add_wanted_object_and_init(config, always_)

int opendir_create_if_non_exist_at(
    int const dir_fd,
    char const *const restrict path,
    unsigned short const len_path
) {
    int subdir_fd = openat(
            dir_fd, path, 
            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (subdir_fd < 0) {
        switch (errno) {
        case ENOENT:
            char path_dup[PATH_MAX];
            memcpy(path_dup, path, len_path + 1);
            if (mkdir_recursively_at(dir_fd, path_dup)) {
                pr_error("Failed to create dir '%s'\n", path);
                return -1;
            }
            if ((subdir_fd = openat(
                dir_fd, path, 
                O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
                pr_error_with_errno("Failed to open dir '%s'", path);
                return -1;
            }
            break;
        default:
            pr_error_with_errno("Failed to open dir '%s'", path);
            return -1;
        }
    }
    return subdir_fd;
}

int guarantee_symlink_at (
    int const links_dirfd,
    char const *const restrict symlink_path,
    unsigned short const len_symlink_path,
    char const *const restrict symlink_target
) {
    char path[PATH_MAX];
    ssize_t len = readlinkat(links_dirfd, symlink_path, path, PATH_MAX);
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
            if (unlinkat(links_dirfd, symlink_path, 0) < 0) {
                pr_error_with_errno("Faild to unlink '%s'", symlink_path);
                return -1;
            }
        } else {
            // pr_info("Symlink '%s' -> '%s' already existing\n",
            //     symlink_path, symlink_target);
            return 0;
        }
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
        pr_info("Created symlink '%s' -> '%s'\n", 
            symlink_path, symlink_target);
        return 0;
    }
    // After above routine, the only possiblity is missing dirs
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
            if (mkdirat(links_dirfd, symlink_path_dup, 0755)) {
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
                        if (mkdirat(links_dirfd, symlink_path_dup, 0755)) {
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
    if (symlinkat(symlink_target, links_dirfd, symlink_path) < 0) {
        pr_error_with_errno(
            "Failed to create symlink '%s' -> '%s'",
            symlink_path, symlink_target);
        return -1;
    }
    pr_info("Created symlink '%s' -> '%s'\n", 
        symlink_path, symlink_target);
    return 0;
}

int wanted_object_guarantee_symlinks(
    struct wanted_object const *const restrict wanted_object,
    struct repo const *const restrict repo,
    char const *const restrict archive_suffix,
    unsigned short const len_archive_suffix,
    int const archives_links_dirfd,
    int const checkouts_links_dirfd
) {
    /* links/[sanitized url]/[commit hash](archive suffix)
                            /named/[name](a.s.)
                            /tags -> refs/tags
                            /branches -> refs/heads
     undetermimed layers -> /refs/[ref name](a.s.)
                            /HEAD(a.s.)
    */                
    bool    link_tags_to_dir_refs_tags = false, 
            link_branches_to_dir_refs_heads = false;
    bool const  archive = wanted_object->archive,
                checkout = wanted_object->checkout;
    char const *dir_link = "";
    // E.g. 
    //  archive: archives/abcdef.tar.gz
    //  link: archives/links/github.com/user/repo/abcdeg.tar.gz
    //  target: ../../../../abcdef.tar.gz
    //   github.com/user/repo has 3 parts, depth is 4
    unsigned short link_depth = repo->url_no_scheme_sanitized_parts + 1;
    switch (wanted_object->type) {
        case WANTED_TYPE_UNKNOWN:
            pr_error("Wanted type unknown for '%s'\n", wanted_object->name);
            return -1;
        case WANTED_TYPE_ALL_BRANCHES:
        case WANTED_TYPE_ALL_TAGS:
            return 0;
        case WANTED_TYPE_BRANCH:
            link_branches_to_dir_refs_heads = true;
            dir_link = "refs/heads/";
            link_depth += 2;
            break;
        case WANTED_TYPE_TAG:
            link_tags_to_dir_refs_tags = true;
            dir_link = "refs/tags/";
            link_depth += 2;
            break;
        case WANTED_TYPE_REFERENCE:
            if (!strncmp(wanted_object->name, "refs/", 5)) {
                char const *const ref_kind = wanted_object->name + 5;
                if (!strncmp(ref_kind, "heads/", 6))
                    link_branches_to_dir_refs_heads = true;
                else if (!strncmp(ref_kind, "tags/", 5))
                    link_tags_to_dir_refs_tags = true;
            }
            break;
        case WANTED_TYPE_COMMIT:
        case WANTED_TYPE_HEAD:
            break;
    }
    if (!wanted_object->commit_resolved) {
        pr_error("Commit not resolved yet\n");
        return -1;
    }
    for (unsigned short i = 0; i < wanted_object->len_name; ++i) {
        switch (wanted_object->name[i]) {
        case '/':
            ++link_depth;
            break;
        case '\0':
            pr_error("Name '%s' ends pre-maturely\n", wanted_object->name);
            return -1;
        }
    }
    int archives_repo_links_dirfd = -1;
    if (archive) {
        if ((archives_repo_links_dirfd = opendir_create_if_non_exist_at(
            archives_links_dirfd, repo->url_no_scheme_sanitized,
            repo->len_url_no_scheme_sanitized)) < 0) {
            pr_error("Failed to open archive repos links dir\n");
            return -1;
        }
    }
    int checkouts_repo_links_dirfd = -1;
    int r = -1;
    if (checkout) {
        if ((checkouts_repo_links_dirfd = opendir_create_if_non_exist_at(
            checkouts_links_dirfd, repo->url_no_scheme_sanitized,
            repo->len_url_no_scheme_sanitized)) < 0) {
            pr_error("Failed to open Checkout repos links dir\n");
            goto close_archives_repo_links_dirfd;
        }
    }
    if (link_branches_to_dir_refs_heads) {
        if (archive && guarantee_symlink_at(
            archives_repo_links_dirfd, "branches", 8, "refs/heads")) {
            goto close_checkouts_repo_links_dirfd;
        }
        if (checkout && guarantee_symlink_at(
            checkouts_repo_links_dirfd, "branches", 8, "refs/heads")) {
            goto close_checkouts_repo_links_dirfd;
        }
    }
    if (link_tags_to_dir_refs_tags) {
        if (archive && guarantee_symlink_at(
            archives_repo_links_dirfd, "tags", 4, "refs/tags")) {
            goto close_checkouts_repo_links_dirfd;
        }
        if (checkout && guarantee_symlink_at(
            checkouts_repo_links_dirfd, "tags", 4, "refs/tags")) {
            goto close_checkouts_repo_links_dirfd;
        }
    }
    // The commit hash one
    char symlink_path[PATH_MAX] = "";
    char *symlink_path_current = 
        stpcpy(symlink_path, wanted_object->id_hex_string);
    // unsigned short len_symlink_path = HASH_STRING_LEN;
    char symlink_target[PATH_MAX] = "";
    char *symlink_target_current = symlink_target;
    for (unsigned short i = 0; i < repo->url_no_scheme_sanitized_parts+1; ++i) {
        symlink_target_current = stpcpy(symlink_target_current, "../");
    }
    symlink_target_current = stpcpy(symlink_target_current, 
                                    wanted_object->id_hex_string);
    if (checkout && guarantee_symlink_at(
        checkouts_repo_links_dirfd, 
        symlink_path, HASH_STRING_LEN, 
        symlink_target)) {
        goto close_checkouts_repo_links_dirfd;
    }
    if (archive) {
        if (archive_suffix[0] == '\0' && guarantee_symlink_at(
            archives_repo_links_dirfd, 
            symlink_path, HASH_STRING_LEN, 
            symlink_target)) {
            goto close_checkouts_repo_links_dirfd;
        } else {
            strcpy(symlink_path_current, archive_suffix);
            strcpy(symlink_target_current, archive_suffix);
            if (guarantee_symlink_at(
                archives_repo_links_dirfd, 
                symlink_path, HASH_STRING_LEN + len_archive_suffix, 
                symlink_target)) {
                goto close_checkouts_repo_links_dirfd;
            }
        }
    }

    // The named one
    if (wanted_object->type != WANTED_TYPE_COMMIT) {
        char *symlink_path_current = stpcpy(symlink_path, dir_link);
        symlink_path_current = stpcpy(symlink_path_current, wanted_object->name);
        unsigned short len_symlink_path = symlink_path_current - symlink_path;
        char *symlink_target_current = symlink_target;
        for (unsigned short i = 0; i < link_depth; ++i) {
            symlink_target_current = stpcpy(symlink_target_current, "../");
        }
        symlink_target_current = stpcpy(
            symlink_target_current, 
            wanted_object->id_hex_string);
        if (checkout && guarantee_symlink_at(
            checkouts_repo_links_dirfd, 
            symlink_path, len_symlink_path, 
            symlink_target)) {
            goto close_checkouts_repo_links_dirfd;
        }
        if (archive) {
            if (archive_suffix[0] == '\0' && guarantee_symlink_at(
                archives_repo_links_dirfd, 
                symlink_path, len_symlink_path, 
                symlink_target)) {
                goto close_checkouts_repo_links_dirfd;
            } else {
                strcpy(symlink_path_current, archive_suffix);
                strcpy(symlink_target_current, archive_suffix);
                if (guarantee_symlink_at(
                    archives_repo_links_dirfd, 
                    symlink_path, wanted_object->len_name + len_archive_suffix, 
                    symlink_target)) {
                    goto close_checkouts_repo_links_dirfd;
                }
            }
        }
    }

    r = 0;

close_checkouts_repo_links_dirfd:
    if (checkout) close(checkouts_repo_links_dirfd);
close_archives_repo_links_dirfd:
    if (archive) close(archives_repo_links_dirfd);
    return r;
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

struct wanted_object *config_get_last_wanted_object_of_last_repo(
    struct config *const restrict config
) {
    struct repo *const restrict repo = get_last(config->repos);
    return get_last(repo->wanted_objects);
}

struct wanted_object *config_get_last_wanted_object_of_type(
    struct config *const restrict config,
    enum yaml_config_wanted_type type
) {
    switch (type) {
    case YAML_CONFIG_WANTED_UNKNOWN:
        pr_error("Wanted type unknown\n");
        return NULL;
    case YAML_CONFIG_WANTED_GLOBAL_EMPTY:
        return get_last(config->empty_wanted_objects);
    case YAML_CONFIG_WANTED_GLOBAL_ALWAYS:
        return get_last(config->always_wanted_objects);
        break;
    case YAML_CONFIG_WANTED_REPO:
        return config_get_last_wanted_object_of_last_repo(config);
    }
    return NULL;
}

int config_update_from_yaml_event(
    struct config *const restrict config,
    yaml_event_t const *const restrict event,
    enum yaml_config_parsing_status *const restrict status,
    enum yaml_config_wanted_type *const restrict wanted_type
) {
    switch (*status) {
    case YAML_CONFIG_PARSING_STATUS_NONE:
        switch (event->type) {
        case YAML_STREAM_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_STREAM;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_STREAM:
        switch (event->type) {
        case YAML_DOCUMENT_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_DOCUMENT;
            break;
        case YAML_STREAM_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_NONE;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_DOCUMENT:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        case YAML_DOCUMENT_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_STREAM;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            char const *const key = (char const *)event->data.scalar.value;
            switch (event->data.scalar.length) {
            case 5:
                if (!strcmp(key, "proxy"))
                    *status = YAML_CONFIG_PARSING_STATUS_PROXY;
                else if (!strcmp(key, "repos"))
                    *status = YAML_CONFIG_PARSING_STATUS_REPOS;
                break;
            case 6:
                if (!strcmp(key, "wanted"))
                    *status = YAML_CONFIG_PARSING_STATUS_WANTED;
                break;
            case 7:
                if (!strcmp(key, "archive"))
                    *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE;
                else if (!strcmp(key, "cleanup"))
                    *status = YAML_CONFIG_PARSING_STATUS_CLEAN;
                break;
            case 9:
                if (!strcmp(key, "dir_repos"))
                    *status = YAML_CONFIG_PARSING_STATUS_DIR_REPOS;
                break;
            case 11:
                if (!strcmp(key, "proxy_after"))
                    *status = YAML_CONFIG_PARSING_STATUS_PROXY_AFTER;
                break;
            case 12:
                if (!strcmp(key, "dir_archives"))
                    *status = YAML_CONFIG_PARSING_STATUS_DIR_ARCHIVES;
                break;
            case 13:
                if (!strcmp(key, "dir_checkouts"))
                    *status = YAML_CONFIG_PARSING_STATUS_DIR_CHECKOUTS;
                break;
            }
            if (*status == YAML_CONFIG_PARSING_STATUS_SECTION) {
                pr_error("Unrecognized config key '%s'\n", key);
                return -1;
            }
            break;
        }
        case YAML_MAPPING_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_DOCUMENT;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_PROXY:
    case YAML_CONFIG_PARSING_STATUS_DIR_REPOS:
    case YAML_CONFIG_PARSING_STATUS_DIR_ARCHIVES:
    case YAML_CONFIG_PARSING_STATUS_DIR_CHECKOUTS:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            char *value = NULL;
            unsigned short *len = NULL;
            switch (*status) {
            case YAML_CONFIG_PARSING_STATUS_PROXY:
                value = config->proxy_url;
                len = &config->len_proxy_url;
                break;
            case YAML_CONFIG_PARSING_STATUS_DIR_REPOS:
                value = config->dir_repos;
                len = &config->len_dir_repos;
                break;
            case YAML_CONFIG_PARSING_STATUS_DIR_ARCHIVES:
                value = config->dir_archives;
                len = &config->len_dir_archives;
                break;
            case YAML_CONFIG_PARSING_STATUS_DIR_CHECKOUTS:
                value = config->dir_checkouts;
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
            memcpy(value, event->data.scalar.value, event->data.scalar.length);
            value[event->data.scalar.length] = '\0';
            *len = event->data.scalar.length;
            *status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        }
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_ARCHIVE:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_SECTION;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_ARCHIVE_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            char const *const key = (char const *)event->data.scalar.value;
            switch (event->data.scalar.length) {
            case 6:
                if (!strcmp(key, "suffix"))
                    *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_SUFFIX;
                break;
            case 12:
                if (!strcmp(key, "pipe_through"))
                    *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_PIPE;
                break;
            case 18:
                if (!strcmp(key, "github_like_prefix")) 
                    *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_GHPREFIX;
                break;
            }
            if (*status == YAML_CONFIG_PARSING_STATUS_ARCHIVE_SECTION) {
                pr_error("Unrecognized key '%s'\n", key);
                return -1;
            }
            break;
        }
        case YAML_MAPPING_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_ARCHIVE_SUFFIX:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            char const *const value = (char const *)event->data.scalar.value;
            if (event->data.scalar.length > NAME_MAX) {
                pr_error("Suffix '%s' is too long\n", value);
                return -1;
            }
            memcpy(config->archive_suffix, event->data.scalar.value, 
                event->data.scalar.length + 1);
            *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_SECTION;
            break;
        }
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_ARCHIVE_PIPE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            config_clean_archive_pipe(config);
            if (event->data.scalar.length == 0) {
                break;
            }
            if (event->data.scalar.length >= 
                sizeof config->archive_pipe_args_buffer) {
                pr_error("Pipe argument and command too long\n");
                return -1;
            }
            memcpy(config->archive_pipe_args_buffer, event->data.scalar.value,
                event->data.scalar.length + 1);
            config->len_archive_pipe_args_buffer = event->data.scalar.length;
            config->archive_pipe_args[config->archive_pipe_args_count++] = 
                config->archive_pipe_args_buffer;
            for (unsigned short i = 0; i < event->data.scalar.length; ++i) {
                switch (config->archive_pipe_args_buffer[i]) {
                case '\t':
                case '\n':
                case '\v':
                case '\f':
                case '\r':
                case ' ':
                    config->archive_pipe_args_buffer[i] = '\0';
                    __attribute__((fallthrough));
                case '\0':
                    if (event->data.scalar.length - i < 2) break;
                    switch (config->archive_pipe_args_buffer[i + 1]) {
                    case '\t':
                    case '\n':
                    case '\v':
                    case '\f':
                    case '\r':
                    case ' ':
                    case '\0':
                        break;
                    default:
                        config->archive_pipe_args[
                            config->archive_pipe_args_count++] =
                                config->archive_pipe_args_buffer + i + 1;
                        if (config->archive_pipe_args_count >= 
                            ARCHIVE_PIPE_ARGS_MAX_COUNT) {
                            pr_error("Failed to parse pipe args\n");
                            config_clean_archive_pipe(config);
                            return -1;
                        }
                    }
                    break;
                }
            }
            config->archive_pipe_args[config->archive_pipe_args_count] = NULL;
            *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_SECTION;
            break;
        case YAML_SEQUENCE_START_EVENT:
            config_clean_archive_pipe(config);
            *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_PIPE_LIST;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_ARCHIVE_PIPE_LIST:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            // 1 null between old and new, 1 null at the end
            if (config->len_archive_pipe_args_buffer + 
                event->data.scalar.length + 2 >=
                sizeof config->archive_pipe_args_buffer) {
                pr_error("Arguments too long\n");
                return -1;
            }
            char *new_buffer = config->archive_pipe_args_buffer + 
                    config->len_archive_pipe_args_buffer + 1;
            memcpy(new_buffer, event->data.scalar.value, 
                                event->data.scalar.length + 1);
            config->archive_pipe_args[config->archive_pipe_args_count++] = 
                new_buffer;
            config->len_archive_pipe_args_buffer += 
                event->data.scalar.length + 1;
            if (config->archive_pipe_args_count >= 
                ARCHIVE_PIPE_ARGS_MAX_COUNT) {
                pr_error("Too many arguments\n");
                return -1;
            }
            break;
        }
        case YAML_SEQUENCE_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_SECTION;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_CLEAN:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_CLEAN_SECTION;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_CLEAN_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            char const *const key = (char const *)event->data.scalar.value;
            switch (event->data.scalar.length) {
            case 5:
                if (!strcmp(key, "repos"))
                    *status = YAML_CONFIG_PARSING_STATUS_CLEAN_REPOS;
                break;
            case 8:
                if (!strcmp(key, "archives"))
                    *status = YAML_CONFIG_PARSING_STATUS_CLEAN_ARCHIVES;
                break;
            case 9:
                if (!strcmp(key, "checkouts"))
                    *status = YAML_CONFIG_PARSING_STATUS_CLEAN_CHECKOUTS;
                break;
            }
            if (*status == YAML_CONFIG_PARSING_STATUS_CLEAN_SECTION) {
                pr_error("Unrecognized config key '%s'\n", key);
                return -1;
            }
            break;
        }
        case YAML_MAPPING_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_WANTED:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_WANTED_SECTION;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_WANTED_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            char const *const key = (char const *)event->data.scalar.value;
            switch (event->data.scalar.length) {
            case 5:
                if (!strcmp(key, "empty")) {
                    *status = YAML_CONFIG_PARSING_STATUS_WANTED_SECTION_START;
                    *wanted_type = YAML_CONFIG_WANTED_GLOBAL_EMPTY;
                }
                break;
            case 6:
                if (!strcmp(key, "always")) {
                    *status = YAML_CONFIG_PARSING_STATUS_WANTED_SECTION_START;
                    *wanted_type = YAML_CONFIG_WANTED_GLOBAL_ALWAYS;
                }
                break;
            }
            if (*status == YAML_CONFIG_PARSING_STATUS_WANTED_SECTION) {
                pr_error("Unrecognized config key '%s'\n", key);
                return -1;
            }
            break;
        }
        case YAML_MAPPING_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_WANTED_SECTION_START:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_WANTED_LIST;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_WANTED_LIST:
        switch (event->type) {
        case YAML_SCALAR_EVENT: { // Simple wanted object with only name
            char const *const name = (char const *)event->data.scalar.value;
            unsigned short const len_name = event->data.scalar.length;
            int r;
            switch (*wanted_type) {
            case YAML_CONFIG_WANTED_UNKNOWN:
                goto wanted_type_unknown;
            case YAML_CONFIG_WANTED_GLOBAL_EMPTY:
                r = 
                config_add_empty_wanted_object_and_init_with_name_and_complete(
                    config, name, len_name);
                break;
            case YAML_CONFIG_WANTED_GLOBAL_ALWAYS:
                r = 
                config_add_always_wanted_object_and_init_with_name_and_complete(
                    config, name, len_name);
                break;
            case YAML_CONFIG_WANTED_REPO:
                r = repo_add_wanted_object_and_init_with_name_and_complete(
                    get_last(config->repos), name, len_name);
                break;
            }
            if (r) {
                pr_error("Failed to add wanted object\n");
                return -1;
            }
            break;
        }
        case YAML_MAPPING_START_EVENT: // Complex wanted object
            *status = YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT;
            break;
        case YAML_SEQUENCE_END_EVENT:
            switch (*wanted_type) {
            case YAML_CONFIG_WANTED_UNKNOWN:
                goto wanted_type_unknown;
            case YAML_CONFIG_WANTED_GLOBAL_EMPTY:
            case YAML_CONFIG_WANTED_GLOBAL_ALWAYS:
                *status = YAML_CONFIG_PARSING_STATUS_WANTED_SECTION;
                *wanted_type = YAML_CONFIG_WANTED_UNKNOWN;
                break;
            case YAML_CONFIG_WANTED_REPO:
                *status = YAML_CONFIG_PARSING_STATUS_REPO_SECTION;
                *wanted_type = YAML_CONFIG_WANTED_UNKNOWN;
                break;
            }
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT:
        switch (event->type) {
        case YAML_SCALAR_EVENT: { // Simple wanted object with only name
            char const *const name = (char const *)event->data.scalar.value;
            unsigned short const len_name = event->data.scalar.length;
            int r;
            switch (*wanted_type) {
            case YAML_CONFIG_WANTED_UNKNOWN:
                goto wanted_type_unknown;
            case YAML_CONFIG_WANTED_GLOBAL_EMPTY:
                r = 
                config_add_empty_wanted_object_and_init_with_name_no_complete(
                    config, name, len_name);
                break;
            case YAML_CONFIG_WANTED_GLOBAL_ALWAYS:
                r = 
                config_add_always_wanted_object_and_init_with_name_no_complete(
                    config, name, len_name);
                break;
            case YAML_CONFIG_WANTED_REPO:
                r = repo_add_wanted_object_and_init_with_name_no_complete(
                    get_last(config->repos), name, len_name);
                break;
            }
            if (r) {
                pr_error("Failed to add wanted object\n");
                return -1;
            }
            *status = YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_START;
            break;
        }
        case YAML_MAPPING_END_EVENT: {
            struct wanted_object *const restrict wanted_object =
                config_get_last_wanted_object_of_type(config, *wanted_type);
            if (wanted_object == NULL) {
                pr_error("Failed to get last wanted object\n");
                return -1;
            }
            if (wanted_object_complete(wanted_object)) {
                pr_error("Failed to finish wanted object\n");
                return -1;
            }
            *status = YAML_CONFIG_PARSING_STATUS_WANTED_LIST;
            break;
        }
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_START:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            *status = 
                YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_SECTION;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:{
            char const *const key = (char const *)event->data.scalar.value;
            switch (event->data.scalar.length) {
            case 4:
                if (!strncmp(key, "type", 4))
                    *status = YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_TYPE;
                break;
            case 7:
                if (!strncmp(key, "archive", 7))
                    *status = YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_ARCHIVE;
                break;
            case 8:
                if (!strncmp(key, "checkout", 8))
                    *status = YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_CHECKOUT;
                break;
            }
            if (*status == 
                YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_SECTION) {
                pr_error("Unrecognized config key '%s'\n", key);
                return -1;
            }
            break;
        }
        case YAML_MAPPING_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_TYPE:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            struct wanted_object *restrict wanted_object = 
                config_get_last_wanted_object_of_type(config, *wanted_type);
            if (wanted_object == NULL) {
                pr_error("Failed to get last wanted object\n");
                return -1;
            }
            char const *const type_string = 
                (char const *)event->data.scalar.value;
            if (wanted_object_fill_type_from_string(wanted_object, type_string)) {
                pr_error(
                    "Invalid object type '%s'\n", type_string);
                return -1;
            }
            *status = YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_SECTION;
            break;
        }
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_PROXY_AFTER:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            config->proxy_after = strtoul(
                (char const *)event->data.scalar.value, NULL, 10);
            *status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        default: goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPOS:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_REPOS_LIST;
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
                event->data.scalar.length,
                REPO_ADDED_FROM_CONFIG
            )) {
                pr_error("Failed to add repo with url '%s'\n", 
                    (char const *) event->data.scalar.value);
                return -1;
            }
            break;
        case YAML_SEQUENCE_END_EVENT: // all end
            *status = YAML_CONFIG_PARSING_STATUS_SECTION;
            break;
        case YAML_MAPPING_START_EVENT: // advanced repo config
            *status = YAML_CONFIG_PARSING_STATUS_REPO_URL;
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
                event->data.scalar.length,
                REPO_ADDED_FROM_CONFIG
            )) {
                pr_error("Failed to add repo with url '%s'\n", 
                    (char const *) event->data.scalar.value);
                return -1;
            }
            *status = YAML_CONFIG_PARSING_STATUS_REPO_AFTER_URL;
            break;
        case YAML_MAPPING_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_REPOS_LIST;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    case YAML_CONFIG_PARSING_STATUS_REPO_AFTER_URL:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_REPO_SECTION;
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
                if (!strncmp(key, "wanted", 6)) {
                    *status = YAML_CONFIG_PARSING_STATUS_WANTED_SECTION_START;
                    *wanted_type = YAML_CONFIG_WANTED_REPO;
                }
                break;
            }
            if (*status == YAML_CONFIG_PARSING_STATUS_REPO_SECTION) {
                pr_error("Unrecognized config key '%s'\n", key);
                return -1;
            }
            break;
        }
        case YAML_MAPPING_END_EVENT:
            *status = YAML_CONFIG_PARSING_STATUS_REPO_URL;
            break;
        default:
            goto unexpected_event_type;
        }
        break;
    // Boolean common
    case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_ARCHIVE:
    case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_CHECKOUT:
    case YAML_CONFIG_PARSING_STATUS_CLEAN_REPOS:
    case YAML_CONFIG_PARSING_STATUS_CLEAN_ARCHIVES:
    case YAML_CONFIG_PARSING_STATUS_CLEAN_CHECKOUTS:
    case YAML_CONFIG_PARSING_STATUS_ARCHIVE_GHPREFIX:
        switch (event->type) {
        case YAML_SCALAR_EVENT: {
            int bool_value = bool_from_string(
                (char const *)event->data.scalar.value);
            if (bool_value < 0) {
                pr_error("Failed to parse '%s' into a bool value\n", 
                    (char const *)event->data.scalar.value);
                return -1;
            }
            switch (*status) {
            case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_ARCHIVE:
            case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_CHECKOUT: {
                struct wanted_object *restrict wanted_object = 
                    config_get_last_wanted_object_of_type(config, *wanted_type);
                if (wanted_object == NULL) goto wanted_type_unknown;
                switch (*status) {
                case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_ARCHIVE:
                    wanted_object->archive = bool_value;
                    break;
                case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_CHECKOUT:
                    wanted_object->checkout = bool_value;
                    break;
                default: goto impossible_status;
                }
                break;
            }
            case YAML_CONFIG_PARSING_STATUS_CLEAN_REPOS:
                config->clean_repos = bool_value;
                break;
            case YAML_CONFIG_PARSING_STATUS_CLEAN_ARCHIVES:
                config->clean_archives = bool_value;
                break;
            case YAML_CONFIG_PARSING_STATUS_CLEAN_CHECKOUTS:
                config->clean_checkouts = bool_value;
                break;
            case YAML_CONFIG_PARSING_STATUS_ARCHIVE_GHPREFIX:
                config->archive_gh_prefix = bool_value;
                break;
            default: goto impossible_status;
            }
            switch (*status) {
            case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_ARCHIVE:
            case YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_CHECKOUT:
                *status = 
                    YAML_CONFIG_PARSING_STATUS_WANTED_OBJECT_SECTION;
                break;
            case YAML_CONFIG_PARSING_STATUS_CLEAN_REPOS:
            case YAML_CONFIG_PARSING_STATUS_CLEAN_ARCHIVES:
            case YAML_CONFIG_PARSING_STATUS_CLEAN_CHECKOUTS:
                *status = 
                    YAML_CONFIG_PARSING_STATUS_CLEAN_SECTION;
                break;
            case YAML_CONFIG_PARSING_STATUS_ARCHIVE_GHPREFIX:
                *status = YAML_CONFIG_PARSING_STATUS_ARCHIVE_SECTION;
                break;
            default: goto impossible_status;
            }
            break;
        }
        default: goto unexpected_event_type;
        }
        break;
    }
    return 0;
wanted_type_unknown:
    pr_error("Wanted type unknown (global empty/ global always/ repo), "
                "this shouldn't happen\n");
    return -1;
impossible_status:
    pr_error("Impossible status %d\n", *status);
    return -1;
unexpected_event_type:
    pr_error(
        "Unexpected YAML event type %d for current status %d\n", 
        event->type, *status);
    return -1;
}

void print_config_repo_wanted(
    struct repo const *const restrict repo) {
    for (unsigned long i = 0; i < repo->wanted_objects_count; ++i) {
        struct wanted_object const *const restrict wanted_object
            = repo->wanted_objects + i;
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
            if (wanted_object->commit_resolved) {
                printf(
                    "|            commit: %s\n",
                    wanted_object->commit.id_hex_string);
            }
            __attribute__((fallthrough));
        case WANTED_TYPE_COMMIT:
            if (wanted_object->parsed_commit_id == (unsigned long) -1) 
                break;
            struct parsed_commit *parsed_commit = 
                repo->parsed_commits + wanted_object->parsed_commit_id;
            if (parsed_commit->submodules_count) {
                printf(
                    "|            submodules:\n");
            }
            for (unsigned long i = 0; 
                i < parsed_commit->submodules_count; 
                ++i) {
                struct parsed_commit_submodule * parsed_commit_submodule =
                    parsed_commit->submodules + i;
                printf(
                    "|              - path: %s\n"
                    "|                url: %s\n"
                    "|                repo_id: %lu\n"
                    "|                commit: %s\n",
                    parsed_commit_submodule->path,
                    parsed_commit_submodule->url,
                    parsed_commit_submodule->target_repo_id,
                    parsed_commit_submodule->id_hex_string);
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
        "|      sanitized: %s\n",
        repo->url,
        repo->added_from ? " (added from submodule)" : "",
        repo->url_hash,
        repo->dir_path,
        repo->url_no_scheme_sanitized);
    if (repo->wanted_objects_count) {
        printf(
        "|      wanted (%lu, %s):\n", 
            repo->wanted_objects_count,
            repo->wanted_dynamic ? "dynamic" : "static");
        print_config_repo_wanted(repo);
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

    enum yaml_config_parsing_status status = 
        YAML_CONFIG_PARSING_STATUS_NONE;
    enum yaml_config_wanted_type wanted_type = 
        YAML_CONFIG_WANTED_UNKNOWN;
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, yaml_buffer, yaml_size);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            pr_error("Failed to parse: %s\n", parser.problem);
            goto error;
        }
        if (config_update_from_yaml_event(
            config, &event, &status, &wanted_type)) {
            pr_error("Failed to update config from yaml event"
#ifdef DEBUGGING
            ", current read config:\n");
            print_config(config);
#else
            "\n");
#endif
            goto error;
        }
        event_type = event.type;
        yaml_event_delete(&event);
    } while (event_type != YAML_STREAM_END_EVENT);

    if (status != YAML_CONFIG_PARSING_STATUS_NONE ||
        wanted_type != YAML_CONFIG_WANTED_UNKNOWN) {
        pr_error("Config parsing unclean\n");
        goto error;
    }

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

int repo_guarantee_symlink(
    struct repo *const restrict repo,
    int const links_dirfd
) {
    if (repo->url_no_scheme_sanitized_parts * 3 + HASH_STRING_LEN + 1
             >= PATH_MAX) {
        pr_error("Link target would be too long");
        return -1;
    }
    char symlink_target[PATH_MAX] = "";
    char *symlink_target_current = symlink_target;
    for (unsigned short i = 0; i < repo->url_no_scheme_sanitized_parts; ++i) {
        symlink_target_current = stpcpy(symlink_target_current, "../");
    }
    symlink_target_current = stpcpy(symlink_target_current, repo->hash_name);
    if (guarantee_symlink_at(links_dirfd, repo->url_no_scheme_sanitized, 
        repo->len_url_no_scheme_sanitized, symlink_target)) {
        pr_error("Failed to guarantee a symlink at '%s' pointing to '%s'\n",
            repo->url_no_scheme_sanitized, symlink_target);
        return -1;
    }
    return 0;
}

int repo_finish(
    struct repo *const restrict repo,
    char const *const restrict dir_repos,
    unsigned short len_dir_repos,
    struct wanted_object const *const restrict empty_wanted_objects,
    struct wanted_object const *const restrict always_wanted_objects,
    unsigned long const empty_wanted_objects_count,
    unsigned long const always_wanted_objects_count
) {
    if (repo == NULL || dir_repos == NULL || len_dir_repos == 0) {
        pr_error("Internal: invalid arguments\n");
        return -1;
    }
    if (repo->wanted_objects_count == 0 && empty_wanted_objects_count != 0) {
        pr_warn("Repo '%s' does not have wanted objects defined, adding global "
            "wanted objects (when empty) to it as wanted\n", repo->url);
        if (repo->wanted_objects) {
            pr_error("Wanted objects already allocated? "
                    "This should not happen\n");
            return -1;
        }
        if ((repo->wanted_objects = malloc(
            sizeof *repo->wanted_objects * empty_wanted_objects_count)) == NULL)
        {
            pr_error("Failed to allocate memory\n");
            return -1;
        }
        memcpy(repo->wanted_objects, empty_wanted_objects, 
            sizeof *repo->wanted_objects * empty_wanted_objects_count);
        repo->wanted_objects_count = empty_wanted_objects_count;
        repo->wanted_objects_allocated = empty_wanted_objects_count;
    }
    if (always_wanted_objects_count != 0) {
        pr_info("Add always wanted objects to repo '%s'\n", repo->url);
        unsigned long const new_wanted_objects_count = 
            repo->wanted_objects_count + always_wanted_objects_count;
        if (new_wanted_objects_count > repo->wanted_objects_allocated) {
            struct wanted_object *wanted_objects_new = 
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
                always_wanted_objects, 
                sizeof *repo->wanted_objects * always_wanted_objects_count);
        repo->wanted_objects_count = new_wanted_objects_count;
    }
    repo->wanted_objects_count_original = repo->wanted_objects_count;
    for (unsigned long i = 0; i < repo->wanted_objects_count; ++i) {
        struct wanted_object const *const restrict wanted_object = 
            repo->wanted_objects + i;
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
            repo->wanted_dynamic = true;
            break;
        default:
            break;
        }
    }
    if (repo->wanted_dynamic) {
        pr_debug("Repo '%s' needs dynamic object, will need to update it\n", 
                repo->url);
    }
    repo->len_dir_path = len_dir_repos + HASH_STRING_LEN + 1;
    if (snprintf(repo->dir_path, repo->len_dir_path + 1, "%s/"HASH_FORMAT, 
        dir_repos, repo->url_hash) < 0) {
        pr_error_with_errno(
            "Failed to format dir path of repo '%s'\n",
            repo->url);
        return -1;
    }
    pr_debug("Repo '%s' will be stored at '%s'\n", repo->url, repo->dir_path);
    return 0;
}

int repo_finish_bare(
    struct repo *const restrict repo,
    char const *const restrict dir_repos,
    unsigned short len_dir_repos
) {
    if (repo == NULL || dir_repos == NULL || len_dir_repos == 0 || 
        repo->wanted_objects_count > 0) {
        pr_error("Internal: invalid arguments\n");
        return -1;
    }
    repo->len_dir_path = len_dir_repos + HASH_STRING_LEN + 1;
    if (snprintf(repo->dir_path, repo->len_dir_path + 1, "%s/"HASH_FORMAT, 
        dir_repos, repo->url_hash) < 0) {
        pr_error_with_errno(
            "Failed to format dir path of repo '%s'\n",
            repo->url);
        return -1;
    }
    pr_debug("Repo '%s' will be stored at '%s'\n", repo->url, repo->dir_path);
    return 0;
}

int config_finish(
    struct config *const restrict config
) {
    if (config->archive_pipe_args_count >= ARCHIVE_PIPE_ARGS_MAX_COUNT) {
        pr_error("Archive pipe arguemnts too many\n");
        return -1;
    }
    if (isatty(STDOUT_FILENO)) {
        config->fetch_options.callbacks.sideband_progress = sideband_progress;
        config->fetch_options.callbacks.transfer_progress = fetch_progress;
    }
    if (config->dir_repos[0] == '\0') {
        memcpy(config->dir_repos, DIR_REPOS, sizeof(DIR_REPOS));
        config->len_dir_repos = sizeof(DIR_REPOS) - 1;
    }
    pr_debug("Repos will be stored in '%s'\n", config->dir_repos);
    if (config->dir_archives[0] == '\0') {
        memcpy(config->dir_archives, DIR_ARCHIVES, sizeof(DIR_ARCHIVES));
        config->len_dir_archives = sizeof(DIR_ARCHIVES) - 1;
    }
    pr_debug("Archives will be stored in '%s'\n", config->dir_archives);
    if (config->dir_checkouts[0] == '\0') {
        memcpy(config->dir_checkouts, DIR_CHECKOUTS, sizeof(DIR_CHECKOUTS));
        config->len_dir_checkouts = sizeof(DIR_CHECKOUTS) - 1;
    }
    pr_debug("Checkouts will be stored in '%s'\n", config->dir_checkouts);
    if (config->proxy_url[0] != '\0') {
        if (config->proxy_after) {
            pr_debug("Will use proxy '%s' after %hu failed fetches\n", 
                config->proxy_url, config->proxy_after);
        } else {
            pr_debug("Will use proxy '%s'\n", config->proxy_url);
        }
        config->fetch_options.proxy_opts.url = config->proxy_url;
    } else if (config->proxy_after) {
        pr_warn(
            "You've set proxy_after but not set proxy, "
            "fixing proxy_after to 0\n");
        config->proxy_after = 0;
    }
    if (config->empty_wanted_objects == NULL) {
        pr_warn("Global wanted objects (when empty) not defined, adding 'HEAD' "
            "as default\n");
#ifdef CONFIG_EMPTY_WANTED_OBJECTS_HEAD_SIMPLE_ALLOCATE
        // This wastes memory for 9 objects
        if (config_add_empty_wanted_object_no_init(config)) {
            pr_error("Failed to add global wanted objects (when empty)\n");
            return -1;
        }
        (get_last(config->empty_wanted_objects))->reference = WANTED_HEAD_INIT;
#else
        if ((config->empty_wanted_objects = 
            malloc(sizeof *config->empty_wanted_objects)) == NULL) {
            pr_error(
                "Failed to allocate memory for global wanted objects "
                "(when empty)\n");
            return -1;
        }
        config->empty_wanted_objects_count = 1;
        config->empty_wanted_objects_allocated = 1;
        config->empty_wanted_objects->reference = WANTED_HEAD_INIT;
#endif
    }
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (repo_finish(
            config->repos + i, config->dir_repos, config->len_dir_repos,
            config->empty_wanted_objects, config->always_wanted_objects,
            config->empty_wanted_objects_count, 
            config->always_wanted_objects_count)) {
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
    unsigned char *config_buffer = NULL;
    ssize_t config_size = buffer_read_from_fd(&config_buffer, config_fd);
    int r = -1;
    if (config_size < 0) {
        pr_error("Failed to read config into buffer\n");
        goto close_config_fd;
    }
    if (config_from_yaml(config, config_buffer, config_size)) {
        pr_error("Failed to read config from YAML\n");
        goto free_config_buffer;
    }
    if (config_finish(config)) {
        pr_error("Failed to finish config\n");
        goto free_config_buffer;
    }
    r = 0;
free_config_buffer:
    if (config_buffer) free(config_buffer);
close_config_fd:
    if (config_fd != STDIN_FILENO) close (config_fd);
    return r;
}

int work_directory_add_keep(
    struct work_directory *const restrict work_directory,
    char const *const restrict keep,
    unsigned short const len_keep
) {
    if (work_directory_add_keep_no_init(work_directory)) {
        pr_error("Failed to add keep to work directory\n");
        return -1;
    }
    if (len_keep >= sizeof *work_directory->keeps) {
        pr_error("Length of keep item '%s' too long\n", keep);
        return -1;
    }
    memcpy(get_last(work_directory->keeps), keep, len_keep + 1);
    return 0;
}

int work_directory_from_path(
    struct work_directory *const restrict work_directory,
    char const *const restrict path
) {
    if ((work_directory->dirfd = 
        open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
        switch (errno) {
        case ENOENT: 
            char path_dup[PATH_MAX];
            strncpy(path_dup, path, PATH_MAX);
            if (mkdir_recursively(path_dup)) {
                pr_error("Failed to create folder '%s'\n", path);
                return -1;
            }
            if ((work_directory->dirfd = 
                open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
                pr_error_with_errno("Still failed to open '%s' as directory\n", 
                                    path);
                return -1;
            }
            break;
        default:
            pr_error_with_errno("Failed to open '%s' as directory", path);
            return -1;
        }
    }
    if ((work_directory->links_dirfd = openat(
                work_directory->dirfd, "links", 
                O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
        switch (errno) {
        case ENOENT:
            if (mkdirat(work_directory->dirfd, "links", 0755) < 0) {
                pr_error_with_errno(
                    "Failed to create links subdir under '%s'", path);
                close(work_directory->dirfd);
                return -1;
            }
            if ((work_directory->links_dirfd = openat(
                        work_directory->dirfd, "links", 
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
                pr_error_with_errno(
                    "Failed to open links subdir under '%s' as directory after "
                    "creating it", path);
                close(work_directory->dirfd);
                return -1;
            }
            break;
        default:
            pr_error_with_errno(
                "Failed to open links subdir under '%s' as directory", path);
            close(work_directory->dirfd);
            return -1;
        }
    }
    work_directory->path = path;
    work_directory->keeps = NULL;
    work_directory->keeps_allocated = 0;
    work_directory->keeps_count = 0;
    return 0;
}

int work_directories_from_paths(
    struct work_directory *const restrict workdir_repos, 
    struct work_directory *const restrict workdir_archives, 
    struct work_directory *const restrict workdir_checkouts,
    char const *const restrict dir_repos,
    char const *const restrict dir_archives,
    char const *const restrict dir_checkouts
) {
    if (work_directory_from_path(workdir_repos, dir_repos)) {
        pr_error("Failed to open work directory '%s' for repos\n", dir_repos);
        return -1;
    }
    if (work_directory_from_path(workdir_archives, dir_archives)) {
        close(workdir_repos->dirfd);
        pr_error("Failed to open work directory '%s' for archives\n", 
                dir_archives);
        return -1;
    }
    if (work_directory_from_path(workdir_checkouts, dir_checkouts)) {
        close(workdir_archives->dirfd);
        close(workdir_repos->dirfd);
        pr_error("Failed to open work directory '%s' for checkouts\n", 
                dir_checkouts);
        return -1;   
    }
    return 0;
}

static inline
void work_directory_free(
    struct work_directory const *const restrict workdir 
) {
    if (workdir->dirfd) close(workdir->dirfd);
    if (workdir->keeps) free(workdir->keeps);
}

static inline
void work_directories_free(
    struct work_directory const *const restrict workdir_repos, 
    struct work_directory const *const restrict workdir_archives, 
    struct work_directory const *const restrict workdir_checkouts
) {
    work_directory_free(workdir_repos);
    work_directory_free(workdir_archives);
    work_directory_free(workdir_checkouts);
}

// 0 existing and opened, 1 does not exist but created, -1 error
int repo_open_or_init_bare(
    struct repo *const restrict repo
) {
    if (repo == NULL || repo->url[0] == '\0' || 
        repo->dir_path[0] == '\0') {
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
        pr_debug(
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

int repo_update(
    struct repo *const restrict repo,
    git_fetch_options *const restrict fetch_options,
    unsigned short const proxy_after
) {
    pr_info("Updating repo '%s'...\r", repo->url);
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
    pr_debug("Beginning fetching from '%s'\n", repo->url);
    fetch_options->proxy_opts.type = GIT_PROXY_NONE;
    unsigned short max_try = proxy_after + 3;
    for (unsigned short try = 0; try < max_try; ++try) {
        if (try == proxy_after) {
            if (try) 
                pr_warn(
                    "Failed for %hu times, use proxy\n", proxy_after);
            fetch_options->proxy_opts.type = GIT_PROXY_SPECIFIED;
            // config->fetch_options.proxy_opts.
        }
        r = git_remote_fetch(remote, NULL, fetch_options, NULL);
        if (r) {
            pr_error(
                "Failed to fetch, libgit return %d%s\n", 
                r, try < max_try ? ", will retry" : "");
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
                pr_debug("Remote HEAD points to '%s' now\n", 
                        head->symref_target);
                if ((r = git_repository_set_head(
                        repo->repository, head->symref_target))) {
                    pr_error("Failed to update repo '%s' HEAD to '%s'\n",
                        repo->url, head->symref_target);
                    r = -1;
                    goto free_strarray;
                }
                pr_debug("Set local HEAD of repo '%s' to '%s'\n",
                    repo->url, head->symref_target);
                break;
            }
        }
    }

    pr_info("Updated repo '%s'\n", repo->url);
    repo->updated = true;
    r = 0;
free_strarray:
    git_strarray_free(&strarray);
free_remote:
    git_remote_free(remote);
    return r;
}

struct repo_update_thread_arg_modifiable {
    struct repo *restrict repo;
    git_fetch_options fetch_options;
    unsigned short proxy_after;
};

struct repo_update_thread_arg {
    struct repo *const restrict repo;
    git_fetch_options fetch_options;
    unsigned short const proxy_after;
};

void *repo_update_thread(void *arg) {
    struct repo_update_thread_arg *private_arg = 
        (struct repo_update_thread_arg *)arg;
    pr_debug("Thread called for repo '%s'\n", private_arg->repo->url);
    return (void *)(long)repo_update(private_arg->repo, 
        &private_arg->fetch_options, private_arg->proxy_after);
}

// Will also create symlink
int repo_prepare_open_or_create_if_needed(
    struct repo *const restrict repo,
    int const links_dirfd,
    git_fetch_options *const restrict fetch_options,
    unsigned short const proxy_after
) {
    if (repo->repository != NULL) return 0;
    if (repo_guarantee_symlink(repo, links_dirfd)) {
        pr_error("Failed to create symlink\n");
        return -1;
    }
    switch (repo_open_or_init_bare(repo)) {
    case -1:
        pr_error("Failed to open or init bare repo for '%s'\n", repo->url);
        return -1;
    case 0:
        break;
    case 1:
        pr_warn(
            "Repo '%s' just created locally, need to update\n", repo->url);
        if (repo_update(repo, fetch_options, proxy_after)) {
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
    if (config->repos) {
        for (unsigned long i = 0; i < config->repos_count; ++i) {
            struct repo *const restrict repo = config->repos + i;
            if (repo->parsed_commits) free (repo->parsed_commits);
            if (repo->wanted_objects) free (repo->wanted_objects);
            if (repo->repository) git_repository_free(repo->repository);
        }
        free (config->repos);
    }
    if (config->always_wanted_objects) free(config->always_wanted_objects);
    if (config->empty_wanted_objects) free(config->empty_wanted_objects);
    return 0;
}

int parsed_commit_add_submodule_and_init_with_path_and_url(
    struct parsed_commit *const restrict parsed_commit,
    char const *const restrict path,
    unsigned short len_path,
    char const *const restrict url,
    unsigned short len_url
) {
    if (parsed_commit_add_submodule_no_init(parsed_commit)) {
        pr_error("Failed to add submodule to commit\n");
        return -1;
    }
    struct parsed_commit_submodule *const restrict submodule =
        parsed_commit->submodules + parsed_commit->submodules_count -1;
    *submodule = PARSED_COMMIT_SUBMODULE_INIT;
    memcpy(submodule->path, path, len_path + 1);
    memcpy(submodule->url, url, len_url + 1);
    submodule->len_path = len_path;
    submodule->len_url = len_url;
    submodule->url_hash = hash_calculate(submodule->url, submodule->len_url);
    return 0;
}

// May re-allocate the config->repos array, must re-assign repo after calling

int parsed_commit_add_submodule_from_commit_tree(
    struct parsed_commit *const restrict parsed_commit,
    git_tree const *const restrict tree, 
    char const *const restrict path,
    unsigned short const len_path,
    char const *const restrict url,
    unsigned short const len_url
) {
    for (unsigned long i = 0; i < parsed_commit->submodules_count; ++i) {
        if (!strcmp(parsed_commit->submodules[i].path, path)) {
            pr_warn(
                "Already defined a submodule at path '%s' for commit %s\n",
                path, parsed_commit->id_hex_string);
            return -1;
        }
    }
    if (parsed_commit_add_submodule_and_init_with_path_and_url(
        parsed_commit, path, len_path, url, len_url)) {
        pr_error("Failed to init submodule for commit %s with path "
                "'%s' and url '%s'\n",
                parsed_commit->id_hex_string, path, url);
        return -1;
    }
    struct parsed_commit_submodule *const restrict submodule = 
        get_last(parsed_commit->submodules);
    git_tree_entry *entry;
    if (git_tree_entry_bypath(&entry, tree, path)) {
        pr_error("Path '%s' of submodule does not exist in tree\n", path);
        return -1;
    }
    int r = -1;
    if (git_tree_entry_type(entry) != GIT_OBJECT_COMMIT) {
        pr_error("Object at path '%s' in tree is not a commit\n", path);
        goto free_entry;
    }
    submodule->id = *git_tree_entry_id(entry);
    if (git_oid_tostr(
            submodule->id_hex_string,
            sizeof submodule->id_hex_string, 
            &submodule->id
        )[0] == '\0') {
        pr_error("Failed to format commit id into hex string\n");
        goto free_entry;
    }
    pr_info(
        "Submodule needed: '%s' <= '%s': %s\n", 
        path, url, submodule->id_hex_string);
    r = 0;
free_entry:
    git_tree_entry_free(entry);
    return r;
}

// May re-allocate repo->parsed_commits
int repo_add_parsed_commit(
    struct repo *const restrict repo,
    git_oid const *const restrict oid
) {
    if (repo_add_parsed_commit_no_init(repo)) {
        pr_error("Failed to add parsed commit without init\n");
        return -1;
    }
    struct parsed_commit *const restrict parsed_commit = 
        get_last(repo->parsed_commits);
    *parsed_commit = PARSED_COMMIT_INIT;
    parsed_commit->id = *oid;
    if (git_oid_tostr(
            parsed_commit->id_hex_string,
            sizeof parsed_commit->id_hex_string, 
            &parsed_commit->id
        )[0] == '\0') {
        pr_error("Failed to format commit id into hex string\n");
        return -1;
    }
    return 0;
}

// May re-allocate repo->parsed_commits
// int repo_add_parsed_commit_optional(
//     struct repo *const restrict repo,
//     git_oid const *const restrict oid
// ) {
//     for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {

//     }
//     return repo_add_parsed_commit(repo, oid);
// }

// May re-allocate config->repos
int repo_parse_commit_submodule_in_tree(
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const commit_id,
    git_tree const *const restrict tree, 
    char const *const restrict path,
    unsigned short const len_path,
    char const *const restrict url,
    unsigned short const len_url
) {
    struct repo const *repo = config->repos + repo_id;
    struct parsed_commit *parsed_commit = 
        repo->parsed_commits + commit_id;
    if (parsed_commit_add_submodule_from_commit_tree(
        parsed_commit, tree, path, len_path, url, len_url)) {
        pr_error("Failed to add submodule from commit tree\n");
        return -1;
    }
    struct parsed_commit_submodule *const restrict submodule = 
        get_last(parsed_commit->submodules);

    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo *const repo_cmp = config->repos + i;
        if (repo_cmp->url_hash == submodule->url_hash) {
            submodule->target_repo_id = i;
            for (unsigned long j = 0; j < repo_cmp->parsed_commits_count; ++j) {
                if (git_oid_cmp(
                    &submodule->id,
                    &repo_cmp->parsed_commits[j].id)) continue;
                pr_debug(
                    "Already added commit %s to repo '%s', skipped\n",
                    submodule->id_hex_string, repo_cmp->url);
                submodule->target_commit_id = j;
                return 0;
            }
            break;
        }
    }
    if (submodule->target_repo_id == (unsigned long) -1) {
        pr_warn("Repo '%s' was not seen before, need to add it\n", url);
        if (config_add_repo_and_init_with_url(config, url, len_url, 
            REPO_ADDED_FROM_SUBMODULE)) {
            pr_error("Failed to add repo '%s'\n", url);
            return -1;
        }
        repo = config->repos + repo_id;
        submodule->target_repo_id = config->repos_count - 1;
        if (repo_finish_bare(
            get_last(config->repos), config->dir_repos, config->len_dir_repos)){
            pr_error("Failed to finish bare repo\n");
            return -1;
        }
    }
    if (submodule->target_repo_id == (unsigned long) -1) {
        pr_error("Submodule '%s' with url '%s' for commmit %s of repo '%s' "
        "still missing target repo id, refuse to continue\n",
            path, url, submodule->id_hex_string, repo->url);
        return -1;
    }
    if (submodule->target_commit_id != (unsigned long) -1) return 0;
    struct repo *repo_target = 
        config->repos + submodule->target_repo_id;
    // The repo is either completely new, or we found it but not found commit
    // There is no need to check for commit duplication here
    int r = repo_add_parsed_commit(repo_target, &submodule->id);
    // The above function may re-allocate repo_target, the re-assign here
    // is in case repo == repo_target
    parsed_commit = repo->parsed_commits + commit_id;
    if (r) {
        pr_error("Failed to add parsed commit to repo\n");
        return -1;
    }
    submodule->target_commit_id = repo_target->parsed_commits_count - 1;
    if (submodule->target_repo_id >= repo_id) {
        pr_debug("Added commit %s as wanted to repo '%s', will handle "
            "that repo later\n", submodule->id_hex_string, repo_target->url);
        return 0;
    }
    pr_warn("Added commit %s as wanted to parsaed repo '%s', need to go back "
            "to handle that specific commit\n",
            submodule->id_hex_string, repo_target->url);
    r = repo_ensure_parsed_commit(config, submodule->target_repo_id, 
                                    submodule->target_commit_id);
    repo = config->repos + repo_id;
    parsed_commit = repo->parsed_commits + commit_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' commit %s 's submodule at '%s' "
                "from '%s' commit %s in target repo\n",
                repo->url, parsed_commit->id_hex_string, path, url, 
                submodule->id_hex_string);
        return 1;
    };
    return 0;
}


// May re-allocate the config->repos array, must re-assign repo after calling
int repo_parse_commit_blob_gitmodules(
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const commit_id,
    git_tree const *const tree,
    git_blob *const restrict blob_gitmodules
) {
    char const *blob_gitmodules_ro_buffer = 
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
    char    submodule_name[NAME_MAX] = "",
            submodule_path[PATH_MAX] = "",
            submodule_url[PATH_MAX] = "";
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
        unsigned short len_line = 0;
        git_object_size_t id_end = id_start + 1;
        for (; id_end < blob_gitmodules_size && len_line == 0;) {
            switch (blob_gitmodules_ro_buffer[id_end]) {
            case '\0':
            case '\n':
                len_line = id_end - id_start;
                break;
            default:
                ++id_end;
                break;
            }
        }
        if (len_line > 7) { // The shortest, "\turl = "
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
                        pr_debug(
                            "Submodule '%s', path '%s', url '%s'\n", 
                            submodule_name, submodule_path, submodule_url);
                        if (repo_parse_commit_submodule_in_tree(
                            config, repo_id, commit_id, tree, 
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
int repo_parse_commit_tree_entry_gitmodules(
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const commit_id,
    git_tree const *const tree,
    git_tree_entry const *const entry_gitmodules
) {
    struct repo const *restrict repo = config->repos + repo_id;
    struct parsed_commit *restrict parsed_commit = 
        repo->parsed_commits + commit_id;        
    if (git_tree_entry_type(entry_gitmodules) != GIT_OBJECT_BLOB) {
        pr_error(
            "Tree entry .gitmodules in commit %s for repo '%s' "
            "is not a blob\n",
            parsed_commit->id_hex_string, repo->url);
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
    r = repo_parse_commit_blob_gitmodules(
        config, repo_id, commit_id, tree, blob_gitmodules);
    repo = config->repos + repo_id;
    parsed_commit = repo->parsed_commits + commit_id;
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

// May re-allocate repo->parsed_commits
int repo_parse_wanted_commit(
    struct repo *const restrict repo,
    struct wanted_commit *const restrict wanted_commit
) {
    for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
        if (!git_oid_cmp(&repo->parsed_commits[i].id, &wanted_commit->id)) {
            wanted_commit->parsed_commit_id = i;
            return 0;
        }
    }
    if (repo_add_parsed_commit(repo, &wanted_commit->id)) {
        pr_error("Failed to add parsed commit\n");
        return -1;
    }
    wanted_commit->parsed_commit_id = repo->parsed_commits_count - 1;
    return 0;
}

// May re-allocate repo->parsed_commits
int repo_parse_wanted_reference_common(
    struct repo *const restrict repo,
    struct wanted_reference *const restrict wanted_reference,
    git_reference *reference,
    git_fetch_options *const restrict fetch_options,
    unsigned short const proxy_after
) {
    git_object *object;
    int r;
    if ((r = git_reference_peel(&object, reference, GIT_OBJECT_COMMIT))) {
        if (repo->updated) {
            pr_error(
                "Failed to peel reference '%s' into a commit object, "
                "libgit return %d\n",
                wanted_reference->name, r);
            return -1;
        }
        pr_warn("Failed to peel reference '%s' into a commit object, "
                "libgit return %d, but repo not updated yet, update to retry\n",
                wanted_reference->name, r);
        if (repo_update(repo, fetch_options, proxy_after)) {
            pr_error("Failed to update\n");
            return -1;
        }
        if ((r = git_reference_peel(&object, reference, GIT_OBJECT_COMMIT))) {
            pr_error("Failed to peel reference '%s' into commit object even "
            "after updating, libgit return %d\n", wanted_reference->name, r);
            return -1;
        }
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
    pr_info("Reference resolved: '%s': '%s' => %s\n",
        repo->url, wanted_reference->name,
        wanted_reference->commit.id_hex_string);
    return repo_parse_wanted_commit(repo, 
                                (struct wanted_commit *)wanted_reference);
}

void repo_parse_wanted_head_explain_libgit_return(int const r) {
    switch (r) {
    case GIT_EUNBORNBRANCH:
        pr_error("Failed to find HEAD, HEAD points to a non-"
            "existing branch\n");
        break;
    case GIT_ENOTFOUND:
        pr_error("Failed to find HEAD, HEAD is missing\n");
        break;
    default:
        pr_error("Failed to find HEAD, unhandled libgit return %d\n", r);
        break;
    }
}

// May re-allocate repo->parsed_commits
int repo_parse_wanted_head(
    struct repo *const restrict repo,
    struct wanted_reference *const restrict wanted_head,
    git_fetch_options *const restrict fetch_options,
    unsigned short const proxy_after
) {
    git_reference *head;
    int r = git_repository_head(&head, repo->repository);
    if (r) {
        repo_parse_wanted_head_explain_libgit_return(r);
        if (repo->updated) {
            pr_error("Failed to find HEAD\n");
            return -1;
        }
        pr_warn("Failed to find HEAD, but repo not updated yet, "
                "update to retry");
        if (repo_update(repo, fetch_options, proxy_after)) {
            pr_error("Failed to update\n");
            return -1;
        }
        if ((r = git_repository_head(&head, repo->repository))) {
            repo_parse_wanted_head_explain_libgit_return(r);
            pr_error("Still failed to find HEAD after updating\n");
            return -1;
        }
    }
    r = repo_parse_wanted_reference_common(
        repo, wanted_head, head, fetch_options, proxy_after);
    git_reference_free(head);
    return r;
}

void repo_parse_wanted_branch_explain_libgit_return(
    int const r, 
    char const *const restrict branch, 
    char const *const restrict repo
) {
    switch (r) {
    case GIT_ENOTFOUND:
        pr_error("Branch '%s' was not found in repo '%s'\n",
            branch, repo);
        break;
    case GIT_EINVALIDSPEC:
        pr_error("'%s' is an illegal branch spec\n", branch);
        break;
    default:
        pr_error("Failed to find branch '%s', "
            "unhandled libgit return %d\n",
            branch, r);
        break;
    }
}

// May re-allocate the config->repos array, must re-assign repo after calling
int repo_parse_wanted_branch(
    struct repo *const restrict repo,
    struct wanted_reference *const restrict wanted_branch,
    git_fetch_options *const restrict fetch_options,
    unsigned short const proxy_after
) {
    git_reference *reference;
    int r = git_branch_lookup(
        &reference, repo->repository, wanted_branch->name, GIT_BRANCH_LOCAL);
    if (r) {
        repo_parse_wanted_branch_explain_libgit_return(
            r, wanted_branch->name, repo->url);
        if (repo->updated) {
            pr_error("Failed to find branch\n");
            return -1;
        }
        pr_warn(
            "Failed to find branch, but repo not updated, update to retry\n");
        if (repo_update(repo, fetch_options, proxy_after)) {
            pr_error("Failed to update repo\n");
            return -1;
        }
        if ((r = git_branch_lookup(
            &reference, repo->repository, wanted_branch->name, GIT_BRANCH_LOCAL
        ))) {
            repo_parse_wanted_branch_explain_libgit_return(
                r, wanted_branch->name, repo->url);
            pr_error("Still failed to lookup branch even after update\n");
            return -1;
        }
    }
    r = repo_parse_wanted_reference_common(
        repo, wanted_branch, reference, fetch_options, proxy_after);
    git_reference_free(reference);
    return r;
}

void repo_parse_wanted_reference_explain_libgit_return(
    int const r,
    char const *const restrict reference,
    char const *const restrict repo
) {
    switch (r) {
    case GIT_ENOTFOUND:
        pr_error("Not found reference '%s' in repo '%s'\n", reference, repo);
        break;
    case GIT_EINVALIDSPEC:
        pr_error("'%s' is not a valid reference spec\n", reference);
        break;
    default:
        pr_error("Failed to lookup reference, unhandled libgit return %d\n", r);
        break;
    }
}

int repo_parse_wanted_reference_with_given_ref_name(
    struct repo *const restrict repo,
    struct wanted_reference *const restrict wanted_reference,
    git_fetch_options *const restrict fetch_options,
    unsigned short const proxy_after,
    char const *const ref_name
) {
    git_reference *reference;
    int r = git_reference_lookup(&reference, repo->repository, ref_name);
    if (r) {
        repo_parse_wanted_reference_explain_libgit_return(
            r, ref_name, repo->url);
        if (repo->updated) {
            pr_error("Failed to lookup reference\n");
            return -1;
        }
        pr_warn("Failed to lookup reference, but repo not updated yet, "
            "update to retry\n");
        if (repo_update(repo, fetch_options, proxy_after)) {
            pr_error("Failed to update\n");
            return -1;
        }
        if ((r = git_reference_lookup(
            &reference, repo->repository, ref_name))) {
            repo_parse_wanted_reference_explain_libgit_return(
                r, ref_name, repo->url);
            pr_error("Failed to lookup reference even after update\n");
            return -1;
        }
    }
    r = repo_parse_wanted_reference_common(
        repo, wanted_reference, reference, fetch_options, proxy_after);
    git_reference_free(reference);
    return r;
}


int repo_parse_wanted_tag(
    struct repo *const restrict repo,
    struct wanted_reference *const restrict wanted_tag,
    git_fetch_options *const restrict fetch_options,
    unsigned short const proxy_after
) {
    char ref_name[NAME_MAX];
    char const *const tag_name = wanted_tag->commit.base.name;
    if (snprintf(ref_name, sizeof ref_name, "refs/tags/%s", tag_name) < 0) {
        pr_error_with_errno(
            "Failed to generate full ref name of tag '%s' for repo '%s'",
            tag_name, repo->url);
        return -1;
    }
    return repo_parse_wanted_reference_with_given_ref_name(
        repo, wanted_tag, fetch_options, proxy_after, ref_name);
}

int repo_parse_wanted_reference(
    struct repo *const restrict repo,
    struct wanted_reference *const restrict wanted_reference,
    git_fetch_options *const restrict fetch_options,
    unsigned short const proxy_after
) {
    return repo_parse_wanted_reference_with_given_ref_name(
        repo, wanted_reference, fetch_options, proxy_after,
        wanted_reference->name);
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
    if (repo_add_wanted_object_and_init_with_name_no_complete(
        repo, reference_name, strlen(reference_name))) {
        pr_error("Failed to add reference '%s' to repo '%s'\n",
            reference_name, repo->url);
        return -1;
    }
    struct wanted_object *const restrict wanted_reference = 
        get_last(repo->wanted_objects);
    wanted_reference->archive = archive;
    wanted_reference->checkout = checkout;
    wanted_reference->type = WANTED_TYPE_REFERENCE;
    pr_debug("Added wanted reference '%s' to repo '%s'\n", 
        wanted_reference->commit.base.name, repo->url);
    return 0;
}

int repo_parse_wanted_all_branches(
    struct repo *const restrict repo,
    struct wanted_base *const restrict wanted_all_branches
) {
    git_branch_iterator *branch_iterator;
    int r = git_branch_iterator_new(
        &branch_iterator, repo->repository, GIT_BRANCH_LOCAL);
    if (r) {
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

struct repo_parse_wanted_all_tags_foreach_payload {
    struct repo *const restrict repo;
    bool const archive;
    bool const checkout;
};

int repo_parse_wanted_all_tags_foreach_callback(
    char const *name, git_oid *oid, void *payload
) {
    (void) oid;
    struct repo_parse_wanted_all_tags_foreach_payload 
        *const restrict private_payload = 
        (struct repo_parse_wanted_all_tags_foreach_payload *
            const restrict) payload;
    if (repo_add_wanted_reference(private_payload->repo, name, 
        private_payload->archive, private_payload->checkout)) {
        pr_error("Failed to add tag reference '%s' as wannted to "
        "repo '%s'\n", name, private_payload->repo->url);
        return -1;
    }
    return 0;
}

int repo_parse_wanted_all_tags(
    struct repo *const restrict repo,
    struct wanted_base *const restrict wanted_all_tags
) {
    unsigned long i = repo->wanted_objects_count;
    struct repo_parse_wanted_all_tags_foreach_payload 
        const private_payload = {
            .repo = repo,
            .archive = wanted_all_tags->archive,
            .checkout = wanted_all_tags->checkout,
        };
    pr_debug(
        "Looping through all tags to create individual wanted references\n");
    int r = git_tag_foreach(
        repo->repository, repo_parse_wanted_all_tags_foreach_callback,
        (void *)&private_payload);
    if (r) {
        pr_error("Failed git_tag_foreach callback, libgit return %d\n", r);
        return -1;
    }
    pr_info("All tags:");
    for (; i < repo->wanted_objects_count; ++i) {
        printf(" '%s'", repo->wanted_objects[i].name);
    }
    printf("\n");
    return 0;
}

// May re-allocate config->repos, and repo->parsed_commits
int repo_lookup_commit_and_update_if_failed(
    git_commit **const restrict commit,
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const commit_id
) {
    struct repo *restrict repo = config->repos + repo_id;
    struct parsed_commit *restrict parsed_commit = 
        repo->parsed_commits + commit_id;
    int r = git_commit_lookup(commit, repo->repository, &parsed_commit->id);
    if (r) {
        if (repo->updated) {
            pr_error(
                "Failed to lookup commit %s in repo '%s' "
                "even it's up-to-date, "
                "libgit return %d, consider failure\n", 
                parsed_commit->id_hex_string, repo->url, r);
            return -1;
        }
        pr_warn(
            "Commit %s does not exist in repo '%s' (libgit return %d), "
            "but the repo is not updated yet, "
            "trying to update the repo before looking up the commit again\n", 
            parsed_commit->id_hex_string, repo->url, r);
        if (repo_update(repo, &config->fetch_options, config->proxy_after)) {
            pr_error("Failed to update repo\n");
            return -1;
        }
        pr_warn(
            "Repo '%s' updated, go back to ensure old parsed commits are "
            "still robust\n", repo->url);
        r = repo_ensure_first_parsed_commits(config, repo_id, commit_id);
        repo = config->repos + repo_id;
        parsed_commit = repo->parsed_commits + commit_id;
        if (r) {
            pr_error("Updated repo '%s' breaks robustness of old parsed commit "
            "%s", repo->url, parsed_commit->id_hex_string);
            return -1;
        }
        if ((r = git_commit_lookup(
            commit, repo->repository, &parsed_commit->id))) {
            pr_error(
                "Failed to lookup commit %s in repo '%s' "
                "even after updating the repo, libgit return %d, "
                "consider failure\n",
                parsed_commit->id_hex_string, repo->url, r);
            return -1;
        }
    }
    return 0;
}

// May re-allocate config->repos, and repo->parsed_commits
int repo_ensure_parsed_commit_submodules (
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const commit_id,
    git_commit *commit
) {
    struct repo *restrict repo = config->repos + repo_id;
    struct parsed_commit *restrict parsed_commit = 
        repo->parsed_commits + commit_id;      
    if (parsed_commit->submodules_parsed) return 0;
    git_tree *tree;
    int r = git_commit_tree(&tree, commit);
    if (r) {
        pr_error(
            "Failed to get the commit tree pointed by commit %s "
            "in repo '%s', libgit return %d\n", 
            parsed_commit->id_hex_string, repo->url, r);
        return -1;
    }
    git_tree_entry const *const entry_gitmodules = 
        git_tree_entry_byname(tree, ".gitmodules");
    if (entry_gitmodules != NULL) {
        pr_debug(
            "Found .gitmodules in commit tree of %s for repo '%s', "
            "parsing submodules\n", parsed_commit->id_hex_string, repo->url);
        r = repo_parse_commit_tree_entry_gitmodules(
            config, repo_id, commit_id, tree, entry_gitmodules);
        repo = config->repos + repo_id;
        parsed_commit = repo->parsed_commits + commit_id;
        if (r) {
            pr_error(
                "Failed to parse submodules in commit tree of %s "
                "for repo '%s'\n", 
                parsed_commit->id_hex_string, repo->url);
            return -1;
        }
    }
    parsed_commit->submodules_parsed = true;
    return 0;
}

// May re-allocate config->repos, and repo->parsed_commits
int repo_ensure_parsed_commit(
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const commit_id
) {
    git_commit *commit;
    int r = repo_lookup_commit_and_update_if_failed(
                &commit, config, repo_id, commit_id);
    
    struct repo *restrict repo = config->repos + repo_id;
    struct parsed_commit *restrict parsed_commit = 
        repo->parsed_commits + commit_id;          
    if (r) {
        pr_error("Failed to lookup commit %s in repo '%s'\n",
            parsed_commit->id_hex_string, repo->url);
        return -1;
    }
    if (!parsed_commit->submodules_parsed) {
        r = (repo_ensure_parsed_commit_submodules(
            config, repo_id, commit_id, commit));
        repo = config->repos + repo_id;
        parsed_commit = repo->parsed_commits + commit_id;
        if (r) {
            pr_error("Failed to parse repo '%s' commit %s submodules\n",
                repo->url, parsed_commit->id_hex_string);
            r = -1;
            goto free_commit;
        }
    }
    pr_info("Commit robust: '%s': %s\n",
        repo->url, parsed_commit->id_hex_string);
    r = 0;
free_commit:
    git_commit_free(commit);
    return r;
}

// May re-allocate config->repos, and repo->parsed_commits
int repo_ensure_first_parsed_commits(
    struct config *const restrict config,
    unsigned long const repo_id,
    unsigned long const stop_before_commit_id
) {
    struct repo *restrict repo = config->repos + repo_id;
    for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
        if (i == stop_before_commit_id) break;
        if (repo_ensure_parsed_commit(config, repo_id, i)) {
            repo = config->repos + repo_id;
            pr_error(
                "Failed to ensure robustness of commit %s of repo '%s'\n",
                repo->parsed_commits[i].id_hex_string, repo->url);
            return -1;
        }
        repo = config->repos + repo_id;
    }
    return 0;
}

// May re-allocate config->repos, and repo->parsed_commits
int repo_ensure_all_parsed_commits(
    struct config *const restrict config,
    unsigned long const repo_id
) {
    struct repo *restrict repo = config->repos + repo_id;
    pr_debug("Ensursing all parsed commit for repo '%s', count %lu\n", 
        repo->url, repo->parsed_commits_count);
    for (unsigned long i = 0; i < repo->parsed_commits_count; ++i) {
        if (repo_ensure_parsed_commit(config, repo_id, i)) {
            repo = config->repos + repo_id;
            pr_error(
                "Failed to ensure robustness of commit %s of repo '%s'\n",
                repo->parsed_commits[i].id_hex_string, repo->url);
            return -1;
        }
        repo = config->repos + repo_id;
    }
    return 0;
}

int mirror_repo(
    struct config *const restrict config,
    unsigned long const repo_id,
    int const links_dirfd
) {
    int r = repo_prepare_open_or_create_if_needed(
        config->repos + repo_id, links_dirfd, 
        &config->fetch_options, config->proxy_after);
    struct repo *restrict repo = config->repos + repo_id;
    if (r) {
        pr_error("Failed to ensure repo '%s' is opened\n", repo->url);
        return -1;
    }
    pr_info("Mirroring repo '%s'\n", repo->url);
    if (repo->wanted_dynamic && !repo->updated) {
        pr_warn(
            "Dynamic wanted objects set for repo '%s', need to update\n", 
            repo->url);
        if (repo_update(
            repo, &config->fetch_options, config->proxy_after)) {
            pr_error(
                "Failed to update repo '%s' to prepare for "
                "dynamic wanted objects\n",
                repo->url);
            return -1;
        }
    }
    git_fetch_options *const fetch_options = &config->fetch_options;
    unsigned short const proxy_after = config->proxy_after;

    bool updated = repo->updated;
    for (;;) {
        for (unsigned i = 0; i < repo->wanted_objects_count;) {
            struct wanted_object *wanted_object = repo->wanted_objects + i;
            switch (wanted_object->type) {
            case WANTED_TYPE_COMMIT:
                if (repo_parse_wanted_commit(repo,
                    (struct wanted_commit *)wanted_object)) {
                    pr_error(
                        "Failed to parse wanted commit %s for repo '%s'\n",
                        wanted_object->id_hex_string, repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_ALL_TAGS:
                if (repo_parse_wanted_all_tags(repo,
                    (struct wanted_base *)wanted_object)) {
                    pr_error(
                        "Failed to parse wanted all branches for repo '%s'\n",
                        repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_ALL_BRANCHES:
                if (repo_parse_wanted_all_branches(repo,
                    (struct wanted_base *)wanted_object)) {
                    pr_error("Failed to parse wanted all tags for repo '%s'\n",
                        repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_BRANCH:
                if (repo_parse_wanted_branch(repo,
                    (struct wanted_reference *)wanted_object,
                    fetch_options, proxy_after)) {
                    pr_error(
                        "Failed to parsed wanted branch '%s'  for repo '%s'\n",
                        wanted_object->name, repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_TAG:
                if (repo_parse_wanted_tag(repo,
                    (struct wanted_reference *)wanted_object,
                    fetch_options, proxy_after)) {
                    pr_error(
                        "Failed to parsed wanted tag '%s'  for repo '%s'\n",
                        wanted_object->name, repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_REFERENCE:
                if (repo_parse_wanted_reference(repo,
                    (struct wanted_reference *)wanted_object,
                    fetch_options, proxy_after)) {
                    pr_error(
                        "Failed to parsed wanted reference '%s'  for "
                        "repo '%s'\n",
                        wanted_object->name, repo->url);
                    return -1;
                }
                break;
            case WANTED_TYPE_HEAD:
                if (repo_parse_wanted_head(repo, 
                    (struct wanted_reference *)wanted_object,
                    fetch_options, proxy_after)) {
                    pr_error("Failed to parsed wanted HEAD for repo '%s'\n",
                    repo->url);
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
            if (repo->updated && !updated) {
                pr_warn(
                    "Silent update happended during run, need to reset loop\n");
                // Drop all wanted objects added later
                updated = true;
                repo->wanted_objects_count = 
                    repo->wanted_objects_count_original;
                i = 0;
                pr_warn("Repo updated, go back to first wanted object\n");
                continue;
            }
            ++i;
        }
        if (repo_ensure_all_parsed_commits(config, repo_id)) {
            pr_error("Failed to ensure robustness of all parsed commits\n");
            return -1;
        }
        repo = config->repos + repo_id;
        if (updated == repo->updated) {
            break;
        } else {
            pr_warn("Silent update happened during run, need to reset loop\n");
            updated = repo->updated;
        }
    }
    pr_info("Finished mirroring repo '%s'\n", repo->url);
    return 0;
}

int open_and_update_all_dynamic_repos_threaded_optional(
    struct config *const restrict config,
    int const links_dirfd
) {
    unsigned long repos_need_update_count = 0;
    git_fetch_options *const fetch_options = &config->fetch_options;
    unsigned short const proxy_after = config->proxy_after;
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo *const restrict repo = config->repos + i;
        if (!repo->wanted_dynamic) continue;
        ++repos_need_update_count;
        if (repo_prepare_open_or_create_if_needed(
            repo, links_dirfd, fetch_options, proxy_after)) {
            pr_error("Failed to prepare repo\n");
            return -1;
        }
    }
    // If there's only 1 thread needed, going this routine just wastes time
    if (repos_need_update_count <= 1) return 0;

    pthread_t *threads = malloc(sizeof *threads * repos_need_update_count);
    if (threads == NULL) {
        pr_error("Failed to allocate memory for threads\n");
        return -1;
    }
    int r = -1;
    struct repo_update_thread_arg *threads_args = malloc(
        sizeof *threads_args * repos_need_update_count);
    if (threads_args == NULL) {
        pr_error("Failed to allocate memory for threads args\n");
        goto free_threads;
    }

    unsigned long thread_id = 0;
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo *const restrict repo = config->repos + i;
        pr_debug("Handling repo %lu '%s' of %lu\n", i, repo->url, repos_need_update_count);
        if (!repo->wanted_dynamic) continue;
        pr_debug("Creating thread for repo '%s'\n", repo->url);
        struct repo_update_thread_arg_modifiable *thread_arg = 
            (struct repo_update_thread_arg_modifiable *)
                (threads_args + thread_id);
        thread_arg->repo = repo;
        thread_arg->fetch_options = *fetch_options;
        thread_arg->proxy_after = proxy_after;
        r = pthread_create(threads + thread_id, NULL, 
            repo_update_thread, threads_args + thread_id);
        ++thread_id;
        if (r) {
            pr_error("Failed to create thread, pthread return %d\n", r);
            repos_need_update_count = i;
            r = -1;
            goto kill_threads;
        }
    }
    pr_debug("%lu threads running\n", repos_need_update_count);
    pr_info("Simultaneously updating %lu repos...\n", repos_need_update_count);
    while (repos_need_update_count) {
        pr_debug("%lu threads running\n", repos_need_update_count);
        for (unsigned long i = 0; i < repos_need_update_count; ++i) {
            long thread_ret;
            r = pthread_tryjoin_np(threads[i], (void **)&thread_ret);
            switch (r) {
            case 0:
                threads[i] = threads[repos_need_update_count-- - 1];
                if (thread_ret) {
                    pr_error(
                        "Repo update thread bad return %ld\n", thread_ret);
                    r = -1;
                    goto kill_threads;
                }
                if (repos_need_update_count)
                    pr_info("%lu repos still updating...\n", 
                        repos_need_update_count);
            case EBUSY:
                break;
            default:
                pr_error("Failed to join thread, pthread return %d\n", r);
                r = -1;
                goto kill_threads;
            }
        }
        usleep(10);
    }
    r = 0;
kill_threads:
    for (unsigned long i = 0; i < repos_need_update_count; ++i) {
        pthread_kill(threads[i], SIGKILL);
    }
// free_threads_args:
    free(threads_args);
free_threads:
    free(threads);
    return r;
}

int mirror_all_repos(
    struct config *const restrict config,
    struct work_directory *const restrict workdir_repos,
    bool const clean
) {
    if (open_and_update_all_dynamic_repos_threaded_optional(
        config, workdir_repos->links_dirfd)) {
        pr_error("Failed to pre-update repos\n");
        return -1;
    }
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        if (clean) {
            struct repo const *const restrict repo = config->repos + i;
            if (work_directory_add_keep(
                workdir_repos, repo->hash_name, HASH_STRING_LEN)) {
                pr_error("Failed to add '%s' to keep items\n", repo->hash_name);
                return -1;
            }
        }
        if (mirror_repo(config, i, workdir_repos->links_dirfd)) {
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
    struct tar_posix_header global_header = 
        TAR_POSIX_HEADER_PAX_GLOBAL_HEADER_INIT;
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
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    char const *const restrict path_archive,
    unsigned short const len_path_archive,
    bool const checkout,    
    char const *const restrict dir_checkout,
    char const *const restrict path_checkout,
    mode_t mode
) {
    if (archive) {
        if (export_commit_tree_entry_blob_file_regular_to_archive(
            ro_buffer, size, path_archive, len_path_archive, mtime, fd_archive, 
            mode)) {
            pr_error("Failed to archive commit tree entry blob regular file "
                "at '%s'\n", path_archive);
            return -1;
        }
    }
    if (checkout) {
        if (export_commit_tree_entry_blob_file_regular_to_checkout(
            ro_buffer, size, path_checkout, dir_checkout, mode)) {
            pr_error("Failed to checkout commit tree entry blob regular file "
                "at '%s'\n", path_checkout);
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
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    char const *const restrict path_archive,
    unsigned short const len_path_archive,
    bool const checkout,    
    char const *const restrict dir_checkout,
    char const *const restrict path_checkout
) {
    if (archive) {
        if (export_commit_tree_entry_blob_file_symlink_to_archive(
            ro_buffer, path_archive, len_path_archive, mtime, fd_archive)) {
            pr_error("Failed to archive commit tree entry blob file symlink "
                "at '%s'\n", path_archive);
            return -1;
        }
    }
    if (checkout) {
        if (export_commit_tree_entry_blob_file_symlink_to_checkout(
            ro_buffer, path_checkout, dir_checkout)) {
            pr_error("Failed to checkout commit tree entry blob file symlink "
                "at '%s'\n", path_checkout);
            return -1;
        }
    }
    return 0;
}

int export_commit_tree_entry_blob(
    git_tree_entry const *const restrict entry,
    struct repo const *const restrict repo,
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    char const *const restrict path_archive,
    unsigned short const len_path_archive,
    bool const checkout,    
    char const *const restrict dir_checkout,
    char const *const restrict path_checkout
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
            archive, mtime, fd_archive, 
            path_archive, len_path_archive,
            checkout, dir_checkout, 
            path_checkout,
            0644);
        break;
    case GIT_FILEMODE_BLOB_EXECUTABLE:
        r = export_commit_tree_entry_blob_file_regular(
            ro_buffer,
            git_blob_rawsize((git_blob *)object),
            archive, mtime, fd_archive, 
            path_archive, len_path_archive,
            checkout, dir_checkout, 
            path_checkout,
            0755);
        break;
    case GIT_FILEMODE_LINK:
        r = export_commit_tree_entry_blob_file_symlink(
            ro_buffer,
            archive, mtime, fd_archive, path_archive, len_path_archive,
            checkout, dir_checkout, path_checkout);
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
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    char const *const restrict path_archive,
    unsigned short const len_path_archive,
    bool const checkout,    
    char const *const restrict dir_checkout,
    char const *const restrict path_checkout
) {
    if (archive) {
        if (export_commit_tree_entry_tree_to_archive(
            path_archive, len_path_archive, mtime, fd_archive)) {
            pr_error("Failed to export '%s' to archive\n", path_archive);
            return -1;
        }
    }
    if (checkout) {
        if (export_commit_tree_entry_tree_to_checkout(
            path_checkout, dir_checkout)) {
            pr_error("Failed to export '%s' to checkout\n", path_checkout);
            return -1;
        }
    }
    return 0;
};

int export_commit_tree_entry_commit(
	char const *const restrict root,
    git_tree_entry const *const restrict entry,
    struct config const *const restrict config,
    struct parsed_commit const *const restrict parsed_commit,
    char *const restrict submodule_path,
    unsigned short const len_submodule_path,
    bool const archive,
    char const *const restrict mtime,
    int const fd_archive,
    char const *const restrict archive_prefix,
    char const *const restrict path_archive,
    unsigned short const len_path_archive,
    bool const checkout,    
    char const *const restrict dir_checkout,
    char const *const restrict path_checkout
) {
    // Export self as a tree (folder)
    if (export_commit_tree_entry_tree(
        archive, mtime, fd_archive, path_archive, len_path_archive,
        checkout, dir_checkout, path_checkout)) {
        pr_error("Failed to export submodule '%s' as a tree\n", path_archive);
        return -1;
    }

    // Find which wanted submodule commit the entry is
    git_oid const *const submodule_commit_id = git_tree_entry_id(entry);
    struct parsed_commit_submodule *parsed_commit_submodule = NULL;
    for (unsigned long i = 0; i < parsed_commit->submodules_count; ++i) {
        pr_debug("Parsed submodule '%s' commit %s\n", 
        parsed_commit->submodules[i].path, 
        parsed_commit->submodules[i].id_hex_string);
        if (!git_oid_cmp(
            &parsed_commit->submodules[i].id, submodule_commit_id)) {
            parsed_commit_submodule = parsed_commit->submodules + i;
            break;
        }
    }
    if (parsed_commit_submodule == NULL) {
        char oid_buffer[GIT_OID_MAX_HEXSIZE + 1];
        pr_error("Failed to find corresponding wanted commit submodule, "
        "path: '%s', commit: %s\n", path_checkout, 
        git_oid_tostr(
            oid_buffer, GIT_OID_MAX_HEXSIZE + 1, submodule_commit_id));
        return -1;
    }

    // Find that wanted commit in target repo
    struct repo const *const restrict target_repo = 
        config->repos + parsed_commit_submodule->target_repo_id;
    struct parsed_commit const *restrict parsed_commit_in_target_repo = 
        target_repo->parsed_commits + parsed_commit_submodule->target_commit_id;
    pr_debug("Submodule from target repo '%s', id %ld\n",
        target_repo->url, parsed_commit_submodule->target_commit_id);

    // Recursively export
    char const *const restrict name = git_tree_entry_name(entry);
    unsigned short len_submodule_path_r = 
        len_submodule_path + strlen(name) + strlen(root) + 1;
    if (len_submodule_path_r >= PATH_MAX) {
        pr_error("Path too long!\n");
        return -1;
    }
    int r = -1;
    if (sprintf(submodule_path + len_submodule_path, 
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
        .parsed_commit = parsed_commit_in_target_repo,
        .submodule_path = submodule_path,
        .len_submodule_path = len_submodule_path_r,
        .archive = archive,
        .mtime = mtime_r,
        .fd_archive = fd_archive,
        .archive_prefix = archive_prefix,
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
    submodule_path[len_submodule_path] = '\0';
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
    char path_checkout[PATH_MAX];
    char const *const name = git_tree_entry_name(entry);
    int r = snprintf(
        path_checkout, PATH_MAX, "%s%s%s", private_payload->submodule_path,
        root, name);
    if (r < 0) {
        pr_error("Failed to format entry path\n");
        return -1;
    }
    unsigned short len_path_archive = r;
    char path_archive[PATH_MAX];
    char const *const restrict archive_prefix = 
        private_payload->archive_prefix;
    if (archive_prefix && archive_prefix[0] != '\0') {
        if ((r = snprintf(path_archive, PATH_MAX, "%s%s", 
                    archive_prefix, path_checkout)) < 0) {
            pr_error("Failed to format entry path\n");
            return -1;
        }
        len_path_archive = r;
    } else {
        memcpy(path_archive, path_checkout, len_path_archive + 1);
    }
    char const *const restrict mtime = private_payload->mtime;
    int const fd_archive = private_payload->fd_archive;
    char const *const restrict dir_checkout = private_payload->dir_checkout;
    switch (git_tree_entry_type(entry)) {
    case GIT_OBJECT_BLOB:
        return export_commit_tree_entry_blob(
            entry, private_payload->repo, 
            archive, mtime, fd_archive, path_archive, len_path_archive,
            checkout, dir_checkout, path_checkout);
    case GIT_OBJECT_TREE:
        return export_commit_tree_entry_tree(
            archive, mtime, fd_archive, path_archive, len_path_archive,
            checkout, dir_checkout, path_checkout);
    case GIT_OBJECT_COMMIT:
        return export_commit_tree_entry_commit(
            root, entry, private_payload->config, 
            private_payload->parsed_commit, private_payload->submodule_path,
            private_payload->len_submodule_path, archive, mtime, fd_archive, 
            archive_prefix, path_archive, len_path_archive,
            checkout, dir_checkout, path_checkout);
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
        case DT_LNK:
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

int ensure_parent_dir(
    char *const restrict path,
    unsigned short const len_path
) {
    for (unsigned short i = len_path; i > 0; --i) {
        if (path[i - 1] == '/') {
            path[i - 1] = '\0';
            int r = mkdir_recursively(path);
            path[i - 1] = '/';
            if (r) {
                pr_error("Failed to ensure parent dir of '%s'\n", path);
                return -1;
            }
            return 0;
        }
    }
    pr_error("Path '%s' does not have parent\n", path);
    return -1;
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

int export_commit_add_global_comment_to_tar(
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

int export_commit(
    struct config const *const restrict config,
    struct repo const *const restrict repo,
    struct parsed_commit const *const restrict parsed_commit,
    bool const archive_config,
    bool const checkout_config
) {
    bool archive = archive_config,
         checkout = checkout_config;
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
            config->dir_checkouts, parsed_commit->id_hex_string);
        if (r < 0) {
            pr_error_with_errno("Failed to format checkout dir");
            return -1;
        } else if (r >= PATH_MAX - 6) {
            pr_error("Dir checkout path '%s' too long\n", 
            dir_checkout);
            return -1;
        }
        pr_debug(
            "Will checkout repo '%s' commit %s to '%s'\n",
            repo->url, parsed_commit->id_hex_string, 
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
                pr_debug("Already checked out to '%s', no neeed to "
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
            file_archive, PATH_MAX, "%s/%s%s", 
            config->dir_archives, parsed_commit->id_hex_string,
            config->archive_suffix);
        if (r < 0) {
            pr_error_with_errno("Failed to format archive file");
            return -1;
        } else if (r >= PATH_MAX - 6) {
            pr_error("Archive file path '%s' too long\n", 
            file_archive);
            return -1;
        }
        pr_debug(
            "Will archive repo '%s' commit %s into '%s'\n",
            repo->url, parsed_commit->id_hex_string, 
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
                pr_debug("Already archived '%s', no neeed to "
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
    pid_t pid = 0;
    if (archive) {
        r = snprintf(file_archive_work, PATH_MAX, "%s.work", file_archive);
        if (r < 0) {
            pr_error_with_errno("Failed to format archive work file");
            return -1;
        }
        if (ensure_parent_dir(file_archive_work, r)) {
            pr_error("Failed to ensure parent folder of '%s'\n", 
                file_archive_work);
            return -1;
        }
        if (ensure_path_non_exist(file_archive_work)) {
            pr_error_with_errno("Failed to ensure '%s' non-exist", 
                file_archive_work);
            return -1;
        }
        fd_archive = open(file_archive_work, 
                            O_WRONLY | O_CREAT | O_CLOEXEC, 
                            0644);
        if (fd_archive < 0) {
            pr_error_with_errno(
                "Failed to create file '%s.work' and open it as write-only",
                file_archive_work);
            return -1;
        }
        if (config->archive_pipe_args[0] && config->archive_pipe_args_count) {
            int fd_pipes[2];
            if (pipe2(fd_pipes, O_CLOEXEC)) {
                pr_error_with_errno("Failed to create pipe\n");
                return -1;
            }
            pid = fork();
            switch (pid) {
            case 0: // Child
                if (dup2(fd_archive, STDOUT_FILENO) < 0) {
                    pr_error_with_errno_file(stderr,
                        "Failed to dup archive fd to stdout");
                    exit(EXIT_FAILURE);
                }
                if (dup2(fd_pipes[0], STDIN_FILENO) < 0) {
                    pr_error_with_errno_file(stderr,
                        "Failed to dup pipe read end to stdin");
                    exit(EXIT_FAILURE);
                }
                // fd_pipes[0] (pipe read), fd_pipes[1] (pipe write)
                // and fd_archive will all be closed as they've been
                // opened/created with O_CLOEXEC
                if (execvp(config->archive_pipe_args[0], 
                    config->archive_pipe_args)) {
                    pr_error_with_errno_file(stderr, "Failed to execute piper");
                    exit(EXIT_FAILURE);
                }
                pr_error_file(stderr, "We should not be here\n");
                exit(EXIT_FAILURE);
                break;
            case -1:
                pr_error_with_errno("Failed to fork");
                return -1;
            default: // Parent
                pr_info("Forked piper to child %d\n", pid);
                if (close(fd_pipes[0])) { // Close the read end
                    pr_error_with_errno("Failed to close read end of the pipe");
                    kill(pid, SIGKILL);
                    return -1;
                }
                if (close(fd_archive)) { // Close the original archive fd
                    pr_error_with_errno(
                        "Failed to close the original archive fd");
                    kill(pid, SIGKILL);
                    return -1;
                }
                fd_archive = fd_pipes[1]; // write to pipe write end
                break;
            }
        }
    }
    if (!archive && !checkout) {
        if (fd_archive >= 0) close(fd_archive);
        return 0;
    }
    git_commit *commit;
    if (git_commit_lookup(
            &commit, repo->repository, &parsed_commit->id)) {
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
    pr_info("Started exporting repo '%s' commit %s\n",
        repo->url, parsed_commit->id_hex_string);
    char submodule_path[PATH_MAX] = "";
    unsigned short len_submodule_path = 0;
    char archive_prefix[PATH_MAX] = "";
    if (config->archive_gh_prefix) {
        if ((r = snprintf(archive_prefix, PATH_MAX, "%s-%s/", repo->short_name, 
        parsed_commit->id_hex_string)) < 0) {
            pr_error_with_errno("Failed to generate github-like prefix\n");
            git_commit_free(commit);
            if (fd_archive >= 0) close(fd_archive);
            return -1;
        }
        pr_info("Will add github-like prefix '%s' to tar\n", archive_prefix);
    }
    char mtime[TAR_POSIX_HEADER_MTIME_LEN] = "";
    if (snprintf(
        mtime, TAR_POSIX_HEADER_MTIME_LEN, "%011lo", git_commit_time(commit)
    ) < 0) {
        pr_error("Failed to format mtime\n");
        git_commit_free(commit);
        if (fd_archive >= 0) close(fd_archive);
        return -1;
    }
    if (archive) {
        if (export_commit_add_global_comment_to_tar(fd_archive,
            repo->url, parsed_commit->id_hex_string, mtime)) {
            pr_error("Failed to add pax global header comment\n");
            git_commit_free(commit);
            if (fd_archive >= 0) close(fd_archive);
            return -1;
        }
    }
    struct export_commit_treewalk_payload export_commit_treewalk_payload = {
        .config = config,
        .repo = repo,
        .parsed_commit = parsed_commit,
        .submodule_path = submodule_path,
        .len_submodule_path = len_submodule_path,
        .archive = archive,
        .mtime = mtime, // second, 
        // there's also git_commit_time_offset(commit), one offset for a minute
        .fd_archive = fd_archive,
        .archive_prefix = archive_prefix,
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
    pr_info("Ended exporting repo '%s' commit %s\n",
        repo->url, parsed_commit->id_hex_string);
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
        int status;
        if (pid) {
            pr_info("Waiting for piper %d to finish...\n", pid);
            r = waitpid(pid, &status, 0);
            if (r != pid) {
                pr_error("Waited piper %d is not the same as %d we've created",
                    r, pid);
                return -1;
            }
            if (status) {
                pr_error("Piper exited with error %d\n", status);
                return -1;
            }
        }
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
    struct config const *const restrict config,
    struct work_directory *const restrict workdir_archives,
    struct work_directory *const restrict workdir_checkouts
) {
    for (unsigned long i = 0; i < config->repos_count; ++i) {
        struct repo const *const restrict repo = config->repos + i;
        for (unsigned long j = 0; j < repo->wanted_objects_count; ++j) {
            struct wanted_object const *const restrict wanted_object = 
                repo->wanted_objects + j;
            if (wanted_object->archive || wanted_object->checkout);
            else continue;
            if (wanted_object_guarantee_symlinks(
                wanted_object, repo, 
                config->archive_suffix, config->len_archive_suffix, 
                workdir_archives->links_dirfd, 
                workdir_checkouts->links_dirfd)) {
                pr_error("Failed to guarantee symlinks for wanted object '%s' "
                    "of repo '%s'\n", wanted_object->name, repo->url);
                return -1;
            }
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
                if (wanted_object->parsed_commit_id == (unsigned long) -1) {
                    pr_error("Commit %s is not parsed yet\n",
                        wanted_object->id_hex_string);
                    return -1;
                }
                if (export_commit(config, repo, 
                    repo->parsed_commits + wanted_object->parsed_commit_id, 
                    wanted_object->archive, wanted_object->checkout)) {
                    pr_error("Failed to export commit %s of repo '%s'\n",
                        wanted_object->id_hex_string, repo->url);
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
    struct config config = CONFIG_INIT;
    int r = -1;
    if (config_read(&config, config_path)) {
        pr_error("Failed to read config\n");
        goto free_config;
    }
    if (config.repos_count == 0) {
        pr_warn("No repos defined, early quit\n");
        r = 0;
        goto free_config;
    }
    struct work_directory workdir_repos, workdir_archives, workdir_checkouts;
    if (work_directories_from_paths(
        &workdir_repos, &workdir_archives, &workdir_checkouts,
        config.dir_repos, config.dir_archives, config.dir_checkouts)) {
        pr_error("Failed to open work directories\n");
        goto free_config;
    }
    pr_info("Initializing libgit2\n");
    git_libgit2_init();
    if ((r = mirror_all_repos(
            &config, &workdir_repos, config.clean_repos))) {
        pr_error("Failed to mirro all repos\n");
        goto shutdown;
    }
    if ((r = export_all_repos(
            &config, &workdir_archives, &workdir_checkouts))) {
        pr_error("Failed to export all repos (archives and checkouts)\n");
        goto shutdown;
    }
    r = 0;
shutdown:
#ifdef DEBUGGING
    pr_info("Current config before shutting down:\n");
    print_config(&config);
#endif
    pr_info("Shutting down libgit2\n");
    git_libgit2_shutdown();
    work_directories_free(
        &workdir_repos, &workdir_archives, &workdir_checkouts);
free_config:
    config_free(&config);
    return r;
}