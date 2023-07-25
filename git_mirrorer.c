#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <unistd.h>
#include <getopt.h>

#include <sys/stat.h>
#include <linux/limits.h>

#include <xxhash.h>
#include <git2.h>

#define BINARY "git_mirrorer"
#define REPOS_DIR "repos"

#ifdef REPO_DIR_HASH_SPLIT
#define REPO_DIR_LEN 24 // repos 5 + xxh3 64-bit 16 + // 2 + null 1
#else
#define REPO_DIR_LEN 23 // repos 5 + xxh3 64-bit 16 + / 1 + null 1
#endif
#define MIRRORS_DIR "mirrors"
#define MIRROR_REMOTE "origin"
#define MIRROR_FETCHSPEC "+refs/*:refs/*"
#define MIRROR_CONFIG "remote."MIRROR_REMOTE".mirror"

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


struct wanted_objects {
    // bool want_commit;
    bool commit;
    git_oid commit_id;
    char commit_id_hex_string[GIT_OID_MAX_HEXSIZE + 1];
    bool all_branches;
    char branch[NAME_MAX];
    bool all_tags;
    char tag[NAME_MAX];
};

char const help_message[] = 
    "Usage:\n"
    "\t"BINARY" [repo url] [commit]";

int clone_or_update(char const *const restrict repo_url, bool const expect_commit, git_oid const *const expected_commit_id);

int repo_url_to_hashed_dir(char const *const restrict repo_url, char repo_dir[REPO_DIR_LEN]) {
    unsigned short repo_url_len = strlen(repo_url);
    if (repo_url_len == 0) {
        pr_warn("Repo url is empty\n");
    }
    XXH64_hash_t repo_url_hash = XXH3_64bits(repo_url, repo_url_len);
    pr_warn("64-bit XXH3 hash of url '%s' is '%016lx'\n", repo_url, repo_url_hash);
#ifdef REPO_DIR_HASH_SPLIT
    if (snprintf(repo_dir, REPO_DIR_LEN, REPOS_DIR"/%02lx/%02lx", 
        (repo_url_hash & 0xFF00000000000000) >> 56,
        repo_url_hash & 0x00FFFFFFFFFFFFFF) < 0) {
#else
    if (snprintf(repo_dir, REPO_DIR_LEN, REPOS_DIR"/%02lx", repo_url_hash) < 0) {
#endif
            pr_error("Failed to generate repo_dir\n");
            return -1;
        }
    pr_warn("repo_dir for repo url '%s' will be '%s'\n", repo_url, repo_dir);
    return 0;
}

// int ensure_dir_sub

/*
int ensure_dir(char *dir_path, unsigned short dir_path_len) {
    struct stat stat_buffer;
    bool revert_slash = false;
    pr_warn("Ensuring '%s' exists and is a folder\n", dir_path);
    for (unsigned short i = 0; i < dir_path_len; ++i) {
        switch (dir_path[i]) {
        case '/':
            revert_slash = true;
            dir_path[i] = '\0';
            __attribute__((fallthrough));
        case '\0':
            if (stat(dir_path, &stat_buffer) == -1) {
                int errno_cache = errno;
                switch (errno_cache) {
                case ENOENT:
                    pr_warn("'%s' does not exist\n", dir_path);
                    if (mkdir(dir_path, 0744) == -1) {
                        pr_error_with_errno("Failed to create folder '%s'", dir_path);
                        return -1;
                    }
                    pr_warn("Created folder '%s'\n", dir_path);
                    break;
                default:
                    pr_error_with_errno("Failed to open '%s'", dir_path);
                    return -1;
                }
            } else if ((stat_buffer.st_mode & S_IFMT) != S_IFDIR) {
                pr_error("Existing '%s' is not a folder", dir_path);
                return -1;
            } else if (stat_buffer.st_uid != getuid() || stat_buffer.st_gid != getgid()) {
                pr_error("Existing '%s' is not owned by the current user\n", dir_path);
                return -1;
            }
            if (revert_slash) dir_path[i] = '/';
            break;
        }
        if (dir_path[i] == '\0') break;
        revert_slash = false;
    }
    return 0;
}
*/

int resolve_head_to_commit(git_commit **commit, git_repository *repository) {
    if (commit == NULL || repository == NULL) {
        pr_error("Empty pointers\n");
        return -1;
    }
    git_reference *refernce;
    if (git_repository_head(&refernce, repository)) {
        pr_error("Failed to get the reference of head\n");
        return -1;
    }
    git_object *object;
    if (git_reference_peel(&object, refernce, GIT_OBJECT_COMMIT)) {
        pr_error("Failed to peel refernce HEAD\n");
        git_reference_free(refernce);
        return -1;
    }
    git_reference_free(refernce);
    if (git_commit_dup(commit, (git_commit *)object)) {
        pr_error("Failed to duplicate object to commit\n");
        git_object_free(object);
        return -1;
    }
    git_object_free(object);
    char oid_string[GIT_OID_MAX_HEXSIZE + 1];
    git_oid_tostr(oid_string, GIT_OID_MAX_HEXSIZE + 1, git_commit_id(*commit));
    pr_warn("Resolved HEAD to commit '%s'\n", oid_string);
    return 0;
}

/*
void generate_symbol_link_from_url(char *link, char const *const url) {
    char *link_current = stpcpy(link, MIRRORS_DIR"/");
    char const *url_no_scheme = url;
    for (char const *c = url; *c; ++c) {
        if (*c == ':' && !strncmp(c, "://", 3)) {
            url_no_scheme = c + 3;
            break;
        }
    }
    for (char const *c = url_no_scheme; *c; ++c) {
        if ((*c == '/' && *(c + 1) != '/') || *c != '/') {
            *(link_current++) = *c;
        }
    }
    *link_current = '\0';
}

int ensure_mirrors_symbol_link(const char *const repo_url, const char *const repo_dir) {
    char link[PATH_MAX];
    snprintf(link, PATH_MAX, MIRRORS_DIR"/%s", repo_url);
    // generate_symbol_link_from_url(link, repo_url);
    pr_warn("Ensuring symbol link at '%s' points to '%s'\n", link, repo_dir);
    struct stat stat_buffer;
    if (lstat(link, &stat_buffer) == -1) {
        int errno_cache = errno;
        if (errno_cache == ENOENT) {
            char link_dup[PATH_MAX];
            memcpy(link_dup, link, PATH_MAX);
            char *sep = NULL;
            for (char *c = link_dup; *c; ++c) {
                if (*c == '/') {
                    sep = c;
                }
            }
            *sep = '\0';
            if (ensure_dir(link_dup, sep - link_dup + 1)) {
                pr_error("Failed to ensure parent folders for link '%s' exists\n", link);
                return -1;
            }
            if (symlink(repo_dir, link) == -1) {
                pr_error_with_errno("Failed to create symlink at '%s' pointing to '%s'", link, repo_dir);
                return -1;
            }
        } else {
            pr_error("Unsolvable error when stating link at '%s', errno %d\n", link, errno_cache);
            return -1;
        }
    }
    char target[PATH_MAX];
    ssize_t target_len = readlink(link, target, PATH_MAX);
    if (target_len == -1) {
        // int errno_cache = errno;
        pr_error_with_errno("Failed to read link at '%s'", link);
        return -1;
    }
    target[target_len] = '\0';
    if (strncmp(target, repo_dir, PATH_MAX)) {
        pr_error("Symbol link at '%s' points to '%s' instead of '%s'\n", link, target, repo_dir);
        return -1;
    }
    return 0;
}
*/


int open_or_create_bare_repo_at(git_repository **repository, const char *const repo_url, const char *const repo_dir) {
    int r = git_repository_open_bare(repository, repo_dir);
    switch (r) {
    case GIT_OK:
        return 0;
    case GIT_ENOTFOUND:
        pr_warn("repo dir '%s' does not exist, trying to create it\n", repo_dir);
        r = git_repository_init(repository, repo_dir, 1);
        if (r < 0) {
            pr_error("Failed to initialize a bare repostitory at '%s', libgit return %d\n", repo_dir, r);
            return -1;
        } else {
            git_remote *remote;
            r = git_remote_create_with_fetchspec(&remote, *repository, MIRROR_REMOTE, repo_url, MIRROR_FETCHSPEC);
            if (r < 0) {
                pr_error("Failed to create remote '"MIRROR_REMOTE"' with fetch spec '"MIRROR_FETCHSPEC"' for url '%s', libgit returns %d\n",
                    repo_url, r);
                git_repository_free(*repository);
                return -1;
            }
            git_config *config;
            r = git_repository_config(&config, *repository);
            if (r < 0) {
                pr_error("Failed to get config for repo for url '%s', libgit return %d\n", repo_url, r);
                git_remote_free(remote);
                git_repository_free(*repository);
                return -1;
            }
            r = git_config_set_bool(config, MIRROR_CONFIG, true);
            if (r < 0) {
                pr_error("Failed to set config '"MIRROR_CONFIG"' to true for repo for url '%s, libgit return %d\n", repo_url, r);
                git_config_free(config);
                git_remote_free(remote);
                git_repository_free(*repository);
                return -1;
            }
            git_config_free(config);
            git_remote_free(remote);
            return 1;
        }
    default:
        pr_error("Failed to open bare repository at '%s' and cannot fix libgit return %d\n", repo_dir, r);
        return -1;
    }
}

struct progress_data {
	git_indexer_progress fetch_progress;
    // struct timespec timespec;   
};

static void print_progress(struct progress_data *const progress_data) {
    // struct timespec timespec;
    // clock_gettime(CLOCK_MONOTONIC, &timespec);
    // if ((timespec.tv_sec - progress_data->timespec.tv_sec) * 1000000000 + 
    //     timespec.tv_nsec - progress_data->timespec.tv_nsec
    //          <= 500000000) {
    //     return;
    // }
    // progress_data->timespec = timespec;

	int network_percent = progress_data->fetch_progress.total_objects > 0 ?
		(100*progress_data->fetch_progress.received_objects) / progress_data->fetch_progress.total_objects :
		0;
	int index_percent = progress_data->fetch_progress.total_objects > 0 ?
		(100*progress_data->fetch_progress.indexed_objects) / progress_data->fetch_progress.total_objects :
		0;

	size_t kbytes = progress_data->fetch_progress.received_bytes / 1024;

	if (progress_data->fetch_progress.total_objects &&
		progress_data->fetch_progress.received_objects == progress_data->fetch_progress.total_objects) {
		printf("Resolving deltas %u/%u\r",
		       progress_data->fetch_progress.indexed_deltas,
		       progress_data->fetch_progress.total_deltas);
	} else {
		printf("net %3d%% (%4zu  kb, %5u/%5u)  /  idx %3d%% (%5u/%5u)\n",
		   network_percent, kbytes,
		   progress_data->fetch_progress.received_objects, progress_data->fetch_progress.total_objects,
		   index_percent, progress_data->fetch_progress.indexed_objects, progress_data->fetch_progress.total_objects);
	}
}

static int sideband_progress(const char *str, int len, void *payload)
{
	(void)payload; /* unused */

	fprintf(stderr, "remote: %.*s", len, str);
	return 0;
}

static int fetch_progress(const git_indexer_progress *stats, void *payload)
{
	struct progress_data *progress_data = (struct progress_data*)payload;
	progress_data->fetch_progress = *stats;
	print_progress(progress_data);
	return 0;
}
// static void checkout_progress(const char *path, size_t cur, size_t tot, void *payload)
// {
// 	progress_data *pd = (progress_data*)payload;
// 	pd->completed_steps = cur;
// 	pd->total_steps = tot;
// 	pd->path = path;
// 	print_progress(pd);
// }

int update_mirror_repo(git_repository *repository, char const *const repo_url) {
    git_remote *remote;
    int r = git_remote_lookup(&remote, repository, MIRROR_REMOTE) < 0;
    if (r) {
        pr_error("Failed to lookup remote '"MIRROR_REMOTE"' from local repo for url '%s', libgit return %d\n", repo_url, r);
        return -1;
    }
    char const *const repo_remote_url = git_remote_url(remote);
    if (strcmp(repo_remote_url, repo_url)) {
        pr_error("Configured remote url is '%s' instead of '%s', give up\n", repo_remote_url, repo_url);
        r = -1;
        goto free_remote;
    }
    git_strarray strarray;
    r = git_remote_get_fetch_refspecs(&strarray, remote);
    if (r < 0) {
        pr_error("Failed to get strarry, libgit return %d\n", r);
        r = -1;
        goto free_strarray;
    }
    if (strarray.count != 1) {
        pr_error("Refspec more than one, refuse to continue\n");
        r = -1;
        goto free_strarray;
    }
    if (strcmp(strarray.strings[0], MIRROR_FETCHSPEC)) {
        pr_error("Fetch spec is '%s' instead of '"MIRROR_FETCHSPEC"', give up\n", strarray.strings[0]);
        r = -1;
        goto free_strarray;
    }
    pr_warn("Begging fetching for '%s'\n", repo_url);
    git_fetch_options fetch_options;
    struct progress_data progress_data = {0};
    // clock_gettime(CLOCK_MONOTONIC, &progress_data.timespec);
    git_fetch_options_init(&fetch_options, GIT_FETCH_OPTIONS_VERSION);
    // fetch_options.proxy_opts.url = "socks5://192.168.7.11:1080";
    fetch_options.proxy_opts.type = GIT_PROXY_SPECIFIED;
	fetch_options.callbacks.sideband_progress = sideband_progress;
    fetch_options.callbacks.transfer_progress = fetch_progress;
    fetch_options.callbacks.payload = &progress_data;
    r = git_remote_fetch(remote, NULL, &fetch_options, NULL);
    if (r) {
        pr_error("Failed to fetch, libgit return %d\n", r);
        r = -1;
        goto free_strarray;
    }
    pr_warn("Ending fetching for '%s'\n", repo_url);
    r = 0;
free_strarray:
    git_strarray_free(&strarray);
free_remote:
    git_remote_free(remote);
    return r;
}

int get_expected_commit_or_head(git_commit **commit, git_repository *const repository, bool const expect_commit, git_oid const *const expected_commit_id) {
    if (expect_commit) {
        if (git_commit_lookup(commit, repository, expected_commit_id)) {
            char git_commit_id[GIT_OID_MAX_HEXSIZE + 1];
            git_oid_fmt(git_commit_id, expected_commit_id);
            git_commit_id[GIT_OID_MAX_HEXSIZE] = '\0';
            pr_warn("Expected commit '%s' does not exist in repo\n", git_commit_id);
            *commit = NULL;
            return 1;
        }
    } else {
        pr_warn("No explicit commit wanted, checking head\n");
        if (resolve_head_to_commit(commit, repository)) {
            pr_warn("Failed to resolve head\n");
            *commit = NULL;
            return 1;
        }
    }
    return 0;
}

int parse_submodule_in_tree(git_tree const *const tree, char const *const path, char const *const url) {
    git_tree_entry *entry;
    if (git_tree_entry_bypath(&entry, tree, path)) {
        pr_error("Path '%s' of submodule does not exist in tree, bad .gitmodules file?\n", path);
        return -1;
    }
    int r = -1;
    if (git_tree_entry_type(entry) != GIT_OBJECT_COMMIT) {
        pr_error("Object at path '%s' in tree is not a commit\n", path);
        goto free_entry;
    }
    git_oid const *const oid = git_tree_entry_id(entry);
    char oid_string[GIT_OID_MAX_HEXSIZE + 1];
    git_oid_tostr(oid_string, GIT_OID_MAX_HEXSIZE + 1, oid);
    pr_warn("Specific commit '%s' is needed for submodule at path '%s' with url '%s'\n", oid_string, path, url);
    if (clone_or_update(url, true, oid)) {
        pr_error("Failed to clone or update submodule at '%s' with url '%s'\n", path, url);
        goto free_entry;
    }
    r = 0;

free_entry:
    git_tree_entry_free(entry);
    return r;
}


int parse_gitmodules_blob(git_blob const *const blob, git_tree const *const tree) {
    char const *const blob_ro_handle = git_blob_rawcontent(blob);
    git_object_size_t blob_size = git_blob_rawsize(blob);
    // char const *submodule_name_ro = NULL;
    char submodule_name[NAME_MAX] = "\0";
    char submodule_path[PATH_MAX] = "\0";
    char submodule_url[PATH_MAX] = "\0";
    for (git_object_size_t id_start = 0; id_start < blob_size; ) {
        switch (blob_ro_handle[id_start]) {
        case '\0':
        case '\n':
        case '\r':
        case '\b':
            ++id_start;
            continue;
        }
        unsigned short line_length = 0;
        git_object_size_t id_end = id_start + 1;
        for (; id_end < blob_size && line_length == 0;) {
            switch (blob_ro_handle[id_end]) {
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
            char const *line = blob_ro_handle + id_start;
            char const *line_end = blob_ro_handle + id_end;
            switch (blob_ro_handle[id_start]) {
            case '[':
                if (!strncmp(line + 1, "submodule \"", 11)) {
                    if (submodule_name[0]) {
                        pr_error("Incomplete submodule definition for '%s'\n", submodule_name);
                        return -1;
                    }
                    char const *submodule_name_start = line + 12;
                    char const *right_quote = submodule_name_start;
                    for (;*right_quote != '"' && right_quote < line_end; ++right_quote);
                    unsigned short submodule_name_len = right_quote - submodule_name_start;
                    strncpy(submodule_name, submodule_name_start, submodule_name_len);
                    submodule_name[submodule_name_len] = '\0';
                }
                break;
            case '\t':
                char const *value = NULL;
                char *submodule_value = NULL;
                if (!strncmp(line + 1, "path = ", 7)) {
                    value = line + 8;
                    submodule_value = submodule_path;
                } else if (!strncmp(line + 1, "url = ", 6)) {
                    value = line + 7;
                    submodule_value = submodule_url;
                }
                if (value) {
                    if (submodule_name[0] == '\0') {
                        pr_error("Submodule definition begins before the submodule name\n");
                        return -1;
                    }
                    if (submodule_value[0] != '\0') {
                        pr_error("Duplicated value definition for submodule '%s'\n", submodule_name);
                        return -1;
                    }
                    unsigned short value_len = line_end - value;
                    strncpy(submodule_value, value, value_len);
                    submodule_value[value_len] = '\0';
                    if (submodule_path[0] != '\0' && submodule_url[0] != '\0') {
                        pr_warn("Submodule '%s', path '%s', url '%s'\n", submodule_name, submodule_path, submodule_url);
                        if (parse_submodule_in_tree(tree, submodule_path, submodule_url)) {
                            pr_error("Failed to recursively clone or update submodule '%s' (url '%s')\n", submodule_name, submodule_url);
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

int parse_commit_submodules(git_commit const *const commit, git_repository *const repository) {
    git_tree *tree;
    if (git_commit_tree(&tree, commit)) {
        pr_error("Failed to get the tree pointed by commit\n");
        return -1;
    }
    int r = 0;
    git_tree_entry *entry = NULL;
    git_object *object = NULL;
    if (git_tree_entry_bypath(&entry, tree, ".gitmodules") == 0 && git_tree_entry_type(entry) == GIT_OBJECT_BLOB) {
        char oid_string[GIT_OID_MAX_HEXSIZE + 1];
        git_oid_tostr(oid_string, GIT_OID_MAX_HEXSIZE + 1, git_commit_id(commit));
        pr_warn(".gitmodules exists in the tree pointed by commit '%s' and is a blob, solving submodules\n", oid_string);
        r = git_tree_entry_to_object(&object, repository, entry);
        if (r) {
            pr_error("Failed to convert tree entry of .gitmodules to object, libgit return %d\n", r);
            r = -1;
            goto free_tree_entry;
        }
        if (git_object_type(object) != GIT_OBJECT_BLOB) {
            pr_error("Converted object type is not blob\n");
            r = -1;
            goto free_object;
        }
        git_blob *blob = (git_blob *)object;
        if (parse_gitmodules_blob(blob, tree)) {
            pr_error("Failed to parse the gitmodules blob\n");
            r = -1;
            goto free_object;
        }
    } else {
        entry = NULL;
    }
    r = 0;
free_object:
    if (object) git_object_free(object);
free_tree_entry:
    if (entry) git_tree_entry_free(entry);
    git_tree_free(tree);
    return r;
}

void print_command_mirror_clone(char const *const repo_dir) {
    printf(
        "git clone git://git.lan/mirrors/%s\n"
        "cd %s\n",
            repo_dir, repo_dir
    );
}

int clone_or_update(char const *const restrict repo_url, bool const expect_commit, git_oid const *const expected_commit_id) {
    char oid_string[GIT_OID_MAX_HEXSIZE + 1];
    if (expect_commit) {
        git_oid_tostr(oid_string, GIT_OID_MAX_HEXSIZE + 1, expected_commit_id);
        pr_warn("Trying to clone/update '%s', expecting commit '%s'\n", repo_url, oid_string);
    } else {
        pr_warn("Trying to clone/update '%s', no expecting commit, will only look up HEAD\n", repo_url);
    }
    char repo_dir[REPO_DIR_LEN];
    if (repo_url_to_hashed_dir(repo_url, repo_dir)) {
        pr_error("Cannot decide repo_dir for url '%s', refuse to continute\n", repo_url);
        return -1;
    }
    git_repository *repository;
    int r = open_or_create_bare_repo_at(&repository, repo_url, repo_dir);
    if (r < 0) {
        pr_error("Failed to open or create bare repo at '%s' for url '%s'\n", repo_dir, repo_url);
        return -1;
    }
    bool need_update = r > 0;
    git_commit *commit = NULL;
    if (!need_update) {
        if (get_expected_commit_or_head(&commit, repository, expect_commit, expected_commit_id)) {
            pr_warn("Failed to find expected oid or head, need to update\n");
            need_update = true;
        }
    }
    if (need_update) {
        if (update_mirror_repo(repository, repo_url)) {
            pr_error("Failed to update mirror repo");
            r = -1;
            goto free_commit;
        }
    }
    if (!commit) {
        if (get_expected_commit_or_head(&commit, repository, expect_commit, expected_commit_id)) {
            pr_warn("Failed to find expectet commit or head even after update, refuse to contonie\n");
            r = -1;
            goto free_commit;
        }
    }
    if (parse_commit_submodules(commit, repository)) {
        pr_error("Failed to parse submodules of commit\n");
    }
    r = 0;
free_commit:
    if (commit) {
        git_commit_free(commit);
    }
// free_repository:
    git_repository_free(repository);
    return r;
}

int main(int const argc, char *const argv[]) {
    struct option const long_options[] = {
        {"commit",          required_argument,  NULL,   'c'},
        {"branch",          required_argument,  NULL,   'b'},
        {"all-branches",    no_argument,        NULL,   'B'},
        {"tag",             required_argument,  NULL,   't'},
        {"all-tags",        no_argument,        NULL,   'T'},
        {"proxy",           required_argument,  NULL,   'p'},
        {"proxy-after",     required_argument,  NULL,   'P'},
        {"help",            no_argument,        NULL,   'h'},
        {"version",         no_argument,        NULL,   'V'},
        {0},
    };
    int c, option_index = 0;
    struct wanted_objects wanted_objects = {0};
    char proxy_url[PATH_MAX] = "\0";
    unsigned short proxy_after = 0;
    while ((c = getopt_long(argc, argv, "c:b:Bt:Tp:P:hV", long_options, &option_index)) != -1) {
        switch (c) {
        case 'c':
            if (git_oid_fromstr(&wanted_objects.commit_id, optarg)) {
                pr_error("Failed to convert '%s' to git commit id\n", optarg);
                return -1;
            }
            strncpy(wanted_objects.commit_id_hex_string, optarg, GIT_OID_MAX_HEXSIZE + 1);
            wanted_objects.commit = true;
            break;
        case 'b':
            strncpy(wanted_objects.branch, optarg, NAME_MAX);
            break;
        case 'B':
            wanted_objects.all_branches = true;
            break;
        case 't':
            strncpy(wanted_objects.tag, optarg, NAME_MAX);
            break;
        case 'T':
            wanted_objects.all_tags = true;
            break;
        case 'p':
            strncpy(proxy_url, optarg, PATH_MAX);
            break;
        case 'P':
            proxy_after = strtoul(optarg, NULL, 10);
            break;
        case 'h':
            fputs(help_message, stderr);
            return 0;
        case 'V':
            fputs("unknown", stderr);
            return 0;
        default:
            pr_error("Impossible result from getopt: %d\n", c);
            return -1;
        }
    }
    if (optind >= argc) {
        pr_error("Expected argument for repo url\n");
    }
    char const *const repo_url = argv[optind];
    pr_warn("Repo url is '%s', wanting commit: %s%s%s, wanting branch: %s%s%s, wanting all branches: %s, wanting tag: %s%s%s, wanting all tags: %s, using proxy: %s%s%s, using proxy after %hu failures\n", 
        repo_url,
        wanted_objects.commit ? "yes ('" : "no",
        wanted_objects.commit_id_hex_string,
        wanted_objects.commit ? "')" : "",
        wanted_objects.branch[0] ? "yes ('" : "no",
        wanted_objects.branch,
        wanted_objects.branch[0] ? "')" : "",
        wanted_objects.all_branches ? "yes" : "no",
        wanted_objects.tag[0] ? "yes ('" : "no",
        wanted_objects.tag,
        wanted_objects.tag[0] ? "')" : "",
        wanted_objects.all_tags ? "yes" : "no",
        proxy_url[0] ? "yes ('" : "no",
        proxy_url,
        proxy_url[0] ? "')" : "",
        proxy_after
    );
    git_fetch_options fetch_options = { 
        .version = GIT_FETCH_OPTIONS_VERSION, 
        .callbacks = GIT_REMOTE_CALLBACKS_INIT,
        .prune = GIT_FETCH_PRUNE_UNSPECIFIED, 
        .update_fetchhead = 1,
        .download_tags = GIT_REMOTE_DOWNLOAD_TAGS_UNSPECIFIED, 
        .proxy_opts = GIT_PROXY_OPTIONS_INIT,
        0,
    };
    if (proxy_url[0]) {
        fetch_options.proxy_opts.url = proxy_url;
        fetch_options.proxy_opts.type = GIT_PROXY_SPECIFIED;
    }
	fetch_options.callbacks.sideband_progress = sideband_progress;
    fetch_options.callbacks.transfer_progress = fetch_progress;
    git_libgit2_init();

    // clone_or_update(argv[1], argc == 3, &wanted_objects.commit_id);
    git_libgit2_shutdown();
    return 0;
}