BINARY = git-mirrorer
CFLAGS = -Wall -Wextra 
LDFLAGS = 
STRIP ?= strip

ifdef DEBUGGING
CFLAGS += -DDEBUGGING -g
else
CFLAGS += -O3
endif

ifndef VERSION
VERSION=$(shell ./version.sh)
endif


# The normal, non-static routine
ifndef STATIC
LDFLAGS += -lxxhash -lgit2 -lyaml
${BINARY}: ${BINARY}.c
	${CC} -o $@ -DVERSION=\"${VERSION}\" ${CFLAGS} ${LDFLAGS} $^
ifndef DEBUGGING
	$(STRIP) $@
endif

# The complex static routine, we do it in one go, no middle object, for best optimization
else # STATIC
# Yes, I know things will become a lot easier if we use each dep's own making routine
# to compile them into libraries first, but I just want a static binary and don't want
# any cross-object calling penalty
all: ${BINARY}
# YAML library
YAML_MAJOR=0
YAML_MINOR=2
YAML_PATCH=5
YAML_VERSION=${YAML_MAJOR}.${YAML_MINOR}.${YAML_PATCH}
_YAML_SRCS = api dumper emitter loader parser reader scanner writer
YAML_SRCS = $(patsubst %,deps/yaml-${YAML_VERSION}/src/%.c,${_YAML_SRCS})
# deps/yaml-${YAML_VERSION}/src/%.c:
CFLAGS += 	-Ideps/yaml-${YAML_VERSION}/include \
			-DYAML_VERSION_MAJOR=${YAML_MAJOR} \
		    -DYAML_VERSION_MINOR=${YAML_MINOR} \
			-DYAML_VERSION_PATCH=${YAML_PATCH} \
			-DYAML_VERSION_STRING=\"${YAML_VERSION}\"

_GIT_SRCS = annotated_commit apply attr attr_file attrcache blame blame_git blob branch buf cache checkout cherrypick clone commit commit_graph commit_list config config_cache config_entries config_file config_mem config_parse config_snapshot crlf delta describe diff diff_driver diff_file diff_generate diff_parse diff_print diff_stats diff_tform diff_xdiff email errors fetch fetchhead filter grafts graph hashsig ident idxmap ignore index indexer iterator libgit2 mailmap merge merge_driver merge_file message midx mwindow notes object object_api odb odb_loose odb_mempack odb_pack offmap oid oidarray oidmap pack-objects pack parse patch patch_generate patch_parse path pathspec proxy push reader rebase refdb refdb_fs reflog refs refspec remote reset revert revparse revwalk signature stash status strarray streams/mbedtls streams/openssl streams/openssl_dynamic streams/openssl_legacy streams/registry streams/schannel streams/socket streams/stransport streams/tls submodule sysdir tag threadstate trace trailer transaction transport transports/auth transports/auth_gssapi transports/auth_ntlmclient transports/auth_sspi transports/credential transports/credential_helpers transports/git transports/http transports/httpclient transports/local transports/smart transports/smart_pkt transports/smart_protocol transports/ssh transports/winhttp tree-cache tree worktree repository
GIT_SRCS = $(patsubst %,deps/libgit2-1.7.1/src/libgit2/%.c,${_GIT_SRCS})
CFLAGS += -Ideps/libgit2-1.7.1/include/git2

DEP_SRCS = ${YAML_SRCS} ${GIT_SRCS}

${DEP_SRCS}: 
	./prepare_deps.sh

${BINARY}: ${BINARY}.c ${DEP_SRCS}
	${CC} -o $@ -static -DVERSION=\"${VERSION}\" ${CFLAGS} $^
ifndef DEBUGGING
	$(STRIP) $@
endif


endif #STATIC


.PHONY: clean all

clean:
	rm -f ${BINARY}