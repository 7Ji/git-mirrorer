BINARY = git-mirrorer
CFLAGS = -Wall -Wextra
LDFLAGS = -lxxhash -lgit2 -lyaml
STRIP ?= strip

ifdef DEBUGGING
CFLAGS += -DDEBUGGING -g
else
CFLAGS += -O3
endif

ifndef VERSION
VERSION=$(shell ./version.sh)
endif

ifdef BUILD_DEPS
LDFLAGS += -Llib
else
LDFLAGS += 
endif

all: ${BINARY}

XXHASH_VER = 0.8.2
XXHASH_DIR = deps/xxhash-${XXHASH_VER}
XXHASH_LIB = libxxhash.so.${XXHASH_VER}
XXHASH_LNK = lib/libxxhash.so
XXHASH_SRC = lib/${XXHASH_LIB}
XXHASH_BLD = ${XXHASH_DIR}/${XXHASH_LIB}
${XXHASH_BLD}: | prepare_deps
	make -C ${XXHASH_DIR} DISPATCH=1 ${XXHASH_LIB}
${XXHASH_SRC}: ${XXHASH_BLD} | mkdirs
	install -m 755 $< $@
${XXHASH_LNK}: ${XXHASH_SRC}
	ln -s ${XXHASH_LIB} $@

YAML_DIR = deps/yaml-0.2.5
YAML_LIB = libyaml-0.so.2.0.9
YAML_LNK = lib/libyaml.so
YAML_SRC = lib/${YAML_LIB}
YAML_BLD = ${YAML_DIR}/src/.libs/${YAML_LIB}
${YAML_BLD}: | prepare_deps
	cd ${YAML_DIR} && \
	./configure --prefix=/usr
	make -C ${YAML_DIR}
${YAML_SRC}: ${YAML_BLD} | mkdirs
	install -m 755 $< $@
${YAML_LNK}: ${YAML_SRC}
	ln -s ${YAML_LIB} $@

GIT2_DIR = deps/libgit2-1.7.1
GIT2_LIB = libgit2.so.1.7.0
GIT2_LNK = lib/libgit2.so
GIT2_SRC = lib/${GIT2_LIB}
GIT2_BLD = ${GIT2_DIR}-build/${GIT2_LIB}
${GIT2_BLD}: | prepare_deps
	cmake 	-S ${GIT2_DIR} \
			-B ${GIT2_DIR}-build \
			-DCMAKE_BUILD_TYPE=None \
			-DCMAKE_INSTALL_PREFIX=/usr \
			-DREGEX_BACKEND=pcre2 \
			-DUSE_HTTP_PARSER=system \
			-DUSE_SSH=ON \
			-Wno-dev
	cmake --build ${GIT2_DIR}-build --verbose
${GIT2_SRC}: ${GIT2_BLD} | mkdirs
	install -m 755  $< $@
${GIT2_LNK}: ${GIT2_SRC}
	ln -s ${GIT2_LIB} $@

DEP_LNKS = ${XXHASH_LNK} ${YAML_LNK} ${GIT2_LNK}

mkdirs:
	mkdir -p lib

prepare_deps: 
	./prepare_deps.sh

ifdef BUILD_DEPS
CFLAGS += -I${GIT2_DIR}/include -I${XXHASH_DIR} -I${YAML_DIR}
${BINARY}: ${BINARY}.c ${DEP_LNKS}
else
${BINARY}: ${BINARY}.c
endif
	${CC} -o $@ -DVERSION=\"${VERSION}\" ${CFLAGS} ${LDFLAGS} $^
ifndef DEBUGGING
	$(STRIP) $@
endif


.PHONY: clean all prepare_deps mkdirs

clean:
	rm -f ${BINARY}