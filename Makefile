BINARY = git-mirrorer
CFLAGS = -Wall -Wextra 
LDFLAGS = -lxxhash -lgit2 -lyaml
STRIP ?= strip

ifdef DEBUGGING
CFLAGS += -DDEBUGGING -g
endif

${BINARY}: ${BINARY}.c
	${CC} -o $@ -DVERSION=\"$(shell ./version.sh)\" ${CFLAGS} ${LDFLAGS} $^
ifndef DEBUGGING
	$(STRIP) $@
endif

.PHONY: clean

clean:
	rm -f ${BINARY}