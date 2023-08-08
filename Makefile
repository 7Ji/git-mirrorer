BINARY = git-mirrorer
CFLAGS = -g -Wall -Wextra 
LDFLAGS = -lxxhash -lgit2 -lyaml

ifdef DEBUGGING
CFLAGS += -DDEBUGGING
endif

${BINARY}: ${BINARY}.c
	${CC} -o $@ -DVERSION=\"$(shell ./version.sh)\" ${CFLAGS} ${LDFLAGS} $^

.PHONY: clean

clean:
	rm -f ${BINARY}