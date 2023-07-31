BINARY = git-mirrorer

${BINARY}: ${BINARY}.c
	${CC} -o $@ -g -Wall -Wextra -lxxhash -lgit2 -lyaml $^

.PHONY: clean

clean:
	rm -f ${BINARY}