BINARY = git_mirrorer

${BINARY}: ${BINARY}.c
	${CC} -o $@ -g -Wall -Wextra -lxxhash -lgit2 $^

.PHONY: clean

clean:
	rm -f ${BINARY}