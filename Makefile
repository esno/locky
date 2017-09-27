all: locky

locky:
	${CC} -o locky src/locky.c

clean:
	rm -f locky
