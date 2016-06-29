COMPILER = gcc
CFLAGS = -Wall -pedantic
LIBS = -lcrypto

EXES = decrypt_ciphertext generate_ciphertext search_keyspace

all: ${EXES}

decrypt_ciphertext: src/decrypt_ciphertext.c
	${COMPILER} -g -o decrypt_ciphertext src/decrypt_ciphertext.c ${LIBS}

generate_ciphertext:	src/generate_ciphertext.c
	${COMPILER} -g -o generate_ciphertext src/generate_ciphertext.c ${LIBS}

search_keyspace:	src/search_keyspace.c
	${COMPILER} -g -o search_keyspace src/search_keyspace.c ${LIBS}

clean:
	rm -f *~ *.o ${EXES}
