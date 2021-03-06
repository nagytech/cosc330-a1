COMPILER = gcc
INCLUDES =
#if __APPLE__
  INCLUDES = -I/usr/local/Cellar/openssl/1.0.2a-1/include/
#endif

CFLAGS = -Wall -pedantic

LIBS = -lcrypto

EXES = decrypt_ciphertext generate_ciphertext search_keyspace psk


all: ${EXES}


debug: CFLAGS += -DDEBUG -g -pg
debug: all


decrypt_ciphertext: src/decrypt_ciphertext.c
	${COMPILER} ${INCLUDES} ${CFLAGS} -o decrypt_ciphertext src/decrypt_ciphertext.c ${LIBS}

generate_ciphertext:	src/generate_ciphertext.c
	${COMPILER} ${INCLUDES} ${CFLAGS} -o generate_ciphertext src/generate_ciphertext.c ${LIBS}

search_keyspace:	src/search_keyspace.c
	${COMPILER} ${INCLUDES} ${CFLAGS} -o search_keyspace src/search_keyspace.c ${LIBS}

psk:	src/parallel_search_keyspace.c
		${COMPILER} ${INCLUDES} ${CFLAGS} -o psk src/parallel_search_keyspace.c ${LIBS}


clean:
	rm -f *~ *.o ${EXES}
