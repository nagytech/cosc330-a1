generate: 	src/generate_ciphertext.c src/search_keyspace.c
	gcc -g -o decrypt_ciphertext src/decrypt_ciphertext.c -lcrypto
	gcc -g -o generate_ciphertext src/generate_ciphertext.c -lcrypto
	gcc -g -o search_keyspace src/search_keyspace.c -lcrypto



