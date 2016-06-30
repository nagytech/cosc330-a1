#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int aes_init(unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx,
	EVP_CIPHER_CTX *d_ctx)
{

	int i;
	unsigned char key[32], iv[32];

	//Only use most significant 32 bytes of data if > 32 bytes
	if(key_data_len > 32) key_data_len =32;

	//Copy bytes to the front of the key array
	for (i = 0; i < key_data_len; i++) {
		 key[i] = key_data[i];
		 iv[i] = key_data[i];
	}

	//If the key data < 32 bytes, pad the remaining bytes with 0s
	for (i = key_data_len; i < 32; i++) {
		 key[i] = 0;
		 iv[i] = 0;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return 0;

}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext,
	int *len)
{
	// plaintext will always be equal to or lesser than length of ciphertext*
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}

int main(int argc, char **argv) {

		/* "opaque" encryption, decryption ctx structures that libcrypto uses to
		record status of enc/dec operations */
		EVP_CIPHER_CTX en, de;

		unsigned char *key_data;
		int	key_data_len;
		char *plaintext;

		/* the key_data is read from the argument list */
		key_data = (unsigned char *)argv[1];
		key_data_len = strlen(argv[1]);

		printf("This is the key: %s \n", key_data);
		printf("It is %d bytes in length\n", key_data_len);

		if (aes_init(key_data, key_data_len,	&en, &de)) {
				printf("Couldn't initialize AES cipher\n");
				return -1;
		}

		FILE *myfile;
		myfile=fopen("./data/cipher.txt", "r");
		if (myfile == NULL) {
				printf("Could not read from file ./data/cipher.txt");
				return -1;
		}

		unsigned char cipher_in[4096];
		fread(cipher_in, 32, 1, myfile);

		printf("Ciphertext: %s \n\n", (char*)cipher_in);

		int cipher_length = 32 ;

		plaintext = (char *)aes_decrypt(&de, (unsigned char *)cipher_in,
			&cipher_length);

		printf("Plaintext: %s \n\n", plaintext);

}
