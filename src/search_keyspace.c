#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAX_KEY_LENGTH 32
#define CIPHER_LENGTH 32

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  int p_len = *len;
  int f_len = 0;

  unsigned char *plaintext = malloc(p_len);

  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

  return plaintext;
}

int aes_init(unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx){

  int i;
  unsigned char key[MAX_KEY_LENGTH], iv[MAX_KEY_LENGTH];

  // Only use most significant 32 bytes of data if > 32 bytes
  if(key_data_len > MAX_KEY_LENGTH) key_data_len = MAX_KEY_LENGTH;

  // Copy bytes to the front of the key array
  for (i = 0; i < key_data_len; i++){
     key[i] = key_data[i];
     iv[i] = key_data[i];
  }

  for (i = key_data_len; i < MAX_KEY_LENGTH; i++){
     key[i] = 0;
     iv[i] = 0;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;

}

void bump_key(unsigned char* trialkey, unsigned long keyLowBits, int iteration, int missingBytes) {

  unsigned long trialLowBits = keyLowBits | iteration;

  for (int i = 0; i < missingBytes; i++) {
    int index = MAX_KEY_LENGTH - i - 1;
    printf("Key bump index: %d\n", index);
    char bumpChar = (unsigned char) (trialLowBits >> i * 8);
    printf("Key bump char: %c\n", index);
    trialkey[MAX_KEY_LENGTH - i - 1] = (unsigned char) (trialLowBits >> (i * 8));
  }

}

void read_file(char *name, void *buffer, int length) {

  FILE *file;
  file=fopen(name, "r");

  if (file == NULL) {
   fprintf(stderr, "Could not open file: %s", name);
   exit(EXIT_FAILURE);
  }

  fread(buffer, length, 1, file);
  fclose(file);

}

int parse_args(int argc, char **argv, int *numprocs, unsigned char **key_data, int *key_data_len) {

    *numprocs = atoi(argv[1]);
    *key_data = (unsigned char *)argv[2];
    *key_data_len = strlen(argv[2]);
    if(*key_data_len > MAX_KEY_LENGTH) {
      *key_data_len = MAX_KEY_LENGTH;
    }

    return 1;

}

int main(int argc, char **argv)
{
  /* Parse arguments */
  int numprocs, key_data_len;
  unsigned char *key_data;

  if (parse_args(argc, argv, &numprocs, &key_data, &key_data_len) < 0) {
    exit(-1);
  }

  printf("STARTKEY[[");
  for(int y = 0; y < key_data_len; y++) {
    printf("%c", key_data[y]);
  }
  printf("]]ENDKEY\n");

  printf("Key Data Length: %d\n", key_data_len);

  /* Perform some auxiliary calculations */
  int missingBytes = MAX_KEY_LENGTH - key_data_len;
  printf("Missing Bytes: %d\n", missingBytes);

  /* Read in files */

  unsigned char cipher_in[4096];
  read_file("./data/cipher.txt", &cipher_in, 4096);
  int cipher_length = strlen((char*)cipher_in);

  char plain_in[4096];
  read_file("./data/plain.txt", &plain_in, 4096);
  int plain_length = strlen((char*)plain_in);

  /* Copy key and pad with zeros */

  unsigned char key[MAX_KEY_LENGTH], trialkey[MAX_KEY_LENGTH];

  for (int i = 0; i < key_data_len; i++) {
   key[i] = key_data[i];
   trialkey[i] = key_data[i];
  }

  for (int i = key_data_len; i < MAX_KEY_LENGTH; i++){
   key[i] = 0;
   trialkey[i] = 0;
  }


  unsigned long keyLowBits = 0;

  // TODO: Iterate dynamically
  keyLowBits = ((unsigned long)((unsigned long)(key[29] & 0xFFFF)<< 16)|
  	((unsigned long)(key[30] & 0xFFFF)<< 8)|
  	((unsigned long)(key[31] & 0xFFFF)));

  int trial_key_length = MAX_KEY_LENGTH;
  unsigned long maxSpace = 0;

  maxSpace = ((unsigned long)1 << ((trial_key_length - key_data_len)*8))-1;

  printf("Max space: %lu\n", maxSpace);

  for(unsigned long c=0; c < maxSpace ; c++){

    unsigned long trialLowBits = keyLowBits | c;

    for (int i = 0; i < missingBytes; i++) {
      int index = MAX_KEY_LENGTH - i - 1;
      //printf("Key bump index: %d\n", index);
      char bumpChar = (unsigned char) (trialLowBits >> i * 8);
      //printf("Key bump char: %c\n", bumpChar);
      trialkey[MAX_KEY_LENGTH - i - 1] = (unsigned char) (trialLowBits >> (i * 8));
    }

    

    //exit(-1);

  	EVP_CIPHER_CTX en, de;

  	if (aes_init(trialkey, trial_key_length, &en, &de)) {
    	   printf("Couldn't initialize AES cipher\n");
    	   return -1;
  	}

  	char *plaintext = (char *)aes_decrypt(&de, (unsigned char *)cipher_in,
      &cipher_length);

    EVP_CIPHER_CTX_cleanup(&en);
    EVP_CIPHER_CTX_cleanup(&de);

    int y;

    if (!strncmp(plaintext, plain_in, 28)) {

  		printf("\nOK: enc/dec ok for \"%s\"\n", plaintext);
  		printf("Key No.:%lu:", c);

  		for(y = 0; y < MAX_KEY_LENGTH; y++) {
        printf("%c", trialkey[y]);
      }

      printf("\n");

      break;

		} else {



    }



  }

}
