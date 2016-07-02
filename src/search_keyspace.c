#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAX_KEY_LENGTH 32
#define CIPHER_LENGTH 32
#define MAX_BUFFER 4096

int make_trivial_ring() {
  int   fd[2];
  if (pipe (fd) == -1)
    return(-1);
  if ((dup2(fd[0], STDIN_FILENO) == -1) ||
      (dup2(fd[1], STDOUT_FILENO) == -1))
    return(-2);
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
    return(-3);
  return(0);
}

int add_new_node(int *pid){
  int fd[2];
  if (pipe(fd) == -1)
    return(-1);
  if ((*pid = fork()) == -1)
    return(-2);
  /*
  extern void _start (void), etext (void);
  monstartup ((unsigned long) &_start, (unsigned long) &etext);
  */
  if(*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0)
    return(-3);
  if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0)
    return(-4);
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
    return(-5);
  return(0);
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext,
  int *len)
{
  int p_len = *len;
  int f_len = 0;

  unsigned char *plaintext = malloc(p_len);

  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

  return plaintext;
}

int aes_init(unsigned char *key_data, int key_data_len,
  EVP_CIPHER_CTX *d_ctx){

  int i;
  unsigned char key[MAX_KEY_LENGTH];

  if(key_data_len > MAX_KEY_LENGTH) key_data_len = MAX_KEY_LENGTH;

  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key_data, key_data);

  return 0;

}

void bump_key(unsigned char* trialkey, unsigned long keyLowBits, int iteration,
  int missingBytes) {

  unsigned long trialLowBits = keyLowBits | iteration;

  for (int i = 0; i < missingBytes; i++) {
    int index = MAX_KEY_LENGTH - i - 1;
    //printf("Key bump index: %d\n", index);
    char bumpChar = (unsigned char) (trialLowBits >> i * 8);
    //printf("Key bump char: %c\n", index);
    trialkey[MAX_KEY_LENGTH - i - 1] = (unsigned char) (trialLowBits >> (i * 8));
  }

}

void read_file(char *name, void *buffer, int length) {

  FILE *file;
  file=fopen(name, "r");

  if (file == NULL) {
   //fprintf(stderr, "Could not open file: %s", name);
   exit(EXIT_FAILURE);
  }

  fread(buffer, length, 1, file);
  fclose(file);

}

int parse_args(int argc, char **argv, int *numnodes, unsigned char **key_data,
  int *key_data_len) {

    *numnodes = atoi(argv[1]);
    *key_data = (unsigned char *)argv[2];
    *key_data_len = strlen(argv[2]);
    if(*key_data_len > MAX_KEY_LENGTH) {
      *key_data_len = MAX_KEY_LENGTH;
    }

    return 1;

}

int try_solve(char *keybase, int key_length, char *cipher_in, int cipher_length,
   char *plain_in, int missingBytes, unsigned long seed,
   unsigned long keyLowBits) {

  unsigned char trialkey[MAX_KEY_LENGTH];
  int trial_key_length = key_length;

  for (int i = 0; i < key_length; i++) {
    trialkey[i] = keybase[i];
  }

  unsigned long trialLowBits = keyLowBits | seed;

  // TODO: Use bump key

  for (int i = 0; i < missingBytes; i++) {
    int index = MAX_KEY_LENGTH - i - 1;
    //printf("Key bump index: %d\n", index);
    char bumpChar = (unsigned char) (trialLowBits >> (i * 8));
    //printf("Key bump char: %c\n", bumpChar);
    trialkey[MAX_KEY_LENGTH - i - 1] = (unsigned char) (trialLowBits >> (i * 8));
  }

	EVP_CIPHER_CTX de;

	if (aes_init(trialkey, trial_key_length, &de)) {
  	   printf("Couldn't initialize AES cipher\n");
  	   return -1;
	}

	char *plaintext = (char *)aes_decrypt(&de, (unsigned char *)cipher_in,
    &cipher_length);

  EVP_CIPHER_CTX_cleanup(&de);

  // TODO: compare length, then compare length of plain in (iff equal length)
  if (!strncmp(plaintext, plain_in, 10)) {

	fprintf(stderr, "\nOK: enc/dec ok for \"%s\"\n", plaintext);
	fprintf(stderr, "Key No.:%lu:", seed);

		for(int y = 0; y < MAX_KEY_LENGTH; y++) {
     fprintf(stderr, "%c", trialkey[y]);
    }
   fprintf(stderr, "\n");

    kill(0, SIGTERM);
    exit(0);

    return 1;

	} else {

    //fprintf(stderr, "Seed %lu Failed\n", seed);
    return -1;

  }
}

int signal_handler(int signum) {

   fprintf(stderr, "%d exiting", nodeid);

   exit(0);
/*
  unsigned char buffer[33];
  int le = 32;

  read(STDIN_FILENO, buffer, 32);

  if (nodeid == 1 && buffer[0] != '\0') {

    buffer[32] = '\0';

    for (int i = 0; i < 32; i++) {
      fprintf(stderr, "%c", buffer[i]);
    }
    fprintf(stderr, "\n");

    exit(0);
  }

  write(STDOUT_FILENO, buffer, 32);

  if (nodeid != 1) {
    exit(0);
  }
*/

}

int nodeid;
int main(int argc, char **argv)
{

  signal(SIGTERM, signal_handler); 

  /* Parse arguments */
  int numnodes, key_data_len;
  unsigned char *key_data;

  if (parse_args(argc, argv, &numnodes, &key_data, &key_data_len) < 0) {
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

  unsigned char cipher_in[MAX_BUFFER];
  read_file("./data/cipher.txt", &cipher_in, MAX_BUFFER);
  int cipher_length = strlen((char*)cipher_in);

  char plain_in[MAX_BUFFER];
  read_file("./data/plain.txt", &plain_in, MAX_BUFFER);
  int plain_length = strlen((char*)plain_in);

  /* Copy key and pad with zeros */

  unsigned char key[MAX_KEY_LENGTH];

  for (int i = 0; i < key_data_len; i++) {
   key[i] = key_data[i];
  }

  for (int i = key_data_len; i < MAX_KEY_LENGTH; i++){
   key[i] = 0;
  }

  unsigned long keyLowBits = 0;

  for (int i = 0; i < missingBytes; i++) {
    int index = MAX_KEY_LENGTH - (missingBytes - 1) - 1;
    //printf("Key bump index: %d\n", index);
    keyLowBits |= ((unsigned long)(key[index] & 0xFFFF) << (missingBytes - i) * 8);
  }

  // TODO: Iterate dynamically
  //keyLowBits = ((unsigned long)((unsigned long)(key[29] & 0xFFFF)<< 16)|
  	//((unsigned long)(key[30] & 0xFFFF)<< 8)|
  	//((unsigned long)(key[31] & 0xFFFF)));

  unsigned long maxSpace = 0;

  maxSpace = ((unsigned long)1 << ((MAX_KEY_LENGTH - key_data_len)*8))-1;

  printf("Max space: %lu\n", maxSpace);

  if(make_trivial_ring() < 0) {
    perror("Could not make trivial ring");
    exit(EXIT_FAILURE);
  }

  int childpid;
  for (nodeid = 1; nodeid < numnodes; nodeid++) {

    if(add_new_node(&childpid) < 0){
      perror("Could not add new node to ring");
      exit(EXIT_FAILURE);
    }

    if (childpid) {
     break;
    }

  }

 //fprintf(stderr, "Init: node %d of %d\n", nodeid, numnodes);

  if (nodeid == 1) {
    char buffer[MAX_BUFFER];
    //fprintf(stderr, "Master initialized\n");
    //write(STDOUT_FILENO, "", MAX_BUFFER);
    if (try_solve(key, MAX_KEY_LENGTH, cipher_in, cipher_length, plain_in, missingBytes, 0, keyLowBits) > 0) {
      exit(0);
    }
    unsigned long seed = (unsigned long)nodeid;
    while (seed <= maxSpace) {

      //if (seed % 10000 < numnodes)
     //fprintf(stderr, "Attempting seed: %lu\n", seed);

      //fprintf(stderr, "Master writing\n");
      //write(STDOUT_FILENO, "ok", MAX_BUFFER);
        if (try_solve(key, MAX_KEY_LENGTH, cipher_in, cipher_length, plain_in, missingBytes, seed, keyLowBits) > 0) {
         kill(0, SIGTERM);
         break;
        }
        seed += (unsigned long)numnodes;
      //fprintf(stderr, "Master waiting to read\n");
      //read(STDIN_FILENO, buffer, MAX_BUFFER);
    }
  } else {
    unsigned long seed = nodeid;
    while (seed <= maxSpace) {
      char buffer[MAX_BUFFER];
        if (try_solve(key, MAX_KEY_LENGTH, cipher_in, cipher_length, plain_in, missingBytes, seed, keyLowBits) > 0) {
	  kill(0, SIGTERM);
     break;
        }
        seed += numnodes;
      }
  }

}
