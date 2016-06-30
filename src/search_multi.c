#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAX_BUFFER 4096

int aes_init(unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx){

  int i;
  unsigned char key[32], iv[32];

  // Only use most significant 32 bytes of data if > 32 bytes
  if(key_data_len > 32) key_data_len =32;

  // Copy bytes to the front of the key array
  for (i = 0; i < key_data_len; i++){
     key[i] = key_data[i];
     iv[i] = key_data[i];
  }

  for (i = key_data_len; i < 32; i++){
     key[i] = 0;
     iv[i] = 0;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;

}

int parse_args(int argc,  char *argv[ ], int *np){
  if ( (argc != 3) || ((*np = atoi (argv[1])) <= 0) ) {
    fprintf (stderr, "Usage: %s nprocs\n", argv[0]);
    return(-1); };
  return(0);
}
int make_trivial_ring(){
  int   fd[2];
  if (pipe (fd) == -1)
    return(-1);
  if ((dup2(fd[0], STDIN_FILENO) == -1) ||
      (dup2(fd[1], STDOUT_FILENO) == -1))
    return(-2);
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
    return(-3);
  return(0); }
int add_new_node(int *pid){
  int fd[2];
  if (pipe(fd) == -1)
    return(-1);
  if ((*pid = fork()) == -1)
    return(-2);
  if(*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0)
    return(-3);
  if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0)
    return(-4);
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
    return(-5);
  return(0);
}
unsigned char read_file(char* name, int length) {
  FILE *file;
  file=fopen(name, "r");
  if (file == NULL) {
   fprintf(stderr, "Could not open file: %s", name);
   exit(EXIT_FAILURE);
  }
  unsigned char str_in[4096];
  fread(str_in, length, 1, file);
  close(file);
  return str_in;
}
unsigned char bump_key(unsigned char* key, unsigned long pos, int trial_key_length, int key_data_len) {

  unsigned char trialkey[32];
  int i;

  fprintf("%s\n", trialkey);

  for (i = 0; i < key_data_len; i++){
   trialkey[i] = key[i];
  }

  fprintf("%s\n", trialkey);

  for (i=key_data_len;i<32;i++){
   trialkey[i] = 0;
  }

  unsigned long keyLowBits = 0;
  keyLowBits = ((unsigned long)(key[24] & 0xFFFF)<< 56)|
   ((unsigned long)(key[25] & 0xFFFF)<< 48)|
   ((unsigned long)(key[26] & 0xFFFF)<< 40)|
   ((unsigned long)(key[27] & 0xFFFF)<< 32)|
   ((unsigned long)(key[28] & 0xFFFF)<< 24)|
   ((unsigned long)(key[29] & 0xFFFF)<< 16)|
   ((unsigned long)(key[30] & 0xFFFF)<< 8)|
   ((unsigned long)(key[31] & 0xFFFF));

  unsigned long trialLowBits = keyLowBits | pos;

  trialkey[25] = (unsigned char) (trialLowBits >> 48);
  trialkey[26] = (unsigned char) (trialLowBits >> 40);
  trialkey[27] = (unsigned char) (trialLowBits >> 32);
  trialkey[28] = (unsigned char) (trialLowBits >> 24);
  trialkey[29] = (unsigned char) (trialLowBits >> 16);
  trialkey[30] = (unsigned char) (trialLowBits >> 8);
  trialkey[31] = (unsigned char) (trialLowBits);

  return trialkey;

}

int main(int argc,  char *argv[ ]){

   int   procn;             /* number of this process (starting with 1)   */
   int   childpid;      /* indicates process should spawn another     */
   int   nprocs;        /* total number of processes in ring          */

   if(parse_args(argc, argv, &nprocs) < 0) {
      exit(EXIT_FAILURE);
   }

   if(make_trivial_ring() < 0) {
     perror("Could not make trivial ring");
     exit(EXIT_FAILURE);
   }

   for (procn = 1; procn < nprocs; procn++) {

     if(add_new_node(&childpid) < 0){
       perror("Could not add new node to ring");
       exit(EXIT_FAILURE);
     }

     if (childpid) {
      break;
     }

   }

   unsigned char cipher_in[32], plain_in[28], key[32];
   int  key_data_len;
   unsigned long  maxSpace = 0;

   if (procn == 1) {

     int i;

     char buffer[MAX_BUFFER];

     int solved = 0;
     char solution[32];

     unsigned char *key_data;

     char *plaintext;

     key_data = (unsigned char *)argv[2];
     key_data_len = strlen(argv[2]);

     unsigned char iv[32];
     unsigned char trialkey[32];

     unsigned char cipher_in = read_file("data/cipher.txt", 32);
     unsigned char plain_in = read_file("data/plain.txt", 28);

     //Only use most significant 32 bytes of data if > 32 bytes
     if(key_data_len > 32) key_data_len = 32;

     //Copy bytes to the front of the key array
     for (i = 0; i < key_data_len; i++){
      key[i] = key_data[i];
     }

     //If the key data < 32 bytes, pad the remaining bytes with 0s
     //int key_diff = 32 - key_data_len;

     for (i=key_data_len;i<32;i++){
      key[i] = 0;
     }

     fprintf(stderr, "Key data length: %d\n", 32);
     maxSpace = ((unsigned long)1 << ((32 - key_data_len)*8))-1;
     fprintf(stderr, "Max space: %d\n", maxSpace);

     unsigned long currentTrial = 0;

     while (currentTrial < maxSpace)
     {

       unsigned char* trialkey = bump_key(key, currentTrial, 32, key_data_len);

       fprintf(stderr, "Master to Slave starting with trial key: %s\n", trialkey);

       // Encourage slave to act while we're thinking
       write(STDOUT_FILENO, "", MAX_BUFFER);

       EVP_CIPHER_CTX en, de;
       if (aes_init(trialkey, 32, &en, &de)) {
         fprintf(stderr, "TRYING TO SOLVE: real_difficult_man.jpg\n");
       } else {
         fprintf(stderr, "AES INIT FAILED\n");
       }

       fprintf(stderr, "Master waiting to read\n");
       // Wait to hear from slave
       read(STDIN_FILENO, buffer, MAX_BUFFER);

       fprintf(stderr, "Master read: %s\n", buffer);
       write(STDOUT_FILENO, "", MAX_BUFFER);

       // If buffer has no solution, keep going
       currentTrial = currentTrial + nprocs;
     }

   } else {

     unsigned long currentTrial = procn - 1;

     while (currentTrial < maxSpace) {

       unsigned char* trialkey = bump_key(key, currentTrial, 32, key_data_len);
       char buffer[MAX_BUFFER];

       // encourage neighbour to act while we think
       write(STDOUT_FILENO, buffer, MAX_BUFFER);

       EVP_CIPHER_CTX en, de;
       if (aes_init(trialkey, 32, &en, &de)) {
         fprintf(stderr, "TRYING TO SOLVE: real_difficult_man.jpg\n");
       }

       fprintf(stderr, "Slave %d waiting to read\n", procn);
       read(STDIN_FILENO, buffer, MAX_BUFFER);
       fprintf(stderr, "Slave read from %d\n", procn, procn-1);
       fprintf(stderr, "Slave %d writing to %d\n", procn, procn+1);

       currentTrial = currentTrial + nprocs;
      }
   }

   exit(EXIT_SUCCESS);

}
