//#define _POSIX_SOURCE 1
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/param.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define CIPHER_PATH "./data/cipher.txt"
#define FOPEN_READONLY "r"
#define FOPEN_ERROR "Could not open file: %s"
#define MAX_BUFFER 1024
#define MAX_KEY_LENGTH 32
#define PLAIN_TEXT_PATH "./data/plain.txt"

/*
 * Function:  read_file
 * --------------------
 * reads a file to the size of the buffer and streams the contents into
 * the buffer.
 *
 * name      file name, relative path
 * buf:      pointer to the buffer (out)
 * len:      length of buffer in bytes
 *
 * returns: negative on error
 */
int read_file(char *name, unsigned char *buf, int len) {

  // Open the file
  FILE *f = fopen(name, FOPEN_READONLY); // TODO: binary, ciphers may have '\0'

  // Check for error
  if (f == NULL) {
   fprintf(stderr, FOPEN_ERROR, name);
   return(-1);
  }

  // Read into buffer
  int read = fread(buf, len, 1, f);

  // Free resources
  fclose(f);

#ifdef DEBUG

  // Print out file contents
  fprintf(stderr, "Read file %s as: ", name);
  int cs = strlen(buf); // TODO: See 'binary' comment above
  for(int y = 0; y < cs; y++) {
   // TODO: If binary, only dump until EOF
   fprintf(stderr, "%c", buf[y]);
  }
  fprintf(stderr, "\n");

#endif

  return(read);

}


int make_trivial_ring()
{
    int fd[2];
    if (pipe(fd) == -1)
        return (-1);
    if ((dup2(fd[0], STDIN_FILENO) == -1) || (dup2(fd[1], STDOUT_FILENO) == -1))
        return (-2);
    if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
        return (-3);
    return (0);
}

int add_new_node(int* pid)
{
    int fd[2];
    if (pipe(fd) == -1)
        return (-1);
    if ((*pid = fork()) == -1)
        return (-2);
    /*
     * extern void _start (void), etext (void); monstartup ((unsigned
     * long) &_start, (unsigned long) &etext);
     */
    if (*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0)
        return (-3);
    if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0)
        return (-4);
    if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
        return (-5);
    return (0);
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX* de, unsigned char* cin, int* clen)
{
    int plen = *clen;
    int flen = 0;

    unsigned char* ptxt = malloc(plen);

    EVP_DecryptUpdate(de, ptxt, &plen, cin, *clen);
    EVP_DecryptFinal_ex(de, ptxt + plen, &flen);

    // Note: Plain text may be longer if block size is > 1

    return ptxt;
}

int aes_init(unsigned char* key_data, int key_data_len, EVP_CIPHER_CTX* d_ctx)
{

    if (key_data_len > MAX_KEY_LENGTH)
        key_data_len = MAX_KEY_LENGTH;

    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key_data, key_data);

    return 0;
}

void bump_key(unsigned char* trialkey, unsigned long keyLowBits, int iteration,
    int missingBytes)
{

    unsigned long trialLowBits = keyLowBits | iteration;

    for (int i = 0; i < missingBytes; i++) {
        trialkey[MAX_KEY_LENGTH - i - 1] = (unsigned char)(trialLowBits >> (i * 8));
    }
}

int parse_args(int argc, char **argv, int *nnode, unsigned char *kd, int *kdl,
  int *ul)
{

    // Validate number of arguments
    if (argc != 3) {
      fprintf(stderr, "Usage: %s nodecount keydata", argv[0]);
      return (-1);
    }

    // Count and validate number of nodes to initialize
    if ((*nnode = atoi(argv[1])) < 1 || *nnode > 16)  {
      perror("Number of nodes limited to between 1 and 16.");
      return(-2);
    };

    // Extract key data, check length
    *kdl = MIN(strlen(argv[2]), MAX_KEY_LENGTH); // HACK: strlen fails on '\0'

    // Move key data to smaller memory space
    // Note: strncpy won't work in the case of binary data inclusive of '\0'
    for (int i = 0; i < *kdl; i++) {
        kd[i] = argv[2][i];
    }
    for (int i = *kdl; i < MAX_KEY_LENGTH; i++) {
        kd[i] = 0;
    }

    // Count missing bytes
    *ul = MAX(MAX_KEY_LENGTH - *kdl, 0);
    if (*ul > 4) {
      fprintf(stderr, "Warning: processing %d bytes may take a while.", *kdl);
    } else if (*ul == 0) {
      fprintf(stderr, "Note: key length is greater than the max length (%d)",
        MAX_KEY_LENGTH);
    }

    return 1;
}

int try_solve(char* keybase, int key_length, char* cipher_in,
    int cipher_length, char* plain_in, int missingBytes,
    unsigned long seed, unsigned long keyLowBits)
{

    unsigned char trialkey[MAX_KEY_LENGTH];
    int trial_key_length = key_length;

    for (int i = 0; i < key_length; i++) {
        trialkey[i] = keybase[i];
    }

    unsigned long trialLowBits = keyLowBits | seed;

    // TODO: gen trialkey once, then keep offsetting

    for (int i = 0; i < missingBytes; i++) {
        trialkey[MAX_KEY_LENGTH - i - 1] = (unsigned char)(trialLowBits >> (i * 8));
    }

    EVP_CIPHER_CTX de;

    if (aes_init(trialkey, trial_key_length, &de)) {
        printf("Couldn't initialize AES cipher\n");
        return -1;
    }

    char* plaintext = (char*)aes_decrypt(&de, (unsigned char*)cipher_in,
        &cipher_length);

    EVP_CIPHER_CTX_cleanup(&de);

    // TODO: compare length, then compare length of plain in (iff equal
    // length)
    if (!strncmp(plaintext, plain_in, 10)) {

        fprintf(stderr, "\nOK: enc/dec ok for \"%s\"\n", plaintext);
        fprintf(stderr, "Key No.:%lu:", seed);

        for (int y = 0; y < MAX_KEY_LENGTH; y++) {
            fprintf(stderr, "%c", trialkey[y]);
        }
        fprintf(stderr, "\n");

        kill(0, SIGTERM);
        exit(0);

        return 1;
    }
    else {

        // fprintf(stderr, "Seed %lu Failed\n", seed);
        return -1;
    }
}

/*
 * Function:  copy_key
 * -------------------
 * Copies a char array from one space to another one byte at a time
 *
 * key:     pointer to the master copy
 * buf:     buffer for copying to
 * len:     length of the <key> string
 *
 */
void copy_key(unsigned char *key, unsigned char *buf, int len) {

  for (int i = 0; i < len; i++) {
    buf[i] = key[i];
  }

}

int nodeid;
void signal_handler(int signum)
{

    fprintf(stderr, "%d exiting", nodeid);

    exit(0);
    /*
     * unsigned char buffer[33]; int le = 32;
     *
     * read(STDIN_FILENO, buffer, 32);
     *
     * if (nodeid == 1 && buffer[0] != '\0') {
     *
     * buffer[32] = '\0';
     *
     * for (int i = 0; i < 32; i++) { fprintf(stderr, "%c", buffer[i]); }
     * fprintf(stderr, "\n");
     *
     * exit(0); }
     *
     * write(STDOUT_FILENO, buffer, 32);
     *
     * if (nodeid != 1) { exit(0); }
     */
}

int main(int argc, char **argv)
{
    // Error code
    int ec;

    // Set up signal handler
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
      perror("Failed to attach signal handler");
      return(-1);
    }

    // Parsed arguments
    int nnodes, kdl, ulen;
    unsigned char keyin[MAX_KEY_LENGTH];
    if ((ec = parse_args(argc, argv, &nnodes, keyin, &kdl, &ulen)) < 0) {
        exit(ec);
    }

    // Read the cipher and plain text files into memory
    unsigned char cin[MAX_BUFFER];
    char pin[MAX_BUFFER];
    ec = read_file(CIPHER_PATH, (unsigned char *)&cin, MAX_BUFFER);
    if (ec < 0) {
        exit(ec);
    }
    int clen = strlen((char*)cin);
    ec = read_file(PLAIN_TEXT_PATH, (unsigned char *)&pin, MAX_BUFFER);
    if (ec < 0) {
        exit(ec);
    }

    // Assign low bits for the unknown interval of the keyspace to the base key
    unsigned long klb = 0;
    for (int i = 0; i < ulen; i++) {
        klb |= ((unsigned long)(
          keyin[MAX_KEY_LENGTH - (ulen - 1) - 1] & 0xFFFF) << (ulen - i) * 8
        );
    }

    // Find the cieling of the unknown keyspace
    unsigned long maxspc = 0;
    maxspc = ((unsigned long)1 << ((MAX_KEY_LENGTH - kdl) * 8)) - 1;

    // Start creating the ring topology
    if (make_trivial_ring() < 0) {
        perror("Could not make trivial ring");
        exit(EXIT_FAILURE);
    }

    // Create new nodes up to the specified number of nodes
    int cpid;
    for (nodeid = 1; nodeid < nnodes; nodeid++) {

        // Add a new node
        if (add_new_node(&cpid) < 0) {
            perror("Could not add new node to ring");
            exit(EXIT_FAILURE);
        }

        // Break if the current process is a child
        if (cpid) {
            break;
        }
    }

    /* -------------------------------------------------------------------- */
    /* Individual contexts start from here (well, just above here really..) */
    /* -------------------------------------------------------------------- */

    EVP_CIPHER_CTX de;
    unsigned long seed = nodeid - 1;
    unsigned char tkey[MAX_KEY_LENGTH];
    copy_key(keyin, tkey, MAX_KEY_LENGTH);

    for (;seed <= maxspc; seed += (unsigned long)nnodes) {

      bump_key((unsigned char *)tkey, klb, seed, ulen);
      aes_init((unsigned char *)tkey, MAX_KEY_LENGTH, &de);
      char *pout = (char *)aes_decrypt(&de, cin, &clen);

      if (strncmp(pin, pout, clen) == 0) {
        fprintf(stderr, "ok");
        kill(0, SIGTERM);
      }

    }
}
