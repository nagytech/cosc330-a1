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

#include "parallel_search_keyspace.h"

int nodeid;

/*
 * Parallel Search Keyspace
 * -------------------------
 * Executes a parallel process brute force attack against an RSA encryption key.
 *
 * arguments:
 * 0:      number of processes to spawn
 * 1:      known bytes of the encryption key
 *
 * remarks: binary keys containing \0 cannot currently be processed
 *
 * returns: output the key to stdout on success, nothing on failure
 */
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

    // Read cipher and plaintext files into memory
    unsigned char cin[MAX_BUFFER];
    char pin[MAX_BUFFER];
    read_file(CIPHER_PATH, (unsigned char *)&cin, MAX_BUFFER);
    int clen = strlen((char*)cin);
    read_file(PLAIN_TEXT_PATH, (unsigned char *)&pin, MAX_BUFFER);
    int plen = strlen(pin);

    // Apply the low end of the keyspace to the input key
    unsigned long klb = 0;
    for (int i = 0; i < ulen; i++) {
        klb |= ((unsigned long)(
          keyin[MAX_KEY_LENGTH - (ulen - 1) - 1] & 0xFFFF) << (ulen - i) * 8
        );
    }

    // Find the cieling of the unknown keyspace
    unsigned long maxspc = 0;
    maxspc = ((unsigned long)1 << ((MAX_KEY_LENGTH - kdl) * 8)) - 1;

    /* -------------------------------------------------------------------- */
    /*          Individual contexts starts from below init_ring             */
    /* -------------------------------------------------------------------- */

    // Initialize ring topology
    nodeid = init_ring(nnodes);

    // Initialize parameters for this node context
    unsigned long seed = nodeid - 1;
    unsigned char tkey[MAX_KEY_LENGTH];
    copy_key(keyin, tkey, MAX_KEY_LENGTH);
    int kfnd = FALSE;

    // Create a reusable cipher context
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(de);

    // Iterate through the node's assigned keyspace and decrypt cipher
    for (;seed <= maxspc; seed += (unsigned long)nnodes) {

      bump_key((unsigned char *)tkey, klb, seed, ulen);
      aes_init(tkey, de);
      char *pout = (char *)aes_decrypt(de, cin, &clen);

      // Write key to wring on successful match
      if (!strncmp(pin, pout, plen - 1)) {
        write(STDOUT_FILENO, tkey, MAX_KEY_LENGTH);
        kfnd = TRUE;
        break;
      }

    }

    // Cleanup cipher context and EVP resources
    EVP_CIPHER_CTX_cleanup(de);
    EVP_cleanup();

    // Trigger the signal handler for all, or just this process
    if (kfnd == TRUE) {
      kill(0, SIGTERM);
    } else {
      kill(getpid(), SIGTERM);
    }

}

int add_new_node(int* pid)
{
    int fd[2];
    if (pipe(fd) == -1)
        return (-1);
    if ((*pid = fork()) == -1)
        return (-2);
#ifdef DEBUG
    extern void _start (void), etext (void);
    monstartup ((unsigned long) &_start, (unsigned long) &etext);
#endif
    if (*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0)
        return (-3);
    if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0)
        return (-4);
    if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
        return (-5);
    return (0);
}

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

int aes_init(unsigned char* keyin, EVP_CIPHER_CTX* d_ctx)
{
    int ec = EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, keyin, keyin);
    if (ec < 1) {
      perror("Failed to initialize EVP decryption");
      // TODO: maybe return error code so the current thread can die gracefully
      kill(0, SIGTERM);
    }
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

int init_ring(int n) {

  if (make_trivial_ring() < 0) {
      perror("Could not make trivial ring");
      exit(EXIT_FAILURE);
  }

  // Fork new nodes and add to the ring
  int cpid, i;
  for (i = 1; i < n; i++) {
      if (add_new_node(&cpid) < 0) {
          perror("Could not add new node to ring");
          exit(EXIT_FAILURE);
      }
      if (cpid) {
          break;
      }
  }
  return i;
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

int parse_args(int argc, char **argv, int *nnode, unsigned char *kd, int *kdl,
  int *ul)
{

    // Validate number of arguments
    if (argc != 3) {
      fprintf(stderr, "Usage: %s nodecount keydata\n", argv[0]);
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
      fprintf(stderr, "Warn: processing %d bytes may take a while.\n", *kdl);
    } else if (*ul == 0) {
      fprintf(stderr, "Warn: key length is not less than the max length: %d\n",
        MAX_KEY_LENGTH);
    }

    return 1;
}

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
int read_file(char *name, unsigned char *buf, int len)
{

  // Open the file
  FILE *f = fopen(name, FOPEN_READONLY); // TODO: binary, ciphers may have '\0'

  // Check for error
  if (f == NULL) {
    perror("Failed to open file.");
    fprintf(stderr, FOPEN_ERROR, name);
    exit(-1);
  }

  // Read into buffer
  int read = fread(buf, len, 1, f);
  if (read < 0) {
    perror("Empty file");
    exit(-2);
  }

  // Free resources
  fclose(f);

  return(read);

}

void signal_handler(int signum)
{

    unsigned char buffer[MAX_KEY_LENGTH];

    // Block until something is written to STDIN
    read(STDIN_FILENO, buffer, MAX_KEY_LENGTH);

    /* --- STDIN RECEIVED --- */

    // Check if the current node is a child
    if (nodeid > 1) {

      /* --- CHILD NODE --- */

      // Child process which has already read data should write, then exit
      write(STDOUT_FILENO, buffer, MAX_KEY_LENGTH);
      exit(0);

    }

    /* --- MASTER NODE --- */

    // TODO: This needs to go to stdout, not stderr

    // Print out the buffer contents which will be the valid key
    for (int i = 0; i < 32; i++) {
      // Note: we iterate since the key is pure binary and may contain \0's
      fprintf(stderr, "%c", buffer[i]);
    }
    fprintf(stderr, "\n");

    // TODO: Maybe try to encrypt with the key so we really know it's valid

    // Terminate, which should cascade to any processes that have not already
    exit(0);

}
