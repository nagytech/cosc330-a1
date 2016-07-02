#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAX_KEY_LENGTH 32
#define CIPHER_LENGTH 32
#define MAX_BUFFER 1024

#define ARG_ERROR "Usage: %s num_nodes partial_key [max_key_bytes]\n"

#define FOPEN_READONLY "r"
#define FOPEN_ERROR "Could not open file: %s"

#define CIPHER_FILE_IN "./data/cipher.txt"
#define PLAIN_FILE_IN "./data/plain.txt"

#define max(a,b) \
  ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
   _a > _b ? _a : _b; })

#define min(a,b) \
  ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })


void bump_key(unsigned char* tk, unsigned long klb, int ci, int max, int mb);
void copy_key(unsigned char *key, unsigned char *buf, int len);
void pad_key(unsigned char *buf, int len, int max);

//#define DEBUG

/*
 * Function:  aes_decrypt
 * ----------------------
 * validates and parses incoming arguments.
 *
 * e:           pointer to evp cipher context
 * cph:         pointer to cipher text string
 * cph_len:     length of the plaintext with an offset (out)
 *
 * returns: pointer to decrypted string
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, const unsigned char *cph, int *cph_len)
{

  // Initialize counters for length
  int pln_len = *cph_len;
  int fnl_len = 0;

  // Allocate memory for the output
  unsigned char *pln = malloc(pln_len);

  // AES decryption sequence
  //EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL); // TODO: Try moving this down for reuse
  EVP_DecryptUpdate(e, pln, &pln_len, cph, *cph_len);
  EVP_DecryptFinal_ex(e, pln + pln_len, &fnl_len);

  // Calculate final total length
  *cph_len = pln_len + fnl_len;

  return pln;

}

int nodeid;
int childpid;
int init_ring(int numnodes) {

  int ec;

  // Create initial ring
  if ((ec = make_trivial_ring()) < 0) {
    perror("Could not make trivial ring");
    exit(ec);
  }

  // Expand ring to the max number of nodes
  for (nodeid = 1; nodeid < numnodes; nodeid++) {

    // Add one new node to the ring
    if((ec = add_new_node(&childpid)) < 0) {
      perror("Could not add new node to ring");
      exit(ec);
    }

    // Break if not required to create a new node
    if (childpid) {
      break;
    }

  }
}

/*
 * Function:  aes_init
 * -------------------
 * Initialize the AES cipher context and decription space
 *
 * key_data:     current key to use for decription
 * key_data_len: length of key_data in bytes
 * mklen:        maximum length of the key
 * d_ctx:        pointer to an uninitialized cipher context
 *
 * returns: negative on error
 */
int aes_init(const unsigned char *trialkey, int klen, int mlen, EVP_CIPHER_CTX *d_ctx){

  // TODO: Try malloc
  unsigned char key[mlen], iv[mlen];

  int minlen = min(klen, mlen);

  copy_key(trialkey, key, mlen);
  copy_key(trialkey, iv, mlen);

  if (minlen < mlen) {
    pad_key(key, mlen, klen);
    pad_key(iv, mlen, klen);
  }

  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;

}

/*
 * Function:  bump_key
 * -------------------
 * Offset the trial key from the low bytes of the search space by the index
 * of the current iteration.
 *
 * tk:     trial key with known bytes (out: complete key)
 * klb:    low bytes of the search space
 * c:      current iteration
 * mklen:  max length allowable
 *
 */
void bump_key(unsigned char* tk, unsigned long klb, int ci, int max, int mb) {

  // Find the low bytes for the search space, offset by the interval 'n'
  unsigned long tlb = klb | ci;

  // Offset the missing bytes (note: reverse iteration)
  for (int i = 0; i < mb; i++) {
    tk[max - i - 1] = (unsigned char) (tlb >> (i * 8));
  }

}

/*
 * Function:  pad_key
 * ------------------
 *
 * Fills a key's unknown bytes with '0'
 *
 * buf:   buffer to pad
 * len:   length of the known bytes
 * max:   max length allowable
 */
void pad_key(unsigned char *buf, int len, int max) {

  // Pad empty space with zeros
  for (int i = len; i < max; i++){
    buf[i] = 0;
  }

}

/*
 * Function:  parse_args
 * ---------------------
 * validates and parses incoming arguments.
 *
 * argc:            argumennt cound from main
 * argv:            array of arguments
 * nnds:            pointer to number of nodes (out)
 * par_key:         pointer to incoming partial key (out)
 * par_key_len:     pointer to partial key length (out)
 * max_key_len:     pointer to max key length, default MAX_KEY_LENGTH (out)
 *
 * returns: negative on error
 */
int parse_args(int argc, char **argv, int *nnds, unsigned char **par_key,
  int *par_key_len, int *max_key_len) {

    // Check for correct argument count
    if (argc < 3 || argc > 4) {
      fprintf (stderr, ARG_ERROR, argv[0]);
      return(-1);
    }

    // Parse arguments
    *nnds = atoi(argv[1]);
    *par_key = (unsigned char *)argv[2];
    *par_key_len = strlen(argv[2]);
    if (argc == 4) {
      *max_key_len = atoi(argv[3]);
    } else {
      *max_key_len = MAX_KEY_LENGTH;
    }

    #ifdef DEBUG

      fprintf(stderr, "Arguments supplied:\n");
      fprintf(stderr, "\tNumber of Nodes: %d\n", *nnds);
      fprintf(stderr, "\tPartial Key: [%s] (%d bytes)\n", *par_key, *par_key_len);
      fprintf(stderr, "\tMax Key Length: %d\n", *max_key_len);

    #endif

    // Set keylength to maximum specified
    if(*par_key_len > max_key_len) {
      #ifdef DEBUG
        fprintf(stderr, "Key is larger than specified maximum.  Setting actual ");
        fprintf(stderr, "length to specified maximum.\n");
      #endif
      *par_key_len = max_key_len;
    }

    // Validate arguments for correctness
    if (nnds <= 0 || max_key_len <= 0 || par_key_len <= 0) {
      fprintf(stderr, ARG_ERROR, argv[0]);
      return (-2);
    }

    return 0;

}



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

#ifdef __APPLE__
#else
  #ifdef DEBUG
  // Aids in retaining attachment of child processes in gdb
  extern void _start (void), etext (void);
  monstartup ((unsigned long) &_start, (unsigned long) &etext);
  #endif
#endif

  if(*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0)
    return(-3);
  if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0)
    return(-4);
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
    return(-5);
  return(0);

}

unsigned long get_key_low_bits(unsigned char *key, int seed, int ulen, int klen) {
  unsigned long lb = 0;
  for (int i = 0; i < ulen; i++) {
    int ki = klen - (ulen - 1) - 1;
    lb |= ((unsigned long)(key[ki] & 0xFFFF) << (ulen - i) * 8);
  }
  return lb;
}

int solve2() {

}

int try_solve(unsigned char *tkey, int klen, char *cipher_in, int cl,
   char *plain_in, int missingBytes, unsigned long seed,
   unsigned long keyLowBits, int mklen) {

  // Cipher context
	EVP_CIPHER_CTX de;

  // Initialize aes for the current trial key and context
	if (aes_init(tkey, klen, mklen, &de)) {
	   fprintf(stderr, "Couldn't initialize AES cipher\n");
	   return -1;
	}

  // Decrypt the cipher into plaintext
	char *plaintext = (char *)aes_decrypt(&de, (unsigned char *)cipher_in,
    &cl);

  // Clean up the cipher context
  EVP_CIPHER_CTX_cleanup(&de);
  EVP_cleanup();

  // TODO: compare length, then compare length of plain in (iff equal length)
  if (!strncmp(plaintext, plain_in, 10)) {

#ifdef DEBUG

#endif

fprintf(stderr, "\nOK: enc/dec ok for \"%s\"\n", plaintext);
fprintf(stderr, "Key No.:%lu:%s\n", seed, tkey);

		return 1;

	} else {

#ifdef DEBUG
  fprintf(stderr, "Seed %lu Failed\n", seed);
#endif

    return -1;

  }
}

int nodeid;
int childpid;
void signal_handler(int signum) {

  fprintf(stderr, "From terminator: %d\n", nodeid);

  char buffer[32];
  int le = 32;

  read(STDIN_FILENO, buffer, le);

  if (nodeid == 1 && buffer[0] != '\0') {
    int out;
    dup2(out, STDOUT_FILENO);
    open(out);

    fprintf(stderr, "we found it\n");
    fprintf(stderr, "Last buffer: %s\n", &buffer);

    exit(0);
  }

  write(STDOUT_FILENO, buffer, le);

  if (nodeid != 1) {
    fprintf(stderr, "terminating: %d\n", nodeid);
    exit(0);
  }


}

int nodeid;
int childpid;
int init_ring(int numnodes) {

  int ec;

  // Create initial ring
  if ((ec = make_trivial_ring()) < 0) {
    perror("Could not make trivial ring");
    exit(ec);
  }

  // Expand ring to the max number of nodes
  for (nodeid = 1; nodeid < numnodes; nodeid++) {

    // Add one new node to the ring
    if((ec = add_new_node(&childpid)) < 0) {
      perror("Could not add new node to ring");
      exit(ec);
    }

    // Break if not required to create a new node
    if (childpid) {
      break;
    }

  }
}


int main(int argc, char **argv)
{
  signal(SIGTERM, signal_handler);

  // Initial arguments
  int numnodes, kdl, mklen, ec;
  unsigned char *key_data;

  // Parse the arguments and check for errors
  if ((ec = parse_args(argc, argv, &numnodes, &key_data, &kdl, &mklen)) < 0) {
    exit(ec);
  }

  // Calculate the missing bytes
  int missingBytes = mklen - kdl;
#ifdef DEBUG
  fprintf(stderr, "Missing Bytes: %d\n", missingBytes);
#endif

  // Read in the cipher text
  int cl;
  char cin[MAX_BUFFER];
  if ((ec = read_file(CIPHER_FILE_IN, &cin, MAX_BUFFER)) < 0) {
    exit(ec);
  }
  cl = strlen((char*)cin);

  // Read in the plain text
  char plain_in[MAX_BUFFER];
  read_file("./data/plain.txt", &plain_in, MAX_BUFFER);

  // Copy the key to a new location for reference only
  unsigned char key[mklen];
  copy_key(key_data, key, kdl);
  pad_key(key, kdl, mklen);

  // Initialize the search space
  unsigned long keyLowBits = get_key_low_bits(key, 0, missingBytes, kdl);

  // Calculate the length of the search spaces
  unsigned long maxSpace = 0;
  maxSpace = ((unsigned long)1 << ((mklen - kdl)*8))-1;
#ifdef DEBUG
  fprintf(stderr, "Max space: %lu\n", maxSpace);
#endif

  // Initialize the ring structure
  init_ring(numnodes);

  /* -----------------------------------------------------------------------
   *                Individual node context from here
   * -----------------------------------------------------------------------
   */

  // Print out node identifiers
  fprintf(stderr, "Node %d process id %d:%d\n", nodeid, getpid(), childpid);

  /*
   * Each node searches the keyspace for intervals of numnodes, offset by the
   * node's own identifier.
   *
   *           [ seed = (iteration * numnodes) + nodeid ]
   *
   * Example: for numnodes of 8, node id 0, will search { 0, 8, 16, ... } where
   * node id 1 would search { 1, 9, 17, ... }.
   */

  if (nodeid < numnodes) {
    char go[1];
    read(STDIN_FILENO, go, mklen);
    write(STDOUT_FILENO, go, 1);
  } else {
    char go[1];
    write(STDOUT_FILENO, "!", 1);
    read(STDIN_FILENO, go, 1);
  }

  // Iterate through the keyspace
  unsigned long seed = nodeid - 1;
  unsigned char *tkey[32];
  copy_key(key, tkey, kdl);

  for (;seed <= maxSpace; seed += (unsigned long)numnodes) {

    // Attempt to solve using current seed
    bump_key((unsigned char *)&tkey, keyLowBits, seed, mklen, missingBytes);

    if (try_solve((unsigned char *)tkey, mklen, cin, cl, plain_in, missingBytes, seed, keyLowBits, mklen) > 0) {

        fprintf(stderr, "%d found solution\n", nodeid);

        // Write solution to stdout (non blocking)
        write(STDOUT_FILENO, tkey, mklen + 1);

        // Kill process group
        kill(0, SIGTERM);
    }
  }

  int status;
  while (waitpid(0, &status, 0) >= 0) {

  }

}
