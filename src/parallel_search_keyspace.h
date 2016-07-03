#ifndef PARALLEL_SEARCH_KEYSPACE_HEADER
  #define PARALLEL_SEARCH_KEYSPACE_HEADER
#endif

#define CIPHER_PATH "./data/cipher.txt"
#define PLAIN_TEXT_PATH "./data/plain.txt"

#define FOPEN_READONLY "r"
#define FOPEN_ERROR "Could not open file: %s\n"
#define TRUE 1
#define FALSE 0
#define MAX_BUFFER 1024
#define MAX_KEY_LENGTH 32

int nodeid;

int add_new_node(int* pid);
unsigned char *aes_decrypt(EVP_CIPHER_CTX* de, unsigned char* cin, int* clen);
int aes_init(unsigned char* keyin, EVP_CIPHER_CTX* d_ctx);
int add_new_node(int* pid);
void bump_key(unsigned char* trialkey, unsigned long keyLowBits, int iteration,
    int missingBytes);
void copy_key(unsigned char *key, unsigned char *buf, int len);
int init_ring(int nnodes);
int make_trivial_ring();
int parse_args(int argc, char **argv, int *nnode, unsigned char *kd,
  int *kdl, int *ul);
int read_file(char *name, unsigned char *buf, int len);
void signal_handler(int signum);
