#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  // plaintext will always be equal to or lesser than length of ciphertext
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);

  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  //*len = p_len + f_len;
  return plaintext;
}

int aes_init(unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx){

  int i;
  unsigned char key[32], iv[32];
  //Some robust programming to start with
  //Only use most significant 32 bytes of data if > 32 bytes
  if(key_data_len > 32) key_data_len =32;

  //Copy bytes to the front of the key array
  for (i=0;i<key_data_len; i++){
     key[i] = key_data[i];
     iv[i] = key_data[i];
  }
  for (i=key_data_len;i<32;i++){
     key[i] = 0;
     iv[i] = 0;
  }
  //Were not using the key gen process as we assume the key has already bee created in this way.

  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  //i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  //if (i != 32) {
  //  return -1;
  //}

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

int main(int argc, char **argv){
   unsigned char *key_data;
   int  key_data_len, i;
   char *plaintext;
    key_data = (unsigned char *)argv[1];
    key_data_len = strlen(argv[1]);


    unsigned char key[32], iv[32];
    unsigned char trialkey[32];

    int cipher_length = 32;
    FILE *mycipherfile;
    mycipherfile=fopen("./data/cipher.txt","r");
    if (mycipherfile == NULL) {
    		printf("Could not open file ./data/cipher.txt");
				return -1;
    }
    unsigned char cipher_in[4096];
    fread(cipher_in, cipher_length, 1, mycipherfile);

    FILE *myplainfile;
    myplainfile=fopen("./data/plain.txt","r");
    if (myplainfile == NULL) {
    		printf("Could not open file ./data/plain.txt");
				return -1;
    }
    char plain_in[4096];
    fread(plain_in, 28, 1, myplainfile);

     int y;
     printf("\nPlain:");
     for(y=0;y<28;y++){
              printf("%c",plain_in[y]);
     }
     printf("\n");
     printf("\nCipher:");
     for(y=0;y<32;y++){
              printf("%c",cipher_in[y]);
     }
    //Only use most significant 32 bytes of data if > 32 bytes
    if(key_data_len > 32) key_data_len =32;

     //Copy bytes to the front of the key array
    for (i=0;i<key_data_len; i++){

       key[i] = key_data[i];
       iv[i] = key_data[i];
       trialkey[i] = key_data[i];
    }

     //If the key data < 32 bytes, pad the remaining bytes with 0s
     //int key_diff = 32 - key_data_len;

     for (i=key_data_len;i<32;i++){
       key[i] = 0;
       iv[i] = 0;
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


      //printf("\n\nkeylowbits: %lu", keyLowBits);
      int trial_key_length=32;
      unsigned long  maxSpace = 0;
      maxSpace = ((unsigned long)1 << ((trial_key_length - key_data_len)*8))-1;
      unsigned long counter;
      //printf("Maxspace: %lu %lu\n",((trial_key_length - key_data_len)*8), maxSpace);
      for(counter=0; counter < maxSpace ; counter++){
         unsigned long trialLowBits = keyLowBits | counter;

         trialkey[25] = (unsigned char) (trialLowBits >> 48);
         trialkey[26] = (unsigned char) (trialLowBits >> 40);
         trialkey[27] = (unsigned char) (trialLowBits >> 32);
	 trialkey[28] = (unsigned char) (trialLowBits >> 24);
	 trialkey[29] = (unsigned char) (trialLowBits >> 16);
	 trialkey[30] = (unsigned char) (trialLowBits >> 8);
         trialkey[31] = (unsigned char) (trialLowBits);
         //if(counter ==56){
         	EVP_CIPHER_CTX en, de;
         	if (aes_init(trialkey, trial_key_length, &en, &de)) {
            	   printf("Couldn't initialize AES cipher\n");
            	   return -1;
         	}
         //if(counter ==56){
         	plaintext = (char *)aes_decrypt(&de, (unsigned char *)cipher_in, &cipher_length);
                EVP_CIPHER_CTX_cleanup(&en);
                EVP_CIPHER_CTX_cleanup(&de);
         	//printf("\nKey %lu:%s plain: %s",counter, trialkey, plaintext);
         	int y;

    		if (strncmp(plaintext, plain_in, 28));
     			 //printf("\nFAIL: enc/dec failed for \"%s\"\n", plain_in);
    		else{
     			printf("\nOK: enc/dec ok for \"%s\"\n", plaintext);


         		printf("Key No.:%zu:", counter);
         		for(y=0;y<32;y++){
              			printf("%c",trialkey[y]);
	 		}
			printf("\n");
			break;
		}
         	free(plaintext);
	//}
      }





}
