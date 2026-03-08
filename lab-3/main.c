#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "present-80.c"

void print_keys_hex(uint64_t keys[ROUNDS + 1])
{
   printf("Key schedule: \n");
   for (int i = 0; i < ROUNDS; i++)
   {
      printf("Round %5d: ", i + 1);
      uint64_t k = keys[i];
      for (int byte = 7; byte >= 0; byte--)
      {
         // extract each byte
         uint8_t b = (k >> (byte * 8)) & 0xFF;
         printf("%02X", b);
         if (byte > 0)
            printf(" ");
      }
      printf("\n");
   }

   printf("Final round: ");
   uint64_t k = keys[ROUNDS];
   for (int byte = 7; byte >= 0; byte--)
   {
      // extract each byte
      uint8_t b = (k >> (byte * 8)) & 0xFF;
      printf("%02X", b);
      if (byte > 0)
         printf(" "); 
   }
   printf("\n");


}

int main()
{
   u80 key;

   FILE *key_file = fopen("key.txt", "rb");
   FILE *plaintext_file = fopen("plaintext.txt", "rb");
   read_key(key_file, &key);

   printf("Key provided: \n");
   for (int i = 0; i < 10; i++)
   {
      printf("%02X ", key.b[i]);
   }
   printf("\n\n");

   uint64_t keys[ROUNDS + 1];
   generate_key_schedule(key, keys);

   uint64_t *plaintext;
   size_t n_blocks = read_plaintext(plaintext_file, &plaintext);
   if (n_blocks == -1) {
      printf("Failed to read the plaintext \n", n_blocks);
      return 1;
   }
   printf("Read %d blocks of plaintext \n", n_blocks);
   
   print_keys_hex(keys);

   uint64_t ciphertext[n_blocks];
   encrypt_present_80_bitsliced(keys, plaintext, n_blocks, ciphertext);

   printf("\nCiphertext: \n");
   for (int i = 0; i < n_blocks; i++)
   {
      printf("Block %5d: ", i + 1);
      uint64_t k = ciphertext[i];
      for (int byte = 7; byte >= 0; byte--)
      {
         // extract each byte
         uint8_t b = (k >> (byte * 8)) & 0xFF;
         printf("%02X", b);
         if (byte > 0)
            printf(" ");
      }
      printf("\n");
   }
   
   free(plaintext);
   return 0;
}