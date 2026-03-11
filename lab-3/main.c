#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "present-80.c"

int main(int argc, char *argv[])
{
   if (argc != 4)
   {
      printf("Usage:\n");
      printf("  %s <key_file> <plaintext_file> <ciphertext_file>\n", argv[0]);
      return 1;
   }

   char *key_path = argv[1];
   char *input_path = argv[2];
   char *output_path = argv[3];

   FILE *key_file = fopen(key_path, "rb");
   if (!key_file)
   {
      perror("Failed to open key file");
      return 1;
   }

   FILE *input_file = fopen(input_path, "rb");
   if (!input_file)
   {
      perror("Failed to open plaintext file");
      return 1;
   }

   FILE *output_file = fopen(output_path, "wb");
   if (!output_file)
   {
      perror("Failed to open ciphertext file");
      return 1;
   }

   u80 key;
   read_key(key_file, &key);
   fclose(key_file);

   uint64_t round_keys[ROUNDS + 1];
   generate_key_schedule(key, round_keys);

   uint64_t *blocks;
   size_t n_blocks = read_blocks_hex(input_file, &blocks);
   fclose(input_file);

   if (n_blocks == (size_t)-1)
   {
      printf("Failed to read input file\n");
      return 1;
   }

   uint64_t *result = malloc(sizeof(uint64_t) * n_blocks);
   if (!result)
   {
      printf("Memory allocation failed\n");
      return 1;
   }

   encrypt_present_80_bitsliced(round_keys, blocks, n_blocks, result);

   write_blocks_hex(output_file, result, n_blocks);

   fclose(output_file);
   free(blocks);
   free(result);

   printf("Success\n");
   return 0;
}