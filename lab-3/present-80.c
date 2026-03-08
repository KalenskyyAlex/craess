#include <stdio.h>
#include <stdint.h>
#include "key-util.c"

#define ROUNDS 31

void generate_key_schedule(const u80 key, uint64_t key_schedule[ROUNDS]);

int main()
{
   u80 key;

   FILE *key_file = fopen("key.txt", "rb");
   read_key(key_file, &key);

   printf("Key provided: ");
   for (int i = 0; i < 10; i++)
   {
      printf("%02X ", key.b[i]);
   }
   printf("\n");

   uint64_t keys[ROUNDS];
   generate_key_schedule(key, keys);

   for (int i = 0; i < ROUNDS; i++)
   {
      printf("%lu\n", keys[i]);
   }

   return 0;
}

void generate_key_schedule(const u80 key, uint64_t key_schedule[ROUNDS])
{
   u80 modified_key = key;
   for (int round = 0; round < ROUNDS; round++)
   {
      // extract round key k79..k16
      key_schedule[round] = (modified_key.b[0] << 56) | ((uint64_t)modified_key.b[1] << 48) | ((uint64_t)modified_key.b[2] << 40) | ((uint64_t)modified_key.b[3] << 32) | ((uint64_t)modified_key.b[4] << 24) | ((uint64_t)modified_key.b[5] << 16) | ((uint64_t)modified_key.b[6] << 8) | ((uint64_t)modified_key.b[7]);

      modified_key = left_rotate_u80(modified_key, 61);
      modified_key = apply_sb_present_79_76(modified_key);
      modified_key = apply_xor_round_19_15(modified_key, round + 1);
   }
}