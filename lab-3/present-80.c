#include <stdint.h>
#include <stdlib.h>
#include "definitions.c"

#ifndef PRESENT_GUARD
#define PRESENT_GUARD

void generate_key_schedule(const u80 key, uint64_t key_schedule[ROUNDS])
{
    u80 modified_key = key;
    // ROUNDS + 1 because we need 32nd final round
    for (int round = 0; round < ROUNDS + 1; round++)
    {
        // extract round key k79..k16
        key_schedule[round] = ((uint64_t)modified_key.b[0] << 56) | ((uint64_t)modified_key.b[1] << 48) | ((uint64_t)modified_key.b[2] << 40) | ((uint64_t)modified_key.b[3] << 32) | ((uint64_t)modified_key.b[4] << 24) | ((uint64_t)modified_key.b[5] << 16) | ((uint64_t)modified_key.b[6] << 8) | ((uint64_t)modified_key.b[7]);

        modified_key = left_rotate_u80(modified_key, 61);
        modified_key = apply_sb_present_79_76(modified_key);
        modified_key = apply_xor_round_19_15(modified_key, round + 1);
    }
}

size_t read_blocks_hex(FILE *file_ptr, uint64_t **dest)
{
    if (!file_ptr || !dest)
        return -1;

    uint8_t buf[17]; // 16 hex chars + null

    // allocate memory
    size_t capacity = 16;
    size_t n_blocks = 0;
    uint64_t *blocks = malloc(capacity * sizeof(uint64_t));
    if (!blocks)
        return -1;

    while (fscanf(file_ptr, "%16s", buf) == 1)
    {
        uint64_t block = 0;
        for (int i = 0; i < 8; i++)
        {
            unsigned int byte;
            sscanf(buf + i * 2, "%2x", &byte);

            block = (uint64_t)((block << 8) | byte);
        }

        // grow if needed
        if (n_blocks >= capacity)
        {
            capacity *= 2;
            uint64_t *tmp = realloc(blocks, capacity * sizeof(uint64_t));
            if (!tmp)
            {
                free(blocks);
                return -1;
            }
            blocks = tmp;
        }

        blocks[n_blocks] = block;
        n_blocks++;
    }

    *dest = blocks;

    return n_blocks;
}

void write_blocks_hex(FILE *f, uint64_t *blocks, size_t n_blocks)
{
    for (size_t i = 0; i < n_blocks; i++)
    {
        fprintf(f, "%016llX\n", (unsigned long long)blocks[i]);
    }
}

void encrypt_present_80_bitsliced(
    const uint64_t key_schedule[ROUNDS + 1],
    const uint64_t *plaintext,
    const size_t n_blocks,
    uint64_t ciphertext[n_blocks])
{
    size_t n_blocks_padded = ((n_blocks / 8) + 1) * 8;
    if (n_blocks % 8 == 0)
    {
        n_blocks_padded = n_blocks;
    }

    uint64_t padded[n_blocks_padded];
    uint64_t ciphertext_padded[n_blocks_padded];
    for (int i = 0; i < n_blocks; i++)
    {
        padded[i] = plaintext[i];
    }
    // pad with 0-blocks to be divisible by 8
    for (int i = n_blocks; i < n_blocks_padded; i++)
    {
        padded[i] = 0;
    }

    for (int i = 0; i < n_blocks_padded; i++)
    {
        ciphertext_padded[i] = 0;
    }

    // process in chunks of 8 blocks assuming 8bit word support (always for modern CPUs)
    // convert keys in convenient form (e.g. 0b1 bit from key becomes 0b11111111 to apply on whole row at once)
    uint8_t bitsliced_key_schedule[ROUNDS + 1][64];
    for (int round = 0; round < ROUNDS + 1; round++)
    {
        for (int j = 0; j < 64; j++)
        {
            if (key_schedule[round] & ((uint64_t)1 << (64 - j - 1)))
            {
                bitsliced_key_schedule[round][j] = 0b11111111;
            }
            else
            {
                bitsliced_key_schedule[round][j] = 0b00000000;
            }
        }
    }

    for (int i = 0; i < n_blocks_padded / 8; i++)
    {
        // uint8_t is 8 bits, so this stores S[64][8] efficiently without separate cell for single bit
        uint8_t S[64];

        // convert to bitsliced form
        for (int j = 0; j < 64; j++)
        {
            S[j] = (((padded[i * 8] >> (64 - j - 1)) & 0b1) << 7) | (((padded[i * 8 + 1] >> (64 - j - 1)) & 0b1) << 6) | (((padded[i * 8 + 2] >> (64 - j - 1)) & 0b1) << 5) | (((padded[i * 8 + 3] >> (64 - j - 1)) & 0b1) << 4) | (((padded[i * 8 + 4] >> (64 - j - 1)) & 0b1) << 3) | (((padded[i * 8 + 5] >> (64 - j - 1)) & 0b1) << 2) | (((padded[i * 8 + 6] >> (64 - j - 1)) & 0b1) << 1) | ((padded[i * 8 + 7] >> (64 - j - 1)) & 0b1);
        }

        // perform PRESENT-80 for bitsliced blocks
        for (int round = 0; round < ROUNDS; round++)
        {
            // Sj XOR Keyj
            for (int j = 0; j < 64; j++)
            {
                S[j] ^= bitsliced_key_schedule[round][j];
            }

            // Sbox
            uint8_t state[64];
            for (int b = 0; b < 16; b++)
            {
                uint8_t x0 = S[4 * b];
                uint8_t x1 = S[4 * b + 1];
                uint8_t x2 = S[4 * b + 2];
                uint8_t x3 = S[4 * b + 3];

                state[4 * b] = phi_3_x(x3, x2, x1, x0);
                state[4 * b + 1] = phi_2_x(x3, x2, x1, x0);
                state[4 * b + 2] = phi_1_x(x3, x2, x1, x0);
                state[4 * b + 3] = phi_0_x(x3, x2, x1, x0);
            }

            // pLayer
            for (int j = 0; j < 64; j++)
            {
                S[p_layer(j)] = state[j];
            }
        }

        // apply last round Sj XOR Keyj
        for (int j = 0; j < 64; j++)
        {
            S[j] ^= bitsliced_key_schedule[ROUNDS][j];
        }

        // convert back to 8 ciphertext blocks
        for (int j = 0; j < 64; j++)
        {
            ciphertext_padded[i * 8] <<= 1;
            ciphertext_padded[i * 8] |= (S[j] & 0b10000000) ? 0b1 : 0b0;

            ciphertext_padded[i * 8 + 1] <<= 1;
            ciphertext_padded[i * 8 + 1] |= (S[j] & 0b01000000) ? 0b1 : 0b0;

            ciphertext_padded[i * 8 + 2] <<= 1;
            ciphertext_padded[i * 8 + 2] |= (S[j] & 0b00100000) ? 0b1 : 0b0;

            ciphertext_padded[i * 8 + 3] <<= 1;
            ciphertext_padded[i * 8 + 3] |= (S[j] & 0b00010000) ? 0b1 : 0b0;

            ciphertext_padded[i * 8 + 4] <<= 1;
            ciphertext_padded[i * 8 + 4] |= (S[j] & 0b00001000) ? 0b1 : 0b0;

            ciphertext_padded[i * 8 + 5] <<= 1;
            ciphertext_padded[i * 8 + 5] |= (S[j] & 0b00000100) ? 0b1 : 0b0;

            ciphertext_padded[i * 8 + 6] <<= 1;
            ciphertext_padded[i * 8 + 6] |= (S[j] & 0b00000010) ? 0b1 : 0b0;

            ciphertext_padded[i * 8 + 7] <<= 1;
            ciphertext_padded[i * 8 + 7] |= (S[j] & 0b00000001) ? 0b1 : 0b0;
        }
    }

    // ignore padded and only include n_blocks to ciphertext
    for (int i = 0; i < n_blocks; i++)
    {
        ciphertext[i] = ciphertext_padded[i];
    }
    
    return;
}

#endif