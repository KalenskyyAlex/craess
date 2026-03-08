#include <stdio.h>
#include <stdint.h>
#include "definitions.c"

// will read 20 hex chars from given text file into destination pointer
void read_key(FILE *file_ptr, u80 *dest)
{
    if (!file_ptr || !dest)
        return;

    uint8_t buf[21]; // 20 hex chars + null

    if (fscanf(file_ptr, "%20s", buf) != 1)
    {
        printf("ERROR: could not read key\n");
        return;
    }

    for (int i = 0; i < 10; i++)
    {
        unsigned int byte;
        sscanf(buf + i * 2, "%2x", &byte);
        dest->b[i] = (uint8_t)byte;
    }
}

// perform left rotate on 10 byte key
u80 left_rotate_u80(const u80 initial, const int shift)
{
    int q_shift = shift / 8;
    int r_shift = shift % 8;

    u80 rotated;
    // first rotate bytes by q_shift
    for (int i = 0; i < 10; i++)
    {
        rotated.b[(i + (10 - q_shift)) % 10] = initial.b[i];
    }

    // then inside each byte apply remainder shift. For this, don't forget to include
    // trailing bits from byte after
    uint8_t head = rotated.b[0];
    for (int i = 0; i < 9; i++)
    {
        uint16_t two_bytes = (rotated.b[i] << 8) | rotated.b[i + 1];
        two_bytes <<= r_shift;
        // write updated state into ith byte, for (i + 1)th byte state is left
        // intact and calculated with corresponding trailing byte in next iteration
        uint8_t updated_i = (uint8_t)(two_bytes >> 8);
        rotated.b[i] = updated_i;
    }

    // special case shift from head to tail
    uint16_t two_bytes = (rotated.b[9] << 8) | head;
    two_bytes <<= r_shift;
    // write updated state into ith byte, for (i + 1)th byte state is left
    // intact and calculated with corresponding trailing byte in next iteration
    uint8_t updated_i = (uint8_t)(two_bytes >> 8);
    rotated.b[9] = updated_i;

    return rotated;
}

u80 apply_sb_present_79_76(const u80 initial)
{
    u80 modified = initial;
    uint8_t head = initial.b[0];
    uint8_t first_4 = head >> 4;
    uint8_t sbox_first_4 = SBOX_PRESENT[first_4];
    uint8_t sbox_head = (sbox_first_4 << 4) | (head & 0b1111);
    modified.b[0] = sbox_head;

    return modified;
}

u80 apply_xor_round_19_15(const u80 initial, const uint8_t round)
{
    u80 modified = initial;

    // 19...16 belongs to 8th byte, 15 belongs to 9th byte
    uint16_t two_bytes = (modified.b[7] << 8) | modified.b[8];

    // clamp 19...15 from two bytes
    uint8_t five_bits = (two_bytes >> 7) & 0b11111;
    uint8_t five_bits_xor = five_bits ^ round;

    // restore into two bytes
    uint16_t two_bytes_xor = (two_bytes & 0b1111000000000000) | (five_bits_xor << 7) | (two_bytes & 0b1111111);

    modified.b[7] = (uint8_t)(two_bytes_xor >> 8);
    modified.b[8] = (uint8_t)(two_bytes_xor & 0b11111111);

    return modified;
}