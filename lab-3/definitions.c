#include <math.h>
#include <stdint.h>

#ifndef DEFINITIONS_GUARD
#define DEFINITIONS_GUARD

#define ROUNDS 31

const int SBOX_PRESENT[16] = {
    0b1100, // 0: C
    0b0101, // 1: 5
    0b0110, // 2: 6
    0b1011, // 3: B
    0b1001, // 4: 9
    0b0000, // 5: 0
    0b1010, // 6: A
    0b1101, // 7: D
    0b0011, // 8: 3
    0b1110, // 9: E
    0b1111, // A: F
    0b1000, // B: 8
    0b0100, // C: 4
    0b0111, // D: 7
    0b0001, // E: 1
    0b0010, // F: 2
};

// PRESENT-80 key is 80 bits = 10 bytes = 1 byte (uint8_t) x 10
// there is no existing type that stores 10 bytes in C
// we will store the key in big endian, i.e.:
//    k79...k72 = b[0]
//    k71...k64 = b[1]
//    ...
//    k7 ...k0  = b[9]
typedef struct
{
    uint8_t b[10];
} u80;

//   uint8_t T1 = x1 ^ X2;
//   uint8_t T2 = x2 & T1;
//   uint8_t T3 = x3 ^ T2;
//   uint8_t Y0 = x0 ^ T3;
//   uint8_t T2 = T1 & T3;
// T1 ^= (Y0);
//   T2 ^= x2;
//   uint8_t T4 = x0 | T2;
//   Y1 = T1 ^ T4;
//   T2 ^= (~x0);
//   uint8_t Y3 = (*Y1) ^ T2;
//   T2 |= T1;
//   Y2 = T3 ^ T2;

uint8_t phi_0_x(
    const uint8_t x0,
    const uint8_t x1,
    const uint8_t x2,
    const uint8_t x3)
{
    return x0 ^ x2 ^ (x1 & x2) ^ x3;
}

uint8_t phi_1_x(
    const uint8_t x0,
    const uint8_t x1,
    const uint8_t x2,
    const uint8_t x3)
{
    return x1 ^ x3 ^ (x1 & x3) ^ (x2 & x3) ^ (x0 & x1 & x2) ^ (x0 & x1 & x3) ^ (x0 & x2 & x3);
}

uint8_t phi_2_x(
    const uint8_t x0,
    const uint8_t x1,
    const uint8_t x2,
    const uint8_t x3)
{
    return 0b11111111 ^ x2 ^ x3 ^ (x0 & x1) ^ (x0 & x3) ^ (x1 & x3) ^ (x0 & x1 & x3) ^ (x0 & x2 & x3);
}

uint8_t phi_3_x(
    const uint8_t x0,
    const uint8_t x1,
    const uint8_t x2,
    const uint8_t x3)
{
    return 0b11111111 ^ x0 ^ x1 ^ x3 ^ (x1 & x2) ^ (x0 & x1 & x2) ^ (x0 & x1 & x3) ^ (x0 & x2 & x3);
}

int p_layer(int j)
{
    return (int)floor(j / 4.0) + (j % 4) * 16;
}

void print_64_bit_hex(uint64_t number)
{
    for (int byte = 7; byte >= 0; byte--)
    {
        // extract each byte
        uint8_t b = (number >> (byte * 8)) & 0xFF;
        printf("%02X", b);
        if (byte > 0)
            printf(" ");
    }
    printf("\n");
}
#endif