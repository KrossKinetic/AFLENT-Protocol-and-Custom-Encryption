#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include "hw2.h"

uint8_t nth_byte(block_t x, uint8_t n);
block_t shuffle1(block_t x);
block_t shuffle4(block_t x);
block_t unshuffle4(block_t x);
block_t unshuffle1(block_t x);
block_t reverse(block_t x);
uint8_t rotr(uint8_t x, uint8_t shamt);
uint8_t rotl(uint8_t x, uint8_t shamt);
uint8_t scramble_op(block_t B, uint8_t i, block_t keyA, block_t keyB);
uint8_t mash_op(block_t B, uint8_t i, block_t *S);
block_t sbu_decrypt_block(block_t plain_text, block_t *expanded_keys);

int main() {
    printf("Hello, World!");
    return 0;
}