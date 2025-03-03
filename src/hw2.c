#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/mman.h>
#include <math.h>
#include <sys/stat.h>
#include <errno.h>

int convert_hex_to_dec(char x);
//Packet Code:
// cmake --build build
// Stick to Hex interpretation of Binary
// {0x0C, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78};
void print_packet(unsigned char packet[])
{
	// Array Number
	int row_zero = packet[0];
	int array_number = (row_zero & 0xFC) >> 2;
	printf("Array Number: %d\n",array_number);

	// Fragment Number
	int first_frag_part = (row_zero & 0x03) << 3;
	int row_one = packet[1];
	int second_frag_part = (row_one & 0xE0) >> 5;
	int full_frag = first_frag_part | second_frag_part;
	printf("Fragment Number: %d\n",full_frag);

	// Length
	int first_length_part = (row_one & 0x1F) << 5;
	int row_two = packet[2];
	int second_length_part = (row_two & 0xF8) >> 3;
	int full_length = first_length_part | second_length_part;
	printf("Length: %d\n",full_length);

	// Encrypt, Endian, Last
	int encrypt = (row_two & 0x04) >> 2;
	int endian = (row_two & 0x02) >> 1;
	int last = (row_two & 0x01);
	printf("Encrypted: %d\n",encrypt);
	printf("Endianness: %d\n",endian);
	printf("Last: %d\n",last);

	printf("Data: ");
	for (int i = 3; i < (full_length*4)+3; i+=4){
		int full_payload_sequence = (packet[i] << 8*3) | (packet[i+1] << 8*2) | (packet[i+2] << 8) | packet[i+3];
		printf("%0x ",full_payload_sequence);
	}
	printf("\n");
}

unsigned char* build_packets(int data[], int data_length, int max_fragment_size, int endianness, int array_number)
{
	(void) data; //This line is only here to avoid compiler issues. Once you implement the function, please delete this line
	(void) data_length; //This line is only here to avoid compiler issues. Once you implement the function, please delete this line
	(void) max_fragment_size; //This line is only here to avoid compiler issues. Once you implement the function, please delete this line
	(void) endianness; //This line is only here to avoid compiler issues. Once you implement the function, please delete this line
	(void) array_number; //This line is only here to avoid compiler issues. Once you implement the function, please delete this line
    return NULL;
}

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths)
{
    (void) packets; //This line is only here to avoid compiler issues. Once you implement the function, please delete this line
	(void) array_count; //This line is only here to avoid compiler issues. Once you implement the function, please delete this line
	(void) array_lengths; //This line is only here to avoid compiler issues. Once you implement the function, please delete this line
    return NULL;
}


//Encryption Code:

#define EXPANDED_KEYS_LENGTH 32

typedef uint64_t sbu_key_t;
typedef uint32_t block_t;
typedef block_t(*permute_func_t)(block_t);

block_t table[] = { 
    0x6a09e667, 0xbb67ae84, 0x3c6ef372, 0xa54ff539, 0x510e527f, 0x9b05688b, 0x1f83d9ab, 0x5be0cd18, 
    0xcbbb9d5c, 0x629a2929, 0x91590159, 0x152fecd8, 0x67332667, 0x8eb44a86, 0xdb0c2e0c, 0x47b5481d, 
    0xae5f9156, 0xcf6c85d2, 0x2f73477d, 0x6d1826ca, 0x8b43d456, 0xe360b595, 0x1c456002, 0x6f196330, 
    0xd94ebeb0, 0x0cc4a611, 0x261dc1f2, 0x5815a7bd, 0x70b7ed67, 0xa1513c68, 0x44f93635, 0x720dcdfd, 
    0xb467369d, 0xca320b75, 0x34e0d42e, 0x49c7d9bd, 0x87abb9f1, 0xc463a2fb, 0xec3fc3f2, 0x27277f6c, 
    0x610bebf2, 0x7420b49e, 0xd1fd8a32, 0xe4773593, 0x092197f5, 0x1b530c95, 0x869d6342, 0xeee52e4e, 
    0x11076689, 0x21fba37b, 0x43ab9fb5, 0x75a9f91c, 0x86305019, 0xd7cd8173, 0x07fe00ff, 0x379f513f, 
    0x66b651a8, 0x764ab842, 0xa4b06be0, 0xc3578c14, 0xd2962a52, 0x1e039f40, 0x857b7bed, 0xa29bf2de
};

// ----------------- Bitwise Functions ----------------- //

uint8_t rotl(uint8_t x, uint8_t shamt)
{
	(void) x;
	(void) shamt;
    return 0;
}

uint8_t rotr(uint8_t x, uint8_t shamt)
{
	(void) x;
	(void) shamt;
    return 0;
}

block_t reverse(block_t x)
{
	(void) x;
    return 0;
}

block_t shuffle4(block_t x)
{
	(void) x;
    return 0;
}

block_t unshuffle4(block_t x)
{
	(void) x;
    return 0;
}

block_t shuffle1(block_t x)
{
	(void) x;
    return 0;
}

block_t unshuffle1(block_t x)
{
	(void) x;
    return 0;
}

uint8_t nth_byte(block_t x, uint8_t n)
{
	(void) x;
	(void) n;
    return 0;
}

// ----------------- Encryption Functions ----------------- //

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys)
{
	(void) key;
	(void) expanded_keys;
}

block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	(void) x;
	(void) keys;
	(void) round;
	(void) op;
    return 0;
}

block_t mash(block_t x, block_t *keys)
{
	(void) x;
	(void) keys;
    return 0;
}

block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys)
{
	(void) plain_text;
	(void) expanded_keys;

    return 0;
}

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	(void) x;
	(void) keys;
	(void) round;
	(void) op;

    return 0;
}

block_t r_mash(block_t x, block_t *keys)
{
	(void) x;
	(void) keys;
	return 0;
}

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys)
{
	(void) cipher_text;
	(void) expanded_keys;
	return 0;
}

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys)
{
	(void) plaintext_input;
	(void) encrypted_output;
	(void) pt_len;
	(void) expanded_keys;
}

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys)
{
	(void) encrypted_input;
	(void) plaintext_output;
	(void) pt_len;
	(void) expanded_keys;
}

// ----------------- Utility Functions ----------------- //