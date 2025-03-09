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
	if (endian == 0){
		for (int i = 3; i < (full_length*4)+3; i+=4){
			int full_payload_sequence = (packet[i] << 8*3) | (packet[i+1] << 8*2) | (packet[i+2] << 8) | packet[i+3];
			printf("%0x ",full_payload_sequence);
		}
	} else if (endian == 1){
		for (int i = 3; i < (full_length*4)+3; i+=4){
			int full_payload_sequence = packet[i]| (packet[i+1] << 8*1) | (packet[i+2] << 8*2) | (packet[i+3] << 8*3);
			printf("%0x ",full_payload_sequence);
		}
	}
	printf("\n");
}

unsigned char* build_packets(int data[], int data_length, int max_fragment_size, int endianness, int array_number)
{
	unsigned char *aflent;

	if ((data_length*4) <= max_fragment_size){
		int size = 3+(data_length*4);
		aflent = (unsigned char *) malloc(size * sizeof(char));

		// Created Row 0
		int row0 = array_number<<2;
		int fragment_number = 0;
		row0 = ((fragment_number & 0x18) >> 3) | row0;

		// Created Row 1
		int row1 = (fragment_number & 0x07) << 5;
		row1 = ((data_length & 0x3E0) >> 5) | row1;
		
		// Created Row 2
		int row2 = ((data_length & 0x1F) << 3);
		row2 = (row2 | (0<<2)); // if encrypte
		row2 = (endianness << 1) | row2; // if endian
		row2 = (row2 | (1)); // if last

		aflent[0] = row0;
		aflent[1] = row1;
		aflent[2] = row2;

		int payload_index = 3;
		for (int i = 0; i < data_length;i++){
			int main_val = data[i];
			
			int first = (main_val & 0xFF000000) >> 24;
			int second = (main_val & 0x00FF0000) >> 16;
			int third = (main_val & 0x0000FF00) >> 8;
			int fourth = (main_val & 0x000000FF);

			if (endianness == 0){
				aflent[payload_index++] = first;
				aflent[payload_index++] = second;
				aflent[payload_index++] = third;
				aflent[payload_index++] = fourth;
			}else{
				aflent[payload_index++] = fourth;
				aflent[payload_index++] = third;
				aflent[payload_index++] = second;
				aflent[payload_index++] = first;
			}

		}
	} else{
		int val = ceil(((data_length*4)/(max_fragment_size*1.0)));
		int size = (data_length)*4 + (3*val);
		aflent = (unsigned char *) malloc(size * sizeof(char));

		int remainder_data = (data_length*4)%(max_fragment_size);

		int payload_index = 0;
		int i = 0;

		for (int frag_number = 0; frag_number < val; frag_number++){
			
			// Created Row 0
			int row0 = array_number<<2;
			int fragment_number = frag_number;
			row0 = ((fragment_number & 0x18) >> 3) | row0;

			// Created Row 1
			int row1 = (fragment_number & 0x07) << 5;
			
			// Created Row 2
			int row2;

			int counter;

			if ((frag_number == val-1) && (remainder_data != 0)){
				row1 = ((((remainder_data/4)) & 0x3E0) >> 5) | row1;
				row2 = ((((remainder_data/4)) & 0x1F) << 3);
				counter = (remainder_data/4);
			} else {
				row1 = (((max_fragment_size/4) & 0x3E0) >> 5) | row1;
				row2 = (((max_fragment_size/4) & 0x1F) << 3);
				counter = (max_fragment_size/4);
			}

			row2 = (row2 | (0<<2)); // if encrypted
			row2 = (endianness << 1) | row2; // if endian
			
			if ((frag_number == val-1)){
				row2 = (row2 | (1)); // if last
			} else {
				row2 = (row2 | (0)); // if not last
			}

			aflent[payload_index++] = row0;
			aflent[payload_index++] = row1;
			aflent[payload_index++] = row2;

			for (int k = 0;k < counter; k++){
				int main_val = data[i++];
				int first = (main_val & 0xFF000000) >> 24;
				int second = (main_val & 0x00FF0000) >> 16;
				int third = (main_val & 0x0000FF00) >> 8;
				int fourth = (main_val & 0x000000FF);
				if (endianness == 0){
					aflent[payload_index++] = first;
					aflent[payload_index++] = second;
					aflent[payload_index++] = third;
					aflent[payload_index++] = fourth;
				}else{
					aflent[payload_index++] = fourth;
					aflent[payload_index++] = third;
					aflent[payload_index++] = second;
					aflent[payload_index++] = first;
				}
			}
		}
	}

	return aflent;
}

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths)
{	
	int sentinel_value = -1;
	int frag_count = 32;
	int **temp_array = malloc(array_count*sizeof(int*));
	for (int i = 0; i < array_count; i++) {
		temp_array[i] = malloc(frag_count*sizeof(int));
	}

	for (int i = 0; i<array_count;i++){
		for (int k = 0; k<frag_count;k++){
			temp_array[i][k] = sentinel_value;
		}
	}

	int header_found_counter = 0;
	int i = 0;
	int last_counter[array_count];
	
	for (int k = 0; k<array_count;k++){
		last_counter[k] = 0;
	}

	int total_fragments = 0;
	int all_found = 0;

	while ((all_found != 1) || (total_fragments != header_found_counter)){
		// Array Number
		int row_zero = packets[i];
		int array_number = (row_zero & 0xFC) >> 2;

		// Fragment Number
		int first_frag_part = (row_zero & 0x03) << 3;
		int row_one = packets[i+1];
		int second_frag_part = (row_one & 0xE0) >> 5;
		int fragment_number = first_frag_part | second_frag_part;

		// Length
		int first_length_part = (row_one & 0x1F) << 5;
		int row_two = packets[i+2];
		int second_length_part = (row_two & 0xF8) >> 3;
		int length = first_length_part | second_length_part;

		// Encrypt, Endian, Last
		int last = (row_two & 0x01);

		if (last == 1 && last_counter[array_number] == 0) {
			last_counter[array_number] = 1;
			total_fragments += (fragment_number+1);
		}		

		all_found = 1;
		for (int k = 0; k < array_count; k++) {
			if (last_counter[k] == 0) {
				all_found = 0;
				break;
			}
		}

		temp_array[array_number][fragment_number] = i;

		i += (length*4)+3;
		header_found_counter++;
	}

	// Creating the final array
	int **final_array = malloc(array_count * sizeof(int*));
	for (int k = 0; k < array_count; k++){
		final_array[k] = malloc(frag_count * sizeof(int));
	}

	for (int j = 0; j<array_count;j++){
		for (int k = 0; k<frag_count;k++){
			final_array[j][k] = sentinel_value;
		}
	}

	for (int k = 0; k < array_count; k++){
		int counter = 0;
		for (int j = 0; j < frag_count; j++){
			int index = temp_array[k][j];
			if (index == sentinel_value) break;

			// Length
			int row_one = packets[index+1];
			int first_length_part = (row_one & 0x1F) << 5;
			int row_two = packets[index+2];
			int second_length_part = (row_two & 0xF8) >> 3;
			int full_length = first_length_part | second_length_part;
			
			// Endian
			int endian = (row_two & 0x02) >> 1;

			int full_payload_sequence;

			if (endian == 0){
				for (int l = index+3; l < (full_length*4)+index+3; l+=4){
					full_payload_sequence = (packets[l] << 8*3) | (packets[l+1] << 8*2) | (packets[l+2] << 8) | packets[l+3];
					final_array[k][counter++] = full_payload_sequence;
				}
			} else if (endian == 1){
				for (int l = index+3; l < (full_length*4)+index+3; l+=4){
					full_payload_sequence = packets[l]| (packets[l+1] << 8*1) | (packets[l+2] << 8*2) | (packets[l+3] << 8*3);
					final_array[k][counter++] = full_payload_sequence;
				}
			}
		}
	}

	// Array Lengths Created
	for (int k = 0; k < array_count; k++){
		int array_lengths_counter = 0;
		for (int j = 0; j < frag_count; j++){
			if (final_array[k][j] == sentinel_value) break;
			array_lengths_counter++;
		}
		array_lengths[k] = array_lengths_counter;
	}

	// Reallocating and Trimming
	for (int k = 0; k < array_count; k++){
		int size = array_lengths[k];
		final_array[k] = realloc(final_array[k],size * sizeof(int));
	}
	
	// Freeing Heap
	for (int k = 0; k< array_count; k++) free(temp_array[k]);
	free(temp_array);
	
	return final_array;
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
	shamt = shamt % 8;
	return (x << shamt) | (x >> (8 - shamt));
}

uint8_t rotr(uint8_t x, uint8_t shamt)
{
	shamt = shamt % 8;
	return (x >> shamt) | (x << (8 - shamt));
}

block_t reverse(block_t x)
{
	for (int i = 0; i < 16; i++){
		block_t first_pos = i;
		block_t second_pos = 31-i;

		block_t first_int = (x & (1 << i)) >> i;
		block_t second_int = (x & (1 << second_pos)) >> second_pos;

		// Setting first bit
		if (first_int == 1) x |= (1 << second_pos);
		else x &= ~(1 << second_pos);

		// Setting second bit
		if (second_int == 1) x |= (1 << first_pos);
		else x &= ~(1 << first_pos);
	}
	return x;
}

block_t shuffle4(block_t x)
{
	block_t shuffled_val = 0;
	block_t first_half = ((x >> 16) & (0xffff));
	block_t second_half = (x & 0xffff);
	block_t masks[] = {0x000F,0x00F0,0x0F00,0xF000};
	for (int i = 0; i < 4; i++){
		block_t first_part = (first_half & masks[i])<<4*(i+1);
		block_t second_part = (second_half & masks[i])<<4*(i);
		shuffled_val |= first_part;
		shuffled_val |= second_part;
	}
	return shuffled_val;
}

block_t unshuffle4(block_t x)
{
	int masks1[] = {0x000000F0,0x0000F000,0x00F00000,0xF0000000};
	int masks2[] = {0x0000000F,0x00000F00,0x000F0000,0x0F000000};
	block_t complete_val = 0;

	for (int i = 0; i < 4; i++){
		complete_val |= (x & masks1[i]) << (3-i)*4;
		complete_val |= (x & masks2[i]) >> i*4;
	}

	return complete_val;
}

block_t shuffle1(block_t x)
{
	block_t shuffled_val = 0;
	
	block_t first_half = ((x >> 16) & (0xffff));
	block_t second_half = (x & 0xffff);
	
	block_t masks[] = {0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 
		0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000};

	for (int i = 0; i < 16; i++){
		shuffled_val |= (first_half & masks[i])<<(i+1);
		shuffled_val |= (second_half & masks[i])<<(i);
	}
	return shuffled_val;
}

block_t unshuffle1(block_t x)
{
	uint32_t masks2[] = {0x00000001,0x00000004,0x00000010,0x00000040,0x00000100,
		0x00000400,0x00001000,0x00004000,0x00010000,0x00040000,0x00100000,
		0x00400000,0x01000000,0x04000000,0x10000000,0x40000000
	};
	
	uint32_t masks1[] = {0x00000002,0x00000008,0x00000020,0x00000080,0x00000200,
		0x00000800,0x00002000,0x00008000,0x00020000,0x00080000,0x00200000,
		0x00800000,0x02000000,0x08000000,0x20000000,0x80000000 
	};
	
	block_t complete_val = 0;

	for (int i = 0; i < 16; i++){
		complete_val |= (x & masks1[i]) << (15-i);
		complete_val |= (x & masks2[i]) >> i;
	}

	return complete_val;
}

uint8_t nth_byte(block_t x, uint8_t n)
{
	uint8_t idx = n & 3;
	return (x >> (8 * idx)) & 0xFF;
}

// ----------------- Encryption Functions ----------------- //

uint8_t scramble_op(block_t B, uint8_t i, block_t keyA, block_t keyB)
{    
	uint8_t rot_table[] = {2, 3, 5, 7};
    uint8_t B1 = nth_byte(B, i) ^ (nth_byte(B, i - 1) & nth_byte(B, i - 2)) ^ ((~nth_byte(B, i - 1)) & nth_byte(B, i - 3)) ^ nth_byte(keyA, i) ^ nth_byte(keyB, i);    
    return rotl(B1, rot_table[i & 3]);
}

uint8_t r_scramble_op(block_t B, uint8_t i, block_t keyA, block_t keyB)
{
    uint8_t r_rot_table[] = {2, 3, 5, 7};
    uint8_t B1 = rotr(nth_byte(B, i), r_rot_table[i & 3]);
    return B1 ^ (nth_byte(B, i - 1) & nth_byte(B, i - 2)) ^ ((~nth_byte(B, i - 1)) & nth_byte(B, i - 3)) ^ nth_byte(keyA, i) ^ nth_byte(keyB, i);
}

uint8_t mash_op(block_t B, uint8_t i, block_t *S)
{
    uint8_t prev_byte = nth_byte(B, i-1);
    uint8_t index = prev_byte & 31;
    block_t key = S[index];
    return nth_byte(B, i) ^ nth_byte(key, i);
}

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys)
{
    expanded_keys[0] = (key & 0xffffffff);
    expanded_keys[1] = ((key >> 32) & (0xffffffff));

    for (int i = 2; i <= 31; i++) {
		expanded_keys[i] = (table[(expanded_keys[i-1] ^ expanded_keys[i-2]) % 64] ^ expanded_keys[i-1]);
	}

    for (int i = 29; i >=0; i--) {
        expanded_keys[i] = (table[(expanded_keys[i+1] ^ expanded_keys[i+2]) % 64] ^ expanded_keys[i]);
    }
}


block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
    block_t keyA = keys[round];
    block_t keyB = keys[31 - round];
    
    block_t result = op(x);
    
    uint8_t byte0 = scramble_op(result, 0, keyA, keyB);
    result = (result & 0xFFFFFF00) | byte0;
    
    uint8_t byte1 = scramble_op(result, 1, keyA, keyB);
    result = (result & 0xFFFF00FF) | (byte1 << 8);
    
    uint8_t byte2 = scramble_op(result, 2, keyA, keyB);
    result = (result & 0xFF00FFFF) | (byte2 << 16);
    
    uint8_t byte3 = scramble_op(result, 3, keyA, keyB);
    result = (result & 0x00FFFFFF) | (byte3 << 24);
    
    return result;
}



block_t mash(block_t x, block_t *keys)
{   
	block_t result = x;
    uint8_t byte0 = mash_op(x, 0, keys);
	result = (result & 0xFFFFFF00) | byte0;

    uint8_t byte1 = mash_op(result, 1, keys);
	result = (result & 0xFFFF00FF) | (byte1 << 8);

    uint8_t byte2 = mash_op(result, 2, keys);
	result = (result & 0xFF00FFFF) | (byte2 << 16);

    uint8_t byte3 = mash_op(result, 3, keys); 
	result = (result & 0x00FFFFFF) | (byte3 << 24);
    
    return result;
}

block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys)
{
    block_t R01 = scramble(plain_text, expanded_keys, 0, reverse);
    block_t R02 = scramble(R01, expanded_keys, 1, shuffle1);
    block_t R03 = scramble(R02, expanded_keys, 2, shuffle4);
    block_t R04 = scramble(R03, expanded_keys, 3, reverse);
    block_t R05 = mash(R04, expanded_keys);
    
    block_t R06 = scramble(R05, expanded_keys, 4, reverse);
    block_t R07 = scramble(R06, expanded_keys, 5, shuffle1);
    block_t R08 = scramble(R07, expanded_keys, 6, shuffle4);
    block_t R09 = scramble(R08, expanded_keys, 7, reverse);
    block_t R10 = mash(R09, expanded_keys);
    
    block_t R11 = scramble(R10, expanded_keys, 8, reverse);
    block_t R12 = scramble(R11, expanded_keys, 9, shuffle1);
    block_t R13 = scramble(R12, expanded_keys, 10, shuffle4);
    block_t R14 = scramble(R13, expanded_keys, 11, reverse);
    block_t R15 = mash(R14, expanded_keys);
    
    block_t R16 = scramble(R15, expanded_keys, 12, reverse);
    block_t R17 = scramble(R16, expanded_keys, 13, shuffle1);
    block_t R18 = scramble(R17, expanded_keys, 14, shuffle4);
    block_t R19 = scramble(R18, expanded_keys, 15, reverse);
    
    return R19;
}

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	block_t keyA = keys[round];
    block_t keyB = keys[31 - round];
    
    block_t result = x;
    
    uint8_t byte0 = r_scramble_op(result, 3, keyA, keyB);
    result = (result & 0x00FFFFFF) | (byte0 << 24);
    
    uint8_t byte1 = r_scramble_op(result, 2, keyA, keyB);
    result = (result & 0xFF00FFFF) | (byte1 << 16);
    
    uint8_t byte2 = r_scramble_op(result, 1, keyA, keyB);
    result = (result & 0xFFFF00FF) | (byte2 << 8);
    
    uint8_t byte3 = r_scramble_op(result, 0, keyA, keyB);
    result = (result & 0xFFFFFF00) | byte3;
    
    return op(result);
}

block_t r_mash(block_t x, block_t *keys)
{
	block_t result = x;

    uint8_t byte0 = mash_op(result, 3, keys);
	result = (result & 0x00FFFFFF) | (byte0 << 24);

    uint8_t byte1 = mash_op(result, 2, keys);
	result = (result & 0xFF00FFFF) | (byte1 << 16);

    uint8_t byte2 = mash_op(result, 1, keys);
	result = (result & 0xFFFF00FF) | (byte2 << 8);

    uint8_t byte3 = mash_op(result, 0, keys); 
	result = (result & 0xFFFFFF00) | byte3;
    
    return result;
}

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys)
{
    block_t R01 = r_scramble(cipher_text, expanded_keys, 15, reverse);
    block_t R02 = r_scramble(R01, expanded_keys, 14, unshuffle4);
    block_t R03 = r_scramble(R02, expanded_keys, 13, unshuffle1);
    block_t R04 = r_scramble(R03, expanded_keys, 12, reverse);
    block_t R05 = r_mash(R04, expanded_keys);
    
    block_t R06 = r_scramble(R05, expanded_keys, 11, reverse);
    block_t R07 = r_scramble(R06, expanded_keys, 10, unshuffle4);
    block_t R08 = r_scramble(R07, expanded_keys, 9, unshuffle1);
    block_t R09 = r_scramble(R08, expanded_keys, 8, reverse);
    block_t R10 = r_mash(R09, expanded_keys);
    
    block_t R11 = r_scramble(R10, expanded_keys, 7, reverse);
    block_t R12 = r_scramble(R11, expanded_keys, 6, unshuffle4);
    block_t R13 = r_scramble(R12, expanded_keys, 5, unshuffle1);
    block_t R14 = r_scramble(R13, expanded_keys, 4, reverse);
    block_t R15 = r_mash(R14, expanded_keys);
    
    block_t R16 = r_scramble(R15, expanded_keys, 3, reverse);
    block_t R17 = r_scramble(R16, expanded_keys, 2, unshuffle4);
    block_t R18 = r_scramble(R17, expanded_keys, 1, unshuffle1);
    block_t R19 = r_scramble(R18, expanded_keys, 0, reverse);
    
    return R19;
}


void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys)
{
    size_t num_blocks = ceil(pt_len/4.0);
    for (size_t i = 0; i < num_blocks; i++) {
        block_t current_block = 0;
        
        size_t bytes_in_block = 4;
        if ((i+1) * 4 > pt_len) {
            bytes_in_block = pt_len - (i * 4);
        }
        
        for (size_t j = 0; j < bytes_in_block; j++) {
            current_block |= ((block_t)plaintext_input[i * 4 + j] << (8 * j));
        }
        encrypted_output[i] = sbu_encrypt_block(current_block, expanded_keys);
    }
}

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys)
{
	size_t num_blocks = ceil(pt_len/4.0);
	unsigned long counter = 0;
	for (size_t i = 0; i < num_blocks; i++) {
        uint32_t val = encrypted_input[i];
		uint32_t decryp_val = sbu_decrypt_block(val,expanded_keys);

		uint8_t first_val = (decryp_val & 0xFF000000) >> 24;
		uint8_t second_val = (decryp_val & 0x00FF0000) >> 16;
		uint8_t third_val = (decryp_val & 0x0000FF00) >> 8;
		uint8_t fourth_val = (decryp_val & 0x000000FF);

		if ((counter)<pt_len) plaintext_output[counter++] = fourth_val;
		else break;

		if ((counter)<pt_len) plaintext_output[counter++] = third_val;
		else break;

		if ((counter)<pt_len) plaintext_output[counter++] = second_val;
		else break;

		if ((counter)<pt_len) plaintext_output[counter++] = first_val;
		else break;
    }
}