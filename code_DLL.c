#include <stdio.h>
#include "cypher_dll_header.h"
#include <conio.h>
#include <malloc.h>

// 10101100 << 2 = 10110000 | 00000010 = 10110010
#define LSHIFT_nBIT(x, L, N) (((x << L) | (x >> (-L & (N - 1)))) & (((uint64_t)1 << N) - 1))
#define RSHIFT_nBIT(x, R, N) (((x >> R) | (x << (-R & (N - 1)))) & (((uint64_t)1 << N) - 1))

#define BUFF_SIZE 1024

static inline void print_array(uint8_t * array, size_t length);
static inline void print_bits(uint64_t x, register uint64_t Nbit);

// 1 | 4 -> 0xC
static const uint8_t Sbox[8][16] = {
	{ 0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3 },
	{ 0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1 },
	{ 0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2 },
	{ 0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8 },
	{ 0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1 },
	{ 0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6 },
	{ 0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7 },
	{ 0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE },
};

// <for debug>
void printBits(size_t const size, void const * const ptr)
{
	unsigned char *b = (unsigned char*)ptr;
	unsigned char byte;
	int i, j;

	for (i = size - 1; i >= 0; i--) {
		for (j = 7; j >= 0; j--) {
			byte = (b[i] >> j) & 1;
			printf("%u", byte);
		}
	}
	puts("");
}

uint8_t *my_strcpy(uint8_t *destination, uint8_t *source, int size)
{
	uint8_t *start = destination;
	int i = 0;
	while (i < size)
	{
		*destination = *source;
		destination++;
		source++;
		i++;
	}
	return start;
}
uint8_t *strdupl(const uint8_t *src, int size) {
	uint8_t *dst = malloc(size + 1);  // Space for length plus nul
	if (dst == NULL) return NULL;          // No memory
	my_strcpy(dst, src, size);                      // Copy the characters

	dst[size] = size;
	return dst;                            // Return the new string
}

// </for debug>

uint8_t * cypher(uint8_t * str, int * length_of_string, uint8_t * key, uint8_t * init_vect, int init_vect_size, uint8_t add_param_size, int cypher_mode, char mode) {

	uint8_t encrypted[BUFF_SIZE], decrypted[BUFF_SIZE];
	uint8_t key256b[32];
	uint8_t mac[8] = "\0\0\0\0\0\0\0\0";
	uint8_t buffer[BUFF_SIZE];
	uint8_t * synchro = malloc(init_vect_size);
	size_t init_vector_size = init_vect_size;
	size_t addit_param_size = add_param_size;
	size_t position = 0;
	
	

	while (position < 32) {
		key256b[position] = key[position];
		position++;
	}
	position = 0;

	if (cypher_mode == 1)
		while (position < 32)
		{
			synchro[position] = init_vect[position];
			position++;
		}
	else if (cypher_mode != 0 && cypher_mode != 1)
		while (position < init_vector_size)
		{
			synchro[position] = init_vect[position];
			position++;
		}
	position = 0;
	while (position != *length_of_string && position < BUFF_SIZE - 1)
		buffer[position] = str[position++];
	buffer[position] = '\0';

/*
	printf("Encrypted message:\n");
//	position = CFB_mode(encrypted, 'E', synchro, 32, size_of_add_param, key256b, buffer, position);
	encrypted[position] = '\0';
	print_array(encrypted, position);
	printf("%s\n", encrypted);
	putchar('\n');

	printf("Decrypted message:\n");
//	position = CFB_mode(decrypted, 'E', synchro, 32, 9, key256b, encrypted, position);
	decrypted[position] = '\0';
	print_array(decrypted, position);
	printf("%s\n", decrypted);
	putchar('\n');
*/
switch (cypher_mode)
{
case 0:
	if (mode == 'e')
		position = GOST_28147(encrypted, 'E', key256b, buffer, position);
	if (mode == 'd')
		position = GOST_28147(decrypted, 'D', key256b, buffer, position);
	break;
case 1:
	if (mode == 'e')
		position = CTR_mode(encrypted, 'E', synchro, key256b, buffer, position);
	if (mode == 'd')
		position = CTR_mode(decrypted, 'E', synchro, key256b, buffer, position);
	break;
case 2:
	if (mode == 'e')
		position = OFB_mode(encrypted, 'E', synchro, init_vector_size, key256b, buffer, position);
	if (mode == 'd')
		position = OFB_mode(decrypted, 'E', synchro, init_vector_size, key256b, buffer, position);
	break;
case 3:
	if (mode == 'e')
		position = CBC_mode(encrypted, 'E', synchro, init_vector_size, key256b, buffer, position);
	if (mode == 'd')
		position = CBC_mode(decrypted, 'D', synchro, init_vector_size, key256b, buffer, position);
	break;
case 4:
	if (mode == 'e')
		position = CFB_mode(encrypted, 'E', synchro, init_vector_size, addit_param_size, key256b, buffer, position);
	if (mode == 'd')
		position = CFB_mode(decrypted, 'D', synchro, init_vector_size, addit_param_size, key256b, buffer, position);
	break;
case 5:
	if (mode == 'e')
		position = MAC_addition(encrypted, 'E', key256b, buffer, mac, position);
	if (mode == 'd')
		position = MAC_addition(encrypted, 'D', key256b, buffer, mac, position);
	break;
}
	if (cypher_mode == 5)
	{
		*length_of_string = 8;
		return strdupl(mac, *length_of_string);
	}
	if (mode == 'e')
	{
		printf("encryption success\n");
		*length_of_string = position;
		printf("new length = %d\n", *length_of_string);
		return strdupl(encrypted, position);
	}
	else if (mode == 'd')
	{
		printf("decryption success/n");
		*length_of_string = position;
		printf("new length = %d\n", *length_of_string);
		return strdupl(decrypted, position);
	}
	else
	{
		*length_of_string = 17;
		return _strdup("need a parameter");
	}
	
}

size_t CTR_mode(uint64_t * to, uint8_t mode, uint32_t * init_vector_second_half, uint8_t * key256b, uint64_t * from, size_t length)
{
	size_t gamma_blocks_quantity = length % 8 == 0 ? length : length + (8 - (length % 8));
	gamma_blocks_quantity /= 8;
	// dangerous malloc goes ON
	uint64_t * init_vector_64b = malloc(gamma_blocks_quantity * 8);
	uint64_t * gamma_blocks_64b = malloc(gamma_blocks_quantity * 8);
	uint32_t init_vector_second_half_32b = *init_vector_second_half;
	// init_vector_first_half_counter_32b = 00000000000000000000000000000000
	uint32_t init_vector_first_half_counter_32b = 0;

	// each of 'proto' gamma blocks (initializing vector and next variations of that vector) has to be assembled of first half and second half
	// init_vector_64b[i] = 01000000111000001100000010011000 + 00000000000000000000000000000000; i = 0
	// init_vector_64b[i] = 01000000111000001100000010011000 + 00000000000000000000000000000001; i = 1
	// init_vector_64b[i] = 01000000111000001100000010011000 + 00000000000000000000000000000010; i = 2
	// init_vector_64b[i] = 01000000111000001100000010011000 + 00000000000000000000000000000011; i = 3

	for (size_t i = 0; i < gamma_blocks_quantity; i++)
	{
		init_vector_64b[i] = join_32bits_to_64bits(init_vector_first_half_counter_32b + i, init_vector_second_half_32b);
	}

	// making gamma blocks
	GOST_28147(gamma_blocks_64b, mode, key256b, init_vector_64b, length);
	// final, XOR operation
	// 0100000011100000110000001001100000000000000000000000000011100010 ^
	// 1010011000001110000001000111000110000000011110000011000011100011 =
	// 1110011011101110110001001110100110000000011110000011000000000001
	// simmilar bits = 0; different bits = 1;

	for (size_t i = 0; i < gamma_blocks_quantity; i++)
	{
		to[i] = from[i] ^ gamma_blocks_64b[i];
	}
	return length;
}

size_t OFB_mode(uint64_t * to, uint8_t mode, uint8_t * init_vector, size_t init_vector_size, uint8_t * key256b, uint64_t * from, size_t length)
{
	size_t gamma_blocks_quantity = length % 8 == 0 ? length : length + (8 - (length % 8));
	gamma_blocks_quantity /= 8;
	uint64_t gamma_block = 0;
	uint64_t * reg_64b = malloc(init_vector_size);


	printf("<<OFB mode is ON>>\n\n");
	// fulfill the register with initial vector bit values as OFB cypher process begins
	for (size_t i = 0; i < init_vector_size / 8; i++)
	{
		reg_64b[i] = join_8bits_to_64bits(init_vector + (i * 8));
	}

	for (size_t i = 0; i < gamma_blocks_quantity; i++)
	{
		// encrypting that into gamma block
		GOST_28147(reg_64b + (init_vector_size / 8) - 1, 'E', key256b, reg_64b + (init_vector_size / 8) - 1, 8);
		// fetching n part from register as 'proto' gamma block
		gamma_block = *(reg_64b + (init_vector_size / 8) - 1);
		// accomplishing XOR procedure	
		to[i] = from[i] ^ gamma_block;

		// shifting the register to the left on 64 bits and inserting n part to 'beginning' of register
		left_shift_array_64(reg_64b, init_vector_size);
		reg_64b[0] = gamma_block;
	}

	printf("\n<<OFB mode is OFF>>\n\n");
	return length;
}

size_t CBC_mode(uint64_t * to, uint8_t mode, uint8_t * init_vector, size_t init_vector_size, uint8_t * key256b, uint64_t * from, size_t length)
{
	// first, ensure that length is multiple of 64
	length = length % 8 == 0 ? length : length + (8 - (length % 8));
	uint64_t * reg_64b = malloc(init_vector_size);
	uint64_t decrypted_cypher_text_storage;
	// fulfill the register with initial vector bit values as CBC cypher process begins
	printf("Init_Vector_Size = %zu\n", init_vector_size);
	for (size_t i = 0; i < init_vector_size / 8; i++)
	{
		reg_64b[i] = join_8bits_to_64bits(init_vector + (i * 8));
	}
	// the encryption cycle begins

	switch (mode)
	{
	case 'E': case 'e': {
		for (size_t i = 0; i < length / 8; i++)
		{
			to[i] = reg_64b[init_vector_size / 8 - 1] ^ from[i];
			GOST_28147(to + i, mode, key256b, to + i, 8);
			left_shift_array_64(reg_64b, init_vector_size);
			reg_64b[0] = to[i];

		}
		break;
	}
	case 'D': case 'd': {
		for (size_t i = 0; i < length / 8; i++)
		{
			GOST_28147(&decrypted_cypher_text_storage, mode, key256b, from + i, 8);
			to[i] = reg_64b[init_vector_size / 8 - 1] ^ decrypted_cypher_text_storage;
			left_shift_array_64(reg_64b, init_vector_size);
			reg_64b[0] = from[i];
		}
		break;
	}
	}
	return length;
}

size_t CFB_mode(uint8_t * to, uint8_t mode, uint8_t * init_vector, size_t init_vector_size, size_t addit_parameter_size, uint8_t * key256b, uint8_t * from, size_t length)
{
	uint8_t * gamma_block = malloc(8);
	uint8_t * reg_8b = malloc(init_vector_size);
	uint8_t size_gamma = 0;

	for (size_t i = 0; i < init_vector_size; i++)
	{
		reg_8b[i] = init_vector[i];
	}

	// the encryption cycle begins
	switch (mode)
	{
	case 'e': case 'E':
	{
		for (size_t i = 0; i < length; i += addit_parameter_size)
		{
			GOST_28147(reg_8b + init_vector_size - 9, 'E', key256b, reg_8b + init_vector_size - 9, 8);
			// encrypting that into gamma block
			// accomplishing XOR procedure	
			while (size_gamma < addit_parameter_size)
			{
				to[i + size_gamma] = from[i + size_gamma] ^ *(reg_8b + init_vector_size - 9 + size_gamma);
				size_gamma++;
			}
			// shifting the register to the left on 64 bits and inserting n part to 'beginning' of register
			for (size_t j = 0; j < size_gamma; j++)
			{
				gamma_block[j] = to[i + j];
			}
			left_shift_array_custom(reg_8b, init_vector_size, addit_parameter_size);
			for (size_t j = 0; j < size_gamma; j++)
			{
				reg_8b[j] = gamma_block[j];
			}
			size_gamma = 0;
		}
		break;
	}
	case 'd': case 'D':
	{
		for (size_t i = 0; i < length; i += addit_parameter_size)
		{
			GOST_28147(reg_8b + init_vector_size - 9, 'E', key256b, reg_8b + init_vector_size - 9, 8);
			// encrypting that into gamma block
			// accomplishing XOR procedure	
			for (size_t j = 0; j < addit_parameter_size; j++)
			{
				gamma_block[j] = from[i + j];
			}
			while (size_gamma < addit_parameter_size)
			{
				to[i + size_gamma] = from[i + size_gamma] ^ *(reg_8b + init_vector_size - 9 + size_gamma);
				size_gamma++;
			}
			// shifting the register to the left on 64 bits and inserting n part to 'beginning' of register
			left_shift_array_custom(reg_8b, init_vector_size, addit_parameter_size);
			for (size_t j = 0; j < size_gamma; j++)
			{
				reg_8b[j] = gamma_block[j];
			}
			size_gamma = 0;
		}
		break;
	}
	}


	return length;
}

size_t MAC_addition(uint8_t * to, uint8_t mode, uint8_t * key256b, uint8_t * from, uint64_t * mac, size_t length)
{
	uint64_t mac_func = 0;
	uint64_t r = 0;
	GOST_28147(&r, 'E', key256b, &r, 8);
	uint64_t key1;
	uint64_t key2;
	uint8_t last_block_has_been_padded_with_bits = 0;
	length = length % 8 == 0 ? length : length + (8 - (length % 8)), last_block_has_been_padded_with_bits++;
	uint32_t N1, N2, keys32b[8];
	split_256bits_to_32bits(key256b, keys32b);

	if (r < 0xA000000000000000)
		key1 = r << 1;
	else
		key1 = (r << 1) ^ 0x000000000000000B;
	if (key1 < 0xA000000000000000)
		key2 = key1 << 1;
	else
		key2 = (key1 << 1) ^ 0x000000000000000B;

	for (size_t i = 0; i < length - 8; i += 8) {
		mac_func = mac_func ^ join_8bits_to_64bits(from + i);
		split_64bits_to_32bits(
			join_8bits_to_64bits(&mac_func),
			&N1, &N2
		);
		feistel_cipher('E', &N1, &N2, keys32b);
		split_64bits_to_8bits(
			join_32bits_to_64bits(N1, N2),
			(&mac_func)
		);
	}
	if (last_block_has_been_padded_with_bits == 0)
	{
		mac_func = mac_func ^ join_8bits_to_64bits(from + length - 1) ^ key1;
		split_64bits_to_32bits(
			join_8bits_to_64bits(&mac_func),
			&N1, &N2
		);
		feistel_cipher('E', &N1, &N2, keys32b);
		split_64bits_to_8bits(
			join_32bits_to_64bits(N1, N2),
			(&mac_func)
		);
	}
	else
	{
		mac_func = mac_func ^ join_8bits_to_64bits(from + length - 1) ^ key2;
		split_64bits_to_32bits(
			join_8bits_to_64bits(&mac_func),
			&N1, &N2
		);
		feistel_cipher(mode, &N1, &N2, keys32b);
		split_64bits_to_8bits(
			join_32bits_to_64bits(N1, N2),
			(&mac_func)
		);
	}
	*mac = mac_func;

	return length;
}

size_t GOST_28147(uint8_t * to, uint8_t mode, uint8_t * key256b, uint8_t * from, size_t length) {
	length = length % 8 == 0 ? length : length + (8 - (length % 8));
	uint32_t N1, N2, keys32b[8];
	split_256bits_to_32bits(key256b, keys32b);

	for (size_t i = 0; i < length; i += 8) {
		split_64bits_to_32bits(
			join_8bits_to_64bits(from + i),
			&N1, &N2
		);
		feistel_cipher(mode, &N1, &N2, keys32b);
		split_64bits_to_8bits(
			join_32bits_to_64bits(N1, N2),
			(to + i)
		);
	}

	return length;
}

// keys32b = [K0, K1, K2, K3, K4, K5, K6, K7]
void feistel_cipher(uint8_t mode, uint32_t * block32b_1, uint32_t * block32b_2, uint32_t * keys32b) {
	switch (mode) {
	case 'E': case 'e': {
		// K0, K1, K2, K3, K4, K5, K6, K7, K0, K1, K2, K3, K4, K5, K6, K7, K0, K1, K2, K3, K4, K5, K6, K7
		for (uint8_t round = 0; round < 24; ++round)
			round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round);

		// K7, K6, K5, K4, K3, K2, K1, K0
		for (uint8_t round = 31; round >= 24; --round)
			round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round);
		break;
	}
	case 'D': case 'd': {
		// K0, K1, K2, K3, K4, K5, K6, K7
		for (uint8_t round = 0; round < 8; ++round)
			round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round);

		// K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0
		for (uint8_t round = 31; round >= 8; --round)
			round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round);
		break;
	}
	}
}

void round_of_feistel_cipher(uint32_t * block32b_1, uint32_t * block32b_2, uint32_t * keys32b, uint8_t round) {
	uint32_t result_of_iter, temp;

	// RES = (N1 + Ki) mod 2^32
	result_of_iter = (*block32b_1 + keys32b[round % 8]) % UINT32_MAX;

	// RES = RES -> Sbox
	result_of_iter = substitution_table(result_of_iter, round % 8);

	// RES = RES <<< 11
	result_of_iter = (uint32_t)LSHIFT_nBIT(result_of_iter, 11, 32);

	// N1, N2 = (RES xor N2), N1
	temp = *block32b_1;
	*block32b_1 = result_of_iter ^ *block32b_2;
	*block32b_2 = temp;
}

uint32_t substitution_table(uint32_t block32b, uint8_t sbox_row) {
	uint8_t blocks4bits[4];
	split_32bits_to_8bits(block32b, blocks4bits);
	substitution_table_by_4bits(blocks4bits, sbox_row);
	return join_4bits_to_32bits(blocks4bits);
}

void substitution_table_by_4bits(uint8_t * blocks4b, uint8_t sbox_row) {
	uint8_t block4b_1, block4b_2;
	for (uint8_t i = 0; i < 4; ++i) {
		// 10101100 & 0x0F = 00001100
		// [example get from table] 1100 -> 1001
		block4b_1 = Sbox[sbox_row][blocks4b[i] & 0x0F];

		// 10101100 >> 4 = 00001010
		// [example get from table] 1010 -> 0111
		block4b_2 = Sbox[sbox_row][blocks4b[i] >> 4];

		// 00001001
		blocks4b[i] = block4b_2;

		// (00001001 << 4) | 0111 = 
		// 1001000 | 0111 = 10010111 
		blocks4b[i] = (blocks4b[i] << 4) | block4b_1;
	}
}

void split_any_to_any(uint8_t * whole, uint8_t * splitted) {
	uint8_t *p1 = whole;
	// p32[0] = 00000000000000000000000000000000

	for (uint8_t *p2 = splitted; p2 < p2 + 8; ++p2) {
		// 00000000000000000000000000000000 << 8 | 10010010 = 00000000000000000000000010010010
		// 00000000000000000000000010010010 << 8 | 00011110 = 00000000000000001001001000011110
		// 00000000000000001001001000011110 << 8 | 11100011 = 00000000100100100001111011100011
		// 00000000100100100001111011100011 << 8 | 01010101 = 10010010000111101110001101010101
		for (uint8_t i = 0; i < 4; ++i) {
			*p2 = (*p2 << 8) | *(p1 + i);
		}
		p1 += 4;
	}
}

void split_256bits_to_32bits(uint8_t * key256b, uint32_t * keys32b) {
	uint8_t *p8 = key256b;
	// p32[0] = 00000000000000000000000000000000
	for (uint32_t *p32 = keys32b; p32 < keys32b + 8; ++p32) {
		// 00000000000000000000000000000000 << 8 | 10010010 = 00000000000000000000000010010010
		// 00000000000000000000000010010010 << 8 | 00011110 = 00000000000000001001001000011110
		// 00000000000000001001001000011110 << 8 | 11100011 = 00000000100100100001111011100011
		// 00000000100100100001111011100011 << 8 | 01010101 = 10010010000111101110001101010101
		for (uint8_t i = 0; i < 4; ++i) {
			*p32 = (*p32 << 8) | *(p8 + i);
		}
		p8 += 4;
	}
}

void split_64bits_to_32bits(uint64_t block64b, uint32_t * block32b_1, uint32_t * block32b_2) {
	// N1 = (uint32_t)0000101010101010101010101010101010101010101010101010101010101111 =
	// = 10101010101010101010101010101111
	*block32b_2 = (uint32_t)(block64b);

	// N2 = (uint32_t)0000101010101010101010101010101010101010101010101010101010101111 >> 32 = 
	// = (uint32_t)000000000000000000000000000010101010101010101010101010101111 = 
	// = 10101010101010101010101010101111
	*block32b_1 = (uint32_t)(block64b >> 32);
}

void split_64bits_to_8bits(uint64_t block64b, uint8_t * blocks8b) {
	for (size_t i = 0; i < 8; ++i) {
		// blocks8b[0] = 
		// = (uint8_t)0000101010101010101010101010101010101010101010101010101010101111 >> ((7 - 0) * 8)
		// = (uint8_t)0000101010101010101010101010101010101010101010101010101010101111 >> 56 =
		// = (uint8_t)0000000000000000000000000000000000000000000000000000000000001010 =
		// = 00001010
		blocks8b[i] = (uint8_t)(block64b >> ((7 - i) * 8));
	}
}

void split_32bits_to_8bits(uint32_t block32b, uint8_t * blocks8b) {
	for (uint8_t i = 0; i < 4; ++i) {
		// blocks8b[0] = (uint8_t)10111101000101010100101110100010 >> (28 - (0 * 8)) =
		// = (uint8_t)10101010101010101010101010101010 >> 28 = 
		// = (uint8_t)00000000000000000000000010111101
		// = 10111101
		blocks8b[i] = (uint8_t)(block32b >> (24 - (i * 8)));
	}
}


uint64_t join_32bits_to_64bits(uint32_t block32b_1, uint32_t block32b_2) {
	uint64_t block64b;
	// block64b = 10101010101010101010101010101010 = 
	// 0000000000000000000000000000000010101010101010101010101010101010
	block64b = block32b_2;
	// block64b = 
	// = (0000000000000000000000000000000010101010101010101010101010101010 << 32) | 11111111111111111111111111111111 = 
	// = 1010101010101010101010101010101000000000000000000000000000000000 | 11111111111111111111111111111111 = 
	// = 101010101010101010101010101010111111111111111111111111111111111
	block64b = (block64b << 32) | block32b_1;
	return block64b;
}

uint64_t join_8bits_to_64bits(uint8_t * blocks8b) {
	uint64_t block64b;
	// block64b = 0000000000000000000000000000000000000000000000000000000000000000
	for (uint8_t *p = blocks8b; p < blocks8b + 8; ++p) {
		// i = 0
		// (0000000000000000000000000000000000000000000000000000000000000000 << 8) | 11001100 = 
		// 0000000000000000000000000000000000000000000000000000000011001100
		// i = 1
		// (0000000000000000000000000000000000000000000000000000000011001100 << 8) | 11110011 = 
		// 0000000000000000000000000000000000000000000000001100110000000000 | 11110011 = 
		// 0000000000000000000000000000000000000000000000001100110011110011
		// ... i < 8 ...
		block64b = (block64b << 8) | *p;
	}
	return block64b;
}

uint32_t join_8bits_to_32bits(uint8_t * blocks8b) {
	uint32_t block32b = 0;
	// block64b = 0000000000000000000000000000000000000000000000000000000000000000
	for (uint8_t *p = blocks8b; p < blocks8b + 4; ++p) {
		// i = 0
		// (0000000000000000000000000000000000000000000000000000000000000000 << 8) | 11001100 = 
		// 0000000000000000000000000000000000000000000000000000000011001100
		// i = 1
		// (0000000000000000000000000000000000000000000000000000000011001100 << 8) | 11110011 = 
		// 0000000000000000000000000000000000000000000000001100110000000000 | 11110011 = 
		// 0000000000000000000000000000000000000000000000001100110011110011
		// ... i < 8 ...
		block32b = (block32b << 8) | *p;
	}
	return block32b;
}

uint32_t join_4bits_to_32bits(uint8_t * blocks4b) {
	uint32_t block32b;
	// block64b = 00000000000000000000000000000000
	for (uint8_t i = 0; i < 4; ++i) {
		// i = 0
		// (00000000000000000000000000000000 << 8) | 11001100 = 
		// 00000000000000000000000011001100
		// i = 1
		// (00000000000000000000000011001100 << 8) | 11110011 = 
		// 00000000000000001100110000000000 | 11110011 = 
		// 00000000000000001100110011110011
		// ... i < 4 ...
		block32b = (block32b << 8) | blocks4b[i];
	}
	return block32b;
}

static inline void print_array(uint8_t * array, size_t length) {
	printf("[ ");
	for (size_t i = 0; i < length; ++i)
		printf("%d ", array[i]);
	printf("]\n");
}

static inline void print_bits(uint64_t x, register uint64_t Nbit) {
	for (Nbit = (uint64_t)1 << (Nbit - 1); Nbit > 0x00; Nbit >>= 1)
		printf("%d", (x & Nbit) ? 1 : 0);
	putchar('\n');
}

void left_shift_array_64(uint8_t * arr, size_t len)
{
	uint64_t bits1 = 0;
	uint64_t bits2 = 0;
	uint64_t * arr64 = arr;
	for (int i = 0; i < len / 8; i++)
	{
		bits2 = arr64[i] & 0xFFFFFFFFFFFFFFFF;
		// 1111111111111111111111111111111111111111111111111111111111111111 0xFFFFFFFFFFFFFFFF
		arr64[i] <<= 64;
		arr64[i] |= bits1;
		bits1 = bits2;
	}
}


void left_shift_array_custom(uint8_t * arr, size_t len, size_t shift)
{
	uint8_t bits1 = 0;
	uint8_t bits2 = 0;
	for (int j = 0; j < shift; j++)
	{
		bits1 = 0;
		bits2 = 0;
		for (int i = 0; i < len; i++)
		{
			bits2 = arr[i] & 0xFF;
			// 1111 1111 0xFF
			arr[i] <<= 8;
			arr[i] |= bits1;
			bits1 = bits2;
		}
	}
}