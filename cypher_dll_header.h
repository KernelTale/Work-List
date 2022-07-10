#include <stdint.h>

size_t GOST_28147(uint8_t * to, uint8_t mode, uint8_t * key256b, uint8_t * from, size_t length);
void feistel_cipher(uint8_t mode, uint32_t * block32b_1, uint32_t * block32b_2, uint32_t * keys32b);
void round_of_feistel_cipher(uint32_t * block32b_1, uint32_t * block32b_2, uint32_t * keys32b, uint8_t round);

uint32_t substitution_table(uint32_t block32b, uint8_t sbox_row);
void substitution_table_by_4bits(uint8_t * blocks4b, uint8_t sbox_row);

void split_256bits_to_32bits(uint8_t * key256b, uint32_t * keys32b);
void split_64bits_to_32bits(uint64_t block64b, uint32_t * block32b_1, uint32_t * block32b_2);
void split_64bits_to_8bits(uint64_t block64b, uint8_t * blocks8b);
void split_32bits_to_8bits(uint32_t block32b, uint8_t * blocks4b);

uint64_t join_32bits_to_64bits(uint32_t block32b_1, uint32_t block32b_2);
uint64_t join_8bits_to_64bits(uint8_t * blocks8b);
uint32_t join_4bits_to_32bits(uint8_t * blocks4b);

// update 28.05.2022

size_t CTR_mode(uint8_t *, uint32_t *, uint8_t *, size_t);
uint32_t join_8bits_to_32bits(uint8_t *);
size_t OFB_mode(uint64_t *, uint8_t, uint8_t *, size_t, uint8_t *, uint64_t *, size_t);
void left_shift_array_64(uint8_t *, size_t);
size_t CFB_mode(uint8_t *, uint8_t, uint8_t *, size_t, size_t, uint8_t *, uint8_t *, size_t);
size_t MAC_addition(uint8_t *, uint8_t, uint8_t *, uint8_t *, uint64_t *, size_t);
__declspec(dllexport) uint8_t * cypher(uint8_t *, int *, uint8_t *, uint8_t *, int, uint8_t, int, char);
void left_shift_array_custom(uint8_t *, size_t, size_t);