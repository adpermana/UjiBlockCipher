#ifndef BLOCK_CIPHER_AWD_H
#define BLOCK_CIPHER_AWD_H

#define BIT_AES 128
#define BYTE_AES (BIT_AES >> 3)

typedef unsigned char byte;

byte *read_hex_line(FILE *file, unsigned int linenumber, unsigned int linelength);
byte *generate_random_bytes(unsigned int length);
byte *xor_bytes(byte *b1, byte *b2, unsigned int length);

void print_bytes(byte *bytes, unsigned int length);
void flip_bit(byte *bytes, unsigned int length, unsigned int pos);

unsigned int hamming_weight_bytes(byte *b, unsigned int length);

double *ac_AES(int num_inputs, unsigned int bit_length);
double *ac_AES_file(FILE *filePlaintext, FILE *fileKey, int num_inputs, unsigned int bit_length);

double bic_AES_file(FILE *filePlaintext, FILE *fileKey, unsigned int num_inputs, unsigned int bit_length);
double bic_AES_random(unsigned int num_inputs, unsigned int bit_length);

float **sac_AES(int num_inputs, unsigned int bit_length);
float **sac_AES_file(FILE *filePlaintext, FILE *fileKey, int num_inputs, unsigned int bit_length);

unsigned int **awd_count_AES(int num_inputs, unsigned int bit_length);
unsigned int **awd_count_AES_file(FILE *filePlaintext, FILE *fileKey, int num_inputs, unsigned int bit_length);
unsigned int *awd_binom_distrib(int num_inputs, unsigned int n);

double awd_resemblance(unsigned int *awd_array, unsigned int *awd_binom, unsigned int n, unsigned int num_inputs);

#endif //BLOCK_CIPHER_AWD_H
