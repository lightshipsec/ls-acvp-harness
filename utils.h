#ifndef _UTILS_H
#define _UTILS_H

#include <openssl/bn.h>

char *bin2hex(unsigned char *bin, int bin_len, char *hex, int hex_len);
char *bin2hex_m(unsigned char *bin, int bin_len, char **hex, int *hex_len);
unsigned char hex2bin_c(unsigned char c);
unsigned char *hex2bin(const char *hex, unsigned char *bin, int bin_len);
unsigned char *hex2bin_m(const char *hex, int *bin_len);
BIGNUM *hex2bn(const char *hex);
void print_bytearray(const unsigned char *b, int l);
int xor_bytearray(const unsigned char *lhs, int lhs_len, const unsigned char *rhs, int rhs_len, unsigned char *output, int output_len);
int concat_bytearray(const unsigned char *lhs, int lhs_len, const unsigned char *rhs, int rhs_len, unsigned char *output, int output_len);
int get_bit(const unsigned char *input, int j);
void set_bit(unsigned char *input, int s, int j);
unsigned char *reverse_bytearray(unsigned char *in, int in_len);

#endif
