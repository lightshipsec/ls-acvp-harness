#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/bn.h>


char *bin2hex(const unsigned char *bin, int bin_len, char *hex, int hex_len)  {
    if (!hex || (bin_len*2+1 > hex_len)) return NULL;
    for(int i=0, j=0; i < bin_len; i++, j+=2)
       sprintf((char *)&hex[j], "%02X", bin[i]);
    hex[bin_len*2] = '\x0';
    return hex;
}

char *bin2hex_m(const unsigned char *bin, int bin_len, char **hex, int *hex_len)  {
    if (!hex) return NULL;
    char *hex_r = *hex;
    hex_r = malloc(bin_len*2+1);
    *hex = bin2hex(bin, bin_len, hex_r, bin_len*2+1);
    *hex_len = bin_len*2+1;
    return hex_r;
}


unsigned char hex2bin_c(unsigned char c) {
    if(c >= 'A' && c <= 'F') return (c - 'A') + 10;
    else if(c >= 'a' && c <= 'f') return (c - 'a') + 10;
    else if(c >= '0' && c <= '9') return c - '0';
    return -1;
}

unsigned char *hex2bin(const char *hex, unsigned char *bin, int bin_len)  {
    /* This function only accepts strings which are even-length.
     * TODO: If we need to deal with odd-length strings, then we can treat the
     * leftmost hex digit as the lower nibble of a byte. 
    */
    int hex_len = strlen(hex);
    if(hex_len < 0) return NULL;
    if((hex_len % 2) || (bin_len != (hex_len / 2))) return NULL;
    if(!hex || !bin) return NULL;

    /* Take each hex pair and form a byte */
    int i = 0, j = 0;
    for(; i < hex_len; j++, i+=2) {
        unsigned char b = 0; 
        unsigned char n1 = 0, n2 = 0;
        /* Most significant nibble */
        n1 = hex2bin_c(hex[i]);
        if(n1 < 0) goto error_die;
        /* least significant nibble */
        n2 = hex2bin_c(hex[i+1]);
        if(n2 < 0) goto error_die;
        b = (n1 << 4) | n2;
        bin[j] = b;
    }
    return bin;

error_die:
    return NULL;
}

unsigned char *hex2bin_m(const char *hex, int *bin_len)  {
    if(!hex || !bin_len) return NULL;
    int bl = (strlen(hex) + 1) / 2;
    unsigned char *bin = malloc(bl);
    if(!bin) return NULL;
    /* Else good */
    if(hex2bin(hex, bin, bl) == NULL)  {
        free(bin);
        return NULL;
    }
    /* Else good */
    *bin_len = bl;
    return bin;
}

BIGNUM *hex2bn(const char *hex)  {
    BIGNUM *bn = BN_new();
    if(!bn) return NULL;
    if(!BN_hex2bn(&bn, hex)) 
        BN_free(bn);
    return bn;
}


void print_bytearray(const unsigned char *b, int l)  {
    for (int i = 0; i < l; i++)  {
        printf("%02x", b[i]);
    }
    printf("\n");
}

void xor_bytearray(const unsigned char *lhs, int lhs_len, const unsigned char *rhs, int rhs_len, unsigned char *output, int output_len)  {
    assert(lhs_len == rhs_len);
    assert(rhs_len == output_len);
    for(int i = 0; i < lhs_len; i ++) 
        output[i] = lhs[i] ^ rhs[i];
}

void concat_bytearray(const unsigned char *lhs, int lhs_len, const unsigned char *rhs, int rhs_len, unsigned char *output, int output_len)  {
    assert(output_len >= (lhs_len + rhs_len));
    for(int i = 0; i < lhs_len; i ++) 
        output[i] = lhs[i];
    for(int i = 0, j = lhs_len; i < rhs_len; i++, j++) 
        output[j] = rhs[i];
}

int get_bit(const unsigned char *input, int j)  {
    /* Get the jth bit of input starting from MSB */
    /* Figure out how many bytes j is, then move that, plus the residual */
    int n = j / 8;
    int r = 7 - (j % 8);
    return (input[n] >> r) & 0x1;
}

void set_bit(unsigned char *input, int s, int j)  {
    /* Set the jth bit to the 1st bit in s starting from MSB. */
    int n = j / 8;
    int r = 7 - (j % 8);
    input[n] |= ((s & 0x1) << r);
}

unsigned char *reverse_bytearray(unsigned char *in, int in_len)  {
    for (int i = 0, j = in_len-1; i < j; i++, j--)  {
        unsigned char c = in[i];
        in[i] = in[j];
        in[j] = c;
    }
    return in;
}
