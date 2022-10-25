#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include <openssl/obj_mac.h>



char * ls_hash_SN_fetch(const char *algname)  {
    if (!strcasecmp(algname, "SHA-1"))
        return SN_sha1;
    else if (!strcasecmp(algname, "SHA2-224"))
        return SN_sha224;
    else if (!strcasecmp(algname, "SHA2-256"))
        return SN_sha256;
    else if (!strcasecmp(algname, "SHA2-384"))
        return SN_sha384;
    else if (!strcasecmp(algname, "SHA2-512"))
        return SN_sha512;

    printf("Error fetching algorithm with identifier '%s'\n", algname);
    return NULL;
};

char * ls_cipher_ctr_SN_fetch(const char *algname)  {
    if (!strcasecmp(algname, "AES-128"))
        return SN_aes_128_ctr;
    else if (!strcasecmp(algname, "AES-192"))
        return SN_aes_192_ctr;
    else if (!strcasecmp(algname, "AES-256"))
        return SN_aes_256_ctr;
    
    printf("Error fetching algorithm with identifier '%s'\n", algname);
    return NULL;
};
