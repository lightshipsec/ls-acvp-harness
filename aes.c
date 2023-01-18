#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "acvp_lib.h"

#include "aes.h"


EVP_CIPHER_CTX *_aes_init(const EVP_CIPHER *cipher, const char *mode, int enc, const unsigned char *key, int key_len, const unsigned char *iv, int iv_len)  {
    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new())
       || !EVP_CipherInit(ctx, cipher, key, iv, enc)
       || !EVP_CIPHER_CTX_set_padding(ctx, 0))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

    /* Mode specific handling */
    if(!strcasecmp(mode, "cfb1"))  {
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS);
    }

error_die:
    return ctx;
}

/* This logic based on OpenSSL FIPS 2.0 module test case as well as
 * acvp_test.c sample in OpenSSL 3.0.
 */
int _aes_aft(const EVP_CIPHER *cipher, const char *mode, int enc, const unsigned char *input, int input_len, unsigned char *output, int *output_len, const unsigned char *key, int key_len, const unsigned char *iv, int iv_len)  {
    int ret = 0;

    EVP_CIPHER_CTX *ctx = _aes_init(cipher, mode, enc, key, key_len, iv, iv_len);
    if(!ctx)  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

    /* Perform the AES op on the input and place into output being
     * aware of finalizing it.
     */
    int outl = 0;
    /* TODO: Certain modes need to be treated carefully with Update and Final */
    if(!EVP_CipherUpdate(ctx, output, &outl, input, input_len))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

    int last_block_len = 0;
    if(!EVP_CipherFinal_ex(ctx, output + outl, &last_block_len))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }
    outl += last_block_len;

    /* Update with actual length (in bytes) */
    if(output_len)  {
        if (!strcasecmp(mode, "cfb1"))
            *output_len = (outl+7)/8;
        else 
            *output_len = outl;
    }
    ret = 1;
error_die:
    SAFE_FUNC_FREE(ctx, EVP_CIPHER_CTX_free);
    return ret;
}

int _aes_gcm_aft(const EVP_CIPHER *cipher, int enc, 
        const unsigned char *input, int input_len, 
        unsigned char *output, int *output_len, 
        const unsigned char *key, int key_len, 
        const unsigned char *iv, int iv_len,
        const unsigned char *aad, int aad_len,
        unsigned char *tag, int tag_len,
        int *pass)  {

    /* Mark as failure unless we get to the end properly */
    *pass = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx =_aes_init(cipher, "gcm", enc, key, key_len, iv, iv_len)) 
       /* GCM needs an IV length added; no IV is passed, just the length. */
       || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }
    if(!enc)
        /* If decrypting, then we need to be able to set the tag for confirmation purposes. */
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag))  {
            raise_error(/* TBD code */0);
            goto error_die;
        }

    int outl = 0;
    int last_block_len = 0;

    /* For GCM, add the aad first before doing the rest.
     * Note we don't care about the aad interim output length value, so throw away.
     * If we are decrypting, it is entirely possible that the provided tag will
     * fail purposefully, so we need to be able to mark the test as pass or fail.
    */
    if(!EVP_CipherInit(ctx, NULL, key, iv, enc)
       || !EVP_CipherUpdate(ctx, NULL, &outl, aad, aad_len)
       || !EVP_CipherUpdate(ctx, output, &outl, input, input_len)
       || !EVP_CipherFinal_ex(ctx, output + outl, &last_block_len))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

    outl += last_block_len;

    /* Finally get the tag if encrypting (so we can output it) */
    if(enc)  {
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag))  {
            raise_error(/* TBD code */0);
            goto error_die;
        }
    }

    /* Update with actual length */
    if(output_len)
        *output_len = outl;

    *pass = 1;

error_die:
    SAFE_FUNC_FREE(ctx, EVP_CIPHER_CTX_free);
    return *pass;              /* Return code 1 is GOOD; so *pass value can proxy it */
}





/**
 * Monte Carlo testing advised from OpenSSL FIPS 2.0.x test code.
 * Based on https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
 */

int _aes_ecb_mct(const EVP_CIPHER *cipher, int enc, const unsigned char *input, int input_len, const unsigned char *key, int key_len, cJSON *out)  {
    TRACE_PUSH;
    int ret = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) goto error_die;

    unsigned char tmpout[64];
    unsigned char keys[101][32];
    unsigned char inputs[1001][32];
    unsigned char outputs[1001][32];

    /* Set Key[0], P[0] */
    memcpy(keys[0], key, sizeof(keys[0]));
    memcpy(inputs[0], input, sizeof(inputs[0]));

    /* 100 iterations */
    for (int i = 0; i < 100; i ++)  {
        /* Prep output */
#ifdef TRACE
        printf("[MCT key[%d]]: ", i);
        print_bytearray(keys[i], key_len);
        printf("[MCT Input[0]]: ");
        print_bytearray(inputs[0], input_len);
#endif
        cJSON *mct_iter = cJSON_CreateObject ();
        SAFEPUT(put_array_item (mct_iter, out), "Unable to allocate MCT iteration in output JSON node\n");
        SAFEPUT(put_bytearray("key", keys[i], key_len, mct_iter), "Unable to add MCT test iteration\n");
        SAFEPUT(put_bytearray(enc ? "pt" : "ct", inputs[0], input_len, mct_iter), "Unable to add MCT test iteration\n");

        int outl = 0;
        int j = 0;
        for (; j < 1000; j ++)  {
            if(!EVP_CIPHER_CTX_reset(ctx)) goto error_die;
            if(!EVP_CipherInit(ctx, cipher, keys[i], /* No IV */NULL, enc)) goto error_die;
            /* Need to turn padding off to make this work so they can be chained */
            if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) goto error_die;
            /* CT[j] = AES(Key[i], PT[j]) */
            if(!EVP_CipherUpdate(ctx, outputs[j], &outl, inputs[j], input_len)) goto error_die;
            /* PT[j+1] = CT[j] */
            memcpy(inputs[j+1], outputs[j], outl);
        }
        /* The NIST document uses j post-loop, but forgets that the loop increments one
         * last time before we exit. So we need to decrement to be able to reference the
         * last output[] that was constructed.
         */
        j--;
#ifdef TRACE
        printf("[MCT Output[j]]: ");
        print_bytearray(outputs[j], outl);
#endif
        SAFEPUT(put_bytearray(enc ? "ct" : "pt", outputs[j], outl, mct_iter), "Unable to add MCT test iteration\n");

        switch(key_len * 8)  {
            case 128: xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/outputs[j], outl, /*dest*/keys[i+1], key_len); 
                      break;
                      /* Trying to make this readable as per the AESAVS algorithm which deals with bits, whereas we deal with bytes */
                      /* Essentially, take the last 64 bits [8 bytes] of the last output and concat with the next output. */
            case 192: concat_bytearray(/*lhs*/&(outputs[j-1][outl-8]), 8, /*rhs*/outputs[j], outl, /*dest*/tmpout, key_len);
                      xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/tmpout, key_len, /*dest*/keys[i+1], key_len); 
                      break;
            case 256: concat_bytearray(/*lhs*/outputs[j-1], outl, /*rhs*/outputs[j], outl, /*dest*/tmpout, key_len); 
                      xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/tmpout, key_len, /*dest*/keys[i+1], key_len); 
                      break;
            default:
                      goto error_die;
        }
        /* PT[0] = CT[j] */
        memcpy(inputs[0], outputs[j], outl);
    }

    ret = 1;
error_die:
    SAFE_FUNC_FREE(ctx, EVP_CIPHER_CTX_free);
    TRACE_POP;
    return ret;
}

int _aes_cbc_mct(const EVP_CIPHER *cipher, int enc, const unsigned char *input, int input_len, const unsigned char *key, int key_len, const unsigned char *iv, int iv_len, cJSON *out)  {
    TRACE_PUSH;
    int ret = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new()))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

    unsigned char tmpout[64];        /* Max size of 2 256-bit concatenated keys */
    unsigned char keys[101][32];
    unsigned char ivs[101][16];      /* AES block size */
    unsigned char inputs[1001][32]; 
    unsigned char outputs[1001][32];

    /* Set Key[0], PT[0], IV[0] */
    memcpy(keys[0], key, key_len);
    memcpy(ivs[0], iv, iv_len);
    memcpy(inputs[0], input, input_len);


    /* 100 iterations */
    for (int i = 0; i < 100; i ++)  {
        /* Prep output */
#ifdef TRACE
        printf("[MCT key[%d]]: ", i);
        print_bytearray(keys[i], key_len);
        printf("[MCT iv[%d]]: ", i);
        print_bytearray(ivs[i], iv_len);
        printf("[MCT Input[0]]: ");
        print_bytearray(inputs[0], input_len);
#endif
        cJSON *mct_iter = cJSON_CreateObject ();
        SAFEPUT(put_array_item (mct_iter, out), "Unable to allocate MCT iteration in output JSON node\n");
        SAFEPUT(put_bytearray("key", keys[i], key_len, mct_iter), "Unable to add MCT test iteration\n");
        SAFEPUT(put_bytearray("iv", ivs[i], iv_len, mct_iter), "Unable to add MCT test iteration\n");
        SAFEPUT(put_bytearray(enc ? "pt" : "ct", inputs[0], input_len, mct_iter), "Unable to add MCT test iteration\n");

        int outl = 0;
        int j = 0;
        for (; j < 1000; j ++)  {
            if(j == 0)  {
                if(!EVP_CIPHER_CTX_reset(ctx)) goto error_die;
                if(!EVP_CipherInit(ctx, cipher, keys[i], ivs[i], enc)) goto error_die;
                /* Have to turn off padding so that this chaining works properly */
                if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) goto error_die;
                /* CT[j] = AES(Key[i], IV[i], PT[j]) */
                if(!EVP_CipherUpdate(ctx, outputs[j], &outl, inputs[j], input_len)) goto error_die;
                /* PT[j+1] = IV[i] */
                memcpy(inputs[j+1], ivs[i], iv_len);
            }
            else  {
                /* CT[j] = AES(Key[i], PT[j]) -- context continues chaining */
                if(!EVP_CipherUpdate(ctx, outputs[j], &outl, inputs[j], input_len)) goto error_die;
                /* PT[j+1] = CT[j-1] */
                memcpy(inputs[j+1], outputs[j-1], outl);
            }
        }
        /* The NIST document uses j post-loop, but forgets that the loop increments one
         * last time before we exit. So we need to decrement to be able to reference the
         * last output[] that was constructed.
         */
        j--;
#ifdef TRACE
        printf("[MCT Output[j]]: ");
        print_bytearray(outputs[j], outl);
#endif
        SAFEPUT(put_bytearray(enc ? "ct" : "pt", outputs[j], outl, mct_iter), "Unable to add MCT test iteration\n");

        switch(key_len * 8)  {
            case 128: xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/outputs[j], outl, /*dest*/keys[i+1], key_len); 
                      break;
                      /* Trying to make this readable as per the AESAVS algorithm which deals with bits, whereas we deal with bytes */
                      /* Essentially, take the last 64 bits [8 bytes] of the last output and concat with the current output. */
            case 192: concat_bytearray(/*lhs*/&(outputs[j-1][outl-8]), 8, /*rhs*/outputs[j], outl, /*dest*/tmpout, key_len);
                      xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/tmpout, key_len, /*dest*/keys[i+1], key_len); 
                      break;
            case 256: concat_bytearray(/*lhs*/outputs[j-1], outl, /*rhs*/outputs[j], outl, /*dest*/tmpout, key_len); 
                      xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/tmpout, key_len, /*dest*/keys[i+1], key_len); 
                      break;
            default:
                      goto error_die;
        }
        /* IV[i+1] = CT[j] */
        memcpy(ivs[i+1], outputs[j], iv_len);
        /* PT[0] = CT[j-1] */
        memcpy(inputs[0], outputs[j-1], outl);
    }

    ret = 1;
error_die:
    SAFE_FUNC_FREE(ctx, EVP_CIPHER_CTX_free);
    TRACE_POP;
    return ret;
}



int _aes_cfb1_mct(const EVP_CIPHER *cipher, int enc, const unsigned char *input, int input_len, const unsigned char *key, int key_len, const unsigned char *iv, int iv_len, cJSON *out)  {
    TRACE_PUSH;
    int ret = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new()))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

#ifdef TRACE
    printf("Input len: %d\n", input_len);
#endif

    unsigned char tmpout[32];        /* Up to 256 bits */      
    unsigned char keys[101][32];
    unsigned char ivs[101][16];      /* AES block size */
    unsigned char inputs[1001][1] = {0}; 
    unsigned char outputs[1001][1] = {0};



    /* Set Key[0], PT[0], IV[0] */
    memcpy(keys[0], key, key_len);
    memcpy(ivs[0], iv, iv_len);
    memcpy(inputs[0], input, (input_len+7)/8);


    /* 100 iterations */
    for (int i = 0; i < 100; i ++)  {
        /* Prep output */
#ifdef TRACE
        printf("[MCT key[%d]]: ", i);
        print_bytearray(keys[i], key_len);
        printf("[MCT iv[%d]]: ", i);
        print_bytearray(ivs[i], iv_len);
        printf("[MCT Input[0]]: ");
        print_bytearray(inputs[0], (input_len+7)/8);
#endif
        cJSON *mct_iter = cJSON_CreateObject ();
        SAFEPUT(put_array_item (mct_iter, out), "Unable to allocate MCT iteration in output JSON node\n");
        SAFEPUT(put_bytearray("key", keys[i], key_len, mct_iter), "Unable to add MCT test iteration\n");
        SAFEPUT(put_bytearray("iv", ivs[i], iv_len, mct_iter), "Unable to add MCT test iteration\n");
        SAFEPUT(put_bytearray(enc ? "pt" : "ct", inputs[0], (input_len+7)/8, mct_iter), "Unable to add MCT test iteration\n");

        int outl_bits = 0;
        int j = 0;
        /* CFB1 is a bit different since we are dealing with bit indices.
         * Thus, this is 1000 iterations, but it's 1000 bits.  Each goes into its
         * own single byte, but the result only occupies the MSB.
         */
        for (; j < 1000; j ++)  {
            if(j == 0)  {
                if(!EVP_CIPHER_CTX_reset(ctx)) goto error_die;
                /* CT[j] = AES(Key[i], IV[i], PT[j]) */
                if(!EVP_CipherInit(ctx, cipher, keys[i], ivs[i], enc)) goto error_die;
                EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS);
                /* Have to turn off padding so that this chaining works properly */
                if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) goto error_die;
                if(!EVP_CipherUpdate(ctx, outputs[j], &outl_bits, inputs[j], input_len)) goto error_die;
                assert(outl_bits == 1);
                /* PT[j+1] = BITJ(IV[i]) */
                set_bit(inputs[j+1], get_bit(ivs[i], j), 0);
            }
            else  {
                /* CT[j] = AES(Key[i], PT[j]) -- context continues chaining */
                if(!EVP_CipherUpdate(ctx, outputs[j], &outl_bits, inputs[j], input_len)) goto error_die;
                assert(outl_bits == 1);
                if(j < 128)  {
                    /* PT[j+1] = BitJ(IV[i]) */
                    set_bit(inputs[j+1], get_bit(ivs[i], j), 0);
                }
                else  {
                    /* PT[j+1] = CT[j-128] */
                    set_bit(inputs[j+1], get_bit(outputs[j-128], 0), 0);
                }
            }
        }
        /* The NIST document uses j post-loop, but forgets that the loop increments one
         * last time before we exit. So we need to decrement to be able to reference the
         * last output[] that was constructed.
         */
        j--;
#ifdef TRACE
        printf("[MCT Output[j]]: %02x\n", (unsigned char)outputs[j][0]);
#endif
        SAFEPUT(put_bytearray(enc ? "ct" : "pt", outputs[j], 1, mct_iter), "Unable to add MCT test iteration\n");
 
        /* Depending on key_len, the index starts from there. For 128-bit keys, CT[j-127] || CT[j-126] || … || CT[j]
         * For 192-bit keys, CT[j-191] || CT[j-190] || … || CT[j]
         * etc.
         */
        /* This sets all of the bits in 'tmpout' based on the values in the outputs.
         * Bit we want the bits to go from MSB to LSB, and MSB is indexed from pos'n 0.
         * The outputs MSB is the one we want -- position 0 according to "get_bit" and the NIST def'n
         * of BITJ().
         * Bit results are placed into the MSB of the outputs buffer, so mask from 0x80 which 
         * gets the upper-most bit.
         */
        memset(tmpout, 0, sizeof(tmpout));
        for(int t = 0, k = (key_len*8)-1; k >= 0; k--, t++)  {
            set_bit(tmpout, get_bit(outputs[j-k], 0), t);
        }
        /* Key[i+1] = Key[i] xor ... above concatenation */
        xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/tmpout, key_len, /*dest*/keys[i+1], key_len); 

        /* IV[i+1] = (CT[j-127] || CT[j-126] || … || CT[j]) */
        memset(tmpout, 0, sizeof(tmpout));
        for(int t = 0, k = 127; k >= 0; k--, t++)
            set_bit(tmpout, get_bit(outputs[j-k], 0), t);
        memcpy(ivs[i+1], tmpout, iv_len);

        /* PT[0] = CT[j-128]; and (carefully) reset in specific order */
        memset(inputs, 0, sizeof(inputs));
        inputs[0][0] = outputs[j-128][0];
        memset(outputs, 0, sizeof(outputs));
    }

    ret = 1;
error_die:
    SAFE_FUNC_FREE(ctx, EVP_CIPHER_CTX_free);
    TRACE_POP;
    return ret;
}

/* Suitable for CFB8, CFB128 and OFB.
 * With some adjustment, could fix up CFB1 to work in here as well.  However, I do want to 
 * ensure that these are readable. CFB1 has some bit manipulation which could make it
 * a bit unreadable if we stick it in here.
 */
int _aes_feedback_mct(const EVP_CIPHER *cipher, int enc, const unsigned char *input, int input_len, const unsigned char *key, int key_len, const unsigned char *iv, int iv_len, cJSON *out)  {
    TRACE_PUSH;
    int ret = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new()))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

#ifdef TRACE
    printf("Input len: %d\n", input_len);
#endif

    unsigned char tmpout[32];        /* Up to 256 bits */      
    unsigned char keys[101][32];
    unsigned char ivs[101][16];      /* AES block size */
    unsigned char inputs[1001][32] = {0}; 
    unsigned char outputs[1001][32] = {0};



    /* Set Key[0], PT[0], IV[0] */
    memcpy(keys[0], key, key_len);
    memcpy(ivs[0], iv, iv_len);
    memcpy(inputs[0], input, input_len);


    /* 100 iterations */
    for (int i = 0; i < 100; i ++)  {
        /* Prep output */
#ifdef TRACE
        printf("[MCT key[%d]]: ", i);
        print_bytearray(keys[i], key_len);
        printf("[MCT iv[%d]]: ", i);
        print_bytearray(ivs[i], iv_len);
        printf("[MCT Input[0]]: ");
        print_bytearray(inputs[0], input_len);
#endif
        cJSON *mct_iter = cJSON_CreateObject ();
        SAFEPUT(put_array_item (mct_iter, out), "Unable to allocate MCT iteration in output JSON node\n");
        SAFEPUT(put_bytearray("key", keys[i], key_len, mct_iter), "Unable to add MCT test iteration\n");
        SAFEPUT(put_bytearray("iv", ivs[i], iv_len, mct_iter), "Unable to add MCT test iteration\n");
        SAFEPUT(put_bytearray(enc ? "pt" : "ct", inputs[0], input_len, mct_iter), "Unable to add MCT test iteration\n");

        int outl = 0;
        int j = 0;
        for (; j < 1000; j ++)  {
            if(j == 0)  {
                if(!EVP_CIPHER_CTX_reset(ctx)) goto error_die;
                /* CT[j] = AES(Key[i], IV[i], PT[j]) */
                if(!EVP_CipherInit(ctx, cipher, keys[i], ivs[i], enc)) goto error_die;
                /* Have to turn off padding so that this chaining works properly */
                if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) goto error_die;
                if(!EVP_CipherUpdate(ctx, outputs[j], &outl, inputs[j], input_len)) goto error_die;
                assert(outl == input_len);
                if(input_len == 1)                  // CFB8
                    /* PT[j+1] = ByteJ(IV[i]) */
                    inputs[j+1][0] = ivs[i][j];
                else                                // CFB128 and OFB
                    /* PT[j+1] = IV[i] */
                    memcpy(inputs[j+1], ivs[i], input_len);
            }
            else  {
                /* CT[j] = AES(Key[i], PT[j]) -- context continues chaining */
                if(!EVP_CipherUpdate(ctx, outputs[j], &outl, inputs[j], input_len)) goto error_die;
                assert(outl == input_len);
                if(input_len == 1)  {                // CFB8
                    if(j < 16)
                        /* PT[j+1] = ByteJ(IV[i]) */
                        inputs[j+1][0] = ivs[i][j];
                    else
                        /* PT[j+1] = CT[j-16] */
                        inputs[j+1][0] = outputs[j-16][0];
                }
                else                                // CFB128 and OFB
                    /* PT[j+1] = CT[j-1] */
                    memcpy(inputs[j+1], outputs[j-1], input_len);
            }
        }
        /* The NIST document uses j post-loop, but forgets that the loop increments one
         * last time before we exit. So we need to decrement to be able to reference the
         * last output[] that was constructed.
         */
        j--;
#ifdef TRACE
        printf("[MCT Output[%d]]: ", j);
        print_bytearray(outputs[j], outl);
#endif
        SAFEPUT(put_bytearray(enc ? "ct" : "pt", outputs[j], outl, mct_iter), "Unable to add MCT test iteration\n");

        /* CFB8 has slightly different treatment */
        if(input_len == 1)  {
            /* Depending on key_len, the index starts from there. For 128-bit keys, CT[j-15] || CT[j-14] || … || CT[j]
             * For 192-bit keys, CT[j-23] || CT[j-22] || … || CT[j]
             * etc.
             */
            memset(tmpout, 0, sizeof(tmpout));
            for(int t = 0, k = key_len-1; k >= 0; k--, t++)  {
               tmpout[t] = outputs[j-k][0];
            }
            /* Key[i+1] = Key[i] xor ... above concatenation */
            xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/tmpout, key_len, /*dest*/keys[i+1], key_len);

            /* IV[i+1] = (CT[j-15] || CT[j-14] || … || CT[j]) */
            memset(tmpout, 0, sizeof(tmpout));
            for(int t = 0, k = 15; k >= 0; k--, t++)
                tmpout[t] = outputs[j-k][0];
            memcpy(ivs[i+1], tmpout, iv_len);
        }
        else  {
            switch(key_len * 8)  {
                case 128: xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/outputs[j], outl, /*dest*/keys[i+1], key_len); 
                          break;
                          /* Trying to make this readable as per the AESAVS algorithm which deals with bits, whereas we deal with bytes */
                          /* Essentially, take the last 64 bits [8 bytes] of the last output and concat with the current output. */
                case 192: concat_bytearray(/*lhs*/&(outputs[j-1][outl-8]), 8, /*rhs*/outputs[j], outl, /*dest*/tmpout, key_len);
                          xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/tmpout, key_len, /*dest*/keys[i+1], key_len); 
                          break;
                case 256: concat_bytearray(/*lhs*/outputs[j-1], outl, /*rhs*/outputs[j], outl, /*dest*/tmpout, key_len); 
                          xor_bytearray(/*lhs*/keys[i], key_len, /*rhs*/tmpout, key_len, /*dest*/keys[i+1], key_len); 
                          break;
                default:
                          goto error_die;
            }
            /* IV[i+1] = CT[j] */
            memcpy(ivs[i+1], outputs[j], iv_len);
        }

        /* Carefully clear old data structures while assigning for next loop iteration */
        memset(inputs, 0, sizeof(inputs));

        if(input_len == 1)          // CFB8
            /* PT[0] = CT[j-16] */
            inputs[0][0] = outputs[j-16][0];
        else                        // CFB128 and OFB
            /* PT[0] = CT[j-1] */
            memcpy(inputs[0], outputs[j-1], input_len);

        memset(outputs, 0, sizeof(outputs));
    }

    ret = 1;
error_die:
    SAFE_FUNC_FREE(ctx, EVP_CIPHER_CTX_free);
    TRACE_POP;
    return ret;
}


int _aes_mct(const EVP_CIPHER *cipher, const char *mode, int enc, const unsigned char *input, int input_len, const unsigned char *key, int key_len, const unsigned char *iv, int iv_len, cJSON *out)  {
    TRACE_PUSH;
    int ret = 0;

    if(!strcasecmp(mode, "ecb"))
        ret = _aes_ecb_mct(cipher, enc, input, input_len, key, key_len, out);
    else if(!strcasecmp(mode, "cbc"))
        ret = _aes_cbc_mct(cipher, enc, input, input_len, key, key_len, iv, iv_len, out);
    else if(!strcasecmp(mode, "cfb1"))
        ret = _aes_cfb1_mct(cipher, enc, input, input_len, key, key_len, iv, iv_len, out);
    else if(!strcasecmp(mode, "cfb8") || !strcasecmp(mode, "cfb") || !strcasecmp(mode, "ofb"))
        ret = _aes_feedback_mct(cipher, enc, input, input_len, key, key_len, iv, iv_len, out);

    TRACE_POP;
    return ret;
}




/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_aes_v1_0(cJSON *j, void *options, cJSON *out, const char *mode)  {
    TRACE_PUSH;
    int ret = 0;    /* Assume failure until the end */

    char algname[32] = {0};
    EVP_CIPHER *cipher = NULL;
    unsigned char *key = NULL;
    int key_len_bytes = 0;
    unsigned char *iv = NULL;
    int iv_len_bytes = 0;
    unsigned char *pt = NULL;
    int pt_len = 0;
    unsigned char *ct = NULL;
    int ct_len = 0;
    const unsigned char *input = NULL;
    int input_len = 0;
    unsigned char *output = NULL;
    int output_len = 0;
    /* For GCM */
    unsigned char *aad = NULL;
    int aad_len_bytes = 0;
    unsigned char *tag = NULL;
    int tag_len_bytes = 0;

    int enc = 0;    /* Are we encrypting? 1 = yes; 0 = no */


    /* We are testing a vector set.
     * Parameters are found in both the testGroup and the test case.
     */
    cJSON *tgs = NULL;
    SAFEGET(get_object(&tgs, j, "testGroups"), "Missing 'testGroups' in input JSON\n");

    cJSON *tgs_output = cJSON_CreateArray ();
    SAFEPUT (put_object ("testGroups", tgs_output, out), "Unable to add testGroups to output JSON\n");

    cJSON *tg = NULL;
    cJSON_ArrayForEach(tg, tgs)  {
        int tgId = ACVP_JSON_get_testgroup_id(tg);
        _ACVP_JSON_context_push("testGroups", "tgId = %d", tgId);

        cJSON *tg_output = cJSON_CreateObject ();
        SAFEPUT (put_array_item (tg_output, tgs_output), "Unable to append test group to output\n");
        SAFEPUT (put_integer ("tgId", tgId, tg_output), "Unable to add tgId to test group %d\n", tgId);

        /* Everything _except_ keywrap has a key length. */
        int keylen_bits = 0;
        if(strcasecmp(mode, "kw"))  {
            cJSON *keyLen = NULL;
            SAFEGET(get_integer_object(&keyLen, tg, "keyLen"), "Missing `keyLen' in input JSON\n");
            keylen_bits = keyLen->valueint;
        }

        /* Check test type */
        cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");

        /* Get the direction */
        cJSON *direction = NULL;
        SAFEGET(get_string_object(&direction, tg, "direction"), "Missing `direction' in input JSON\n");

        cJSON *tests = NULL;
        SAFEGET(get_object(&tests, tg, "tests"), "Missing test cases in test group %d\n", tgId);

        cJSON *tests_output = cJSON_CreateArray ();
        SAFEPUT (put_object ("tests", tests_output, tg_output), "Unable to add tests array to output JSON for test group %d\n", tgId);

        cJSON *tc = NULL;
        cJSON_ArrayForEach(tc, tests)  {
            int tcId = ACVP_JSON_get_testcase_id(tc);
            _ACVP_JSON_context_push("tests", "tcId = %d", tcId);

            cJSON *tc_output = cJSON_CreateObject ();
            SAFEPUT (put_array_item (tc_output, tests_output), "Unable to append test case to test case array for group %d in JSON output\n", tgId);
            SAFEPUT (put_integer ("tcId", tcId, tc_output), "Unable to provide tcId to test case %d in test group %d in JSON output\n", tcId, tgId);

            SAFEGET(get_as_bytearray(&key, &key_len_bytes, tc, "key"), "Missing `key' in test case %d in test group %d\n", tcId, tgId);

            /* We should verify that key_len_bytes is consistent with keylen_bits? */
            assert(keylen_bits == key_len_bytes * 8);

            /* Everything except ECB, KW and possibly GCM has an IV */
            if(strcasecmp(mode, "ecb") != 0 && strcasecmp(mode, "kw") != 0)  {
                if(get_as_bytearray(&iv, &iv_len_bytes, tc, "iv") != 0)  { /* Missing in input */
                    /* Only an error if not gcm. Otherwise it is optional and we need to generate. */
                    if(!strcasecmp(mode, "gcm"))  {
                        /* Generate some IV bytes */
                        cJSON *ivLen_bits = NULL;
                        SAFEGET(get_integer_object(&ivLen_bits, tg, "ivLen"), "Missing ivLen in GCM test group %d\n", tgId);
                        iv_len_bytes = ivLen_bits->valueint / 8;
                        iv = malloc(iv_len_bytes);
                        if(!iv || !RAND_bytes(iv, iv_len_bytes))  {
                            raise_error(/*TBD code */0);
                            goto error_die;
                        }
                    }
                    else
                        fprintf(stdout, "Missing `iv' in test case %d in test group %d\n", tcId, tgId);
                }
            }


            /* Get the ciphertext or plaintext depending on which direction */
            if(strcmp("encrypt", direction->valuestring) == 0)  {
                SAFEGET(get_as_bytearray(&pt, &pt_len, tc, "pt"), "Missing plaintext in test case %d in test group %d\n", tcId, tgId);
#ifdef TRACE
                printf("Plaintext: ");
                print_bytearray(pt, pt_len);
#endif
                /* Ciphertext length can grow at most one more block depending on mode */
                ct_len = pt_len + EVP_MAX_BLOCK_LENGTH;
                if(!(ct = malloc(ct_len))
                   || !memset(ct, 0, ct_len)  )  {
                    goto error_die;
                }

                input = pt;
                input_len = pt_len;
                output = ct;
                output_len = ct_len;
                enc = 1;
            } 
            else if (strcmp("decrypt", direction->valuestring) == 0)  {
                SAFEGET(get_as_bytearray(&ct, &ct_len, tc, "ct"), "Missing ciphertext in test case %d in test group %d\n", tcId, tgId);
#ifdef TRACE
                printf("Ciphertext: ");
                print_bytearray(ct, ct_len);
#endif
                /* Plaintext can't be larger than ct_len, so set this */
                pt_len = ct_len;
                if(!(pt = malloc(pt_len))
                   || !memset(pt, 0, pt_len))  {
                    goto error_die;
                }

                input = ct;
                input_len = ct_len;
                output = pt;
                output_len = pt_len;
                enc = 0;
            } 
            else {
                raise_error(/*TBD code */0);
                goto error_die;
            }


            /* CFB bit-mode uses length from payloadLen */
            if(strcasecmp(mode, "cfb1") == 0)  {
                cJSON *payloadLen = NULL;
                SAFEGET(get_integer_object(&payloadLen, tc, "payloadLen"), "Missing payloadLen in CFB1 test case %d in test group %d\n", tcId, tgId);
                /* We will treat it has bits in the encryption/decryption routine */
                input_len = payloadLen->valueint;
            }
            /* GCM has an aad and a tag for decrypt */
            if(!strcasecmp(mode, "gcm"))  {
                cJSON *tagLen = NULL;
                SAFEGET(get_integer_object(&tagLen, tg, "tagLen"), "Missing tagLen in GCM test group %d\n", tgId);
                SAFEGET(get_as_bytearray(&aad, &aad_len_bytes, tc, "aad"), "Missing aad in test case %d in test group %d\n", tcId, tgId);
                if(strcmp("decrypt", direction->valuestring) == 0)  {
                    SAFEGET(get_as_bytearray(&tag, &tag_len_bytes, tc, "tag"), "Missing tag in test case %d in test group %d\n", tcId, tgId);
                    assert(tagLen->valueint == tag_len_bytes * 8);  /* JSON has it in bits */
                }
                else  {
                    /* We need to allocate space for it to be returned */
                    tag_len_bytes = tagLen->valueint / 8;
                    if(!(tag = malloc(tag_len_bytes))
                       || !memset(tag, 0, tag_len_bytes)) {
                        goto error_die;
                    }
                }

                /* Do a quick sanity check on payloadLen, aadLen and tagLen */
                cJSON *objLen = NULL;
                SAFEGET(get_integer_object(&objLen, tg, "payloadLen"), "Missing payloadLen in GCM test group %d\n", tgId);
                assert(input_len * 8 == objLen->valueint);
                SAFEGET(get_integer_object(&objLen, tg, "aadLen"), "Missing aadLen in GCM test group %d\n", tgId);
                assert(aad_len_bytes * 8 == objLen->valueint);
            }


            /* Execute AES test */
            snprintf(algname, sizeof(algname), "AES-%d-%s", keylen_bits, mode); /* Take advantage that name is case insensitive */
            cipher = EVP_CIPHER_fetch(NULL, algname, provider_str);

            char *out_label = "pt";
            if(enc)
                out_label = "ct";

            if(strcasecmp("AFT", test_type->valuestring) == 0)  {
                if(strcasecmp("gcm", mode) == 0)  {
                    int pass = 1;
                    if(_aes_gcm_aft(cipher, enc, input, input_len, output, &output_len, key, key_len_bytes, iv, iv_len_bytes, aad, aad_len_bytes, tag, tag_len_bytes, &pass) != 0)  {
                        raise_error(/*TBD code */0);
                    }
                    if(!pass)  {
#ifdef TRACE
                        fprintf(stdout, "testPassed = false\n");
#endif
                        SAFEPUT(put_boolean("testPassed", (cJSON_bool)pass, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
                    }
                    else  {
                        if(enc)
                            SAFEPUT(put_bytearray("tag", tag, tag_len_bytes, tc_output), "Unable to add tag to test case %d in test group %d in JSON output\n", tcId, tgId);
                        SAFEPUT(put_bytearray("iv", iv, iv_len_bytes, tc_output), "Unable to add iv to test case %d in test group %d in JSON output\n", tcId, tgId);
                        SAFEPUT(put_bytearray(out_label, output, output_len, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
                    }
                }
                else  {
                    if(!_aes_aft(cipher, mode, enc, input, input_len, output, &output_len, key, key_len_bytes, iv, iv_len_bytes))  {
                        raise_error(/*TBD code */0);
                    }
                    SAFEPUT(put_bytearray(out_label, output, output_len, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
                }
            }
            /* Just a version of AFT test cases with long input */
            if(strcasecmp("CTR", test_type->valuestring) == 0)  {
                if(!_aes_aft(cipher, mode, enc, input, input_len, output, &output_len, key, key_len_bytes, iv, iv_len_bytes))  {
                    raise_error(/*TBD code */0);
                }
                SAFEPUT(put_bytearray(out_label, output, output_len, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
            }
            if(strcasecmp("MCT", test_type->valuestring) == 0)  {
                cJSON *mct_results = cJSON_CreateArray ();
                SAFEPUT(put_object ("resultsArray", mct_results, tc_output),  "Unable to allocate resultsArray for MCT in test group %d\n", tgId);

                if(!_aes_mct(cipher, mode, enc, input, input_len, key, key_len_bytes, iv, iv_len_bytes, mct_results))  {
                    raise_error(/*TBD code */0);
                }
            }


#ifdef TRACE
            printf("[%s:%d:%d] Output: ", test_type->valuestring, tgId, tcId);
            print_bytearray(output, output_len);
            if(!strcasecmp("gcm", mode))  {
                printf("[%s:%d:%d] Tag: ", test_type->valuestring, tgId, tcId);
                print_bytearray(tag, tag_len_bytes);
                printf("[%s:%d:%d] IV: ", test_type->valuestring, tgId, tcId);
                print_bytearray(iv, iv_len_bytes);
            }
#endif

            SAFE_FUNC_FREE(cipher, EVP_CIPHER_free);
            SAFE_FUNC_FREE(ct, free);
            SAFE_FUNC_FREE(pt, free);
            SAFE_FUNC_FREE(key, free);
            SAFE_FUNC_FREE(iv, free);
            SAFE_FUNC_FREE(tag, free);
            SAFE_FUNC_FREE(aad, free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }
        _ACVP_JSON_context_pop();
    }

    /* Everything worked fine */
    ret = 1;

error_die:

    SAFE_FUNC_FREE(cipher, EVP_CIPHER_free);
    SAFE_FUNC_FREE(ct, free);
    SAFE_FUNC_FREE(pt, free);
    SAFE_FUNC_FREE(key, free);
    SAFE_FUNC_FREE(iv, free);
    SAFE_FUNC_FREE(tag, free);
    SAFE_FUNC_FREE(aad, free);

    TRACE_POP;
    return ret;
}


ACVP_TEST_ALG_SPEC_BEGIN(aes_ecb)
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "ecb")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(aes_cbc)
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "cbc")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(aes_ctr)
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "ctr")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(aes_cfb1)
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "cfb1")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(aes_cfb8)
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "cfb8")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(aes_cfb128)
/* OpenSSL treats CFB128 as 'CFB' since it is the default AES block size */
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "cfb")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(aes_gcm)
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "gcm")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(aes_ofb)
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "ofb")
ACVP_TEST_ALG_SPEC_END


ACVP_TEST_ALG_SPEC_BEGIN(aes_kw)
ACVP_TEST_ALG_SPEC_REV(aes, 1_0, ACVP_ALG_REVISION_1_0, "kw")
ACVP_TEST_ALG_SPEC_END
