#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#include "acvp_lib.h"

#include "tdes.h"


EVP_CIPHER_CTX *_tdes_init(const EVP_CIPHER *cipher, int enc, 
        const unsigned char *key1, int key1_len, 
        const unsigned char *key2, int key2_len, 
        const unsigned char *key3, int key3_len, 
        const unsigned char *iv, int iv_len)  {
    EVP_CIPHER_CTX *ctx = NULL;

    assert(key1_len == 8 && key2_len == 8 && key3_len == 8);

    /* Combine the keys */
    unsigned char key[8*3] = {0};
    memcpy(&key[0], key1, key1_len);
    memcpy(&key[8], key2, key2_len);
    memcpy(&key[16], key3, key3_len);

    if(!(ctx = EVP_CIPHER_CTX_new())
       || !EVP_CipherInit(ctx, cipher, key, iv, enc)
       || !EVP_CIPHER_CTX_set_padding(ctx, 0))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

error_die:
    return ctx;
}


int _tdes_aft(const EVP_CIPHER *cipher, int enc, 
        const unsigned char *input, int input_len, 
        unsigned char *output, int *output_len, 
        const unsigned char *key1, int key1_len, 
        const unsigned char *key2, int key2_len, 
        const unsigned char *key3, int key3_len, 
        const unsigned char *iv, int iv_len)  {
    int ret = 0;

    EVP_CIPHER_CTX *ctx = _tdes_init(cipher, enc, key1, key1_len, key2, key2_len, key3, key3_len, iv, iv_len);
    if(!ctx)  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

    /* Perform the TDES op on the input and place into output being
     * aware of finalizing it.
     */
    int outl = 0;
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
    *output_len = outl;
    ret = 1;
error_die:
    SAFE_FUNC_FREE(ctx, EVP_CIPHER_CTX_free);
    return ret;
}





#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
void _deprecated_DES_set_odd_parity(unsigned char *key)  {
    DES_set_odd_parity((unsigned char (*)[8])key);
}
#pragma GCC diagnostic pop


/**
 * This Monte Carlo testing works for both CBC and ECB modes.
 * The only difference between them is whether the IV is used.
 *
 * NOTE: One of the things I originally wanted to ensure was
 * that these routines were readable when compared with the spec.
 * We only support CBC and ECB for this Monte Carlo routine.
 * The differences between them are reasonably small that the 
 * logic differences do not get lost.  With that said, there
 * are enough minor differences that I almost want to pull 
 * these into two separate functions.
 * We do not have a flag to indicate if this is "ECB" vs
 * "CBC".  Instead I use a proxy measure in some cases: whether
 * there is a non-NULL IV being used.
 */
int _tdes_mct(const EVP_CIPHER *cipher, int enc, 
        const unsigned char *input, int input_len, 
        const unsigned char *key1, int key1_len, 
        const unsigned char *key2, int key2_len, 
        const unsigned char *key3, int key3_len, 
        int keyingOption,
        const unsigned char *iv, int iv_len, 
        cJSON *out)  {
    TRACE_PUSH;
    int ret = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new()))  {
        raise_error(/* TBD code */0);
        goto error_die;
    }

    unsigned char keys1[401][8];
    unsigned char keys2[401][8];
    unsigned char keys3[401][8];
    unsigned char ivs[10001][8];          /* 3DES block size */
    unsigned char inputs[10001][32]; 
    unsigned char outputs[10001][32];

    /* Set Key1[0], Key2[0], Key[3], PT[0], IV[0] */
    memcpy(keys1[0], key1, key1_len);
    memcpy(keys2[0], key2, key2_len);
    memcpy(keys3[0], key3, key3_len);
    if(iv)
        memcpy(ivs[0], iv, iv_len);
    memcpy(inputs[0], input, input_len);


    for (int i = 0; i < 400; i ++)  {
        /* Prep output */
        cJSON *mct_iter = cJSON_CreateObject ();
        SAFEPUT(put_array_item (mct_iter, out), "Unable to allocate MCT iteration in output JSON node\n");
        SAFEPUT(put_bytearray("key1", keys1[i], key1_len, mct_iter), "Unable to add key 1 to MCT test iteration\n");
        SAFEPUT(put_bytearray("key2", keys2[i], key2_len, mct_iter), "Unable to add key 2 to MCT test iteration\n");
        SAFEPUT(put_bytearray("key3", keys3[i], key3_len, mct_iter), "Unable to add key 3 to MCT test iteration\n");
        if(iv)
            SAFEPUT(put_bytearray("iv", ivs[0], iv_len, mct_iter), "Unable to add iv to MCT test iteration\n");
        SAFEPUT(put_bytearray(enc ? "pt" : "ct", inputs[0], input_len, mct_iter), "Unable to add output to MCT test iteration\n");

        /* Concat the keys together which will be Key1[i]||Key2[i]||Key3[i] */
        unsigned char key[8*3] = {0};
        memcpy(&key[0],  keys1[i], key1_len);
        memcpy(&key[8],  keys2[i], key2_len);
        memcpy(&key[16], keys3[i], key3_len);

        int outl = 0;
        int j = 0;
        for (; j < 10000; j ++)  {
            /* The NIST spec says to run standard 3DES each of the inner loop times and use
             * the IV for the current 'j'th iteration.
             * However, this assumes that the "context" has been reset each time.  The end of
             * the iteration sets the 'j'th IV to be the last ciphertext (though it does this
             * for both encrypt *AND* decrypt, which is bizarre). SO we *could* do this using
             * the ctx object and resetting it once each of the outer iterations, except that
             * wouldn't work for decrypt modes.  So we will let each encrypt/decrypt op
             * stand on its own for each of the 400,000 iterations.
             */
            if(!EVP_CIPHER_CTX_reset(ctx)) goto error_die;
            /* We have to use IV[j] here according to the test spec */
            if(!EVP_CipherInit(ctx, cipher, key, iv ? ivs[j] : NULL, enc)) goto error_die;
            /* Disable padding so this works properly */
            if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) goto error_die;
            /* CT[j] = TDES_*_ENCRYPT(Key1[i], Key2[i], Key3[i], PT[j], IV[j]) */
            /* CT[j] = TDES_*_DECRYPT(Key1[i], Key2[i], Key3[i], CT[j], IV[j]) */
            if(!EVP_CipherUpdate(ctx, outputs[j], &outl, inputs[j], input_len)) goto error_die;

            /* There is different behaviour if we are encrypting vs. decrypting for CBC mode only.
             * Since CBC mode has an IV, we will differentiate on that.
            */
            if(iv)  {   /* A proxy for whether this is CBC mode or ECB mode */
                if(enc)  {
                    if(j == 0) 
                        /* PT[j+1] = IV[0] */
                        memcpy(inputs[j+1], ivs[0], input_len);
                    else 
                        /* PT[j+1] = CT[j-1] */
                        memcpy(inputs[j+1], outputs[j-1], outl);

                    /* IV[j+1] = CT[j] */
                    memcpy(ivs[j+1], outputs[j], iv_len);
                }
                else  { /* Decrypting */
                    /* NOTE: This looks the same as some of the logic above, but because this is
                     * the //decryption// side of things, some of it is actually reversed
                     * purposefully.  Therefore, do NOT refactor this.
                     */
                    /* CT[j+1] = PT[j] */
                    memcpy(inputs[j+1], outputs[j], outl);
                    /* IV[j+1] = CT[j] */
                    memcpy(ivs[j+1], inputs[j], iv_len);
                }
            }
            else  { /* ECB mode */
                /* PT[j+1] = CT[i] */
                memcpy(inputs[j+1], outputs[j], outl);
            }
        }   /* End of inner loop */

        /* The NIST document uses j post-loop, but forgets that the loop increments one
         * last time before we exit. So we need to decrement to be able to reference the
         * last output[] that was constructed.
         */
        j--;
        SAFEPUT(put_bytearray(enc ? "ct" : "pt", outputs[j], outl, mct_iter), "Unable to add output to MCT test iteration\n");

        /* Key1[i+1] = Key1[i] XOR CT[j] */
        xor_bytearray(/*lhs*/keys1[i], key1_len, /*rhs*/outputs[j], outl, /*dest*/keys1[i+1], key1_len); 
        /* We have to fix up the parity of the resulting key. Time to use a deprecated API, since I can't seem to
         * find a OSSL_PARAM or CTRL handler to force this.
         * Discovered this while reading the issues log for the NIST ACVP github page.
         */
        _deprecated_DES_set_odd_parity(keys1[i+1]);
        /* Key2[i+1] = Key2[i] XOR CT[j-1] */
        xor_bytearray(/*lhs*/keys2[i], key2_len, /*rhs*/outputs[j-1], outl, /*dest*/keys2[i+1], key2_len); 
        _deprecated_DES_set_odd_parity(keys2[i+1]);
        if(keyingOption == 1)
            /* Key3[i+1] = Key3[i] XOR CT[j-2] */
            xor_bytearray(/*lhs*/keys3[i], key3_len, /*rhs*/outputs[j-2], outl, /*dest*/keys3[i+1], key3_len); 
        else
            /* Key3[i+1] = Key1[i+1] */
            memcpy(keys3[i+1], keys1[i+1], key3_len);

        _deprecated_DES_set_odd_parity(keys3[i+1]);

        if(iv)  {   /* Proxy for whether this is CBC or ECB mode */
            /* CBC mode */
            /* The NIST spec appears to be inaccurate.
             * When truing up the IV and outputs for the next outer loop iteration, we need
             * to do different things depending on if this is encrypting or decrypting.
             */
            if(enc)  {
                /* PT[0] = CT[j-1] */
                memcpy(inputs[0], outputs[j-1], input_len);
                /* IV[0] = CT[j] */
                memcpy(ivs[0], outputs[j], iv_len);
            }
            else {
                /* This was discovered when we found that the 2nd loop IV and CT (input)
                 * were reversed to what the samples suggested they should have been.
                 * Reading some of the NIST comments in the ACVP github page suggests that
                 * the MCT functions for TDES have all sorts of logic issues and ambiguities
                 * and need to be significantly fixed.
                 */
                /* CT[0] = PT[j] */
                memcpy(inputs[0], outputs[j], input_len);
                /* IV[0] = PT[j-1] */
                memcpy(ivs[0], outputs[j-1], iv_len);
            }
        }
        else  {
            /* ECB mode */
            /* PT[0] = CT[j] */
            memcpy(inputs[0], outputs[j], input_len);
        }
    }

    ret = 1;
error_die:
    SAFE_FUNC_FREE(ctx, EVP_CIPHER_CTX_free);

    TRACE_POP;
    return ret;
}




/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_tdes_v1_0(cJSON *j, void *options, cJSON *out, const char *mode)  {
    TRACE_PUSH;
    int ret = 0;    /* Assume failure until the end */

    EVP_CIPHER *cipher = NULL;
    unsigned char *key1 = NULL, *key2 = NULL, *key3 = NULL;
    int key1_len = 0, key2_len = 0, key3_len = 0;
    unsigned char *iv = NULL;
    int iv_len = 0;
    unsigned char *input = NULL;
    int input_len = 0;
    unsigned char *output = NULL;
    int output_len = 0;

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

        cJSON *keyingOption = NULL;
        SAFEGET(get_integer_object(&keyingOption, tg, "keyingOption"), "Missing `keyingOption' in input JSON\n");

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

            SAFEGET(get_as_bytearray(&key1, &key1_len, tc, "key1"), "Missing `key1' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&key2, &key2_len, tc, "key2"), "Missing `key2' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&key3, &key3_len, tc, "key3"), "Missing `key3' in test case %d in test group %d\n", tcId, tgId);

            /* Sanity check the keys */
            if(keyingOption->valueint == 1)  {
                /* K1 != K2 != K3 */
                if(!memcmp(key1, key2, key1_len)
                  || !memcmp(key1, key3, key1_len)
                  || !memcmp(key2, key3, key2_len))
                    goto error_die;
            }
            else if(keyingOption->valueint == 2)  {
                /* K1 == K3 != K2 */
                if(memcmp(key1, key3, key1_len)
                  || !memcmp(key3, key2, key3_len))
                    goto error_die;
            }

            /* Everything except ECB has an IV */
            if(strcasecmp(mode, "DES-EDE3-ECB") != 0)  {
                SAFEGET(get_as_bytearray(&iv, &iv_len, tc, "iv"), "Missing `iv' in test case %d in test group %d\n", tcId, tgId);
            }


            /* Get the ciphertext or plaintext depending on which direction */
            if(strcmp("encrypt", direction->valuestring) == 0)  {
                SAFEGET(get_as_bytearray(&input, &input_len, tc, "pt"), "Missing plaintext in test case %d in test group %d\n", tcId, tgId);
#ifdef TRACE
                printf("Plaintext: ");
                print_bytearray(input, input_len);
#endif
                /* Ciphertext length can grow at most one more block depending on mode */
                output_len = input_len + EVP_MAX_BLOCK_LENGTH;
                if(!(output = OPENSSL_zalloc(output_len)))  {
                    goto error_die;
                }
                enc = 1;
            } 
            else if (strcmp("decrypt", direction->valuestring) == 0)  {
                SAFEGET(get_as_bytearray(&input, &input_len, tc, "ct"), "Missing ciphertext in test case %d in test group %d\n", tcId, tgId);
#ifdef TRACE
                printf("Ciphertext: ");
                print_bytearray(input, input_len);
#endif
                /* Plaintext can't be larger than ct_len, so set this */
                output_len = input_len;
                if(!(output = OPENSSL_zalloc(output_len)))  {
                    goto error_die;
                }
                enc = 0;
            } 
            else {
                raise_error(/*TBD code */0);
                goto error_die;
            }


            /* Execute TDES test */
            cipher = EVP_CIPHER_fetch(NULL, mode, provider_str);

            char *out_label = "pt";
            if(enc)
                out_label = "ct";


            if(strcasecmp("AFT", test_type->valuestring) == 0)  {
                if(!_tdes_aft(cipher, enc, input, input_len, output, &output_len, key1, key1_len, key2, key2_len, key3, key3_len, iv, iv_len))  {
                    raise_error(/*TBD code */0);
                }
                SAFEPUT(put_bytearray(out_label, output, output_len, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
            }
            if(strcasecmp("MCT", test_type->valuestring) == 0)  {
                cJSON *mct_results = cJSON_CreateArray ();
                SAFEPUT(put_object ("resultsArray", mct_results, tc_output),  "Unable to allocate resultsArray for MCT in test group %d\n", tgId);

                if(!_tdes_mct(cipher, enc, input, input_len, key1, key1_len, key2, key2_len, key3, key3_len, keyingOption->valueint, iv, iv_len, mct_results))  {
                    raise_error(/*TBD code */0);
                }
            }


#ifdef TRACE
            printf("[%s:%d:%d] Output: ", test_type->valuestring, tgId, tcId);
            print_bytearray(output, output_len);
#endif

            SAFE_FUNC_FREE(cipher, EVP_CIPHER_free);
            SAFE_FUNC_FREE(input, free);
            SAFE_FUNC_FREE(output, free);
            SAFE_FUNC_FREE(key1, free);
            SAFE_FUNC_FREE(key2, free);
            SAFE_FUNC_FREE(key3, free);
            SAFE_FUNC_FREE(iv, free);

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
    SAFE_FUNC_FREE(input, free);
    SAFE_FUNC_FREE(output, free);
    SAFE_FUNC_FREE(key1, free);
    SAFE_FUNC_FREE(key2, free);
    SAFE_FUNC_FREE(key3, free);
    SAFE_FUNC_FREE(iv, free);

    TRACE_POP;
    return ret;
}


ACVP_TEST_ALG_SPEC_BEGIN(tdes_ecb)
ACVP_TEST_ALG_SPEC_REV(tdes, 1_0, ACVP_ALG_REVISION_1_0, "DES-EDE3-ECB")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(tdes_cbc)
ACVP_TEST_ALG_SPEC_REV(tdes, 1_0, ACVP_ALG_REVISION_1_0, "DES-EDE3-CBC")
ACVP_TEST_ALG_SPEC_END
