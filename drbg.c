#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "acvp_lib.h"
#include "fetch.h"



static EVP_RAND_CTX *seed_entropy_source(EVP_RAND_CTX *parent, unsigned int strength, unsigned char *ent, int ent_len, unsigned char *nonce, int nonce_len)  {
    TRACE_PUSH;

    EVP_RAND_CTX *ctx = NULL;
    OSSL_PARAM params[4], *p = &params[0];
    EVP_RAND *rand = NULL;

    /* Create the seed source: this acts like a container for seeding
     * material for the child DRBG.
    */
    /* If parent is NULL, init a new context, else use the existing */
    ctx = parent;

    if(!ctx)
        if(!(rand = EVP_RAND_fetch(libctx, "TEST-RAND", "-fips"))
            || !(ctx = EVP_RAND_CTX_new(rand, NULL)))
            goto error_die;

    *(p++) = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    if(ent)
       *(p++) = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, ent, ent_len);
    if(nonce)
       *(p++) = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nonce, nonce_len); 
    *(p++) = OSSL_PARAM_construct_end();

    if (!EVP_RAND_CTX_set_params(ctx, params))
        goto error_die;

    EVP_RAND_free(rand);
    goto success;

error_die:
    SAFE_FUNC_FREE(rand, EVP_RAND_free);
    SAFE_FUNC_FREE(ctx, EVP_RAND_CTX_free);

success:
    TRACE_POP;
    return ctx;
}




/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_drbg_v1_0(cJSON *j, void *options, cJSON *out, const char *algname)  {
    TRACE_PUSH;

    EVP_RAND_CTX *seedSource = NULL;
    EVP_RAND_CTX *ctx = NULL;
    EVP_RAND *drbg = NULL;

    int ret = 0;    /* Everything considered failed until it gets to end */

    unsigned char *entropyInput = NULL;
    int entropyInput_len = 0;
    unsigned char *nonce = NULL;
    int nonce_len = 0;
    unsigned char *persoString = NULL;
    int persoString_len = 0;
    unsigned char *additionalInput = NULL;
    int additionalInput_len = 0;
    unsigned char *entropyInput_seed = NULL;
    int entropyInput_seed_len = 0;
    unsigned char *output = NULL;
    int output_len = 0;

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

        cJSON *predResistance = NULL;
        SAFEGET(get_boolean_object(&predResistance, tg, "predResistance"), "Missing `predResistance` in test group %d\n", tgId);
        int has_pr = cJSON_IsTrue(predResistance);

        cJSON *returnedBitsLen = NULL;
        SAFEGET(get_integer_object(&returnedBitsLen, tg, "returnedBitsLen"), "Missing `returnedBitsLen` in test group %d\n", tgId);
        output_len = returnedBitsLen->valueint / 8;     /* In bytes */
        cJSON *mode = NULL;
        SAFEGET(get_integer_object(&mode, tg, "mode"), "Missing `mode` in test group %d\n", tgId);

        cJSON *derFunc = NULL;
        int use_df = 0;
        /* Optional if derivation function is used: default to 0 (no DF used) */
        if (get_boolean_object(&derFunc, tg, "derFunc") == 0) 
            use_df = cJSON_IsTrue(derFunc);

        cJSON *reSeed = NULL;
        int can_reseed = 0;
        SAFEGET(get_boolean_object(&reSeed, tg, "reSeed"), "Unable to get reSeed in JSON in test group %d\n", tgId);
        can_reseed = cJSON_IsTrue(reSeed);

        /* Check test type */
        cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");

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

            /* ... Params go here ... */
            SAFEGET(get_as_bytearray(&entropyInput, &entropyInput_len, tc, "entropyInput"), "Unable to get entropyInput in JSON in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&nonce, &nonce_len, tc, "nonce"), "Unable to get nonce in JSON in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&persoString, &persoString_len, tc, "persoString"), "Unable to get persoString in JSON in test case %d in test group %d\n", tcId, tgId);

            cJSON *otherInputs = NULL;
            SAFEGET(get_object(&otherInputs, tc, "otherInput"), "Unable to get otherInput in JSON in test case %d in test group %d\n", tcId, tgId);

            /* In order to be able to use the DRBG in a deterministic way, we need to construct a seed source that isn't from
             * the system provider.  Otherwise we can't do proper comparisons.
             *
             * The seed source strength must match the entropy input size
             */

            if(!(seedSource = seed_entropy_source(NULL, (entropyInput_len * 8), entropyInput, entropyInput_len, nonce, nonce_len)))
                goto error_die;

            /* We also need our actual drbg instance */
            drbg = EVP_RAND_fetch(NULL, algname, provider_str);

            /* Now we bind the entropy test source with the drbg instance using a parent-child relationship */
            /* This was discovered by examining the OpenSSL 3.0 source code */
            if(!(ctx = EVP_RAND_CTX_new(drbg, seedSource)))
                goto error_die;

            /* Set parameters depending on the type of DRBG we are requesting */
            OSSL_PARAM drbg_params[3] = {0};
            if(!strcasecmp("HMAC-DRBG", algname))  {
                /* Ensure the right Hash is used */
                drbg_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, SN_hmac, 0);  /* Always HMAC */
                drbg_params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, mode->valuestring, 0);
                drbg_params[2] = OSSL_PARAM_construct_end();
            }
            if(!strcasecmp("HASH-DRBG", algname))  {
                /* Ensure the right Hash is used */
                drbg_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, mode->valuestring, 0);
                drbg_params[1] = OSSL_PARAM_construct_end();
            }
            if(!strcasecmp("CTR-DRBG", algname))  {
                /* Ensure the right properties for AES are used */
                drbg_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, ls_cipher_ctr_SN_fetch(mode->valuestring), 0);
                drbg_params[1] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &use_df);
                drbg_params[2] = OSSL_PARAM_construct_end();
            }

            if(strcasecmp("AFT", test_type->valuestring) == 0)  {
                /* Execute */
                /* Security strength minimum bar is 112 bits as per FIPS current minimum effort */

                if(!EVP_RAND_instantiate(ctx, 112, has_pr, persoString, persoString_len, drbg_params)) 
                    goto error_die;
                /* Process additional input, for sequence of events that we need to follow post-init */
                int gen_count = 0;
                cJSON *otherInput = NULL;
                cJSON_ArrayForEach(otherInput, otherInputs)  {
                    /* There are two operations that can be done: reseed or generate. The array is designed to
                     * be read in order and executed on. 
                     */
                    cJSON *intendedUse = NULL;
                    SAFEGET(get_string_object(&intendedUse, otherInput, "intendedUse"), "Unable to get intendedUse from otherInput in test case %d\n", tcId);
                    SAFEGET(get_as_bytearray(&additionalInput, &additionalInput_len, otherInput, "additionalInput"), "Unable to get additionalInput from otherInput in test case %d\n", tcId);
                    SAFEGET(get_as_bytearray(&entropyInput_seed, &entropyInput_seed_len, otherInput, "entropyInput"), "Unable to get entropyInput from otherInput in test case %d\n", tcId);

                    /* We are only permitted to output when we've generated the *second* time. So keep track of the number
                     * of times we generate.
                     */
                    if(!strcasecmp(intendedUse->valuestring, "generate"))  {
                        if(!(output = malloc(output_len)))
                            goto error_die;

                        /* When prediction resistance is enabled, we must "pre-seed" the entropy source */
                        if(has_pr){
                            if(!(seed_entropy_source(seedSource, (entropyInput_seed_len * 8), entropyInput_seed, entropyInput_seed_len, NULL, 0)))
                                        goto error_die;
                        }
                        if(!EVP_RAND_generate(ctx, output, output_len, 0, has_pr, additionalInput, additionalInput_len))
                            goto error_die;

                        gen_count ++;

                        /* Produce output only when we've generated once already (to throw away as per the NIST spec) */
                        if(!(gen_count % 2)) {
#ifdef TRACE
                            printf("[%s:%d:%d] Output: ", test_type->valuestring, tgId, tcId);
                            print_bytearray(output, output_len);
#endif
                            SAFEPUT(put_bytearray("returnedBits", output, output_len, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
                        }

                        SAFE_FUNC_FREE(output, free);
                    }

                    /* If prediction resistance is enabled, then no reseeding, even if provided. */
                    /* This according to NIST ACVP document re: DRBG test scenario for pr and reseed interactions */
                    else if (!has_pr && can_reseed && !strcasecmp(intendedUse->valuestring, "reseed"))  {
                        /* TODO: Understand this: Completely non-intuitive, but the "reseed" function accepts additional entropy as an input.
                         * However, for some reason, adding the entropy here does NOT do the same thing as additional fresh entropy to
                         * the test entropy pool.  We need to add to the test entropy context instead (eg. the parent).
                         */

                        if(!(seed_entropy_source(seedSource, (entropyInput_seed_len * 8), entropyInput_seed, entropyInput_seed_len, NULL, 0))
                           || !EVP_RAND_reseed(ctx, has_pr, NULL, 0, additionalInput, additionalInput_len))
                            goto error_die;
                    }

                    /* Clear allocated mem */
                    SAFE_FUNC_FREE(additionalInput, free);
                    SAFE_FUNC_FREE(entropyInput_seed, free);
                }

                assert(gen_count == 2);

                /* Uninstantiate the DRBG */
                EVP_RAND_uninstantiate(ctx);
            }

            /* Uninstantiate the seed source */
            EVP_RAND_uninstantiate(seedSource);

            /* Free structures here */
            SAFE_FUNC_FREE(entropyInput, free);
            SAFE_FUNC_FREE(nonce, free);
            SAFE_FUNC_FREE(persoString, free);
            SAFE_FUNC_FREE(ctx, EVP_RAND_CTX_free);
            SAFE_FUNC_FREE(drbg, EVP_RAND_free);
            SAFE_FUNC_FREE(seedSource, EVP_RAND_CTX_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }
        _ACVP_JSON_context_pop();
    }

    ret = 1;

error_die:
    /* Free structures for final time */
    SAFE_FUNC_FREE(output, free);
    SAFE_FUNC_FREE(additionalInput, free);
    SAFE_FUNC_FREE(entropyInput_seed, free);
    SAFE_FUNC_FREE(entropyInput, free);
    SAFE_FUNC_FREE(nonce, free);
    SAFE_FUNC_FREE(persoString, free);
    SAFE_FUNC_FREE(ctx, EVP_RAND_CTX_free);
    SAFE_FUNC_FREE(drbg, EVP_RAND_free);
    SAFE_FUNC_FREE(seedSource, EVP_RAND_CTX_free);

    TRACE_POP;
    return ret;
}



ACVP_TEST_ALG_SPEC_BEGIN(drbg_ctr)
ACVP_TEST_ALG_SPEC_REV(drbg, 1_0, ACVP_ALG_REVISION_1_0, "CTR-DRBG")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(drbg_hash)
ACVP_TEST_ALG_SPEC_REV(drbg, 1_0, ACVP_ALG_REVISION_1_0, "HASH-DRBG")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(drbg_hmac)
ACVP_TEST_ALG_SPEC_REV(drbg, 1_0, ACVP_ALG_REVISION_1_0, "HMAC-DRBG")
ACVP_TEST_ALG_SPEC_END

