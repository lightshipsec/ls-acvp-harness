#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>

#include "acvp_lib.h"



/**
 * The following is designed from the SHAVS document at NIST:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf
 */
int _shs_1_2_mct(EVP_MD *md, unsigned char *seed, int seed_len, cJSON *out)  {
    TRACE_PUSH;

    int ret = 0;
    int hash_len = EVP_MD_get_size(md);
    unsigned char dgst[1003][EVP_MAX_MD_SIZE] = {0};

    assert(hash_len <= EVP_MAX_MD_SIZE);
    assert(hash_len == seed_len);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

#ifdef TRACE
        printf("[MCT Seed]: ");
        print_bytearray(seed, hash_len);
#endif

    for (int j = 0; j < 100; j++)  {
        memcpy(dgst[2], seed, seed_len);    /* MD[2] = seed */
        memcpy(dgst[1], dgst[2], seed_len); /* MD[1] = MD[2] */
        memcpy(dgst[0], dgst[1], seed_len); /* MD[0] = MD[1] */

        /* Ensure i is defined within this parent scope so we have access to it
         * after the loop ends.
         */
        int i = 3;
        for (; i < 1003; i++)  {
            int msg_len = hash_len*3;
            unsigned char msg[EVP_MAX_MD_SIZE*3] = {0};
            unsigned int tmp_len = 0;

            /* We could use some space optimization to prevent building 1000 hashes in RAM,
             * but the logic easily gets complicated for no real gain. Better to stay readable
             * than to try to optimize for things that don't matter in the long run.
             */

            /* Mi = MDi-3 || MDi-2 || MDi-1; */
            memcpy(&msg[0], dgst[i-3], hash_len);
            memcpy(&msg[hash_len], dgst[i-2], hash_len);
            memcpy(&msg[hash_len*2], dgst[i-1], hash_len);

            /* MDi = SHS(Mi) and check for final length is expected */
            if(!EVP_DigestInit(ctx, md) ||
               !EVP_DigestUpdate(ctx, msg, msg_len) ||
               !EVP_DigestFinal(ctx, dgst[i], &tmp_len) ||
               tmp_len != hash_len)  {
                /* Error occurred */
                goto error_die;
            }
        }

        /* MDj = Seed = MD1002 */
        memcpy(seed, dgst[1002], hash_len);     /* Seed = MD1002 */
        memcpy(dgst[j], seed, hash_len);        /* MDj = Seed */

#ifdef TRACE
        printf("[MCT Output[j]]: ");
        print_bytearray(dgst[j], hash_len);
#endif
        cJSON *mct_iter = cJSON_CreateObject ();
        SAFEPUT(put_array_item (mct_iter, out), "Unable to allocate MCT iteration in output JSON node\n");
        SAFEPUT(put_bytearray("md", dgst[j], hash_len, mct_iter), "Unable to add MCT test iteration\n");
    }

    ret = 1;

error_die:
    SAFE_FUNC_FREE(ctx, EVP_MD_CTX_free);

    TRACE_POP;
    return ret;
}


/**
 * The following is designed from the SHAVS document at NIST:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
 */
int _shs_3_mct(EVP_MD *md, unsigned char *seed, int seed_len, cJSON *out)  {
    TRACE_PUSH;

    int ret = 0;
    int hash_len = EVP_MD_get_size(md);
    unsigned char dgst[1001][EVP_MAX_MD_SIZE] = {0};

    assert(hash_len <= EVP_MAX_MD_SIZE);
    assert(hash_len == seed_len);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

#ifdef TRACE
    printf("[MCT Seed]: ");
    print_bytearray(seed, hash_len);
#endif

    /* MD0 = Seed */
    memcpy(dgst[0], seed, seed_len);
    for (int j = 0; j < 100; j++)  {
        /* Ensure i is defined within this parent scope so we have access to it
         * after the loop ends.
         */
        int i = 1;
        for (; i < 1001; i++)  {
            unsigned int tmp_len = 0;
            /* Msgi = MDi-1 and MDi = SHA3(Msgi) which means that ... 
               MDi = SHA3(MDi-1) and check for final length is expected */
            if(!EVP_DigestInit(ctx, md) ||
               !EVP_DigestUpdate(ctx, dgst[i-1], hash_len) ||
               !EVP_DigestFinal(ctx, dgst[i], &tmp_len) ||
               tmp_len != hash_len)  {
                /* Error occurred */
                goto error_die;
            }
        }

        /* MD0 = MD1000 */
        memcpy(dgst[0], dgst[1000], hash_len);

#ifdef TRACE
        printf("[MCT Output[0]]: ");
        print_bytearray(dgst[0], hash_len);
#endif
        cJSON *mct_iter = cJSON_CreateObject ();
        SAFEPUT(put_array_item (mct_iter, out), "Unable to allocate MCT iteration in output JSON node\n");
        SAFEPUT(put_bytearray("md", dgst[0], hash_len, mct_iter), "Unable to add MCT test iteration\n");
    }

    ret = 1;

error_die:
    SAFE_FUNC_FREE(ctx, EVP_MD_CTX_free);

    TRACE_POP;
    return ret;
}



int _is_sha3(const char *algname)  {
    return !!strcasestr(algname, "sha3-");    /* strstr/strcasestr returns non-NULL pointer to location if found (!! casts to int) */
}


/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_shs_v1_0(cJSON *j, void *options, cJSON *out, const char *algname)  {
    TRACE_PUSH;

    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;

    int ret = 1;    /* Everything consider failure until it gets to end */

    unsigned char *msg = NULL;
    int msg_len = 0;

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

            SAFEGET(get_as_bytearray(&msg, &msg_len, tc, "msg"), "Missing message in test case %d in test group %d\n", tcId, tgId);
            cJSON *msgLen = NULL;
            SAFEGET(get_integer_object(&msgLen, tc, "len"), "Missing message length in test %d in test group %d\n", tcId, tgId);
            assert(msg_len == (msgLen->valueint / 8));

            /* Execute SHS test */
            md = EVP_MD_fetch(NULL, algname, provider_str);

            if(strcasecmp("AFT", test_type->valuestring) == 0)  {
                ctx = EVP_MD_CTX_new();
                unsigned char output[EVP_MAX_MD_SIZE] = {0};
                unsigned int output_len = 0;
                if(!EVP_DigestInit(ctx, md) ||
                   !EVP_DigestUpdate(ctx, msg, msg_len) ||
                   !EVP_DigestFinal(ctx, output, &output_len))  {
                    raise_error(/*TBD code */0);
                }
#ifdef TRACE
                printf("[%s:%d:%d] Output: ", test_type->valuestring, tgId, tcId);
                print_bytearray(output, output_len);
#endif
                SAFEPUT(put_bytearray("md", output, output_len, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
            }
            if(strcasecmp("MCT", test_type->valuestring) == 0)  {
                cJSON *mct_results = cJSON_CreateArray ();
                SAFEPUT(put_object ("resultsArray", mct_results, tc_output),  "Unable to allocate resultsArray for MCT in test group %d\n", tgId);
                if(_is_sha3(algname))  {
                    if(!_shs_3_mct(md, msg, msg_len, mct_results))
                        goto error_die;
                }
                else  {
                    if(!_shs_1_2_mct(md, msg, msg_len, mct_results))
                        goto error_die;
                }
            }

            /* Free structures here */
            SAFE_FUNC_FREE(ctx, EVP_MD_CTX_free);
            SAFE_FUNC_FREE(md, EVP_MD_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }
        _ACVP_JSON_context_pop();
    }

    ret = 1;

error_die:
    /* Free structures for final time */
    SAFE_FUNC_FREE(ctx, EVP_MD_CTX_free);
    SAFE_FUNC_FREE(md, EVP_MD_free);

    TRACE_POP;
    return ret;
}

ACVP_TEST_ALG_SPEC_BEGIN(shs_sha1)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_1_0, "sha1")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(shs_sha2_224)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_1_0, "sha2-224")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(shs_sha2_256)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_1_0, "sha2-256")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(shs_sha2_384)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_1_0, "sha2-384")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(shs_sha2_512)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_1_0, "sha2-512")
ACVP_TEST_ALG_SPEC_END

//need to modify function for differentiating 1.0 and 2.0 revs for sha2 vs sha3
ACVP_TEST_ALG_SPEC_BEGIN(shs_sha3_224)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_2_0, "sha3-224")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(shs_sha3_256)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_2_0, "sha3-256")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(shs_sha3_384)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_2_0, "sha3-384")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(shs_sha3_512)
ACVP_TEST_ALG_SPEC_REV(shs, 1_0, ACVP_ALG_REVISION_2_0, "sha3-512")
ACVP_TEST_ALG_SPEC_END

