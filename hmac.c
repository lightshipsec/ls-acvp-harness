#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "acvp_lib.h"



/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_hmac_v1_0(cJSON *j, void *options, cJSON *out, const char *mac_name, const char *md_name)  {
    TRACE_PUSH;

    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;

    int ret = 0;    /* Everything considered failed until it gets to end */

    unsigned char *msg = NULL;
    int msg_len = 0;
    unsigned char *key = NULL;
    int key_len = 0;

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

        /* Get MAC length */
        cJSON *macLen = NULL;
        SAFEGET(get_integer_object(&macLen, tg, "macLen"), "Missing `macLen` in test group %d\n", tgId);

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
            SAFEGET(get_as_bytearray(&key, &key_len, tc, "key"), "Missing key in test case %d in test group %d\n", tcId, tgId);

            /* Execute MAC test */
            mac = EVP_MAC_fetch(NULL, mac_name, provider_str);

            if(strcasecmp("AFT", test_type->valuestring) == 0)  {
                ctx = EVP_MAC_CTX_new(mac);
                /* Ensure we construct with the proper digest and any truncation */
                OSSL_PARAM params[3];
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)md_name, 0);
                /* HMAC-SHA* don't permit truncation in the alg, we do that manually at output time */
                params[1] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_SIZE, &macLen->valueint);
                params[2] = OSSL_PARAM_construct_end();

                unsigned char output[EVP_MAX_MD_SIZE] = {0};
                size_t output_len = 0;
                if(!EVP_MAC_init(ctx, key, key_len, params) 
                   || !EVP_MAC_update(ctx, msg, msg_len)
                   || !EVP_MAC_final(ctx, output, &output_len, sizeof(output)))  {
                    raise_error(/*TBD code */0);
                }
                assert(output_len >= macLen->valueint/8);
#ifdef TRACE
                printf("[%s:%d:%d] Output: ", test_type->valuestring, tgId, tcId);
                /* As per FIPS 198-1, SHA1 and SHA2 truncation consists of 
                 * outputting the leftmost n bits.
                 */
                print_bytearray(output, macLen->valueint/8);
#endif
                SAFEPUT(put_bytearray("mac", output, macLen->valueint/8, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(ctx, EVP_MAC_CTX_free);
            SAFE_FUNC_FREE(mac, EVP_MAC_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }
        _ACVP_JSON_context_pop();
    }

    ret = 1;

error_die:
    /* Free structures for final time */
    SAFE_FUNC_FREE(ctx, EVP_MAC_CTX_free);
    SAFE_FUNC_FREE(mac, EVP_MAC_free);

    TRACE_POP;
    return ret;
}



ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha1)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha1")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha2_224)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha2-224")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha2_256)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha2-256")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha2_384)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha2-384")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha2_512)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha2-512")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha3_224)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha3-224")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha3_256)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha3-256")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha3_384)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha3-384")
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(hmac_sha3_512)
ACVP_TEST_ALG_SPEC_REV(hmac, 1_0, ACVP_ALG_REVISION_1_0, "hmac", "sha3-512")
ACVP_TEST_ALG_SPEC_END

