#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "acvp_lib.h"


/*
Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
Licensed under the Apache License 2.0 (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html
*/
static int pkey_get_bn_bytes(EVP_PKEY *pkey, const char *name,
                             unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    BIGNUM *bn = NULL;
    int sz;

    if (!EVP_PKEY_get_bn_param(pkey, name, &bn))
        goto err;
    sz = BN_num_bytes(bn);
    buf = OPENSSL_zalloc(sz);
    if (buf == NULL)
        goto err;
    if (!BN_bn2binpad(bn, buf, sz))
        goto err;

    *out_len = sz;
    *out = buf;
    BN_free(bn);
    return 1;
err:
    OPENSSL_free(buf);
    BN_free(bn);
    return 0;
}



int ACVP_TEST_vs_safeprimes_keyver_v1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *dh_pkey = NULL;
    unsigned char *x = NULL, *y = NULL;
    size_t x_len = 0, y_len = 0;


    int ret = 1;    /* Everything consider failure until it gets to end */

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

        cJSON *safePrimeGroup = NULL;
        SAFEGET(get_string_object(&safePrimeGroup, tg, "safePrimeGroup"), "Missing `safePrimeGroup' in test group %d\n", tgId);
        /* Convert the hyphen to an underscore in the group name */
        for(int i = 0; i < strlen(safePrimeGroup->valuestring); i++)
            if(safePrimeGroup->valuestring[i] == '-')
                safePrimeGroup->valuestring[i] = '_';

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

            SAFEGET(get_as_bytearray(&x, (int *)&x_len, tc, "x"), "Missing `x' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&y, (int *)&y_len, tc, "y"), "Missing `y' in test case %d in test group %d\n", tcId, tgId);

#ifdef TRACE
            printf("x: ");
            print_bytearray(x, x_len);
            printf("y: ");
            print_bytearray(y, y_len);
#endif

            if(!strcasecmp(test_type->valuestring, "AFT"))  {
                /* Because sending directly as BIGNUM, we have to alter the endian-ness and reverse the array */
                reverse_bytearray(x, x_len);
                reverse_bytearray(y, y_len);

                OSSL_PARAM params[4] = {
                    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, safePrimeGroup->valuestring, strlen(safePrimeGroup->valuestring)),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, y, y_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, x, x_len),
                    OSSL_PARAM_END,
                };

                int passed = 1;
                /* Much of this comes from OpenSSL 3.0 test/acvp_test.c */
                if(!(pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", provider_str))
                   || (EVP_PKEY_fromdata_init(pkey_ctx) != 1)
                   || (EVP_PKEY_fromdata(pkey_ctx, &dh_pkey, EVP_PKEY_KEYPAIR, params) != 1)
                   || !(pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_pkey, provider_str))
                   || ((ret = EVP_PKEY_check(pkey_ctx)) != 1))
                    passed = 0;

#ifdef TRACE
                printf("tcid: %d\n", tcId);
                printf("testPassed: %s\n", passed ? "true" : "false");
#endif
                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(x, free);
            SAFE_FUNC_FREE(y, free);
            SAFE_FUNC_FREE(dh_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(pkey_ctx, EVP_PKEY_CTX_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    SAFE_FUNC_FREE(dh_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(pkey_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(x, free);
    SAFE_FUNC_FREE(y, free);

    TRACE_POP;
    return ret;
}


int ACVP_TEST_vs_safeprimes_keygen_v1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *dh_pkey = NULL;
    unsigned char *x = NULL, *y = NULL;
    size_t x_len = 0, y_len = 0;

    int ret = 1;    /* Everything consider failure until it gets to end */

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

        cJSON *safePrimeGroup = NULL;
        SAFEGET(get_string_object(&safePrimeGroup, tg, "safePrimeGroup"), "Missing `safePrimeGroup' in test group %d\n", tgId);
        /* Convert the hyphen to an underscore in the group name */
        for(int i = 0; i < strlen(safePrimeGroup->valuestring); i++)
            if(safePrimeGroup->valuestring[i] == '-')
                safePrimeGroup->valuestring[i] = '_';


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

            if(!strcasecmp(test_type->valuestring, "AFT"))  {
                OSSL_PARAM params[4] = {
                    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, safePrimeGroup->valuestring, strlen(safePrimeGroup->valuestring)),
                    OSSL_PARAM_END,
                };

                if(!(pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", provider_str))
                   || !EVP_PKEY_keygen_init(pkey_ctx)
                   || !EVP_PKEY_CTX_set_params(pkey_ctx, params)
                   || (EVP_PKEY_keygen(pkey_ctx, &dh_pkey) <= 0))
                    goto error_die;

                /* Now get the necessary output params */
                if (!pkey_get_bn_bytes(dh_pkey, OSSL_PKEY_PARAM_PRIV_KEY, &x, &x_len)
                    || !pkey_get_bn_bytes(dh_pkey, OSSL_PKEY_PARAM_PUB_KEY, &y, &y_len))
                    goto error_die;

#ifdef TRACE
                printf("x: ");
                print_bytearray(x, x_len);
                printf("y: ");
                print_bytearray(y, y_len);
#endif
                SAFEPUT(put_bytearray("x", x, x_len, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("y", y, y_len, tc_output), "Unable to output for test case %d in test group %d\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(pkey_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(dh_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(x, free);
            SAFE_FUNC_FREE(y, free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    SAFE_FUNC_FREE(pkey_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(dh_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(x, free);
    SAFE_FUNC_FREE(y, free);

    TRACE_POP;
    return ret;
}



/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_safeprimes_v1_0(cJSON *j, void *options, cJSON *out, const char *algname_UNUSED)  {
    TRACE_PUSH;

    int ret = 1;    /* Everything consider failure until it gets to end */

    cJSON *mode = NULL;
    SAFEGET(get_string_object(&mode, j, "mode"), "Missing `mode' in vector set\n");
    cJSON *revision = NULL;
    SAFEGET(get_string_object(&revision, j, "revision"), "Missing `revision' in vector set\n");

    if(!strcasecmp(mode->valuestring, "keyGen"))
        ret = ACVP_TEST_vs_safeprimes_keygen_v1_0(j, options, out);
    else if(!strcasecmp(mode->valuestring, "keyVer"))
        ret = ACVP_TEST_vs_safeprimes_keyver_v1_0(j, options, out);

error_die:
    return ret;
}


ACVP_TEST_ALG_SPEC_BEGIN(safeprimes)
ACVP_TEST_ALG_SPEC_REV(safeprimes, 1_0, ACVP_ALG_REVISION_1_0, NULL);
ACVP_TEST_ALG_SPEC_END

