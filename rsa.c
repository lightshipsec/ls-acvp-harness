#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
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



int ACVP_TEST_vs_rsa_sigver_fips186_4(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *rsa_pkey = NULL;
    unsigned char *sig = NULL;
    int sig_len = 0;
    unsigned char *n = NULL, *e = NULL;
    int n_len = 0, e_len = 0;
    unsigned char *msg = NULL;
    int msg_len = 0;

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
        char saltLen_str[64] = {0};
        int tgId = ACVP_JSON_get_testgroup_id(tg);
        _ACVP_JSON_context_push("testGroups", "tgId = %d", tgId);

        cJSON *tg_output = cJSON_CreateObject ();
        SAFEPUT (put_array_item (tg_output, tgs_output), "Unable to append test group to output\n");
        SAFEPUT (put_integer ("tgId", tgId, tg_output), "Unable to add tgId to test group %d\n", tgId);

        /* Check test type */
        cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");

        cJSON *sigType = NULL;
        SAFEGET(get_string_object(&sigType, tg, "sigType"), "Missing `sigType' in test group %d\n", tgId);
        cJSON *modulo = NULL;
        SAFEGET(get_integer_object(&modulo, tg, "modulo"), "Missing `modulo' in test group %d\n", tgId);
        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in test group %d\n", tgId);
        cJSON *saltLen = NULL;
        SAFEGET(get_integer_object(&saltLen, tg, "saltLen"), "Missing `saltLen' in test group %d\n", tgId);
        /* OpenSSL expects the salt length as a string */
        snprintf(saltLen_str, sizeof(saltLen_str), "%u", saltLen->valueint);
        
        SAFEGET(get_as_bytearray(&n, &n_len, tg, "n"), "Missing `n' in test group %d\n", tgId);
        SAFEGET(get_as_bytearray(&e, &e_len, tg, "e"), "Missing `e' in test group %d\n", tgId);

        /* Creating the key basically same as function from OpenSSL 3.0 test/acvp_test.c */
        /* Each test group assumes the use of the same public RSA key */
        if(!strcasecmp(test_type->valuestring, "GDT"))  {
            /* Create an RSA public key with the right properties */
            /* Because sending directly as BIGNUM, we have to alter the endian-ness and reverse the array */
            reverse_bytearray(n, n_len);
            reverse_bytearray(e, e_len);

            OSSL_PARAM params[3] = {
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, n, n_len),
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, e, e_len),
                OSSL_PARAM_END,
            };

            if (!(pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", provider_str))
                || (EVP_PKEY_fromdata_init(pkey_ctx) != 1)
                || (EVP_PKEY_fromdata(pkey_ctx, &rsa_pkey, EVP_PKEY_PUBLIC_KEY, params) != 1))
                goto error_die;

            /* After setting the params, we need to free this CTX structure since the
             * params are now encoded in the rsa_pkey structure.
             * We will reuse this structure later and it needs to be freed and set to NULL.
             */
            EVP_PKEY_CTX_free(pkey_ctx);
            pkey_ctx = NULL;
        }


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

            SAFEGET(get_as_bytearray(&msg, &msg_len, tc, "message"), "Missing message in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&sig, &sig_len, tc, "signature"), "Missing signature in test case %d in test group %d\n", tcId, tgId);

            if(!strcasecmp(test_type->valuestring, "GDT"))  {
                /* Determine padding mode */
                char *padding = OSSL_PKEY_RSA_PAD_MODE_NONE;
                if(!strcasecmp(sigType->valuestring, "pkcs1v1.5")) padding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
                if(!strcasecmp(sigType->valuestring, "pss"))        padding = OSSL_PKEY_RSA_PAD_MODE_PSS;

                OSSL_PARAM params[4] = {0}, *p = params;
                *(p++) = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, padding, 0);
                *(p++) = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, hashAlg->valuestring, 0);
                if(!strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_PSS))
                    *(p++) = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, &saltLen->valueint);
                *(p++) = OSSL_PARAM_construct_end();

#ifdef TRACE
                printf("Message: ");
                print_bytearray(msg, msg_len);
                printf("Signature: ");
                print_bytearray(sig, sig_len);
#endif
                /* Build a buffer for the return signature data */
                int passed = 1;
                if(!(md_ctx = EVP_MD_CTX_new())
                   || !EVP_DigestVerifyInit_ex(md_ctx, &pkey_ctx, hashAlg->valuestring, NULL, provider_str, rsa_pkey, NULL)
                   || !EVP_PKEY_CTX_set_params(pkey_ctx, params)
                   || (EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len) != 1))
                    passed = 0;

#ifdef TRACE
                printf("testPassed: %s\n", passed ? "true" : "false");
#endif
                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
            SAFE_FUNC_FREE(sig, free);
            SAFE_FUNC_FREE(msg, free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        SAFE_FUNC_FREE(n, OPENSSL_free);
        SAFE_FUNC_FREE(e, OPENSSL_free);
        SAFE_FUNC_FREE(rsa_pkey, EVP_PKEY_free);

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    SAFE_FUNC_FREE(rsa_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
    SAFE_FUNC_FREE(n, OPENSSL_free);
    SAFE_FUNC_FREE(e, OPENSSL_free);
    SAFE_FUNC_FREE(msg, free);
    SAFE_FUNC_FREE(sig, free);

    TRACE_POP;
    return ret;
}

int ACVP_TEST_vs_rsa_keygen_fips186_4(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *rsa_pkey = NULL;
    unsigned char *e = NULL;
    int e_len = 0;
    unsigned char *xP = NULL, *xQ = NULL, *xP1 = NULL, *xP2 = NULL, *xQ1 = NULL, *xQ2 = NULL;
    size_t xP_len = 0, xQ_len = 0, xP1_len = 0, xP2_len = 0, xQ1_len = 0, xQ2_len = 0;
    unsigned char *p = NULL, *p1 = NULL, *p2 = NULL, *q = NULL, *q1 = NULL, *q2 = NULL;
    size_t p_len = 0, p1_len = 0, p2_len = 0, q_len = 0, q1_len = 0, q2_len = 0;
    unsigned char *n = NULL;
    size_t n_len = 0;
    /* When the keytype is "standard" */
    unsigned char *d = NULL;
    size_t d_len = 0;
    /* When the keytype is "crt" */
    unsigned char *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    size_t dmp1_len = 0, dmq1_len = 0, iqmp_len = 0;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *e_bn = NULL;
    BIGNUM *xp1_bn = NULL, *xp2_bn = NULL, *xp_bn = NULL;
    BIGNUM *xq1_bn = NULL, *xq2_bn = NULL, *xq_bn = NULL;



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

        cJSON *modulo = NULL;
        SAFEGET(get_integer_object(&modulo, tg, "modulo"), "Missing `modulo' in test group %d\n", tgId);

        cJSON *keyFormat = NULL;
        SAFEGET(get_string_object(&keyFormat, tg, "keyFormat"), "Missing `keyFormat' in test group %d\n", tgId);


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

            /* These are arrays of integers, representing, in order
             * the bit lengths of p1, p2, q1 and q2.
             */

            cJSON *bitlens = NULL;
            SAFEGET(get_object(&bitlens, tc, "bitlens"), "Missing `bitlens' in test case %d in test group %d\n", tcId, tgId);
            SAFEPUT(put_object("bitlens", bitlens, tc_output), "Error adding `bitlens' to output in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&xP, (int *)&xP_len, tc, "xP"), "Missing `xP' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&xQ, (int *)&xQ_len, tc, "xQ"), "Missing `xQ' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&xP1, (int *)&xP1_len, tc, "xP1"), "Missing `xP1' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&xP2, (int *)&xP2_len, tc, "xP2"), "Missing `xP2' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&xQ1, (int *)&xQ1_len, tc, "xQ1"), "Missing `xQ1' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&xQ2, (int *)&xQ2_len, tc, "xQ2"), "Missing `xQ2' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&e, (int *)&e_len, tc, "e"), "Missing `e' in test case %d in test group %d\n", tcId, tgId);

            if(!strcasecmp(test_type->valuestring, "AFT"))  {
                /* The majority of this came from the OpenSSL test/acvp_test.c program in keygen. */
                bld = OSSL_PARAM_BLD_new();
                if(!bld) goto error_die;

                /* Convert everything to BIGNUM, the build out a parameters array 
                 * to set all of these params for test purposes as per RSA(7) in the
                 * man pages.
                 */
                if(!(xp1_bn = BN_bin2bn(xP1, xP1_len, NULL))
                   || !(xp2_bn = BN_bin2bn(xP2, xP2_len, NULL))
                   || !(xp_bn = BN_bin2bn(xP, xP_len, NULL))
                   || !(xq2_bn = BN_bin2bn(xQ2, xQ2_len, NULL))
                   || !(xq1_bn = BN_bin2bn(xQ1, xQ1_len, NULL))
                   || !(xq_bn = BN_bin2bn(xQ, xQ_len, NULL))
                   || !(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP1, xp1_bn))
                   || !(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP2, xp2_bn))
                   || !(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP, xp_bn))
                   || !(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ1, xq1_bn))
                   || !(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ2, xq2_bn))
                   || !(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ, xq_bn))
                   || !(params = OSSL_PARAM_BLD_to_param(bld)))
                    goto error_die;

                if (!(pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", provider_str))
                    || !(e_bn = BN_bin2bn(e, e_len, NULL))
                    || (EVP_PKEY_keygen_init(pkey_ctx) <= 0)
                    || !EVP_PKEY_CTX_set_params(pkey_ctx, params)
                    || !EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, modulo->valueint)
                    || !EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pkey_ctx, e_bn)
                    || (EVP_PKEY_keygen(pkey_ctx, &rsa_pkey) <= 0)
                    /* These are only gettable in FIPS mode */
                    || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_TEST_P1, &p1, &p1_len)
                    || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_TEST_P2, &p2, &p2_len)
                    || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_TEST_Q1, &q1, &q1_len)
                    || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_TEST_Q2, &q2, &q2_len)
                    || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p, &p_len)
                    || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q, &q_len)
                    || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_N, &n, &n_len))
                    goto error_die;

                /* These return values are documented in the RSA(7) man page. */
                if(!strcasecmp(keyFormat->valuestring, "standard")) {
                    if(!pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_D, &d, &d_len))
                        goto error_die;
                } 
                else if(!strcasecmp(keyFormat->valuestring, "crt"))  {
                    if(!pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1, &dmp1_len)
                       || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1, &dmq1_len)
                       || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp, &iqmp_len))
                        goto error_die;
                }


#ifdef TRACE
                printf("n: ");
                print_bytearray(n, n_len);
                printf("p: ");
                print_bytearray(p, p_len);
                printf("q: ");
                print_bytearray(q, q_len);
                printf("dmp1: ");
                print_bytearray(dmp1, dmp1_len);
                printf("dmq1: ");
                print_bytearray(dmq1, dmq1_len);
                printf("iqmp: ");
                print_bytearray(iqmp, iqmp_len);
#endif

                SAFEPUT(put_bytearray("xP", xP, xP_len, tc_output), "Unable to output xP for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("xQ", xQ, xQ_len, tc_output), "Unable to output xQ for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("xP1", xP1, xP1_len, tc_output), "Unable to output xP1 for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("xP2", xP2, xP2_len, tc_output), "Unable to output xP2 for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("xQ1", xQ1, xQ1_len, tc_output), "Unable to output xQ1 for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("xQ2", xQ2, xQ2_len, tc_output), "Unable to output xQ2 for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("n", n, n_len, tc_output), "Unable to output n for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("e", e, e_len, tc_output), "Unable to output e for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("p", p, p_len, tc_output), "Unable to output p for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("q", q, q_len, tc_output), "Unable to output q for test case %d in test group %d\n", tcId, tgId);
                if(!strcasecmp(keyFormat->valuestring, "standard")) {
                    SAFEPUT(put_bytearray("d", d, d_len, tc_output), "Unable to output d for test case %d in test group %d\n", tcId, tgId);
                }else if(!strcasecmp(keyFormat->valuestring, "crt"))  {
                    SAFEPUT(put_bytearray("dmp1", dmp1, dmp1_len, tc_output), "Unable to output dmp1 for test case %d in test group %d\n", tcId, tgId);
                    SAFEPUT(put_bytearray("dmq1", dmq1, dmq1_len, tc_output), "Unable to output dmq1 for test case %d in test group %d\n", tcId, tgId);
                    SAFEPUT(put_bytearray("iqmp", iqmp, iqmp_len, tc_output), "Unable to output iqmp for test case %d in test group %d\n", tcId, tgId);
                }
            }

            /* Free structures here */
            SAFE_FUNC_FREE(pkey_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(rsa_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(e, free);
            SAFE_FUNC_FREE(xP, free);
            SAFE_FUNC_FREE(xQ, free);
            SAFE_FUNC_FREE(xP1, free);
            SAFE_FUNC_FREE(xQ1, free);
            SAFE_FUNC_FREE(xP2, free);
            SAFE_FUNC_FREE(xQ2, free);
            SAFE_FUNC_FREE(p, free);
            SAFE_FUNC_FREE(p1, free);
            SAFE_FUNC_FREE(p2, free);
            SAFE_FUNC_FREE(q, free);
            SAFE_FUNC_FREE(q1, free);
            SAFE_FUNC_FREE(q2, free);
            SAFE_FUNC_FREE(n, free);
            SAFE_FUNC_FREE(d, free);
            SAFE_FUNC_FREE(dmp1, free);
            SAFE_FUNC_FREE(dmq1, free);
            SAFE_FUNC_FREE(iqmp, free);
            SAFE_FUNC_FREE(bld, OSSL_PARAM_BLD_free);
            SAFE_FUNC_FREE(params, OSSL_PARAM_free);
            SAFE_FUNC_FREE(e_bn, BN_free);
            SAFE_FUNC_FREE(xp1_bn, BN_free);
            SAFE_FUNC_FREE(xp2_bn, BN_free);
            SAFE_FUNC_FREE(xp_bn, BN_free);
            SAFE_FUNC_FREE(xq1_bn, BN_free);
            SAFE_FUNC_FREE(xq2_bn, BN_free);
            SAFE_FUNC_FREE(xq_bn, BN_free);

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
    SAFE_FUNC_FREE(rsa_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(e, free);
    SAFE_FUNC_FREE(xP, free);
    SAFE_FUNC_FREE(xQ, free);
    SAFE_FUNC_FREE(xP1, free);
    SAFE_FUNC_FREE(xQ1, free);
    SAFE_FUNC_FREE(xP2, free);
    SAFE_FUNC_FREE(xQ2, free);
    SAFE_FUNC_FREE(p, free);
    SAFE_FUNC_FREE(p1, free);
    SAFE_FUNC_FREE(p2, free);
    SAFE_FUNC_FREE(q, free);
    SAFE_FUNC_FREE(q1, free);
    SAFE_FUNC_FREE(q2, free);
    SAFE_FUNC_FREE(n, free);
    SAFE_FUNC_FREE(d, free);
    SAFE_FUNC_FREE(dmp1, free);
    SAFE_FUNC_FREE(dmq1, free);
    SAFE_FUNC_FREE(iqmp, free);
    SAFE_FUNC_FREE(bld, OSSL_PARAM_BLD_free);
    SAFE_FUNC_FREE(params, OSSL_PARAM_free);
    SAFE_FUNC_FREE(e_bn, BN_free);
    SAFE_FUNC_FREE(xp1_bn, BN_free);
    SAFE_FUNC_FREE(xp2_bn, BN_free);
    SAFE_FUNC_FREE(xp_bn, BN_free);
    SAFE_FUNC_FREE(xq1_bn, BN_free);
    SAFE_FUNC_FREE(xq2_bn, BN_free);
    SAFE_FUNC_FREE(xq_bn, BN_free);

    TRACE_POP;
    return ret;
}



/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_rsa_siggen_fips186_4(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *rsa_pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    unsigned char *n = NULL, *e = NULL;
    size_t n_len = 0, e_len = 0;
    unsigned char *msg = NULL;
    int msg_len = 0;

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
        char saltLen_str[64] = {0};
        int tgId = ACVP_JSON_get_testgroup_id(tg);
        _ACVP_JSON_context_push("testGroups", "tgId = %d", tgId);

        cJSON *tg_output = cJSON_CreateObject ();
        SAFEPUT (put_array_item (tg_output, tgs_output), "Unable to append test group to output\n");
        SAFEPUT (put_integer ("tgId", tgId, tg_output), "Unable to add tgId to test group %d\n", tgId);

        /* Check test type */
        cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");

        cJSON *sigType = NULL;
        SAFEGET(get_string_object(&sigType, tg, "sigType"), "Missing `sigType' in test group %d\n", tgId);
        cJSON *modulo = NULL;
        SAFEGET(get_integer_object(&modulo, tg, "modulo"), "Missing `modulo' in test group %d\n", tgId);
        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in test group %d\n", tgId);
        cJSON *saltLen = NULL;
        SAFEGET(get_integer_object(&saltLen, tg, "saltLen"), "Missing `saltLen' in test group %d\n", tgId);
        /* OpenSSL expects the salt length as a string */
        snprintf(saltLen_str, sizeof(saltLen_str), "%u", saltLen->valueint);

        /* Creating the key basically same as function from OpenSSL 3.0 test/acvp_test.c */
        /* Each test group assumes the use of the same public/private RSA key pair */
        if(!strcasecmp(test_type->valuestring, "GDT"))  {
            /* Create an RSA key with the right properties, then get the buffers */
            /* TODO: I might have to generate a random E value here. */
            if(!(rsa_pkey = EVP_PKEY_Q_keygen(NULL, provider_str, "RSA", modulo->valueint))
               || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_N, &n, &n_len)
               || !pkey_get_bn_bytes(rsa_pkey, OSSL_PKEY_PARAM_RSA_E, &e, &e_len))
                    goto error_die;

            

            /* Dump out the properties of the keys we are using */
#ifdef TRACE
            printf("N: ");
            print_bytearray(n, n_len);
            printf("E: ");
            print_bytearray(e, e_len);
#endif
            SAFEPUT(put_bytearray("n", n, n_len, tg_output), "Unable to output n for test group %d\n", tgId);
            SAFEPUT(put_bytearray("e", e, e_len, tg_output), "Unable to output e for test group %d\n", tgId);
        }



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

            SAFEGET(get_as_bytearray(&msg, &msg_len, tc, "message"), "Missing message in test case %d in test group %d\n", tcId, tgId);

            if(!strcasecmp(test_type->valuestring, "GDT"))  {
                /* Determine padding mode */
                char *padding = OSSL_PKEY_RSA_PAD_MODE_NONE;
                if(!strcasecmp(sigType->valuestring, "pkcs1v1.5")) padding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
                if(!strcasecmp(sigType->valuestring, "pss"))        padding = OSSL_PKEY_RSA_PAD_MODE_PSS;
                if(!strcasecmp(sigType->valuestring, "ansx9.31"))        padding = OSSL_PKEY_RSA_PAD_MODE_X931;

                OSSL_PARAM params[4] = {0}, *p = params;
                *(p++) = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, padding, 0);
                *(p++) = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, hashAlg->valuestring, 0);
                if(!strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_PSS))
                    *(p++) = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, &saltLen->valueint);
                *(p++) = OSSL_PARAM_construct_end();

                /* Build a buffer for the return signature data */
                if(!(sig = malloc(EVP_PKEY_get_size(rsa_pkey)))
                   || !(md_ctx = EVP_MD_CTX_new())
                   || !EVP_DigestSignInit_ex(md_ctx, &pkey_ctx, hashAlg->valuestring, NULL, provider_str, rsa_pkey, NULL)
                   || !EVP_PKEY_CTX_set_params(pkey_ctx, params)
                   || !(sig_len = EVP_PKEY_get_size(rsa_pkey))
                   || !EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len))
                        goto error_die;

#ifdef TRACE
                printf("Signature: ");
                print_bytearray(sig, sig_len);

                /* Verify that it matches */
                EVP_MD_CTX_free(md_ctx);
                md_ctx = NULL;
                int passed = 1;
                if(!(md_ctx = EVP_MD_CTX_new())
                   || !EVP_DigestVerifyInit_ex(md_ctx, &pkey_ctx, hashAlg->valuestring, NULL, provider_str, rsa_pkey, NULL)
                   || !EVP_PKEY_CTX_set_params(pkey_ctx, params)
                   || !EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len))
                    passed = 0;
                
                assert(passed);
#endif
                SAFEPUT(put_bytearray("signature", sig, sig_len, tc_output), "Unable to output signature for test case %d in test group %d\n", tcId, tgId);
            }

            /* Free structures here */
            /* NOTE: We do not free pkey_ctx as per the man pages which says that the
             * context will be freed when EVP_MD_CTX is freed.
             */
            SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
            SAFE_FUNC_FREE(sig, free);
            SAFE_FUNC_FREE(msg, free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        SAFE_FUNC_FREE(n, OPENSSL_free);
        SAFE_FUNC_FREE(e, OPENSSL_free);
        SAFE_FUNC_FREE(rsa_pkey, EVP_PKEY_free);

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    /* NOTE: We do not free pkey_ctx as per the man pages which says that the
     * context will be freed when EVP_MD_CTX is freed.
     */
    SAFE_FUNC_FREE(rsa_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
    SAFE_FUNC_FREE(n, OPENSSL_free);
    SAFE_FUNC_FREE(e, OPENSSL_free);
    SAFE_FUNC_FREE(msg, free);
    SAFE_FUNC_FREE(sig, free);

    TRACE_POP;
    return ret;
}




/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_rsa_vFIPS186_4(cJSON *j, void *options, cJSON *out, const char *algname_UNUSED)  {
    TRACE_PUSH;

    int ret = 1;    /* Everything consider failure until it gets to end */

    cJSON *mode = NULL;
    SAFEGET(get_string_object(&mode, j, "mode"), "Missing `mode' in vector set\n");
    cJSON *revision = NULL;
    SAFEGET(get_string_object(&revision, j, "revision"), "Missing `revision' in vector set\n");

    if(!strcasecmp(mode->valuestring, "sigGen") && !strcasecmp(revision->valuestring, "FIPS186-4"))
        ret = ACVP_TEST_vs_rsa_siggen_fips186_4(j, options, out);
    else if(!strcasecmp(mode->valuestring, "sigVer") && !strcasecmp(revision->valuestring, "FIPS186-4"))
        ret = ACVP_TEST_vs_rsa_sigver_fips186_4(j, options, out);
    else if(!strcasecmp(mode->valuestring, "keyGen") && !strcasecmp(revision->valuestring, "FIPS186-4"))
        ret = ACVP_TEST_vs_rsa_keygen_fips186_4(j, options, out);

error_die:
    return ret;
}


ACVP_TEST_ALG_SPEC_BEGIN(rsa)
ACVP_TEST_ALG_SPEC_REV(rsa, FIPS186_4, ACVP_ALG_REVISION_FIPS186_4, NULL);
ACVP_TEST_ALG_SPEC_END

