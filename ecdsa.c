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



int ACVP_TEST_vs_ecdsa_sigver_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *ecdsa_pkey = NULL;
    unsigned char *sig = NULL;
    int sig_len = 0;
    unsigned char *r = NULL, *s = NULL;
    size_t r_len = 0, s_len = 0;
    unsigned char *qx = NULL, *qy = NULL;
    size_t qx_len = 0, qy_len = 0;
    unsigned char *msg = NULL;
    int msg_len = 0;
    ECDSA_SIG *sign = NULL;
    unsigned char *ecp = NULL;
    int ecp_len = 0;


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

        cJSON *curve = NULL;
        SAFEGET(get_integer_object(&curve, tg, "curve"), "Missing `curve' in test group %d\n", tgId);
        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in test group %d\n", tgId);

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

            SAFEGET(get_as_bytearray(&r, (int *)&r_len, tc, "r"), "Missing `r' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&s, (int *)&s_len, tc, "s"), "Missing `s' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&qx, (int *)&qx_len, tc, "qx"), "Missing `qx' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&qy, (int *)&qy_len, tc, "qy"), "Missing `qy' in test case %d in test group %d\n", tcId, tgId);

            SAFEGET(get_as_bytearray(&msg, &msg_len, tc, "message"), "Missing message in test case %d in test group %d\n", tcId, tgId);

            if(!strcasecmp(test_type->valuestring, "AFT"))  {
                /* First build a key */
                /* It appears that you cannot use the OSSL_PARAM API to set the 
                 * QX and QY directly.  Instead, you need to encode as a EC POINT
                 * structure which is composed of a leading byte describing the 
                 * compression, then the QX and QY in that compression format.
                 * We are going to use uncompressed (0x04) point data.
                 */
                ecp_len = qx_len + qy_len + 1;
                ecp = malloc(ecp_len);
                if(!ecp) goto error_die;

                ecp[0] = '\x04';    /* uncompressed */
                memcpy(ecp+1, qx, qx_len);
                memcpy(ecp+1+qx_len, qy, qy_len);

#ifdef TRACE
                printf("message: ");
                print_bytearray(msg, msg_len);
                printf("qx: ");
                print_bytearray(qx, qx_len);
                printf("qy: ");
                print_bytearray(qy, qy_len);
                printf("EC POINT[0x04||qx||qy]: ");
                print_bytearray(ecp, ecp_len);
                printf("r: ");
                print_bytearray(r, r_len);
                printf("s: ");
                print_bytearray(s, s_len);
#endif


                OSSL_PARAM params[4] = {
                    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve->valuestring, strlen(curve->valuestring)),
                    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, ecp, qx_len + qy_len + 1),
#if 0
                    /* These, alas, do not work directly */
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, qx, qx_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, qy, qy_len),
#endif
                    OSSL_PARAM_END,
                };

                if(!(pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", provider_str))
                   || (EVP_PKEY_fromdata_init(pkey_ctx) != 1)
                   || (EVP_PKEY_fromdata(pkey_ctx, &ecdsa_pkey, EVP_PKEY_PUBLIC_KEY, params) != 1))
                    goto error_die;

                SAFE_FUNC_FREE(pkey_ctx, EVP_PKEY_CTX_free);

#if 0
                /* Just a verification routine to show that qx/qy were decoded properly from the
                 * EC POINT structure.
                 */
                if (!pkey_get_bn_bytes(ecdsa_pkey, OSSL_PKEY_PARAM_EC_PUB_X, &qx, &qx_len)
                    || !pkey_get_bn_bytes(ecdsa_pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &qy, &qy_len))
                    goto error_die;

#ifdef TRACE
                printf("qx: ");
                print_bytearray(qx, qx_len);
                printf("qy: ");
                print_bytearray(qy, qy_len);
#endif

#endif

                /* Construct a signature using r and s to verify */
                BIGNUM *rbn = NULL, *sbn = NULL;
                if (!(sign = ECDSA_SIG_new())
                    || !(rbn = BN_bin2bn(r, r_len, NULL))
                    || !(sbn = BN_bin2bn(s, s_len, NULL))
                    || !ECDSA_SIG_set0(sign, rbn, sbn))
                    goto error_die;

                rbn = sbn = NULL;

                int passed = 1;
                /* Convert r/s signature to binary format (DER) and then verify it */
                if(!(sig_len = i2d_ECDSA_SIG(sign, &sig))
                   || !(md_ctx = EVP_MD_CTX_new())
                   || !EVP_DigestVerifyInit_ex(md_ctx, NULL, hashAlg->valuestring, NULL, provider_str, ecdsa_pkey, NULL)
                   || (EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len) != 1))
                    passed = 0;

#ifdef TRACE
                printf("tcid: %d\n", tcId);
                printf("testPassed: %s\n", passed ? "true" : "false");
#endif
                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
            SAFE_FUNC_FREE(sig, OPENSSL_free);
            SAFE_FUNC_FREE(msg, free);
            SAFE_FUNC_FREE(sign, ECDSA_SIG_free);
            SAFE_FUNC_FREE(r, OPENSSL_free);
            SAFE_FUNC_FREE(s, OPENSSL_free);
            SAFE_FUNC_FREE(qx, free);
            SAFE_FUNC_FREE(qy, free);
            SAFE_FUNC_FREE(ecp, free);
            SAFE_FUNC_FREE(ecdsa_pkey, EVP_PKEY_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    SAFE_FUNC_FREE(ecdsa_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
    SAFE_FUNC_FREE(r, OPENSSL_free);
    SAFE_FUNC_FREE(s, OPENSSL_free);
    SAFE_FUNC_FREE(qx, free);
    SAFE_FUNC_FREE(qy, free);
    SAFE_FUNC_FREE(ecp, free);
    SAFE_FUNC_FREE(msg, free);
    SAFE_FUNC_FREE(sig, OPENSSL_free);
    SAFE_FUNC_FREE(sign, ECDSA_SIG_free);

    TRACE_POP;
    return ret;
}



int ACVP_TEST_vs_ecdsa_keyver_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *ecdsa_pkey = NULL;
    unsigned char *qx = NULL, *qy = NULL;
    size_t qx_len = 0, qy_len = 0;
    unsigned char *ecp = NULL;
    int ecp_len = 0;


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

        cJSON *curve = NULL;
        SAFEGET(get_integer_object(&curve, tg, "curve"), "Missing `curve' in test group %d\n", tgId);

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

            SAFEGET(get_as_bytearray(&qx, (int *)&qx_len, tc, "qx"), "Missing `qx' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&qy, (int *)&qy_len, tc, "qy"), "Missing `qy' in test case %d in test group %d\n", tcId, tgId);

            if(!strcasecmp(test_type->valuestring, "AFT"))  {
                /* First build a key */
                /* It appears that you cannot use the OSSL_PARAM API to set the 
                 * QX and QY directly.  Instead, you need to encode as a EC POINT
                 * structure which is composed of a leading byte describing the 
                 * compression, then the QX and QY in that compression format.
                 * We are going to use uncompressed (0x04) point data.
                 */
                ecp_len = qx_len + qy_len + 1;
                ecp = malloc(ecp_len);
                if(!ecp) goto error_die;

                ecp[0] = '\x04';    /* uncompressed */
                memcpy(ecp+1, qx, qx_len);
                memcpy(ecp+1+qx_len, qy, qy_len);

#ifdef TRACE
                printf("qx: ");
                print_bytearray(qx, qx_len);
                printf("qy: ");
                print_bytearray(qy, qy_len);
                printf("EC POINT[0x04||qx||qy]: ");
                print_bytearray(ecp, ecp_len);
#endif


                OSSL_PARAM params[4] = {
                    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve->valuestring, strlen(curve->valuestring)),
                    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, ecp, qx_len + qy_len + 1),
#if 0
                    /* These, alas, do not work directly */
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, qx, qx_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, qy, qy_len),
#endif
                    OSSL_PARAM_END,
                };

                int passed = 1;
                if(!(pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", provider_str))
                   || (EVP_PKEY_fromdata_init(pkey_ctx) != 1)
                   || (EVP_PKEY_fromdata(pkey_ctx, &ecdsa_pkey, EVP_PKEY_PUBLIC_KEY, params) != 1))
                    passed = 0;

#ifdef TRACE
                printf("tcid: %d\n", tcId);
                printf("testPassed: %s\n", passed ? "true" : "false");
#endif
                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(qx, free);
            SAFE_FUNC_FREE(qy, free);
            SAFE_FUNC_FREE(ecp, free);
            SAFE_FUNC_FREE(ecdsa_pkey, EVP_PKEY_free);
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
    SAFE_FUNC_FREE(ecdsa_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(pkey_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(qx, free);
    SAFE_FUNC_FREE(qy, free);
    SAFE_FUNC_FREE(ecp, free);

    TRACE_POP;
    return ret;
}


int ACVP_TEST_vs_ecdsa_keygen_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *ecdsa_pkey = NULL;
    unsigned char *d = NULL, *qx = NULL, *qy = NULL;
    size_t d_len = 0, qx_len = 0, qy_len = 0;

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

        cJSON *curve = NULL;
        SAFEGET(get_string_object(&curve, tg, "curve"), "Missing `curve' in test group %d\n", tgId);


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
                /* The majority of this came from the OpenSSL test/acvp_test.c program in keygen. */
                if(!(ecdsa_pkey = EVP_PKEY_Q_keygen(NULL, provider_str, "EC", curve->valuestring)))
                    goto error_die;

                /* Now get the necessary output params */
                if (!pkey_get_bn_bytes(ecdsa_pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d, &d_len)
                    || !pkey_get_bn_bytes(ecdsa_pkey, OSSL_PKEY_PARAM_EC_PUB_X, &qx, &qx_len)
                    || !pkey_get_bn_bytes(ecdsa_pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &qy, &qy_len))
                    goto error_die;

#ifdef TRACE
                printf("d: ");
                print_bytearray(d, d_len);
                printf("qx: ");
                print_bytearray(qx, qx_len);
                printf("qy: ");
                print_bytearray(qy, qy_len);
#endif

                SAFEPUT(put_bytearray("d", d, d_len, tc_output), "Unable to output d for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("qx", qx, qx_len, tc_output), "Unable to output qx for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("qy", qy, qy_len, tc_output), "Unable to output qy for test case %d in test group %d\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(pkey_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(ecdsa_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(d, free);
            SAFE_FUNC_FREE(qx, free);
            SAFE_FUNC_FREE(qy, free);

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
    SAFE_FUNC_FREE(ecdsa_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(d, free);
    SAFE_FUNC_FREE(qx, free);
    SAFE_FUNC_FREE(qy, free);

    TRACE_POP;
    return ret;
}


/*
Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
Licensed under the Apache License 2.0 (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html
*/
/* Extract r and s  from an ecdsa signature */
static int get_ecdsa_sig_rs_bytes(const unsigned char *sig, size_t sig_len,
                                  unsigned char **r, unsigned char **s,
                                  size_t *rlen, size_t *slen)
{
    int ret = 0;
    unsigned char *rbuf = NULL, *sbuf = NULL;
    size_t r1_len, s1_len;
    const BIGNUM *r1, *s1;
    ECDSA_SIG *sign = d2i_ECDSA_SIG(NULL, &sig, sig_len);

    if (sign == NULL)
        return 0;
    r1 = ECDSA_SIG_get0_r(sign);
    s1 = ECDSA_SIG_get0_s(sign);
    if (r1 == NULL || s1 == NULL)
        return 0;

    r1_len = BN_num_bytes(r1);
    s1_len = BN_num_bytes(s1);
    rbuf = OPENSSL_zalloc(r1_len);
    sbuf = OPENSSL_zalloc(s1_len);
    if (rbuf == NULL || sbuf == NULL)
        goto err;
    if (BN_bn2binpad(r1, rbuf, r1_len) <= 0)
        goto err;
    if (BN_bn2binpad(s1, sbuf, s1_len) <= 0)
        goto err;
    *r = rbuf;
    *s = sbuf;
    *rlen = r1_len;
    *slen = s1_len;
    ret = 1;
err:
    if (ret == 0) {
        OPENSSL_free(rbuf);
        OPENSSL_free(sbuf);
    }
    ECDSA_SIG_free(sign);
    return ret;
}


/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_ecdsa_siggen_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *ecdsa_pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    unsigned char *r = NULL, *s = NULL;
    size_t r_len = 0, s_len = 0;
    unsigned char *qx = NULL, *qy = NULL;
    size_t qx_len = 0, qy_len = 0;
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
        int tgId = ACVP_JSON_get_testgroup_id(tg);
        _ACVP_JSON_context_push("testGroups", "tgId = %d", tgId);

        cJSON *tg_output = cJSON_CreateObject ();
        SAFEPUT (put_array_item (tg_output, tgs_output), "Unable to append test group to output\n");
        SAFEPUT (put_integer ("tgId", tgId, tg_output), "Unable to add tgId to test group %d\n", tgId);

        /* Check test type */
        cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");

        /* Make sure componentTest is False */
        cJSON *componentTest = NULL;
        SAFEGET(get_boolean_object(&componentTest, tg, "componentTest"), "Missing `componentTest' in input JSON\n");
        assert(cJSON_IsFalse(componentTest));

        cJSON *curve = NULL;
        SAFEGET(get_integer_object(&curve, tg, "curve"), "Missing `curve' in test group %d\n", tgId);
        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in test group %d\n", tgId);

        /* Creating the key basically same as function from OpenSSL 3.0 test/acvp_test.c */
        /* Each test group assumes the use of the same public/private ECDSA key pair */
        if(!strcasecmp(test_type->valuestring, "AFT"))  {
            /* Create an ECDSA key with the right properties, then get the buffers */
            if(!(ecdsa_pkey = EVP_PKEY_Q_keygen(NULL, provider_str, "EC", curve->valuestring))
               || !pkey_get_bn_bytes(ecdsa_pkey, OSSL_PKEY_PARAM_EC_PUB_X, &qx, &qx_len)
               || !pkey_get_bn_bytes(ecdsa_pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &qy, &qy_len))
               goto error_die;

            /* Dump out the properties of the keys we are using */
#ifdef TRACE
            printf("qx: ");
            print_bytearray(qx, qx_len);
            printf("qy: ");
            print_bytearray(qy, qy_len);
#endif
            SAFEPUT(put_bytearray("qx", qx, qx_len, tg_output), "Unable to output qx for test group %d\n", tgId);
            SAFEPUT(put_bytearray("qy", qy, qy_len, tg_output), "Unable to output qy for test group %d\n", tgId);
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

            if(!strcasecmp(test_type->valuestring, "AFT"))  {
                /* Build a buffer for the return signature data */
                sig_len = EVP_PKEY_get_size(ecdsa_pkey);
                if(!(sig = malloc(sig_len))
                   || !(md_ctx = EVP_MD_CTX_new())
                   || !EVP_DigestSignInit_ex(md_ctx, &pkey_ctx, hashAlg->valuestring, NULL, provider_str, ecdsa_pkey, NULL)
                   || !EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len)
                   || !get_ecdsa_sig_rs_bytes(sig, sig_len, &r, &s, &r_len, &s_len))
                        goto error_die;

#ifdef TRACE
                printf("r: ");
                print_bytearray(r, r_len);
                printf("s: ");
                print_bytearray(s, s_len);

                /* Verify that it matches */
                SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
                ECDSA_SIG *sign = NULL;
                BIGNUM *rbn = NULL, *sbn = NULL;
                int passed = 1;
                if (!(sign = ECDSA_SIG_new())
                    || !(rbn = BN_bin2bn(r, r_len, NULL))
                    || !(sbn = BN_bin2bn(s, s_len, NULL))
                    || !ECDSA_SIG_set0(sign, rbn, sbn))
                    goto error_die;

                rbn = sbn = NULL;

                if(!(md_ctx = EVP_MD_CTX_new())
                   || !EVP_DigestVerifyInit_ex(md_ctx, &pkey_ctx, hashAlg->valuestring, NULL, provider_str, ecdsa_pkey, NULL)
                   || !EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len))
                    passed = 0;
                
                assert(passed);
#endif

                SAFEPUT(put_bytearray("r", r, r_len, tc_output), "Unable to output r for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("s", s, s_len, tc_output), "Unable to output s for test case %d in test group %d\n", tcId, tgId);
            }

            /* Free structures here */
            /* NOTE: We do not free pkey_ctx as per the man pages which says that the
             * context will be freed when EVP_MD_CTX is freed.
             */
            SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
            SAFE_FUNC_FREE(sig, free);
            SAFE_FUNC_FREE(msg, free);
            SAFE_FUNC_FREE(r, OPENSSL_free);
            SAFE_FUNC_FREE(s, OPENSSL_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        SAFE_FUNC_FREE(qx, free);
        SAFE_FUNC_FREE(qy, free);
        SAFE_FUNC_FREE(ecdsa_pkey, EVP_PKEY_free);

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    /* NOTE: We do not free pkey_ctx as per the man pages which says that the
     * context will be freed when EVP_MD_CTX is freed.
     */
    SAFE_FUNC_FREE(ecdsa_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
    SAFE_FUNC_FREE(qx, free);
    SAFE_FUNC_FREE(qy, free);
    SAFE_FUNC_FREE(r, OPENSSL_free);
    SAFE_FUNC_FREE(s, OPENSSL_free);
    SAFE_FUNC_FREE(msg, free);
    SAFE_FUNC_FREE(sig, free);

    TRACE_POP;
    return ret;
}




/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_ecdsa_v1_0(cJSON *j, void *options, cJSON *out, const char *algname_UNUSED)  {
    TRACE_PUSH;

    int ret = 1;    /* Everything consider failure until it gets to end */

    cJSON *mode = NULL;
    SAFEGET(get_string_object(&mode, j, "mode"), "Missing `mode' in vector set\n");
    cJSON *revision = NULL;
    SAFEGET(get_string_object(&revision, j, "revision"), "Missing `revision' in vector set\n");

    if(!strcasecmp(mode->valuestring, "sigGen"))
        ret = ACVP_TEST_vs_ecdsa_siggen_1_0(j, options, out);
    else if(!strcasecmp(mode->valuestring, "sigVer"))
        ret = ACVP_TEST_vs_ecdsa_sigver_1_0(j, options, out);
    else if(!strcasecmp(mode->valuestring, "keyGen"))
        ret = ACVP_TEST_vs_ecdsa_keygen_1_0(j, options, out);
    else if(!strcasecmp(mode->valuestring, "keyVer"))
        ret = ACVP_TEST_vs_ecdsa_keyver_1_0(j, options, out);

error_die:
    return ret;
}


ACVP_TEST_ALG_SPEC_BEGIN(ecdsa)
ACVP_TEST_ALG_SPEC_REV(ecdsa, 1_0, ACVP_ALG_REVISION_1_0, NULL);
ACVP_TEST_ALG_SPEC_END

