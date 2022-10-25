#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <internal/ffc.h>   /* Required for unverifiable G test */

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

/*
Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
Licensed under the Apache License 2.0 (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html
*/
/* Extract r and s from a dsa signature */
static int get_dsa_sig_rs_bytes(const unsigned char *sig, size_t sig_len,
                                unsigned char **r, unsigned char **s,
                                size_t *r_len, size_t *s_len)
{
    int ret = 0;
    unsigned char *rbuf = NULL, *sbuf = NULL;
    size_t r1_len, s1_len;
    const BIGNUM *r1, *s1;
    DSA_SIG *sign = d2i_DSA_SIG(NULL, &sig, sig_len);

    if (sign == NULL)
        return 0;
    DSA_SIG_get0(sign, &r1, &s1);
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
    *r_len = r1_len;
    *s_len = s1_len;
    ret = 1;
err:
    if (ret == 0) {
        OPENSSL_free(rbuf);
        OPENSSL_free(sbuf);
    }
    DSA_SIG_free(sign);
    return ret;
}



int ACVP_TEST_vs_dsa_sigver_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *sig_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *msg = NULL;
    int msg_len = 0;
    unsigned char *p = NULL, *q = NULL, *g = NULL, *r = NULL, *s = NULL, *y = NULL;
    int p_len = 0, q_len = 0, g_len = 0, r_len = 0, s_len = 0, y_len = 0;
    BIGNUM *rbn = NULL, *sbn = NULL;
    DSA_SIG *sign = NULL;
    EVP_MD *md = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned char *sig = NULL;
    size_t sig_len;
    unsigned int digest_len = 0;

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


        cJSON *l = NULL;
        SAFEGET(get_integer_object(&l, tg, "l"), "Missing `l' in test group %d\n", tgId);
        cJSON *n = NULL;
        SAFEGET(get_integer_object(&n, tg, "n"), "Missing `n' in test group %d\n", tgId);
        SAFEGET(get_as_bytearray(&p, &p_len, tg, "p"), "Missing `p' in test group %d\n", tgId);
        SAFEGET(get_as_bytearray(&q, &q_len, tg, "q"), "Missing `q' in test group %d\n", tgId);
        SAFEGET(get_as_bytearray(&g, &g_len, tg, "g"), "Missing `g' in test group %d\n", tgId);
        /* We are about to convert to BIGNUM, so reverse for endian-ness */
        reverse_bytearray(p, p_len);
        reverse_bytearray(q, q_len);
        reverse_bytearray(g, g_len);

        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in input JSON\n");

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


            if(!strcasecmp(test_type->valuestring, "AFT"))  {
                SAFEGET(get_as_bytearray(&y, &y_len, tc, "y"), "Missing `y' in test case %d in test group %d\n", tcId, tgId);
                /* About to become a BIGNUM, reverse */
                reverse_bytearray(y, y_len);

                SAFEGET(get_as_bytearray(&r, &r_len, tc, "r"), "Missing `r' in test case %d in test group %d\n", tcId, tgId);
                SAFEGET(get_as_bytearray(&s, &s_len, tc, "s"), "Missing `s' in test case %d in test group %d\n", tcId, tgId);
                SAFEGET(get_as_bytearray(&msg, &msg_len, tc, "message"), "Missing message in test case %d in test group %d\n", tcId, tgId);

                assert(l->valueint/8 == y_len);
                assert(n->valueint/8 == msg_len);

                int yes = 1;
            
                OSSL_PARAM params[7] = {
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, p, p_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, q, q_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, g, g_len),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, &yes),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_VALIDATE_G, &yes),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, y, y_len),
                    OSSL_PARAM_END,
                };

                /* Compose the public key and ensure is valid */
                if(!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", provider_str))
                   || !EVP_PKEY_fromdata_init(ctx)
                   || !EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
                    goto error_die;

                /* Hash the message */
                if (!(md = EVP_MD_fetch(NULL, hashAlg->valuestring, provider_str))
                    || !EVP_Digest(msg, msg_len, digest, &digest_len, md, NULL))
                    goto error_die;

                /* Compose the signature */
                if(!(sign = DSA_SIG_new())
                   || !(rbn = BN_bin2bn(r, r_len, NULL))
                   || !(sbn = BN_bin2bn(s, s_len, NULL))
                   || !(DSA_SIG_set0(sign, rbn, sbn)))
                    goto error_die;

                rbn = sbn = NULL;

                /* Must convert the signature from OSSL internal to DER (binary) format */
                if (((sig_len = i2d_DSA_SIG(sign, &sig)) <= 0)
                   || !(sig_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, provider_str))
                   || (EVP_PKEY_verify_init(sig_ctx) <= 0))
                    goto error_die;

                int passed = (EVP_PKEY_verify(sig_ctx, sig, sig_len, digest, digest_len) == 1);
                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(sig_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(md, EVP_MD_free);
            SAFE_FUNC_FREE(sign, DSA_SIG_free);
            SAFE_FUNC_FREE(sig, OPENSSL_free);
            SAFE_FUNC_FREE(msg, free);
            SAFE_FUNC_FREE(y, free);
            SAFE_FUNC_FREE(r, free);
            SAFE_FUNC_FREE(s, free);
            SAFE_FUNC_FREE(rbn, BN_free);
            SAFE_FUNC_FREE(sbn, BN_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        SAFE_FUNC_FREE(p, free);
        SAFE_FUNC_FREE(q, free);
        SAFE_FUNC_FREE(g, free);

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    SAFE_FUNC_FREE(ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(sig_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(md, EVP_MD_free);
    SAFE_FUNC_FREE(sign, DSA_SIG_free);
    SAFE_FUNC_FREE(sig, OPENSSL_free);
    SAFE_FUNC_FREE(msg, free);
    SAFE_FUNC_FREE(y, free);
    SAFE_FUNC_FREE(r, free);
    SAFE_FUNC_FREE(s, free);
    SAFE_FUNC_FREE(rbn, BN_free);
    SAFE_FUNC_FREE(sbn, BN_free);
    SAFE_FUNC_FREE(p, free);
    SAFE_FUNC_FREE(q, free);
    SAFE_FUNC_FREE(g, free);

    TRACE_POP;
    return ret;
}



int ACVP_TEST_vs_dsa_keygen_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *paramgen_ctx = NULL;
    EVP_PKEY *param_key = NULL;
    EVP_PKEY_CTX *keygen_ctx = NULL;
    EVP_PKEY *dsa_pkey = NULL;

    unsigned char *p = NULL, *q = NULL, *g = NULL, *x = NULL, *y = NULL;
    size_t p_len = 0, q_len = 0, g_len = 0, x_len = 0, y_len = 0;


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

        cJSON *l = NULL;
        SAFEGET(get_integer_object(&l, tg, "l"), "Missing `l' in test group %d\n", tgId);
        cJSON *n = NULL;
        SAFEGET(get_integer_object(&n, tg, "n"), "Missing `n' in test group %d\n", tgId);

        /* Based on l and n, generate p, q, g */
        if (!(paramgen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", provider_str))
           || !EVP_PKEY_paramgen_init(paramgen_ctx)
           || !EVP_PKEY_CTX_set_dsa_paramgen_bits(paramgen_ctx, l->valueint)
           || !EVP_PKEY_CTX_set_dsa_paramgen_q_bits(paramgen_ctx, n->valueint)
           || !EVP_PKEY_paramgen(paramgen_ctx, &param_key)
           || !pkey_get_bn_bytes(param_key, OSSL_PKEY_PARAM_FFC_P, &p, &p_len)
           || !pkey_get_bn_bytes(param_key, OSSL_PKEY_PARAM_FFC_Q, &q, &q_len)
           || !pkey_get_bn_bytes(param_key, OSSL_PKEY_PARAM_FFC_G, &g, &g_len))
            goto error_die;

        SAFEPUT(put_bytearray("p", p, p_len, tg_output), "Unable to add `p' to test group %d\n", tgId);
        SAFEPUT(put_bytearray("q", q, q_len, tg_output), "Unable to add `q' to test group %d\n", tgId);
        SAFEPUT(put_bytearray("g", g, g_len, tg_output), "Unable to add `g' to test group %d\n", tgId);


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
                /* Use the pre-generated parameters to compose new keypairs */
                if(!(keygen_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, provider_str))
                   || (EVP_PKEY_keygen_init(keygen_ctx) <= 0)
                   || !EVP_PKEY_keygen(keygen_ctx, &dsa_pkey)
                   || !pkey_get_bn_bytes(dsa_pkey, OSSL_PKEY_PARAM_PRIV_KEY, &x, &x_len)
                   || !pkey_get_bn_bytes(dsa_pkey, OSSL_PKEY_PARAM_PUB_KEY,  &y, &y_len))
                    goto error_die;

                SAFEPUT(put_bytearray("x", x, x_len, tc_output), "Unable to output x for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("y", y, y_len, tc_output), "Unable to output y for test case %d in test group %d\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(keygen_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(dsa_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(x, free);
            SAFE_FUNC_FREE(y, free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        SAFE_FUNC_FREE(paramgen_ctx, EVP_PKEY_CTX_free);
        SAFE_FUNC_FREE(param_key, EVP_PKEY_free);
        SAFE_FUNC_FREE(p, free);
        SAFE_FUNC_FREE(q, free);
        SAFE_FUNC_FREE(g, free);

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    SAFE_FUNC_FREE(paramgen_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(param_key, EVP_PKEY_free);
    SAFE_FUNC_FREE(p, free);
    SAFE_FUNC_FREE(q, free);
    SAFE_FUNC_FREE(g, free);
    SAFE_FUNC_FREE(keygen_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(dsa_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(x, free);
    SAFE_FUNC_FREE(y, free);

    TRACE_POP;
    return ret;
}



/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_dsa_siggen_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *paramgen_ctx = NULL;
    EVP_PKEY *param_key = NULL;
    EVP_PKEY_CTX *keygen_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *p = NULL, *q = NULL, *g = NULL, *y = NULL;
    size_t p_len = 0, q_len = 0, g_len = 0, y_len = 0;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    unsigned char *msg = NULL;
    int msg_len = 0;
    unsigned char *r = NULL, *s = NULL;
    size_t r_len = 0, s_len = 0;

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

        cJSON *l = NULL;
        SAFEGET(get_integer_object(&l, tg, "l"), "Missing `l' in test group %d\n", tgId);
        cJSON *n = NULL;
        SAFEGET(get_integer_object(&n, tg, "n"), "Missing `n' in test group %d\n", tgId);
        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in input JSON\n");

        /* Build a new key for each test group */
        /* Based on l and n, generate p, q, g */
        if (!(paramgen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", provider_str))
           || !EVP_PKEY_paramgen_init(paramgen_ctx)
           || !EVP_PKEY_CTX_set_dsa_paramgen_bits(paramgen_ctx, l->valueint)
           || !EVP_PKEY_CTX_set_dsa_paramgen_q_bits(paramgen_ctx, n->valueint)
           || !EVP_PKEY_paramgen(paramgen_ctx, &param_key)
           || !(keygen_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, provider_str))
           || (EVP_PKEY_keygen_init(keygen_ctx) <= 0)
           || (EVP_PKEY_keygen(keygen_ctx, &pkey) <= 0)
           || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_PUB_KEY, &y, &y_len)
           || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_FFC_P, &p, &p_len)
           || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_FFC_Q, &q, &q_len)
           || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_FFC_G, &g, &g_len))
            goto error_die;

        SAFEPUT(put_bytearray("p", p, p_len, tg_output), "Unable to output `p' for test group %d\n", tgId);
        SAFEPUT(put_bytearray("q", q, q_len, tg_output), "Unable to output `q' for test group %d\n", tgId);
        SAFEPUT(put_bytearray("g", g, g_len, tg_output), "Unable to output `g' for test group %d\n", tgId);
        SAFEPUT(put_bytearray("y", y, y_len, tg_output), "Unable to output `y' for test group %d\n", tgId);


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


                sig_len = EVP_PKEY_get_size(pkey);
                /* Generate a signature using the key */
                if (!(sig = malloc(EVP_PKEY_get_size(pkey)))
                   || !(md_ctx = EVP_MD_CTX_new())
                   || (EVP_DigestSignInit_ex(md_ctx, NULL, hashAlg->valuestring, NULL, provider_str, pkey, NULL) != 1)
                   || (EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len) <= 0))
                    goto error_die;

                /* Get the r and s values */
                if(!get_dsa_sig_rs_bytes(sig, sig_len, &r, &s, &r_len, &s_len))
                    goto error_die;

                SAFEPUT(put_bytearray("r", r, r_len, tc_output), "Unable to output `r' for test case %d for test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("s", s, s_len, tc_output), "Unable to output `s' for test case %d for test group %d\n", tcId, tgId);

                /* This block of code here will simply re-verify the signature that we just built. */
#ifdef TRACE
                SAFE_FUNC_FREE(sig, free);
                sig_len = 0;

                /* Verify that it matches */
                /* Hash the message */
                unsigned char digest[EVP_MAX_MD_SIZE] = {0};
                unsigned int digest_len = 0;
                EVP_MD *md = NULL;
                BIGNUM *rbn = NULL, *sbn = NULL;
                DSA_SIG *sign = NULL;
                EVP_PKEY_CTX *sig_ctx = NULL;

                if (!(md = EVP_MD_fetch(NULL, hashAlg->valuestring, provider_str))
                    || !EVP_Digest(msg, msg_len, digest, &digest_len, md, NULL))
                    goto error_die;

                /* Compose the signature */
                if(!(sign = DSA_SIG_new())
                   || !(rbn = BN_bin2bn(r, r_len, NULL))
                   || !(sbn = BN_bin2bn(s, s_len, NULL))
                   || !(DSA_SIG_set0(sign, rbn, sbn)))
                    goto verify_error_die;

                rbn = sbn = NULL;

                /* Must convert the signature from OSSL internal to DER (binary) format */
                if (((sig_len = i2d_DSA_SIG(sign, &sig)) <= 0)
                   || !(sig_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, provider_str))
                   || (EVP_PKEY_verify_init(sig_ctx) <= 0))
                    goto verify_error_die;

                int passed = (EVP_PKEY_verify(sig_ctx, sig, sig_len, digest, digest_len) == 1);
                assert(passed);
verify_error_die:
                SAFE_FUNC_FREE(md, EVP_MD_free);
                SAFE_FUNC_FREE(sign, DSA_SIG_free);
                SAFE_FUNC_FREE(rbn, BN_free);
                SAFE_FUNC_FREE(sbn, BN_free);
                SAFE_FUNC_FREE(sig_ctx, EVP_PKEY_CTX_free);
#endif
            }

            /* Free structures here */
            /* NOTE: We do not free pkey_ctx as per the man pages which says that the
             * context will be freed when EVP_MD_CTX is freed.
             */
            SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
            SAFE_FUNC_FREE(sig, free);
            SAFE_FUNC_FREE(msg, free);
            SAFE_FUNC_FREE(r, free);
            SAFE_FUNC_FREE(s, free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        SAFE_FUNC_FREE(paramgen_ctx, EVP_PKEY_CTX_free);
        SAFE_FUNC_FREE(param_key, EVP_PKEY_free);
        SAFE_FUNC_FREE(keygen_ctx, EVP_PKEY_CTX_free);
        SAFE_FUNC_FREE(pkey, EVP_PKEY_free);
        SAFE_FUNC_FREE(p, OPENSSL_free);
        SAFE_FUNC_FREE(q, OPENSSL_free);
        SAFE_FUNC_FREE(g, OPENSSL_free);
        SAFE_FUNC_FREE(y, OPENSSL_free);

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    SAFE_FUNC_FREE(md_ctx, EVP_MD_CTX_free);
    SAFE_FUNC_FREE(sig, free);
    SAFE_FUNC_FREE(msg, free);
    SAFE_FUNC_FREE(r, free);
    SAFE_FUNC_FREE(s, free);
    SAFE_FUNC_FREE(paramgen_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(param_key, EVP_PKEY_free);
    SAFE_FUNC_FREE(keygen_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(p, OPENSSL_free);
    SAFE_FUNC_FREE(q, OPENSSL_free);
    SAFE_FUNC_FREE(g, OPENSSL_free);
    SAFE_FUNC_FREE(y, OPENSSL_free);

    TRACE_POP;
    return ret;
}


int ACVP_TEST_vs_dsa_pqgver_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;
    EVP_PKEY *pkey = NULL;

    unsigned char *p = NULL, *q = NULL, *g = NULL, *h = NULL, *domainSeed = NULL;
    int p_len = 0, q_len = 0, g_len = 0, h_len = 0, domainSeed_len = 0;
    int yes = 1;
    int no = 0;


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

        /* I don't actually need this since OSSL picks the right hash alg depending on the size
         * of the parameters.
         */
        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in input JSON\n");

        cJSON *pqMode = NULL;
        cJSON *gMode = NULL;
        get_string_object(&pqMode, tg, "pqMode");
        get_string_object(&gMode, tg, "gMode");



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

            SAFEGET(get_as_bytearray(&p, &p_len, tc, "p"), "Missing `p' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&q, &q_len, tc, "q"), "Missing `q' in test case %d in test group %d\n", tcId, tgId);
            /* P and Q are about to go in as BIGNUM, so reverse */
            reverse_bytearray(p, p_len);
            reverse_bytearray(q, q_len);

            SAFEGET(get_as_bytearray(&domainSeed, &domainSeed_len, tc, "domainSeed"), "Missing `domainSeed' in test case %d in test group %d\n", tcId, tgId);

            if(!strcasecmp(test_type->valuestring, "GDT") && pqMode && !strcasecmp(pqMode->valuestring, "probable"))  {
                cJSON *counter = NULL;
                SAFEGET(get_integer_object(&counter, tc, "counter"), "Missing `counter' in test case %d in test group %d\n", tcId, tgId);

                int counter_val = counter->valueint;
                OSSL_PARAM params[10] = {
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, p, p_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, q, q_len),
                    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, domainSeed, domainSeed_len),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, &counter_val),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, &yes),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_VALIDATE_G, &no),
                    OSSL_PARAM_END,
                };

                int passed = 1;

                /* Compose the public key from the domain params above and ensure is valid */
                if(!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", provider_str))
                   || !EVP_PKEY_fromdata_init(ctx)
                   || !EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
                    passed = 0;

                /* Generate a key off those params and see if it checks out */
                if(passed &&
                   (!(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, provider_str))
                    || !EVP_PKEY_param_check(key_ctx))
                  )
                    passed = 0;

                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }
            else if(!strcasecmp(test_type->valuestring, "GDT") && gMode && !strcasecmp(gMode->valuestring, "unverifiable"))  {
                SAFEGET(get_as_bytearray(&g, &g_len, tc, "g"), "Missing `g' in test case %d in test group %d\n", tcId, tgId);
                SAFEGET(get_as_bytearray(&h, &h_len, tc, "h"), "Missing `h' in test case %d in test group %d\n", tcId, tgId);
                reverse_bytearray(g, g_len);
                reverse_bytearray(h, h_len);

                OSSL_PARAM params[10] = {
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, p, p_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, q, q_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, g, g_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_H, h, h_len),
                    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, domainSeed, domainSeed_len),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, &no),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_VALIDATE_G, &yes),
                    OSSL_PARAM_END,
                };

                int passed = 1;

                /* Compose the public key from the domain params above and ensure is valid */
                if(!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", provider_str))
                   || !EVP_PKEY_fromdata_init(ctx)
                   || !EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
                    passed = 0;

                /* Generate a key ctx off those params and see if it checks out */
                if(passed &&
                   (!(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, provider_str))
                    || !EVP_PKEY_param_check(key_ctx))
                  )
                    passed = 0;

                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }
            else  {
                printf("Unknown pqgVer test mode\n");
                goto error_die;
            }

            /* Free structures here */
            SAFE_FUNC_FREE(ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(key_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(p, free);
            SAFE_FUNC_FREE(q, free);
            SAFE_FUNC_FREE(g, free);
            SAFE_FUNC_FREE(h, free);
            SAFE_FUNC_FREE(domainSeed, free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:

    /* Free structures for final time */
    SAFE_FUNC_FREE(ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(key_ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(p, free);
    SAFE_FUNC_FREE(q, free);
    SAFE_FUNC_FREE(g, free);
    SAFE_FUNC_FREE(h, free);
    SAFE_FUNC_FREE(domainSeed, free);

    TRACE_POP;
    return ret;
}



#if 0
/* This is the example from OpenSSL's github page issue #15546 indicating that 
 * you can generate G from P&Q. I don't think they tested it because (a) there
 * are typos and (b) paramgen never sets P and Q.  There is a way to generate
 * G if P and Q are set, but there doesn't seem to be a public API to just set
 * P and Q.
 * The example P and Q came from a NIST ACVP sample and I changed the OSSL_PARAM_BLD
 * to a straight-up array.
 */
void github_15546()  {
    EVP_PKEY_CTX *paramgen_ctx = NULL;
    EVP_PKEY *param_key = NULL;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bnp = NULL, *bnq = NULL;
    unsigned char *dsa_p = (unsigned char *)"\xD5\xD9\x30\x92\xF6\x44\xE7\xAB\xE5\xAD\xAB\x43\x1B\x4D\x7B\xA1\xFC\x9C\x95\x1B\x20\x97\x61\x76\x4E\x08\x89\x06\xC1\xA7\xC7\xF0\xBF\x3C\x91\x6D\xD9\x5F\x26\x8E\xBE\x40\x9C\xDF\x95\xE9\xF7\x15\x2A\x06\x66\xB8\xCA\x99\x4C\xDB\xCA\xE6\x80\x4A\x3D\xF2\xAF\x7A\x14\x1D\xE5\x1C\xF6\x05\xCE\x15\x69\xB6\xEA\xC8\xB7\x04\xC4\xDE\xB6\x25\xD1\x8D\x3F\x51\xE7\x05\x29\x03\x1B\x61\x22\x24\x55\x86\x58\x57\x55\x51\x3C\xF6\x26\x6F\x2C\xCA\x2B\xEE\x58\x79\xB8\xF2\x7B\xDA\x05\xB0\xA4\xF3\x80\x7B\x33\x6C\x14\x7C\x6D\x04\x91\xF2\x12\x2F\xE1\x00\x18\xEB\xD9\xF0\xB0\xF6\xA8\x90\xE0\xBB\x0A\x5F\x59\x8B\xCE\xBF\x3B\xAB\x79\xA5\x12\x30\x50\x9A\xDF\x3E\x60\xD6\x8E\xCF\xED\x13\x19\xB0\x57\x34\x20\x73\x22\xB9\x44\xF4\x94\xC7\x0C\x6D\x8E\xB9\x48\x01\x31\x64\x98\xC3\xB9\x33\x8A\x02\x85\xE5\x17\x5A\xA0\xFD\x22\x25\x48\x5A\xC9\x26\x7C\xB5\x1E\xCD\x3A\x28\xD0\x68\xDA\x91\xAC\x31\x03\x0C\x95\x6B\x23\xC0\x6C\xB2\x01\x51\x27\x6C\x5B\x3D\xDD\x9B\x3A\xEA\xAA\x38\x30\x5B\x48\xB2\x69\x7C\xF3\x89\x6A\x8C\xE5\x5F\x94\x30\x19\x1F\xFC\xFA\x61\x5B\x10\xF4\xA3\xF8\xCA\xDF\x0C\xD5\x61\xD9\x30\xB8\xA7\xEF\xFD\x02\x21\x17\x3C\x05\xF0\xB7\x1D\x5E\xA2\x17\xF9\x2C\x50\x9E\xDF\x24\x8A\x2F\x89\xCF\xCF\x47\x20\x4B\x1F\x3B\x61\x7C\xCB\x76\x32\x56\x65\x0D\xF8\xD1\xAC\x38\x1A\x86\x4B\x4B\x5E\x91\x01\xA2\x7D\x7E\xA3\x4D\x26\x6E\xD4\xDE\x77\x4A\x2C\x4D\x8E\x6A\xA8\x3E\xF6\x4A\x6B\x6A\x0B\xA8\x12\x3A\x36\x29\x5F\x5D\x1E\x82\x88\xA8\x63\xB2\x24\x5F\xFB\x3D\x51\xCD\x07\x5C\xBD\xA7\x27\x7B\x4B\x29\xC3\x5D\x4F\x04\xD1\x9B\x64\x4A\x8A\xD2\x26\x67\x25\x04\x8D\x97\x77\x95\x36\xB5";
    unsigned char *dsa_q = (unsigned char *)"\xB6\x69\xDF\xAB\x94\xFE\xCC\xB0\x3F\xB7\xC5\x9A\x4B\x77\x22\x22\x1A\x67\xF5\xE7\xA1\x94\x9B\x90\xF1\x7A\x47\x90\xF6\xFB\x00\x75";
    unsigned char *g = NULL;
    size_t glen = 0;

if (!(bn_ctx = BN_CTX_new_ex(libctx))
        || !(bnp = BN_CTX_get(bn_ctx))
        || !(bnq = BN_CTX_get(bn_ctx))
        || !(BN_bin2bn(dsa_p, sizeof(dsa_p), bnp))
        || !(BN_bin2bn(dsa_q, sizeof(dsa_q), bnq)))
        return;

int pbits = 3072;
int qbits = 256;
    OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &pbits),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_QBITS, &qbits),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_4", 9),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, "SHA2-256", 8),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, bnp, BN_num_bytes(bnp)),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, bnq, BN_num_bytes(bnq)),
        OSSL_PARAM_END,
    };

    if (!(paramgen_ctx = EVP_PKEY_CTX_new_from_name(libctx, "DSA", NULL))
        || !(EVP_PKEY_paramgen_init(paramgen_ctx))
        || !(EVP_PKEY_CTX_set_params(paramgen_ctx, params))
        || !(EVP_PKEY_paramgen(paramgen_ctx, &param_key))
        || !(pkey_get_bn_bytes(param_key, OSSL_PKEY_PARAM_FFC_G,
                                        &g, &glen)))
            return;
    return;
}
#endif


int ACVP_TEST_vs_dsa_pqggen_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bnp = NULL, *bnq = NULL;

    unsigned char *p = NULL, *q = NULL, *g = NULL;
    int p_len = 0, q_len = 0, g_len = 0;


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

        /* I don't actually need this since OSSL picks the right hash alg depending on the size
         * of the parameters.
         */
        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in input JSON\n");

        cJSON *pqMode = NULL;
        cJSON *gMode = NULL;
        get_string_object(&pqMode, tg, "pqMode");
        get_string_object(&gMode, tg, "gMode");


        cJSON *l = NULL;
        SAFEGET(get_integer_object(&l, tg, "l"), "Missing `l' in test group %d\n", tgId);
        cJSON *n = NULL;
        SAFEGET(get_integer_object(&n, tg, "n"), "Missing `n' in test group %d\n", tgId);


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

            if(!strcasecmp(test_type->valuestring, "GDT") && pqMode && !strcasecmp(pqMode->valuestring, "probable"))  {
                int counter = 0;

                unsigned char domainSeed[1024] = {0};
                int domainSeed_len = 0;

                /* Based on l and n, generate p, q, g */
                if (!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", provider_str))
                   || !EVP_PKEY_paramgen_init(ctx)
                   || !EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, l->valueint)
                   || !EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, n->valueint)
                   || !EVP_PKEY_paramgen(ctx, &pkey)
                   || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_FFC_P, &p, (size_t *)&p_len)
                   || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_FFC_Q, &q, (size_t *)&q_len)
                   || !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_FFC_SEED, domainSeed, sizeof(domainSeed), (size_t *)&domainSeed_len)
                   || !EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_FFC_PCOUNTER, &counter))
                    goto error_die;

                SAFEPUT(put_bytearray("p", p, p_len, tc_output), "Unable to add `p' to test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("q", q, q_len, tc_output), "Unable to add `q' to test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("domainSeed", domainSeed, domainSeed_len, tc_output), "Unable to add `domainSeed' to test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_integer("counter", counter, tc_output), "Unable to add `counter' to test case %d in test group %d\n", tcId, tgId);
            }
            else if(!strcasecmp(test_type->valuestring, "GDT") && gMode && !strcasecmp(gMode->valuestring, "unverifiable"))  {
                /* As far as I can tell, there is no public interface to actually generate 
                 * an unverifiable G based on having the P and Q already.  This is an
                 * internal test of the implementation.
                 * Contrary to the note provided in github issue #15546, the code provided
                 * in that issue body does not actually work since the 'set_params' doesn't 
                 * actually ever attempt to set P and Q from the parameters (it only sets 
                 * PBITS and QBITS). (See example in this file in function github_15546() 
                 * above.)  While the net result *might* be an unverifiable G, it generates 
                 * new P and Q in the process.
                 */
                SAFEGET(get_as_bytearray(&p, &p_len, tc, "p"), "Missing `p' in test case %d in test group %d\n", tcId, tgId);
                SAFEGET(get_as_bytearray(&q, &q_len, tc, "q"), "Missing `q' in test case %d in test group %d\n", tcId, tgId);

#if 1
                FFC_PARAMS params;
                const BIGNUM *bng = NULL;

                int res = 0;

                ossl_ffc_params_init(&params);
                if(!(bnp = BN_bin2bn(p, p_len, NULL))
                  || !(bnq = BN_bin2bn(q, q_len, NULL)))
                    goto error_die;

                /* Do not set flags. We want to avoid validating PQ and G since the OSSL3 code 
                 * will generate G when PQ are present and VALIDATE_G is not set.
                 * If G is not set going into the "ossl_ffc_params_FIPS186_4_validate" routine
                 * then enabling VALIDATE_G will fail as well.  So we disable all checks and we
                 * can manually check the set after.
                 *
                 * It is super important to note that the function ossl_ffc_params_FIPS186_4_validate
                 * is called during the normal course of things.  It's just that there is no
                 * public API to allow us to set P and Q and let G get generated.
                 * In fact, this was primarily imformed by the OpenSSL internal testing
                 * routine under tests/ffc_internal_test.c.
                 * Secondly, the original OpenSSL 2.0 FOM, it uses the a similar
                 * technique to intercept and use the internal APIs from the 1.0.x code repo.  The
                 * benefit it had then was that all of the structures were transparent and many 
                 * functions were not static.  We are fortunate that the same functions are not
                 * static here... But we do need to use the opaque structures and that's why we
                 * need to include <internal/ffc.h> in the include headers at the top of the file.
                 */
                ossl_ffc_params_enable_flags(&params, FFC_PARAM_FLAG_VALIDATE_G,  /*enable = 1, disable = 0*/0);
                ossl_ffc_params_enable_flags(&params, FFC_PARAM_FLAG_VALIDATE_PQ, /*enable = 1, disable = 0*/0);

                /* Set the P & Q, and leave G NULL so we can generate */
                /* Since we are using set0 here, we own the memory and need to free */
                ossl_ffc_params_set0_pqg(&params, bnp, bnq, NULL);

                /* Set the digest algorithm */
                ossl_ffc_set_digest(&params, hashAlg->valuestring, NULL);

                /* Generate G. */
                if (!ossl_ffc_params_FIPS186_4_generate(/*DSA libctx*/NULL, &params, FFC_PARAM_TYPE_DSA, l->valueint, n->valueint, &res, /*callback*/NULL))
                    goto error_die;

                /* G should now be set */
                ossl_ffc_params_get0_pqg(&params, NULL, NULL, &bng);

                g_len = BN_num_bytes(bng);
                if(!(g = OPENSSL_zalloc(g_len))
                  || !BN_bn2binpad(bng, g, g_len))
                    goto error_die;


#ifdef TRACE
                        printf("P: ");
                print_bytearray(p, p_len);
                        printf("Q: ");
                print_bytearray(q, q_len);
                        printf("G: ");
                print_bytearray(g, g_len);
#endif

#else
                /* This code -- which uses the public API does not work. */
                int unverifiable_g = -1;
                int no = 0;
                OSSL_PARAM params[10] = {
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, p, p_len),
                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, q, q_len),
                    OSSL_PARAM_uint(OSSL_PKEY_PARAM_FFC_PBITS, &l->valueint),
                    OSSL_PARAM_uint(OSSL_PKEY_PARAM_FFC_QBITS, &n->valueint),
                    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_4", 9),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, &unverifiable_g),
                    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, &no),
                    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, hashAlg->valuestring, strlen(hashAlg->valuestring)),
                    OSSL_PARAM_END,
                };

                /* Based on l and n, provide p qnd q and generate g */
                if (!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", provider_str))
                   || !EVP_PKEY_paramgen_init(ctx)
                   || !EVP_PKEY_CTX_set_params(ctx, params)
                   || !EVP_PKEY_paramgen(ctx, &pkey)
                   || !pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_FFC_G, &g, (size_t *)&g_len))
                    goto error_die;
#endif
                SAFEPUT(put_bytearray("g", g, g_len, tc_output), "Unable to add `g' to test case %d in test group %d\n", tcId, tgId);
            }
            else  {
                printf("Unknown pqgVer test mode\n");
                goto error_die;
            }

            /* Free structures here */
            SAFE_FUNC_FREE(ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(p, free);
            SAFE_FUNC_FREE(q, free);
            SAFE_FUNC_FREE(g, free);
            SAFE_FUNC_FREE(bnp, BN_free);
            SAFE_FUNC_FREE(bnq, BN_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }   /* End of TC */

        _ACVP_JSON_context_pop();
    }

    ret = 0;

error_die:
    /* Free structures for final time */
    SAFE_FUNC_FREE(ctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(p, free);
    SAFE_FUNC_FREE(q, free);
    SAFE_FUNC_FREE(g, free);
    SAFE_FUNC_FREE(bnp, BN_free);
    SAFE_FUNC_FREE(bnq, BN_free);

    TRACE_POP;
    return ret;
}




/* At this point, the cJSON object is the vector set */
int ACVP_TEST_vs_dsa_v1_0(cJSON *j, void *options, cJSON *out, const char *algname_UNUSED)  {
    TRACE_PUSH;

    int ret = 1;    /* Everything consider failure until it gets to end */

    cJSON *mode = NULL;
    SAFEGET(get_string_object(&mode, j, "mode"), "Missing `mode' in vector set\n");
    cJSON *revision = NULL;
    SAFEGET(get_string_object(&revision, j, "revision"), "Missing `revision' in vector set\n");

    if(!strcasecmp(mode->valuestring, "sigGen") && !strcasecmp(revision->valuestring, "1.0"))
        ret = ACVP_TEST_vs_dsa_siggen_1_0(j, options, out);
    else if(!strcasecmp(mode->valuestring, "sigVer") && !strcasecmp(revision->valuestring, "1.0"))
        ret = ACVP_TEST_vs_dsa_sigver_1_0(j, options, out);
    else if(!strcasecmp(mode->valuestring, "keyGen") && !strcasecmp(revision->valuestring, "1.0"))
        ret = ACVP_TEST_vs_dsa_keygen_1_0(j, options, out);
    else if(!strcasecmp(mode->valuestring, "pqgVer") && !strcasecmp(revision->valuestring, "1.0"))
        ret = ACVP_TEST_vs_dsa_pqgver_1_0(j, options, out);
    else if(!strcasecmp(mode->valuestring, "pqgGen") && !strcasecmp(revision->valuestring, "1.0"))
        ret = ACVP_TEST_vs_dsa_pqggen_1_0(j, options, out);

error_die:
    return ret;
}


ACVP_TEST_ALG_SPEC_BEGIN(dsa)
ACVP_TEST_ALG_SPEC_REV(dsa, 1_0, ACVP_ALG_REVISION_1_0, NULL);
ACVP_TEST_ALG_SPEC_END

