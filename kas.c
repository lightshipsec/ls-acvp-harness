#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

#include "acvp_lib.h"

#ifdef TRACE
#include <openssl/err.h>
#endif

/*
Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
Licensed under the Apache License 2.0 (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html
*/
/* From OpenSSL 3.0 test/test_acvp.c */
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


static int construct_ec_point(const unsigned char *x, size_t x_len, const unsigned char *y, size_t y_len, unsigned char **out, size_t *out_len)  {
    /* TODO: Refactor this function out as common between this and ecdsa.c */

    /* It appears that you cannot use the OSSL_PARAM API to set the 
     * QX and QY directly.  Instead, you need to encode as a EC POINT
     * structure which is composed of a leading byte describing the 
     * compression, then the QX and QY in that compression format.
     * We are going to use uncompressed (0x04) point data.
     */
    size_t ecp_len = x_len + y_len + 1;
    unsigned char *ecp = malloc(ecp_len);
    if(!ecp) return 0;

    ecp[0] = '\x04';    /* uncompressed */
    memcpy(ecp+1, x, x_len);
    memcpy(ecp+1+x_len, y, y_len);

    *out = ecp;
    *out_len = ecp_len;

    return 1;
}


int ACVP_TEST_vs_kas_ffc_component_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    int ret = 1;    /* Everything consider failure until it gets to end */

    unsigned char *ephemeralPrivateIut = NULL, *ephemeralPublicIut = NULL;
    size_t ephemeralPrivateIut_len = 0, ephemeralPublicIut_len = 0;
    unsigned char *ephemeralPublicServer = NULL;
    int ephemeralPublicServer_len = 0;
    unsigned char *p = NULL, *q = NULL, *g = NULL;
    int p_len = 0, q_len = 0, g_len = 0;
    unsigned char *z = NULL;
    size_t z_len = 0;
    unsigned char *hashZ = NULL;
    size_t hashZ_len = 0;
    int key_confirm = 0;
    int kdf = 0;

    EVP_PKEY_CTX *pctx = NULL, *gctx = NULL, *peer_ctx = NULL, *kex_ctx = NULL;
    EVP_PKEY *dh_param_pkey = NULL, *dh_pkey = NULL, *peer_pkey = NULL;


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

        cJSON *scheme = NULL;
        SAFEGET(get_string_object(&scheme, tg, "scheme"), "Missing `scheme' in test group %d\n", tgId);

        /* This is the only supported scheme */
        if(strcasecmp(scheme->valuestring, "dhEphem"))
            goto error_die;

        cJSON *kasRole = NULL;
        SAFEGET(get_string_object(&kasRole, tg, "kasRole"), "Missing `kasRole' in test group %d\n", tgId);

        cJSON *kasMode = NULL;
        SAFEGET(get_string_object(&kasMode, tg, "kasMode"), "Missing `kasMode' in test group %d\n", tgId);
        /* This is the only mode supported */
        if(strcasecmp(kasMode->valuestring, "noKdfNoKc"))
            goto error_die;
        else  {
            key_confirm = 0;
            kdf = 0;  /* Ignore warning about unused var here */
            kdf = kdf;
        }

        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in test group %d\n", tgId);

        SAFEGET(get_as_bytearray(&p, &p_len, tg, "p"), "Missing `p' in test group %d\n", tgId);
        SAFEGET(get_as_bytearray(&q, &q_len, tg, "q"), "Missing `q' in test group %d\n", tgId);
        SAFEGET(get_as_bytearray(&g, &g_len, tg, "g"), "Missing `g' in test group %d\n", tgId);
        /* Convert to BIGNUM means adjusting for endian-ness; reverse */
        reverse_bytearray(p, p_len);
        reverse_bytearray(q, q_len);
        reverse_bytearray(g, g_len);

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

            SAFEGET(get_as_bytearray(&ephemeralPublicServer, &ephemeralPublicServer_len, tc, "ephemeralPublicServer"), "Missing `ephemeralPublicServer' in test case %d in test group %d\n", tcId, tgId);
            /* Convert to BIGNUM means adjusting for endian-ness; reverse */
            reverse_bytearray(ephemeralPublicServer, ephemeralPublicServer_len);

            OSSL_PARAM host_params[8] = {0}, *host = &host_params[0];
            OSSL_PARAM peer_params[8] = {0}, *peer = &peer_params[0];
            OSSL_PARAM kex_params[8] = {0}, *kex = &kex_params[0];

            /* Set the parameters on both the host and the peer */
            *(host++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, p, p_len);
            *(host++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, q, q_len);
            *(host++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, g, g_len);

            *(peer++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, p, p_len);
            *(peer++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, q, q_len);
            *(peer++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, g, g_len);

            if(!strcasecmp("AFT", test_type->valuestring))  {
                /* Nothing else on the host */
                *(host++) = OSSL_PARAM_construct_end();

                /* Import the public key on the peer */
                *(peer++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, ephemeralPublicServer, ephemeralPublicServer_len);
                *(peer++) = OSSL_PARAM_construct_end();

                /* Generate the host and peer keys 
                 * As per docs, DHX stores Q, and that's the one we need to use for
                 * the host key. The peer must use the same.
                 */
                if(!(pctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", provider_str))
                   || (EVP_PKEY_fromdata_init(pctx) <= 0)
                   || (EVP_PKEY_fromdata(pctx, &dh_param_pkey, EVP_PKEY_KEYPAIR, host_params) <= 0)
                   || !(peer_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", provider_str))
                   || (EVP_PKEY_fromdata_init(peer_ctx) <= 0)
                   || (EVP_PKEY_fromdata(peer_ctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, peer_params) <= 0))
                    goto error_die;
    
                /* Now we have a PKEY with PQG in it and a peer with a public key. Generate a 
                 * host key from PQG.
                 * Note that the man pages for DH_generate_key recommend using EVP_PKEY_derive
                 * which is actually not correct.  That is a replacement for DH_compute_key only.
                 * To generate a DH keypair from PQG, you need to create a new PKEY CTX from the
                 * PQG parameterized PKEY parameter set.
                 */
                if(!(gctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_param_pkey, provider_str))
                   || (EVP_PKEY_keygen_init(gctx) <= 0)
                   || (EVP_PKEY_keygen(gctx, &dh_pkey) <= 0))
                    goto error_die;

                /* There are no specific KEX parameters for the AFT test */
            }
            else if(!strcasecmp("VAL", test_type->valuestring))  {
                SAFEGET(get_as_bytearray(&ephemeralPrivateIut, (int *)&ephemeralPrivateIut_len, tc, "ephemeralPrivateIut"), "Missing `ephemeralPrivateIut' in test case %d in test group %d\n", tcId, tgId);
                SAFEGET(get_as_bytearray(&ephemeralPublicIut, (int *)&ephemeralPublicIut_len, tc, "ephemeralPublicIut"), "Missing `ephemeralPublicIut' in test case %d in test group %d\n", tcId, tgId);
                /* Reverse ephemeral values to deal with converting to BIGNUM */
                reverse_bytearray(ephemeralPrivateIut, ephemeralPrivateIut_len);
                reverse_bytearray(ephemeralPublicIut, ephemeralPublicIut_len);

                /* Import the keypair -- we still need the domain generation parameters, though */
                *(host++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, ephemeralPublicIut, ephemeralPublicIut_len);
                *(host++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, ephemeralPrivateIut, ephemeralPrivateIut_len);
                *(host++) = OSSL_PARAM_construct_end();

                /* Import the peer's public key */
                *(peer++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, ephemeralPublicServer, ephemeralPublicServer_len);
                *(peer++) = OSSL_PARAM_construct_end();

                /* Generate the host and peer keys. Don't need DHX really because don't need Q, but continue to use anyway. */
                if(!(pctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", provider_str))
                   || (EVP_PKEY_fromdata_init(pctx) <= 0)
                   || (EVP_PKEY_fromdata(pctx, &dh_pkey, EVP_PKEY_KEYPAIR, host_params) <= 0)
                   || !(peer_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", provider_str))
                   || (EVP_PKEY_fromdata_init(peer_ctx) <= 0)
                   || (EVP_PKEY_fromdata(peer_ctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, peer_params) <= 0))
                    goto error_die;

                /* There are no specific KEX parameters for the VAL test */
            }

            /* Fill out the common KEX parameters */
            unsigned int pad = 1;
            *(kex++) = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
            *(kex++) = OSSL_PARAM_construct_end();

            /* Now we have a public/private key in dh_pkey and a public key in peer_pkey. */
            /* Generate the shared secret Z. */
            int passed = 1;
            if(!(kex_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_pkey, provider_str))
               || (EVP_PKEY_derive_init_ex(kex_ctx, kex_params) <= 0)
               || (EVP_PKEY_derive_set_peer_ex(kex_ctx, peer_pkey, key_confirm) <= 0)
               || (EVP_PKEY_derive(kex_ctx, NULL, &z_len) <= 0)
               || !(z_len)
               || !(z = OPENSSL_zalloc(z_len))
               || (EVP_PKEY_derive(kex_ctx, z, &z_len) <= 0))
                passed = 0;


            if(!strcasecmp("AFT", test_type->valuestring))  {
                if(!passed
                   || !pkey_get_bn_bytes(dh_pkey, OSSL_PKEY_PARAM_PUB_KEY, &ephemeralPublicIut, &ephemeralPublicIut_len)
                   || !(hashZ = OPENSSL_zalloc(EVP_MAX_MD_SIZE))
                   || !EVP_Q_digest(NULL, hashAlg->valuestring, provider_str, z, z_len, hashZ, &hashZ_len))
                    goto error_die;

                /* Write out the hashZ value */
                SAFEPUT(put_bytearray("ephemeralPublicIut", ephemeralPublicIut, ephemeralPublicIut_len, tc_output), "Unable to output ephemeralPublicIut for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("hashZIut", hashZ, hashZ_len, tc_output), "Unable to output hashZIut for test case %d in test group %d\n", tcId, tgId);
            }
            else if(!strcasecmp("VAL", test_type->valuestring))  {
                /* Outputting testPassed */
                unsigned char tmpHashZ[EVP_MAX_MD_SIZE] = {0};
                size_t tmpHashZ_len = 0;

                /* Need for comparison purposes */
                SAFEGET(get_as_bytearray(&hashZ, (int *)&hashZ_len, tc, "hashZIut"), "Missing `hashZIut' in test case %d in test group %d\n", tcId, tgId);

                /* We only need to do the hashing check if we thought we passed before */
                if(passed &&
                   (    !EVP_Q_digest(NULL, hashAlg->valuestring, provider_str, z, z_len, tmpHashZ, &tmpHashZ_len)
                     || memcmp(hashZ, tmpHashZ, tmpHashZ_len)
                     || (hashZ_len != tmpHashZ_len)
                   ))
                    passed = 0;

                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }


            /* Free structures here */
            SAFE_FUNC_FREE(ephemeralPublicServer, free);
            SAFE_FUNC_FREE(ephemeralPrivateIut, free);
            SAFE_FUNC_FREE(ephemeralPublicIut, free);
            SAFE_FUNC_FREE(z, OPENSSL_free);
            SAFE_FUNC_FREE(hashZ, OPENSSL_free);
            SAFE_FUNC_FREE(gctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(pctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(peer_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(kex_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(dh_param_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(dh_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(peer_pkey, EVP_PKEY_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }

        /* Free up structures at the test group level */
        SAFE_FUNC_FREE(q, free);
        SAFE_FUNC_FREE(p, free)
        SAFE_FUNC_FREE(g, free);

        _ACVP_JSON_context_pop();
    }

    ret = 1;

error_die:
#ifdef TRACE
    ERR_print_errors_fp(stdout);
#endif

    /* Free structures for final time */
    SAFE_FUNC_FREE(ephemeralPublicServer, free);
    SAFE_FUNC_FREE(ephemeralPrivateIut, free);
    SAFE_FUNC_FREE(ephemeralPublicIut, free);
    SAFE_FUNC_FREE(z, OPENSSL_free);
    SAFE_FUNC_FREE(hashZ, OPENSSL_free);
    SAFE_FUNC_FREE(gctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(pctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(dh_param_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(dh_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(peer_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(q, free);
    SAFE_FUNC_FREE(p, free)
    SAFE_FUNC_FREE(g, free);

    TRACE_POP;
    return ret;
}




int ACVP_TEST_vs_kas_ecc_component_1_0(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;

    int ret = 1;    /* Everything consider failure until it gets to end */

    unsigned char *ephemeralPrivateIut = NULL, *ephemeralPublicIutX = NULL, *ephemeralPublicIutY = NULL;
    size_t ephemeralPrivateIut_len = 0, ephemeralPublicIutX_len = 0, ephemeralPublicIutY_len;
    unsigned char *ephemeralPublicServerX = NULL, *ephemeralPublicServerY = NULL;
    int ephemeralPublicServerX_len = 0, ephemeralPublicServerY_len = 0;
    unsigned char *ecp = NULL, *ecpu = NULL;
    size_t ecp_len = 0, ecpu_len = 0;
    unsigned char *z = NULL;
    size_t z_len = 0;
    unsigned char *hashZ = NULL;
    size_t hashZ_len = 0;
    int key_confirm = 0;
    int kdf = 0;

    EVP_PKEY_CTX *pctx = NULL, *gctx = NULL, *peer_ctx = NULL, *kex_ctx = NULL;
    EVP_PKEY *ecdh_param_pkey = NULL, *ecdh_pkey = NULL, *peer_pkey = NULL;


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

        cJSON *scheme = NULL;
        SAFEGET(get_string_object(&scheme, tg, "scheme"), "Missing `scheme' in test group %d\n", tgId);

        /* This is the only supported scheme */
        if(strcasecmp(scheme->valuestring, "ephemeralUnified"))
            goto error_die;

        cJSON *kasRole = NULL;
        SAFEGET(get_string_object(&kasRole, tg, "kasRole"), "Missing `kasRole' in test group %d\n", tgId);

        cJSON *kasMode = NULL;
        SAFEGET(get_string_object(&kasMode, tg, "kasMode"), "Missing `kasMode' in test group %d\n", tgId);
        /* This is the only mode supported */
        if(strcasecmp(kasMode->valuestring, "noKdfNoKc"))
            goto error_die;
        else  {
            key_confirm = 0;
            kdf = 0;      /* Ignore warning about unused var here */
            kdf = kdf;
        }

        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in test group %d\n", tgId);
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

            SAFEGET(get_as_bytearray(&ephemeralPublicServerX, &ephemeralPublicServerX_len, tc, "ephemeralPublicServerX"), "Missing `ephemeralPublicServerX' in test case %d in test group %d\n", tcId, tgId);
            SAFEGET(get_as_bytearray(&ephemeralPublicServerY, &ephemeralPublicServerY_len, tc, "ephemeralPublicServerY"), "Missing `ephemeralPublicServerY' in test case %d in test group %d\n", tcId, tgId);

            /* Import the public key on the peer in EC point format */
            if(!construct_ec_point(ephemeralPublicServerX, ephemeralPublicServerX_len, ephemeralPublicServerY, ephemeralPublicServerY_len, &ecp, &ecp_len)) 
                goto error_die;

            OSSL_PARAM host_params[8] = {0}, *host = &host_params[0];
            OSSL_PARAM peer_params[8] = {0}, *peer = &peer_params[0];
            OSSL_PARAM kex_params[8] = {0}, *kex = &kex_params[0];

            /* Set the parameters on both the host and the peer */
            *(host++) = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve->valuestring, 0);
            *(peer++) = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve->valuestring, 0);

            int passed = 1;
            if(!strcasecmp("AFT", test_type->valuestring))  {
                /* Nothing else on the host */
                *(host++) = OSSL_PARAM_construct_end();

                *(peer++) = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, ecp, ecp_len);
                *(peer++) = OSSL_PARAM_construct_end();

                /* Construct the peer public key. */
                if(!(peer_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", provider_str))
                   || (EVP_PKEY_fromdata_init(peer_ctx) <= 0)
                   || (EVP_PKEY_fromdata(peer_ctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, peer_params) <= 0))
                    goto error_die;
    
                /* Generate a host key from the curve spec. */
                if(!(gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", provider_str))
                   || (EVP_PKEY_keygen_init(gctx) <= 0)
                   || !EVP_PKEY_CTX_set_params(gctx, host_params)
                   || (EVP_PKEY_generate(gctx, &ecdh_pkey) <= 0))
                    goto error_die;

                /* There are no specific KEX parameters for the AFT test */
            }
            else if(!strcasecmp("VAL", test_type->valuestring))  {
                SAFEGET(get_as_bytearray(&ephemeralPrivateIut, (int *)&ephemeralPrivateIut_len, tc, "ephemeralPrivateIut"), "Missing `ephemeralPrivateIut' in test case %d in test group %d\n", tcId, tgId);
                /* About to load as BIGNUM, so adjust for endian */
                reverse_bytearray(ephemeralPrivateIut, ephemeralPrivateIut_len);

                SAFEGET(get_as_bytearray(&ephemeralPublicIutX, (int *)&ephemeralPublicIutX_len, tc, "ephemeralPublicIutX"), "Missing `ephemeralPublicIutX' in test case %d in test group %d\n", tcId, tgId);
                SAFEGET(get_as_bytearray(&ephemeralPublicIutY, (int *)&ephemeralPublicIutY_len, tc, "ephemeralPublicIutY"), "Missing `ephemeralPublicIutY' in test case %d in test group %d\n", tcId, tgId);

                /* Import the keypair as EC point formats (public key done above) */
                if(!construct_ec_point(ephemeralPublicIutX, ephemeralPublicIutX_len, ephemeralPublicIutY, ephemeralPublicIutY_len, &ecpu, &ecpu_len))
                    goto error_die;

                *(host++) = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, ecpu, ecpu_len);
                *(host++) = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, ephemeralPrivateIut, ephemeralPrivateIut_len);
                *(host++) = OSSL_PARAM_construct_end();

                /* Import the peer's public key */
                *(peer++) = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, ecp, ecp_len);
                *(peer++) = OSSL_PARAM_construct_end();

                /* Generate the host and peer keys. */
                /* The vectors will be testing whether we are failing on checking for points that
                 * do not lie on the curve.  So don't die; instead mark as not passing.
                 */
                if(!(pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", provider_str))
                   || (EVP_PKEY_fromdata_init(pctx) <= 0)
                   || (EVP_PKEY_fromdata(pctx, &ecdh_pkey, EVP_PKEY_KEYPAIR, host_params) <= 0)
                   || !(peer_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", provider_str))
                   || (EVP_PKEY_fromdata_init(peer_ctx) <= 0)
                   || (EVP_PKEY_fromdata(peer_ctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, peer_params) <= 0))
                    passed = 0;

                /* There are no specific KEX parameters for the VAL test */
            }

            /* Fill out the common KEX parameters */
            unsigned int pad = 1;
            *(kex++) = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
            *(kex++) = OSSL_PARAM_construct_end();

            /* Now we have a public/private key in ecdh_pkey and a public key in peer_pkey. */
            /* Generate the shared secret Z. */
            if(!(kex_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ecdh_pkey, provider_str))
               || (EVP_PKEY_derive_init(kex_ctx) <= 0)
               || !EVP_PKEY_CTX_set_params(kex_ctx, kex_params)
               || (EVP_PKEY_derive_set_peer_ex(kex_ctx, peer_pkey, key_confirm) <= 0)
               || (EVP_PKEY_derive(kex_ctx, NULL, &z_len) <= 0)
               || !(z_len)
               || !(z = OPENSSL_zalloc(z_len))
               || (EVP_PKEY_derive(kex_ctx, z, &z_len) <= 0))
                passed = 0;


            if(!strcasecmp("AFT", test_type->valuestring))  {
                if(!passed
                   || !pkey_get_bn_bytes(ecdh_pkey, OSSL_PKEY_PARAM_EC_PUB_X, &ephemeralPublicIutX, &ephemeralPublicIutX_len)
                   || !pkey_get_bn_bytes(ecdh_pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &ephemeralPublicIutY, &ephemeralPublicIutY_len)
                   || !(hashZ = OPENSSL_zalloc(EVP_MAX_MD_SIZE))
                   || !EVP_Q_digest(NULL, hashAlg->valuestring, provider_str, z, z_len, hashZ, &hashZ_len))
                    goto error_die;

                /* Write out the hashZ value */
                SAFEPUT(put_bytearray("ephemeralPublicIutX", ephemeralPublicIutX, ephemeralPublicIutX_len, tc_output), "Unable to output ephemeralPublicIutX for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("ephemeralPublicIutY", ephemeralPublicIutY, ephemeralPublicIutY_len, tc_output), "Unable to output ephemeralPublicIutY for test case %d in test group %d\n", tcId, tgId);
                SAFEPUT(put_bytearray("hashZIut", hashZ, hashZ_len, tc_output), "Unable to output hashZIut for test case %d in test group %d\n", tcId, tgId);
            }
            else if(!strcasecmp("VAL", test_type->valuestring))  {
                /* Outputting testPassed */
                unsigned char tmpHashZ[EVP_MAX_MD_SIZE] = {0};
                size_t tmpHashZ_len = 0;

                /* Need for comparison purposes */
                SAFEGET(get_as_bytearray(&hashZ, (int *)&hashZ_len, tc, "hashZIut"), "Missing `hashZIut' in test case %d in test group %d\n", tcId, tgId);

                /* We only need to do the hashing check if we thought we passed before */
                if(passed &&
                   (    !EVP_Q_digest(NULL, hashAlg->valuestring, provider_str, z, z_len, tmpHashZ, &tmpHashZ_len)
                     || memcmp(hashZ, tmpHashZ, tmpHashZ_len)
                     || (hashZ_len != tmpHashZ_len)
                   ))
                    passed = 0;

                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }


            /* Free structures here */
            SAFE_FUNC_FREE(ephemeralPublicServerX, free);
            SAFE_FUNC_FREE(ephemeralPublicServerY, free);
            SAFE_FUNC_FREE(ephemeralPrivateIut, free);
            SAFE_FUNC_FREE(ephemeralPublicIutX, free);
            SAFE_FUNC_FREE(ephemeralPublicIutY, free);
            SAFE_FUNC_FREE(ecp, free);
            SAFE_FUNC_FREE(ecpu, free);
            SAFE_FUNC_FREE(z, OPENSSL_free);
            SAFE_FUNC_FREE(hashZ, OPENSSL_free);
            SAFE_FUNC_FREE(gctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(pctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(peer_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(kex_ctx, EVP_PKEY_CTX_free);
            SAFE_FUNC_FREE(ecdh_param_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(ecdh_pkey, EVP_PKEY_free);
            SAFE_FUNC_FREE(peer_pkey, EVP_PKEY_free);

            /* Mark test case as passed or failed */
            _ACVP_TEST_status(ret);

            _ACVP_JSON_context_pop();
        }

        _ACVP_JSON_context_pop();
    }

    ret = 1;

error_die:
#ifdef TRACE
    ERR_print_errors_fp(stdout);
#endif

    /* Free structures for final time */
    SAFE_FUNC_FREE(ephemeralPublicServerX, free);
    SAFE_FUNC_FREE(ephemeralPublicServerY, free);
    SAFE_FUNC_FREE(ephemeralPrivateIut, free);
    SAFE_FUNC_FREE(ephemeralPublicIutX, free);
    SAFE_FUNC_FREE(ephemeralPublicIutY, free);
    SAFE_FUNC_FREE(ecp, free);
    SAFE_FUNC_FREE(ecpu, free);
    SAFE_FUNC_FREE(z, OPENSSL_free);
    SAFE_FUNC_FREE(hashZ, OPENSSL_free);
    SAFE_FUNC_FREE(gctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(pctx, EVP_PKEY_CTX_free);
    SAFE_FUNC_FREE(ecdh_param_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(ecdh_pkey, EVP_PKEY_free);
    SAFE_FUNC_FREE(peer_pkey, EVP_PKEY_free);

    TRACE_POP;
    return ret;
}


int ACVP_TEST_vs_kas_ffc_v1_0(cJSON *j, void *options, cJSON *out, const char *algname_UNUSED)  {
    TRACE_PUSH;

    int ret = 1;    /* Everything consider failure until it gets to end */

    cJSON *mode = NULL;
    SAFEGET(get_string_object(&mode, j, "mode"), "Missing `mode' in vector set\n");
    cJSON *revision = NULL;
    SAFEGET(get_string_object(&revision, j, "revision"), "Missing `revision' in vector set\n");

    if(!strcasecmp(mode->valuestring, "Component") && !strcasecmp(revision->valuestring, "1.0"))
        ret = ACVP_TEST_vs_kas_ffc_component_1_0(j, options, out);

error_die:
    TRACE_POP;
    return ret;
}


int ACVP_TEST_vs_kas_ecc_v1_0(cJSON *j, void *options, cJSON *out, const char *algname_UNUSED)  {
    TRACE_PUSH;

    int ret = 1;    /* Everything consider failure until it gets to end */

    cJSON *mode = NULL;
    SAFEGET(get_string_object(&mode, j, "mode"), "Missing `mode' in vector set\n");
    cJSON *revision = NULL;
    SAFEGET(get_string_object(&revision, j, "revision"), "Missing `revision' in vector set\n");

    if(!strcasecmp(mode->valuestring, "Component") && !strcasecmp(revision->valuestring, "1.0"))
        ret = ACVP_TEST_vs_kas_ecc_component_1_0(j, options, out);

error_die:
    TRACE_POP;
    return ret;
}


ACVP_TEST_ALG_SPEC_BEGIN(kas_ffc)
//ACVP_TEST_ALG_SPEC_REV(kas_ffc, 1_0, ACVP_ALG_REVISION_SP800_56AR3, NULL)
ACVP_TEST_ALG_SPEC_REV(kas_ffc, 1_0, ACVP_ALG_REVISION_1_0, NULL)
ACVP_TEST_ALG_SPEC_END

ACVP_TEST_ALG_SPEC_BEGIN(kas_ecc)
ACVP_TEST_ALG_SPEC_REV(kas_ecc, 1_0, ACVP_ALG_REVISION_1_0, NULL)
ACVP_TEST_ALG_SPEC_END
