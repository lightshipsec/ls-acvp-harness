#include "acvp_lib.h"

#include "algs.h"

int ACVP_v1_execute_tests(cJSON *j, void *options, cJSON *out) {
    TRACE_PUSH;
    /* From here, iterate over each vector set in the array
     * and run the correct algorithm.
     */
    cJSON *vs = NULL;
    int item = 0;

    /* Construct the (empty) response body */
    cJSON *response = cJSON_CreateObject ();

    cJSON_ArrayForEach(vs, j)  {
        int ret = 0;
        /* The first array item is the version, which we skip */
        if( item++ == 0 ) continue;

        int vsId = ACVP_JSON_get_vector_set_id(vs);
        if(vsId < 0) {
            raise_error(/*TBD code */0);
            goto error_die;
        }
        _ACVP_JSON_context_push("vs", "vsId = %d\n", vsId);

        /* Put the necessary parts in the header */
        SAFEPUT (put_integer ("vsId", vsId, response), "Unable to add vsId to output JSON\n");
        if(!ACVP_JSON_output_algorithm_and_mode(vs, response)) goto error_die;
        SAFEPUT (put_array_item (response, out), "Unable to add response body to output JSON\n");
        printf("For vector set id: %d\n",vsId);
        /* Otherwise, pull in the alg */
        switch(ACVP_JSON_get_alg(vs))  {
            case ACVP_ALG_AES_ECB: ret = ACVP_TEST_vs_aes_ecb(vs, options, response); break;
            case ACVP_ALG_AES_CBC: ret = ACVP_TEST_vs_aes_cbc(vs, options, response); break;
            case ACVP_ALG_AES_CTR: ret = ACVP_TEST_vs_aes_ctr(vs, options, response); break;
            case ACVP_ALG_AES_GCM: ret = ACVP_TEST_vs_aes_gcm(vs, options, response); break;
            case ACVP_ALG_AES_CFB1: ret = ACVP_TEST_vs_aes_cfb1(vs, options, response); break;
            case ACVP_ALG_AES_CFB8: ret = ACVP_TEST_vs_aes_cfb8(vs, options, response); break;
            case ACVP_ALG_AES_CFB128: ret = ACVP_TEST_vs_aes_cfb128(vs, options, response); break;
#if 0
            case ACVP_ALG_AES_OFB: ret = ACVP_TEST_vs_aes_ofb(vs, options); break;
#endif
            case ACVP_ALG_AES_KW: ret = ACVP_TEST_vs_aes_kw(vs, options, response); break;

            case ACVP_ALG_SHS_SHA1: ret = ACVP_TEST_vs_shs_sha1(vs, options, response); break;
            case ACVP_ALG_SHS_SHA2_224: ret = ACVP_TEST_vs_shs_sha2_224(vs, options, response); break;
            case ACVP_ALG_SHS_SHA2_256: ret = ACVP_TEST_vs_shs_sha2_256(vs, options, response); break;
            case ACVP_ALG_SHS_SHA2_384: ret = ACVP_TEST_vs_shs_sha2_384(vs, options, response); break;
            case ACVP_ALG_SHS_SHA2_512: ret = ACVP_TEST_vs_shs_sha2_512(vs, options, response); break;
            case ACVP_ALG_SHS_SHA3_224: ret = ACVP_TEST_vs_shs_sha3_224(vs, options, response); break;
            case ACVP_ALG_SHS_SHA3_256: ret = ACVP_TEST_vs_shs_sha3_256(vs, options, response); break;
            case ACVP_ALG_SHS_SHA3_384: ret = ACVP_TEST_vs_shs_sha3_384(vs, options, response); break;
            case ACVP_ALG_SHS_SHA3_512: ret = ACVP_TEST_vs_shs_sha3_512(vs, options, response); break;

            case ACVP_ALG_HMAC_SHA1: ret = ACVP_TEST_vs_hmac_sha1(vs, options, response); break;
            case ACVP_ALG_HMAC_SHA2_224: ret = ACVP_TEST_vs_hmac_sha2_224(vs, options, response); break;
            case ACVP_ALG_HMAC_SHA2_256: ret = ACVP_TEST_vs_hmac_sha2_256(vs, options, response); break;
            case ACVP_ALG_HMAC_SHA2_384: ret = ACVP_TEST_vs_hmac_sha2_384(vs, options, response); break;
            case ACVP_ALG_HMAC_SHA2_512: ret = ACVP_TEST_vs_hmac_sha2_512(vs, options, response); break;

            case ACVP_ALG_DRBG_HASH: ret = ACVP_TEST_vs_drbg_hash(vs, options, response); break;
            case ACVP_ALG_DRBG_HMAC: ret = ACVP_TEST_vs_drbg_hmac(vs, options, response); break;
            case ACVP_ALG_DRBG_CTR: ret = ACVP_TEST_vs_drbg_ctr(vs, options, response); break;

            case ACVP_ALG_RSA: ret = ACVP_TEST_vs_rsa(vs, options, response); break;
            case ACVP_ALG_DSA: ret = ACVP_TEST_vs_dsa(vs, options, response); break;
            case ACVP_ALG_ECDSA: ret = ACVP_TEST_vs_ecdsa(vs, options, response); break;

            case ACVP_ALG_SAFEPRIMES: ret = ACVP_TEST_vs_safeprimes(vs, options, response); break;

            case ACVP_ALG_KAS_FFC: ret = ACVP_TEST_vs_kas_ffc(vs, options, response); break;
            case ACVP_ALG_KAS_ECC: ret = ACVP_TEST_vs_kas_ecc(vs, options, response); break;

            case ACVP_ALG_TDES_ECB: ret = ACVP_TEST_vs_tdes_ecb(vs, options, response); break;
            case ACVP_ALG_TDES_CBC: ret = ACVP_TEST_vs_tdes_cbc(vs, options, response); break;

            default: raise_error(/*TBD code */0);
        }

        report_test_result(ACVP_JSON_get_alg(vs), ret);

        _ACVP_JSON_context_pop();
    }

    TRACE_POP;
    return 0;

error_die:
    TRACE_POP;
    return 1;
}

