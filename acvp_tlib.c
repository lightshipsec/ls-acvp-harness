#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/err.h>
#include "acvp_lib.h"


#ifdef TRACE
int _trace_level = 0;
#endif


/* TODO */
void generate_error_stack(FILE *out)  {
    if(!out) return;
    return;
}

/* TODO */
void raise_error(int code)  {
    /* Convert code to error string and uses the JSON context if available. */
    //print openssl error stack
    ERR_print_errors_fp(stderr);
    switch(code){
        case 1000:
            printf("Error:  Algorithm or mode not supported\n");
            break;
        case 1001: 
            printf("Error reading input vector file\n");
            break;
        case 1002:
            printf("Error initializing OSSL Context, verify your installation is fips enabled\n");
            break;
        case 1003:
            printf("Error loading .cnf file.  Verify the location using ./acvpt -a and check for issues\n");
            break;
        case 1004:
            printf("Error setting default libctx values\n");
            break;
        case 1005:
            printf("Error:  Null provider not permitted\n");
            break;
    }

    return;
}


/* TODO */
void _ACVP_JSON_context_push(const char *context, const char *format, ...) {
    /* This function will add a string context to a stack of contexts so
     * that the error function can identify where in the stack the error
     * occurred.  The variable args is to permit additional context
     * information to be provided if necessary.
     */
    return;
}

/* TODO */
void _ACVP_JSON_context_pop(void) {
    /* Removes the last context from the stack. */
    return;
}


/* TODO */
static unsigned int ACVP_input_version(cJSON *j)  {
    TRACE_PUSH;
    /* Get the item called "acvVersion" which is a float
     * that needs to be coded as a int.
     * We are assuming that NIST might code this as 
     * major.minor.revision.build (or similar).
     * So 1.2.3.4 is 0x01020304.
    */
    TRACE_POP;
    return 0x01000000;
}
    
int ACVP_JSON_get_alg(cJSON *j)  {
    TRACE_PUSH;
    int alg = ACVP_ALG_UNKNOWN;

    /* Get the item called "algorithm" */
    cJSON *algStr = NULL;
    SAFEGET(get_string_object(&algStr, j, "algorithm"), "Algorithm identifier missing in JSON\n");
    if(!strcasecmp(algStr->valuestring, "ACVP-AES-ECB")) alg = ACVP_ALG_AES_ECB;
    else if (!strcasecmp(algStr->valuestring, "ACVP-AES-CBC")) alg = ACVP_ALG_AES_CBC;
    else if (!strcasecmp(algStr->valuestring, "ACVP-AES-CTR")) alg = ACVP_ALG_AES_CTR;
    else if (!strcasecmp(algStr->valuestring, "ACVP-AES-CFB1")) alg = ACVP_ALG_AES_CFB1;
    else if (!strcasecmp(algStr->valuestring, "ACVP-AES-CFB8")) alg = ACVP_ALG_AES_CFB8;
    else if (!strcasecmp(algStr->valuestring, "ACVP-AES-CFB128")) alg = ACVP_ALG_AES_CFB128;
    else if (!strcasecmp(algStr->valuestring, "ACVP-AES-GCM")) alg = ACVP_ALG_AES_GCM;
    else if (!strcasecmp(algStr->valuestring, "ACVP-AES-OFB")) alg = ACVP_ALG_AES_OFB;
    //else if (!strcasecmp(algStr->valuestring, "ACVP-AES-KW")) alg = ACVP_ALG_AES_KW;

    else if (!strcasecmp(algStr->valuestring, "SHA-1")) alg = ACVP_ALG_SHS_SHA1;

    else if (!strcasecmp(algStr->valuestring, "SHA2-224")) alg = ACVP_ALG_SHS_SHA2_224;
    else if (!strcasecmp(algStr->valuestring, "SHA2-256")) alg = ACVP_ALG_SHS_SHA2_256;
    else if (!strcasecmp(algStr->valuestring, "SHA2-384")) alg = ACVP_ALG_SHS_SHA2_384;
    else if (!strcasecmp(algStr->valuestring, "SHA2-512")) alg = ACVP_ALG_SHS_SHA2_512;

    else if (!strcasecmp(algStr->valuestring, "SHA3-224")) alg = ACVP_ALG_SHS_SHA3_224;
    else if (!strcasecmp(algStr->valuestring, "SHA3-256")) alg = ACVP_ALG_SHS_SHA3_256;
    else if (!strcasecmp(algStr->valuestring, "SHA3-384")) alg = ACVP_ALG_SHS_SHA3_384;
    else if (!strcasecmp(algStr->valuestring, "SHA3-512")) alg = ACVP_ALG_SHS_SHA3_512;

    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA-1")) alg = ACVP_ALG_HMAC_SHA1;

    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA2-224")) alg = ACVP_ALG_HMAC_SHA2_224;
    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA2-256")) alg = ACVP_ALG_HMAC_SHA2_256;
    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA2-384")) alg = ACVP_ALG_HMAC_SHA2_384;
    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA2-512")) alg = ACVP_ALG_HMAC_SHA2_512;

    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA3-224")) alg = ACVP_ALG_HMAC_SHA3_224;
    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA3-256")) alg = ACVP_ALG_HMAC_SHA3_256;
    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA3-384")) alg = ACVP_ALG_HMAC_SHA3_384;
    else if (!strcasecmp(algStr->valuestring, "HMAC-SHA3-512")) alg = ACVP_ALG_HMAC_SHA2_512;

    else if (!strcasecmp(algStr->valuestring, "hashDRBG")) alg = ACVP_ALG_DRBG_HASH;
    else if (!strcasecmp(algStr->valuestring, "hmacDRBG")) alg = ACVP_ALG_DRBG_HMAC;
    else if (!strcasecmp(algStr->valuestring, "ctrDRBG")) alg = ACVP_ALG_DRBG_CTR;

    else if (!strcasecmp(algStr->valuestring, "RSA")) alg = ACVP_ALG_RSA;
    else if (!strcasecmp(algStr->valuestring, "DSA")) alg = ACVP_ALG_DSA;
    else if (!strcasecmp(algStr->valuestring, "ECDSA")) alg = ACVP_ALG_ECDSA;

    else if (!strcasecmp(algStr->valuestring, "safePrimes")) alg = ACVP_ALG_SAFEPRIMES;

    else if (!strcasecmp(algStr->valuestring, "KAS-FFC")) alg = ACVP_ALG_KAS_FFC;
    else if (!strcasecmp(algStr->valuestring, "KAS-ECC")) alg = ACVP_ALG_KAS_ECC;

    else if (!strcasecmp(algStr->valuestring, "ACVP-TDES-CBC")) alg = ACVP_ALG_TDES_CBC;
    else if (!strcasecmp(algStr->valuestring, "ACVP-TDES-ECB")) alg = ACVP_ALG_TDES_ECB;

error_die:
    TRACE_POP;
    return alg;
}
int ACVP_JSON_get_vector_set_id(cJSON *j)  {
    TRACE_PUSH;
    /* Get the item called "vsId" */
    cJSON *vsId = NULL;
    int vsId_int = -1;
    SAFEGET (get_integer_object (&vsId, j, "vsId"), "vsId missing in JSON\n");
    vsId_int = vsId->valueint;
error_die:
    TRACE_POP;
    return vsId_int;
}
int ACVP_JSON_get_testgroup_id(cJSON *j)  {
    TRACE_PUSH;
    /* Get the item called "tgId" */
    cJSON *tgId = NULL;
    int tgId_int = -1;
    SAFEGET (get_integer_object (&tgId, j, "tgId"), "tgId missing in JSON\n");
    tgId_int = tgId->valueint;
error_die:
    TRACE_POP;
    return tgId_int;
}
int ACVP_JSON_get_testcase_id(cJSON *j)  {
    TRACE_PUSH;
    /* Get the item called "tcId" */
    cJSON *tcId = NULL;
    int tcId_int = -1;
    SAFEGET (get_integer_object (&tcId, j, "tcId"), "tcId missing in JSON\n");
    tcId_int = tcId->valueint;
error_die:
    TRACE_POP;
    return tcId_int;
}
/* TODO */

static unsigned int _alg_revision_table(char *rev)  {
    if(!strcasecmp(rev, "1.0"))
        return ACVP_ALG_REVISION_1_0;
    if(!strcasecmp(rev, "2.0"))
        return ACVP_ALG_REVISION_2_0; 
    if(!strcasecmp(rev, "FIPS186-4"))
        return ACVP_ALG_REVISION_FIPS186_4;
    if(!strcasecmp(rev, "Sp800-56Ar3"))
        return ACVP_ALG_REVISION_SP800_56AR3;
    return ACVP_ALG_REVISION_UNKNOWN;
}
unsigned int ACVP_JSON_get_alg_revision(cJSON *j)  {
    /* The revision is a string.  Usually "1.0", but 
     * sometimes a variant of a standard (eg. "FIPS186-4" vs. "FIPS186-5").
     * We return an integer which is coded for the revision.
    */
    TRACE_PUSH;
    cJSON *revision = NULL;
    SAFEGET(get_string_object(&revision, j, "revision"), "revision missing in JSON\n");
    printf("Revision: %s\n",revision->valuestring);
error_die:
    TRACE_POP;
    return _alg_revision_table(revision->valuestring);
}

int ACVP_JSON_output_revision(cJSON *in, cJSON *out)  {
    cJSON *revision = NULL;
    SAFEGET(get_string_object(&revision, in, "revision"), "revision missing in JSON\n");
    SAFEPUT(put_string("revision", revision->valuestring, out), "Unable to add revision to output JSON\n");
    return 1;
error_die:
    return 0;
}

int ACVP_JSON_output_algorithm_and_mode(cJSON *in, cJSON *out)  {
    cJSON *alg = NULL;
    cJSON *mode = NULL;
    SAFEGET(get_string_object(&alg, in, "algorithm"), "algorithm missing in JSON\n");
    printf("Using algorithm: %s\n",alg->valuestring);
    SAFEPUT(put_string("algorithm", alg->valuestring, out), "Unable to add algorithm to output JSON\n");
    if(get_string_object(&mode, in, "mode") == 0){
        /* Found it */
        printf("Mode: %s\n",mode->valuestring);
        SAFEPUT(put_string("mode", mode->valuestring, out), "Unable to add mode to output JSON\n");
    } 

    return 1;
error_die:
    return 0;
} 

void _ACVP_TEST_status (int ret)  {
    TRACE_PUSH;
    goto error_die;
error_die:
    TRACE_POP;
}

void report_test_result(int algId, int ret)  {
    TRACE_PUSH;
    goto error_die;
error_die:
    TRACE_POP;
}


int execute_tests(cJSON *j, void *options, cJSON *out)  {
    TRACE_PUSH;
    int ret = 0;

    /* Algorithm
     * Parse version of file.
     * Run that version of the parser/tester.
     */
    switch(ACVP_input_version(j))  {
        case 0x01000000: ret = ACVP_v1_execute_tests(j, options, out); break;
        default:
            raise_error(/* TBD code */0);
            goto error_die;
    }

error_die:
    TRACE_POP;
    return ret;
}
