#ifndef _ACVP_LIB_H
#define _ACVP_LIB_H

#include <openssl/crypto.h>
#include <cJSON.h>

#include "json_utl.h"
#include "utils.h"

#ifdef TRACE
extern int _trace_level;
# define TRACE_INDENT    2
# define TRACE_PUSH  { printf("%*sEntering %s\n", _trace_level, "", __FUNCTION__); _trace_level+=TRACE_INDENT; }
# define TRACE_POP   { _trace_level-=TRACE_INDENT; printf("%*sLeaving %s\n", _trace_level, "", __FUNCTION__); }
#else
# define TRACE_PUSH
# define TRACE_POP
#endif


/* A simply macro to safely dispose of an potentially reuse allocated variables */
#define SAFE_FUNC_FREE(p, func) if(p) { func(p); p = NULL; }


extern OSSL_LIB_CTX *libctx;

extern int verbose;
extern char provider_str[128];

enum {
    ACVP_ALG_REVISION_UNKNOWN = 0,
    ACVP_ALG_REVISION_1_0,
    ACVP_ALG_REVISION_2_0,
    ACVP_ALG_REVISION_FIPS186_4,
    ACVP_ALG_REVISION_SP800_56AR3,
};

enum {
    ACVP_ALG_UNKNOWN,
    ACVP_ALG_AES_ECB,
    ACVP_ALG_AES_CBC,
    ACVP_ALG_AES_CTR,
    ACVP_ALG_AES_CFB1,
    ACVP_ALG_AES_CFB8,
    ACVP_ALG_AES_CFB128,
    ACVP_ALG_AES_GCM,
    ACVP_ALG_AES_KW,

    ACVP_ALG_SHS_SHA1,
    ACVP_ALG_SHS_SHA2_224,
    ACVP_ALG_SHS_SHA2_256,
    ACVP_ALG_SHS_SHA2_384,
    ACVP_ALG_SHS_SHA2_512,

    ACVP_ALG_SHS_SHA3_224,
    ACVP_ALG_SHS_SHA3_256,
    ACVP_ALG_SHS_SHA3_384,
    ACVP_ALG_SHS_SHA3_512,

    ACVP_ALG_HMAC_SHA1,
    ACVP_ALG_HMAC_SHA2_224,
    ACVP_ALG_HMAC_SHA2_256,
    ACVP_ALG_HMAC_SHA2_384,
    ACVP_ALG_HMAC_SHA2_512,

    ACVP_ALG_HMAC_SHA3_224,
    ACVP_ALG_HMAC_SHA3_256,
    ACVP_ALG_HMAC_SHA3_384,
    ACVP_ALG_HMAC_SHA3_512,

    ACVP_ALG_DRBG_HASH,
    ACVP_ALG_DRBG_HMAC,
    ACVP_ALG_DRBG_CTR,

    ACVP_ALG_RSA,
    ACVP_ALG_DSA,
    ACVP_ALG_ECDSA,

    ACVP_ALG_SAFEPRIMES,

    ACVP_ALG_KDF,

    ACVP_ALG_KAS_FFC,
    ACVP_ALG_KAS_ECC,

    ACVP_ALG_TDES_ECB,
    ACVP_ALG_TDES_CBC,
    /* ... */
};


void generate_error_stack(FILE *out);
void raise_error(int code);
void _ACVP_JSON_context_push(const char *context, const char *format, ...);
void _ACVP_JSON_context_pop(void);
void _ACVP_TEST_status (int ret);
void report_test_result(int algId, int ret);
int execute_tests(cJSON *j, void *options, cJSON *out);

int ACVP_JSON_get_vector_set_id(cJSON *j);
int ACVP_JSON_get_testgroup_id(cJSON *j);
int ACVP_JSON_get_testcase_id(cJSON *j);
int ACVP_JSON_get_alg(cJSON *j);
unsigned int ACVP_JSON_get_alg_revision(cJSON *j);

int ACVP_JSON_output_revision(cJSON *in, cJSON *out);
int ACVP_JSON_output_algorithm_and_mode(cJSON *in, cJSON *out);

/* Version specific calls */
int ACVP_v1_execute_tests(cJSON *j, void *options, cJSON *out);


/* Macros to help build out revision stubs */
#define ACVP_TEST_ALG_PROTO(fn) \
int ACVP_TEST_vs_ ##fn (cJSON *j, void *options, cJSON *out)

#define ACVP_TEST_ALG_SPEC_BEGIN(fn) \
ACVP_TEST_ALG_PROTO(fn)  { \
    TRACE_PUSH; \
    int ret = 1; \
    /* Get the revision and put back into output */ \
    if(!ACVP_JSON_output_revision(j, out)) goto error_die; \
    switch(ACVP_JSON_get_alg_revision(j))  {

#define ACVP_TEST_ALG_SPEC_REV(impl, fnrev, acvprev, ...) \
        case acvprev: ret = ACVP_TEST_vs_##impl##_v##fnrev (j, options, out, __VA_ARGS__); break;

#define ACVP_TEST_ALG_SPEC_END \
        default: \
            raise_error(/* TBD code */0); \
            goto error_die; \
    } \
error_die: \
    TRACE_POP; \
    return ret; \
}


#endif
