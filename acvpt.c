#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/conf.h>

#include "acvp_lib.h"


OSSL_LIB_CTX *libctx = NULL;

int verbose = 0;
char provider_str[128] = {0};

static void usage(void)  {
    printf("\nUsage: acvpt <args>\n");
    printf("\nArguments:\n");
    printf("\t\t-i\t vector set file to process\n");
    printf("\t\t-o\t desired response output filename\n");
    printf("\t\t-p\t override the default provider.  Use arg fips to force the fips provider.\n");
    printf("\t\t-a\t print OpenSSL install information.\n");
    printf("\t\t-v\t verbose debugging\n");

}
static void openssl_info(void){
    printf("\nLocal OSSL Install info:\n%s\n%s\n%s\nCONFIGDIR: %s\n",OPENSSL_VERSION_TEXT,OpenSSL_version(OPENSSL_DIR),OpenSSL_version(OPENSSL_MODULES_DIR),OPENSSL_info(OPENSSL_INFO_CONFIG_DIR));
}

typedef struct Options {
    FILE* input;
    FILE* output;
} Options ;

int parse_cmd_options(int argc, char *argv[], struct Options *options)  {
    int ret = 0;
    if(!argv || argc < 2) return 0; /* No args to parse */
    if(!options) return 0;          /* No values to return, so no sense parsing */

    int c = 0;
    while ((c = getopt (argc, argv, "ahp:vi:o:")) != -1)  {
        switch (c)  {
            case 'p': if(strcasecmp(optarg, "fips") == 0)
                          strcpy(provider_str, "fips=yes");
                      else if (strcasecmp(optarg, "null") == 0)  {
                          /* TODO */
                          raise_error(1005);
                          ret = 1;
                      }
                      else
                          snprintf(provider_str, sizeof(provider_str)-1, "provider=%s", optarg);
                      break;
            case 'v': verbose++;
                      break;
            /* The next few options fall through */
            case '?': fprintf (stderr, "Unknown option %c.\n", optopt);
            case 'h': usage();
                      exit(0);
                      break;
            case 'i': (*options).input = fopen(optarg,"r");
                      break;
            case 'o': (*options).output = fopen(optarg,"w");
                      printf("Outputting response to: %s\n", optarg);
                      break;
            case 'a': openssl_info();
                      break;

            default:
                      ret = 1;
                      break;
        }
    }
    return ret;
}


cJSON *init_output(cJSON *json)  {
    /* Take in the initial structure and copy the necessary pieces out */
    cJSON *output = cJSON_CreateArray();

    /* Data is parsed already; now we need to extract everything to give to the caller. */
    /* Validate that the structure is sound and conforms with the expected structure format. */
    if (cJSON_GetArraySize(json) != 2)  {
        printf("Expecting array of size 2 in top-level JSON. Check input format.\n");
        goto error_die;
    }

    /* Check version is correct */
    cJSON *a0 = NULL;
    SAFEGET(get_array_item(&a0, json, 0), "JSON not structured properly\n");

    cJSON *versionStr = NULL;
    SAFEGET(get_string_object(&versionStr, a0, "acvVersion"), "Version identifier is missing\n");

    cJSON *out_versionObj = cJSON_CreateObject();
    SAFEPUT(put_string("acvVersion", versionStr->valuestring, out_versionObj), "Unable to add version string");

    if (!output) return NULL;
    SAFEPUT(put_array_item(out_versionObj, output), "Unable to add version string to output structure");

    goto success;

error_die:
    SAFE_FUNC_FREE(output, cJSON_Delete);

success:
    return output;
}



int main(int argc, char *argv[])  {
    TRACE_PUSH;
    int ret = 1;

    /* TODO: This is a structure of options which get values assigned */
    struct Options options;
    options.input = stdin;
    options.output = stdout;

    printf("Running version %s located at %s\n", OPENSSL_VERSION_TEXT,OpenSSL_version(OPENSSL_DIR));

    /* Parse options, if any. At very least, to read input and write output. */
    if (parse_cmd_options(argc, argv, &options) != 0)
        goto error_die;

    /* Read the JSON input */
    /* TODO */
    cJSON *input = read_fd_as_json(options.input);
    if(!input)  {
        /* Push error to stack... */
        raise_error(1001);
        goto error_die;
    }
    /* Get the proper library context for ops */
    if ((libctx = OSSL_LIB_CTX_new()) == NULL) {
        raise_error(1002);
        goto error_die;
    }

    if(CONF_modules_load_file_ex(libctx, NULL, NULL, 0) != 1)  {
        raise_error(1003);
        goto error_die;
    }
    if(!OSSL_LIB_CTX_set0_default(libctx))  {
        raise_error(1004);
        goto error_die;
    }
    /* Top-level runner */
    cJSON *output = init_output(input);
    if(!output || (execute_tests(input, &options, output) != 0) )
        goto error_die;

    /* Dump output */
    fprintf (options.output, "%s\n", cJSON_Print(output));

    ret = 0;
    printf("Success!\n");
error_die:
    if(libctx)
        OSSL_LIB_CTX_free(libctx);

    /* TODO: Print error stack */
    if(ret != 0)
        generate_error_stack(stderr);

    TRACE_POP;
    return ret;
}
