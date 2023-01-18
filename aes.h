#ifndef _AES_H
#define _AES_H

int ACVP_TEST_vs_aes_ecb(cJSON *j, void *options, cJSON *out);
int ACVP_TEST_vs_aes_cbc(cJSON *j, void *options, cJSON *out);
int ACVP_TEST_vs_aes_ctr(cJSON *j, void *options, cJSON *out);
int ACVP_TEST_vs_aes_cfb1(cJSON *j, void *options, cJSON *out);
int ACVP_TEST_vs_aes_cfb8(cJSON *j, void *options, cJSON *out);
int ACVP_TEST_vs_aes_cfb128(cJSON *j, void *options, cJSON *out);
int ACVP_TEST_vs_aes_gcm(cJSON *j, void *options, cJSON *out);
int ACVP_TEST_vs_aes_ofb(cJSON *j, void *options, cJSON *out);
//int ACVP_TEST_vs_aes_kw(cJSON *j, void *options, cJSON *out);

#endif
