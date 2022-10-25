#ifndef _JSON_UTIL_H
#define _JSON_UTIL_H

#include <cJSON.h>


/* Assumes caller has `error_die' guards set up.
 * If error is NULL, then we ignore the error.
 */
#define SAFEGET(call, error, ...)   \
    if(call != 0) { \
        if(error)  { \
            printf(error, ## __VA_ARGS__); \
            goto error_die; \
        } \
    }

#define SAFEPUT(call, error, ...)   \
    if(call != 0) { \
        if(error)  { \
            printf(error, ## __VA_ARGS__); \
            goto error_die; \
        } \
    }



int get_object(cJSON **to, const cJSON *from, char *name);
int get_array_item(cJSON **to, const cJSON *from, int index);
int get_string_object(cJSON **to, const cJSON *from, char *name);
int get_integer_object(cJSON **to, const cJSON *from, char *name);
int get_boolean_object(cJSON **to, const cJSON *from, char *name);
int get_as_bytearray(unsigned char **to, int *to_len, const cJSON *from, char *name);

int put_array_item(cJSON *obj, cJSON *to_arr);
int put_object(char *name, cJSON *obj, cJSON *to);
int put_string(const char *name, const char *value, cJSON *to);
int put_integer(const char *name, int value, cJSON *to);
int put_boolean(const char *name, cJSON_bool value, cJSON *to);
int put_bytearray(const char *name, unsigned char *value, int value_len, const cJSON *to);

unsigned char *read_fd_as_string(FILE *fd, unsigned char **buf);
unsigned char *read_file_as_string(char *fn, unsigned char **buf);
cJSON *read_fd_as_json(FILE *fd);
cJSON *read_file_as_json(char *fn);

#endif
