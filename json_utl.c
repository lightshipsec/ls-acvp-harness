#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/bn.h>
#include <cJSON.h>

#include "utils.h"

int get_object(cJSON **to, const cJSON *from, char *name) {
    if(!from || !name || !to) return -1;
    cJSON *t = cJSON_DetachItemFromObjectCaseSensitive((cJSON *)from, name);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_array_item(cJSON **to, const cJSON *from, int index) {
    if(!from || !to || index<0) return -1;
    cJSON *t = cJSON_GetArrayItem((cJSON *)from, index);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_string_object(cJSON **to, const cJSON *from, char *name) {
    if(!from || !name || !to) return -1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive((cJSON *)from, name);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_integer_object(cJSON **to, const cJSON *from, char *name) {
    if(!from || !name || !to) return -1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive((cJSON *)from, name);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_boolean_object(cJSON **to, const cJSON *from, char *name) {
    if(!from || !name || !to) return -1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive((cJSON *)from, name);
    if(!t) return -1;
    *to = t;
    return 0;
}
int get_as_bytearray(unsigned char **to, int *to_len, const cJSON *from, char *name) {
    if(!from || !name || !to || !to_len) return 1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive((cJSON *)from, name);
    if(!t) return 1;
    /* Convert from string to allocated byte array */
    int bin_len = 0;
    *to = hex2bin_m(t->valuestring, &bin_len);
    if(*to) {
        *to_len = bin_len;
        return 0;
    }
    /* else error */
    free(*to);
    *to = NULL;
    return 1;
}



/* Appends; else use cJSON_InsertItemInArray to insert */
int put_array_item(cJSON *obj, cJSON *to_arr)  {
    if(!to_arr || !obj) return -1;
    /* Get array size before adding */
    //int before = cJSON_GetArraySize(to_arr);
    cJSON_AddItemToArray(to_arr, obj);
    //int after = cJSON_GetArraySize(to_arr);
    //if (after != (before + 1)) return -1;
    return 0;
}
/* Any object */
int put_object(char *name, cJSON *obj, cJSON *to)  {
    if(!to || !obj || !name) return -1;
    cJSON_AddItemToObject(to, name, obj);
    return 0;
}

/* Specific objects */
int put_string(const char *name, const char *value, cJSON *to) { 
    if(!to || !name) return -1;
    cJSON *s = cJSON_CreateString((const char *)value);
    if(!s) return -1;
    int before = 0, after = 0;
    if (cJSON_IsArray(to))
        before = cJSON_GetArraySize(to);

    cJSON_AddItemToObject(to, name, s);
    /* Unfortunately, the current cJSON API does not check if the addition was successful.
     * Therefore, we check if the object is in there after adding.
     */
    cJSON *verify = NULL;
    if (cJSON_IsObject(to))  {
        int err = get_string_object(&verify, (const cJSON *)to, (char *)name); 
        if (err < 0 || !verify) return -1;
    } else if (cJSON_IsArray(to))  {
        after = cJSON_GetArraySize(to);
        if (after != (before + 1)) return -1;
        verify = cJSON_GetArrayItem(to, after-1);
    }
    if (strncmp((const char *)value, verify->valuestring, strlen((const char *)value)) != 0) return -1;
    return 0;
}
int put_integer(const char *name, int value, cJSON *to) {
    if(!to || !name) return -1;
    cJSON *s = cJSON_CreateNumber(value);
    if(!s) return -1;
    int before = 0, after = 0;
    if (cJSON_IsArray(to))
        before = cJSON_GetArraySize(to);

    cJSON_AddItemToObject(to, name, s);
    /* Unfortunately, the current cJSON API does not check if the addition was successful.
     * Therefore, we check if the object is in there after adding.
     */
    cJSON *verify = NULL;
    if (cJSON_IsObject(to))  {
        int err = get_integer_object(&verify, (const cJSON *)to, (char *)name); 
        if (err < 0 || !verify) return -1;
    } else if (cJSON_IsArray(to))  {
        after = cJSON_GetArraySize(to);
        if (after != (before + 1)) return -1;
        verify = cJSON_GetArrayItem(to, after-1);
    }
    if (value != verify->valueint) return -1;
    return 0;
}

int put_boolean(const char *name, cJSON_bool value, cJSON *to) {
    if(!to || !name) return -1;
    cJSON *s = cJSON_CreateBool(value);
    if(!s) return -1;
    int before = 0, after = 0;
    if (cJSON_IsArray(to))
        before = cJSON_GetArraySize(to);

    cJSON_AddItemToObject(to, name, s);
    /* Unfortunately, the current cJSON API does not check if the addition was successful.
     * Therefore, we check if the object is in there after adding.
     */
    cJSON *verify = NULL;
    if (cJSON_IsObject(to))  {
        int err = get_boolean_object(&verify, (const cJSON *)to, (char *)name); 
        if (err < 0 || !verify) return -1;
    } else if (cJSON_IsArray(to))  {
        after = cJSON_GetArraySize(to);
        if (after != (before + 1)) return -1;
        verify = cJSON_GetArrayItem(to, after-1);
    }
    if (cJSON_IsTrue(verify) && cJSON_IsFalse(s)) return -1;
    if (cJSON_IsTrue(s) && cJSON_IsFalse(verify)) return -1;
    return 0;
}
int put_bytearray(const char *name, unsigned char *value, int value_len, cJSON *to)  {
    if(!name || !value || !value_len || !to) return 1;
    char out[value_len*2+1];
    if(!bin2hex(value, value_len, out, sizeof(out)))
        return 1;

    if(put_string(name, out, to) != 0) return 1;
    return 0;
}



/**
 * Read a file into a memory buffer
 */
unsigned char *read_fd_as_string(FILE *fd, unsigned char **buf)  {
    if (!fd || !buf) return NULL;

    int length = 0;

    /* Read entire file into memory, dynamically resizing the memory buffer */
    if (fd)  {
        fseek (fd, 0, SEEK_END);
        length = ftell (fd);
        fseek (fd, 0, SEEK_SET);
        *buf = malloc (length);
        if (*buf)
            fread (*buf, 1, length, fd);
        else
            return NULL;
    }
    else
        return NULL;

    return *buf;
}

unsigned char *read_file_as_string(char *fn, unsigned char **buf)  {
    if (!fn || !buf) return NULL;
    FILE *fd = fopen (fn, "rt");
    read_fd_as_string(fd, buf);
    fclose (fd);
    fd = NULL;
    return *buf;
}

/**
 * Read a file as a JSON object.
 */
cJSON *read_fd_as_json(FILE *fd)  {
    if (!fd) return NULL;

    unsigned char *buf = NULL;
    cJSON *c = NULL;

    if (!read_fd_as_string(fd, &buf))  {
        perror("Unable to load JSON file to memory structure.");
        goto error_die;
    }

    c = cJSON_Parse((const char *)buf);
    if(!c)  {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)  {
            fprintf(stderr, "JSON parsing error before: %s\n", error_ptr);
        }
        goto error_die;
    }
    goto success;

error_die:
    if (c) cJSON_Delete(c);
    c = NULL;

success:
    if (buf) free(buf);
    buf = NULL;

    return c;
}


cJSON *read_file_as_json(char *fn)  {
    if (!fn) return NULL;
    FILE *fd = fopen (fn, "rt");
    cJSON *json = read_fd_as_json(fd);
    fclose (fd);
    fd = NULL;
    return json;
}


