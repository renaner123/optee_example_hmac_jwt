// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <err.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <crypto_poc_ta.h>

struct host_ctx
{
    TEEC_Context ctx;
    TEEC_Session sess;
};

typedef struct {
    uint8_t hmac_sha256_digest[32];
    TEEC_Result res;
} Hmac;

typedef struct {
    uint8_t jwt_result[255];
    TEEC_Result res;
} JWT_res;

/**
 * Initializes a context connecting to the TEE and opens a session with the TA.
 *
 * @param ctx The context.
 */
void prepare_tee_session(struct host_ctx *ctx)
{
    TEEC_UUID uuid = TA_CRYPTO_POC_UUID;
    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    /* Open a session with the TA */
    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
             res, origin);
}

/**
 * Reads a secure object from the Trusted Application (TA) secure storage.
 *
 * @param ctx The context.
 * @param id  The ID of the secure object to read.
 * @param data The buffer to store the read data.
 * @param data_len The length of the buffer to store the read data.
 * @return A TEEC_Result indicating the success or failure of the operation.
 */
TEEC_Result read_secure_object(struct host_ctx *ctx, char *id,
                               char *data, size_t data_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;

    op.params[1].tmpref.buffer = data;
    op.params[1].tmpref.size = data_len;

    res = TEEC_InvokeCommand(&ctx->sess,
                             TA_SECURE_STORAGE_POC_CMD_READ_RAW,
                             &op, &origin);

    switch (res)
    {
    case TEEC_SUCCESS:
    case TEEC_ERROR_SHORT_BUFFER:
    case TEEC_ERROR_ITEM_NOT_FOUND:
        break;
    default:
        printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
    }

    return res;
}


/**
 * Writes a secure object with the given ID and data to the secure storage.
 * 
 * @param ctx The context.
 * @param id  The ID of the secure object.
 * @param data The data to be written to the secure object.
 * @param data_len The length of the data to be written.
 * 
 * @return A TEEC_Result indicating the success or failure of the operation.
 */
TEEC_Result write_secure_object(struct host_ctx *ctx, char *id,
                                char *data, size_t data_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;

    op.params[1].tmpref.buffer = data;
    op.params[1].tmpref.size = data_len;

    res = TEEC_InvokeCommand(&ctx->sess,
                             TA_SECURE_STORAGE_POC_CMD_WRITE_RAW,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

    switch (res)
    {
    case TEEC_SUCCESS:
        break;
    default:
        printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
    }

    return res;
}


/**
 * Calculates the HMAC-SHA256 digest of a given message using a given key ID from TA.
 * 
 * @param ctx The context.
 * @param key_id The ID of the key to use for HMAC calculation.
 * @param message The message to calculate HMAC for.
 * 
 * @return The HMAC-SHA256 digest of the message.
 */
Hmac get_hmac_sha256(struct host_ctx *ctx, char *key_id,
                            char *message)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    Hmac result;

    // Handle HMAC option
    //printf("HMAC option selected. Message: %s, Key ID: %s\n", message, key_id);

    uint8_t hmac_sha256_digest[32] = {0};
    memset(hmac_sha256_digest, 0, sizeof(hmac_sha256_digest));

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

    op.params[0].tmpref.buffer = (void *)message;
    op.params[0].tmpref.size = strlen(message) + 1;

    op.params[1].tmpref.buffer = hmac_sha256_digest;
    op.params[1].tmpref.size = sizeof(hmac_sha256_digest);

    op.params[2].tmpref.buffer = (void *)key_id;
    op.params[2].tmpref.size = strlen(key_id) + 1;

    res = TEEC_InvokeCommand(&ctx->sess, TA_GET_HMAC_SHA256, &op,
                             &origin);
    if (res != TEEC_SUCCESS)
    {
        fprintf(stderr, "TEEC_InvokeCommand get_hmac failed with code "
                        "0x%x origin 0x%x\n",
                res, origin);
    }                   
    result.res = res;
    memcpy(result.hmac_sha256_digest, hmac_sha256_digest, sizeof(hmac_sha256_digest));

    return result;
}



/**
 * Generates a JWT using the HS256 algorithm in the secure world.
 * 
 * @param ctx The host context.
 * @param key_id The key identifier.
 * @param message The message to be signed.
 * @return JWT_res The result of the operation and the generated JWT.
 */
JWT_res get_jwt_hs256(struct host_ctx *ctx, char *key_id,
                            char *message)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    JWT_res result;
    // Define your input data, output data, and parameters
    char output_data[256]; // Adjust the size accordingly
    memset(output_data, 0, sizeof(output_data));

    time_t current_time;
    time(&current_time);
    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, 
        TEEC_MEMREF_TEMP_OUTPUT, 
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_VALUE_INPUT
    );

    op.params[0].tmpref.buffer = (void *)message;
    op.params[0].tmpref.size = strlen(message) + 1;

    op.params[2].tmpref.buffer = (void *)key_id;
    op.params[2].tmpref.size = strlen(key_id) + 1;

    op.params[1].tmpref.buffer = output_data;
    op.params[1].tmpref.size = sizeof(output_data);

    op.params[3].value.a = current_time;

    // Invoke your TA function
    res = TEEC_InvokeCommand(&ctx->sess, TA_GET_JWT_HS256, &op, &origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand failed: 0x%x\n", res);
    }

    result.res = res;
    memcpy(result.jwt_result, output_data, sizeof(output_data));
    return result;
}

/**
 * Prints the usage of the program.
 *
 * @param programName The name of the program.
 */
void printUsage(char *programName)
{
    // FIXME conversion/arguments should be validated
    printf("Usage:\n");
    printf("For HMAC: %s  <h> <key_id> <message>\n", programName);
    printf("For write: %s <w> <key_id> <obj_data>\n", programName);
    printf("For read: %s  <r> <key_id> <obj_size>\n", programName);
    printf("For jwt: %s   <j> <key_id> <message>\n", programName);
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printUsage(argv[0]);
        return 1;
    }

    TEEC_Result res;
    struct host_ctx ctx;

    const char *option = argv[1];
    char *key_id = argv[2];


    prepare_tee_session(&ctx);

    if (strcmp(option, "h") == 0)
    {
        char *message = argv[3];

        Hmac res = get_hmac_sha256(&ctx, key_id, message);

        if (res.res != TEEC_SUCCESS)
            errx(1, "Failed to get_hmac_sha256");
        int i =0;
        for (i = 0; i < 32; i++)
		    printf("%02x", res.hmac_sha256_digest[i]);
        printf("\n");

    }
    else if (strcmp(option, "w") == 0)
    {
        // Handle write option
        char *objData = argv[3];
        //printf("Write option selected. Object Data: %s, Key ID: %s\n", objData, key_id);

        res = write_secure_object(&ctx, key_id,
                                  objData, strlen(objData));                                  

        if (res != TEEC_SUCCESS)
            errx(1, "Failed to write an object from the secure storage");
    }
    else if (strcmp(option, "r") == 0)
    {
        // Handle read option
        char *objSize = argv[3];
        //printf("Read option selected. Object Size: %s, Key ID: %s\n", objSize, key_id);
        char read_data[atoi(objSize)];

        res = read_secure_object(&ctx, key_id,
                                 read_data, sizeof(read_data));

        if (res != TEEC_SUCCESS)
            errx(1, "Failed to read an object from the secure storage");

        printf(read_data);
        printf("\n");
    }
    else if (strcmp(option , "j") == 0){
        
        char *message = argv[3];

        //printf("JWT option selected. Message: %s, Key ID: %s\n", message, key_id);

        JWT_res res = get_jwt_hs256(&ctx, key_id, message);

        if (res.res != TEEC_SUCCESS)
            errx(1, "Failed to get_hmac_sha256");

        printf("%s",res.jwt_result);
        printf("\n");

    }
    else
    {
        printf("Invalid option: %s\n", option);
        printUsage(argv[0]);
        return 1; // Exit with an error status
    }

    TEEC_CloseSession(&ctx.sess);
    TEEC_FinalizeContext(&ctx.ctx);

    return 0;
}