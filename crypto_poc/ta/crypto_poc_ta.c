// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <crypto_poc_ta.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#define JWT_HEADER "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
#define JWT_CLAIMS_TEMPLATE "{\"sub\":\"%s\"}"

#define SHA256_HASH_SIZE 32
#define KEY_HMAC_SIZE 128

/* GP says that for HMAC SHA-256, max is 1024 bits and min 192 bits. */
#define MAX_KEY_SIZE 128 /* In bytes */
#define MIN_KEY_SIZE 24	 /* In bytes */

struct hmac_key
{
	char K[KEY_HMAC_SIZE];
	uint32_t K_len;
};

struct HmacResult
{
	TEE_Result res;
	char *data;
};


// Prototypes
bool base64_enc(const void *data, size_t dlen, char *buf, size_t *blen);
void convertDataToUint8(struct HmacResult result, uint8_t *output);
bool base64_dec(const char *data, size_t size, void *buf, size_t *blen);
size_t base64_enc_len(size_t size);

// Functions for Base64URL encoding (adapted from optee_os/lib/libutee/base64.c)

static const char base64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t base64_enc_len(size_t size)
{
	return 4 * ((size + 2) / 3) + 1;
}

bool base64_enc(const void *data, size_t dlen, char *buf, size_t *blen) {
    size_t n = 0;
    size_t boffs = 0;
    const unsigned char *d = data;

    n = base64_enc_len(dlen);
    if (*blen < n) {
        *blen = n;
        return false;
    }

    for (n = 0; n < dlen; n += 3) {
        uint32_t igrp;

        igrp = d[n];
        igrp <<= 8;

        if ((n + 1) < dlen)
            igrp |= d[n + 1];
        igrp <<= 8;

        if ((n + 2) < dlen)
            igrp |= d[n + 2];

        buf[boffs] = base64_table[(igrp >> 18) & 0x3f];
        buf[boffs + 1] = base64_table[(igrp >> 12) & 0x3f];
        if ((n + 1) < dlen)
            buf[boffs + 2] = base64_table[(igrp >> 6) & 0x3f];
        else
            buf[boffs + 2] = '=';
        if ((n + 2) < dlen)
            buf[boffs + 3] = base64_table[igrp & 0x3f];
        else
            buf[boffs + 3] = '=';

        boffs += 4;
    }

    //Remove padding characters ('=') from the end of the encoded string
    while (buf[boffs - 1] == '=') {
        buf[boffs - 1] = '\0';
        boffs--;
    }

    buf[boffs] = '\0';

    *blen = boffs;
    return true;
}

static bool get_idx(char ch, uint8_t *idx)
{
	size_t n = 0;

	for (n = 0; base64_table[n] != '\0'; n++) {
		if (ch == base64_table[n]) {
			*idx = n;
			return true;
		}
	}
	return false;
}

bool base64_dec(const char *data, size_t size, void *buf, size_t *blen)
{
	bool ret = false;
	size_t n = 0;
	uint8_t idx = 0;
	uint8_t *b = buf;
	size_t m = 0;
	size_t s = 0;
	uint8_t byte = 0;

	for (n = 0; n < size && data[n] != '\0'; n++) {
		if (data[n] == '=')
			break;	/* Reached pad characters, we're done */

		if (!get_idx(data[n], &idx))
			continue;

		switch (s) {
		case 0:
			byte = idx << 2;
			s++;
			break;
		case 1:
			if (b && m < *blen)
				b[m] = byte | (idx >> 4);
			m++;
			byte = (idx & 0xf) << 4;
			s++;
			break;
		case 2:
			if (b && m < *blen)
				b[m] = byte | (idx >> 2);
			m++;
			byte = (idx & 0x3) << 6;
			s++;
			break;
		case 3:
			if (b && m < *blen)
				b[m] = byte | idx;
			m++;
			s = 0;
			break;
		default:
			return false;	/* "Can't happen" */
		}
	}

	/*
	 * We don't detect if input was bad, but that's OK with the spec.
	 * We expect that each fully extracted byte is stored in output buffer.
	 */
	ret = (!m && !*blen) || (b && (m <= *blen));
	*blen = m;

	return ret;
}


/**
 * Calculates the HMAC-SHA256 of the input data using the provided key.
 * 
 * @param key The key to use for the HMAC-SHA256 operation.
 * @param keylen The length of the key in bytes.
 * @param in The input data to calculate the HMAC-SHA256 of in base64URL.
 * @param inlen The length of the input data in bytes.
 * @param out The output buffer to store the calculated HMAC-SHA256 in.
 * @param outlen The length of the output buffer in bytes.
 * 
 * @return TEE_Result The result of the HMAC-SHA256 operation.
 */
static TEE_Result hmac_sha256(const char *key, const size_t keylen,
							  const uint8_t *in, const size_t inlen,
							  uint8_t *out, uint32_t *outlen)
{
	TEE_Attribute attr = {0};
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	size_t encoded_length = base64_enc_len(inlen);
	size_t decoded_length = base64_enc_len(encoded_length); 
    char decoded_buffer[decoded_length];
	
	IMSG("key lenght check %zu", keylen);

	if ((keylen) < MIN_KEY_SIZE || keylen > MAX_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("data validate");
	if (!in || !out || !outlen)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Allocate Operation");
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
								keylen * 8);
	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 2. Allocate a container (key handle) for the HMAC attributes. Note
	 *    that the expected size here is in bits (and therefore times 8)!
	 */
	IMSG("Allocate key handle");

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, keylen * 8,
									  &key_handle);
	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 3. Initialize the attributes, i.e., point to the actual HMAC key.
	 *    Here, the expected size is in bytes and not bits as above!
	 */
	IMSG("Iniciatlize the attributes");
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	/* 4. Populate/assign the attributes with the key object */
	IMSG("Populate the attributes");
	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

	/* 5. Associate the key (object) with the operation */
	IMSG("Associate the key");
	res = TEE_SetOperationKey(op_handle, key_handle);
	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

	DMSG(" keylen: %zu", keylen);
	DMSG(" inlen: %zu", inlen);

	if (sizeof(key) > 0)
		DMSG("The key is: %s. \n", key);
	// decode the input data. This is necessary because the input data can be bytes and not a string, so the base64URL is used to encode the data
    if (base64_dec((const char*)in, encoded_length, decoded_buffer, &decoded_length)) {
        DMSG("Base64 Decoded: %s\n", decoded_buffer);
    } else {
        EMSG("Decoding failed.\n");
    }
	
	/* 6. Do the HMAC operations */
	IMSG("Do the HMAC init operations");
	TEE_MACInit(op_handle, NULL, 0);
	IMSG("Do the HMAC update operations");
	TEE_MACUpdate(op_handle, decoded_buffer, decoded_length);
	IMSG("Do the HMAC Final operations");
	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, outlen);

	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

exit:
	if (op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(op_handle);

	/* It is OK to call this when key_handle is TEE_HANDLE_NULL */
	TEE_FreeTransientObject(key_handle);

	return res;
}

/**
 * Calculates the HMAC-SHA256 of the input data using the provided key.
 * 
 * @param key The key to use for the HMAC-SHA256 operation.
 * @param keylen The length of the key in bytes.
 * @param in The input data to calculate the HMAC-SHA256.
 * @param inlen The length of the input data in bytes.
 * @param out The output buffer to store the calculated HMAC-SHA256 in.
 * @param outlen The length of the output buffer in bytes.
 * 
 * @return TEE_Result The result of the HMAC-SHA256 operation.
 */
static TEE_Result hmac_sha256_bytes(const char *key, const size_t keylen,
							  const uint8_t *in, const size_t inlen,
							  uint8_t *out, uint32_t *outlen)
{
	TEE_Attribute attr = {0};
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	
	IMSG("key lenght check %zu", keylen);

	if ((keylen) < MIN_KEY_SIZE || keylen > MAX_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("data validate");
	if (!in || !out || !outlen)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Allocate Operation");
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
								keylen * 8);
	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 2. Allocate a container (key handle) for the HMAC attributes. Note
	 *    that the expected size here is in bits (and therefore times 8)!
	 */
	IMSG("Allocate key handle");

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, keylen * 8,
									  &key_handle);
	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 3. Initialize the attributes, i.e., point to the actual HMAC key.
	 *    Here, the expected size is in bytes and not bits as above!
	 */
	IMSG("Iniciatlize the attributes");
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	/* 4. Populate/assign the attributes with the key object */
	IMSG("Populate the attributes");
	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

	/* 5. Associate the key (object) with the operation */
	IMSG("Associate the key");
	res = TEE_SetOperationKey(op_handle, key_handle);
	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

	DMSG(" keylen: %zu", keylen);
	DMSG(" inlen: %zu", inlen);

	if (sizeof(key) > 0)
		DMSG("The key is: %s. \n", key);
	
	/* 6. Do the HMAC operations */
	IMSG("Do the HMAC init operations");
	TEE_MACInit(op_handle, NULL, 0);
	IMSG("Do the HMAC update operations");
	TEE_MACUpdate(op_handle, in, inlen);
	IMSG("Do the HMAC Final operations");
	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, outlen);

	if (res != TEE_SUCCESS)
	{
		EMSG("0x%08x", res);
		goto exit;
	}

exit:
	if (op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(op_handle);

	/* It is OK to call this when key_handle is TEE_HANDLE_NULL */
	TEE_FreeTransientObject(key_handle);

	return res;
}

/**
 * Creates a persistent object in secure storage and fills it with data.
 *
 * @param param_types The types of the parameters passed to the function.
 * @param params The parameters passed to the function.
 *
 * @return TEE_Result The result of the operation.
 */
static TEE_Result create_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	uint32_t obj_data_flag;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(data, params[1].memref.buffer, data_sz);

	/*
	 * Create object in secure storage and fill with data
	 */
	obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		  /* we can later read the oject */
					TEE_DATA_FLAG_ACCESS_WRITE |	  /* we can later write into the object */
					TEE_DATA_FLAG_ACCESS_WRITE_META | /* we can later destroy or rename the object */
					TEE_DATA_FLAG_OVERWRITE;		  /* destroy existing object of same ID */

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
									 obj_id, obj_id_sz,
									 obj_data_flag,
									 TEE_HANDLE_NULL,
									 NULL, 0, /* we may not fill it right now */
									 &object);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}

	res = TEE_WriteObjectData(object, data, data_sz);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
	}
	else
	{
		TEE_CloseObject(object);
	}
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}


/**
 * Reads a raw object from persistent storage and dumps it into the output buffer.
 *
 * @param param_types The types of the input parameters.
 * @param params The input parameters.
 *
 * @return TEE_Result The result of the operation.
 */
static TEE_Result read_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
								   obj_id, obj_id_sz,
								   TEE_DATA_FLAG_ACCESS_READ |
									   TEE_DATA_FLAG_SHARE_READ,
								   &object);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to create persistent object, res=0x%08x", res);
		goto exit;
	}

	if (object_info.dataSize > data_sz)
	{
		/*
		 * Provided buffer is too short.
		 * Return the expected size together with status "short buffer"
		 */
		params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	res = TEE_ReadObjectData(object, data, object_info.dataSize-1,
							 &read_bytes);
	if (res == TEE_SUCCESS)
		TEE_MemMove(params[1].memref.buffer, data, read_bytes);

	if (strlen(data) > 0)
		DMSG("The read data is: %s. \n", data);

	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize)
	{
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
			 res, read_bytes, object_info.dataSize);
		goto exit;
	}

	/* Return the number of byte effectively filled */
	params[1].memref.size = read_bytes;
exit:
	TEE_CloseObject(object);
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}

/**
 * Reads a key for HMAC from a persistent object and returns it as a HmacResult struct.
 *
 * @param state The hmac_key struct to store the result.
 * @param param_types The types of the parameters passed to the function.
 * @param params The parameters passed to the function.
 * @return A HmacResult struct containing the result of the function.
 */
static struct HmacResult read_key_for_hmac(struct hmac_key *state, TEE_Param params[4])
{


	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	struct HmacResult result;

	IMSG("Entering read_key_for_hmac");

	obj_id_sz = params[2].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id){
		result.res = TEE_ERROR_OUT_OF_MEMORY;
		return result;
	}
	IMSG("obj_id_sz: %zu", obj_id_sz);

	TEE_MemMove(obj_id, params[2].memref.buffer, obj_id_sz);

	IMSG("strlen obj_id: %zu", strlen(obj_id));

	data_sz = KEY_HMAC_SIZE;
	data = TEE_Malloc(data_sz, 0);
	if (!data){
		result.res = TEE_ERROR_OUT_OF_MEMORY;
		return result;
	}
	/*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
	IMSG("TEE_OpenPersistentObject");
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
								   obj_id, strlen(obj_id),
								   TEE_DATA_FLAG_ACCESS_READ |
									   TEE_DATA_FLAG_SHARE_READ,
								   &object);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		result.res = res;
		return result;
	}
	IMSG("TEE_GetObjectInfo1");
	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to create persistent object, res=0x%08x", res);
		goto exit;
	}
	IMSG("Compare dataSize and data_sz %zu:%zu", object_info.dataSize, data_sz);
	if (object_info.dataSize > data_sz)
	{
		/*
		 * Provided buffer is too short.
		 * Return the expected size together with status "short buffer"
		 */
		// params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}
	IMSG("TEE_ReadObjectData");
	res = TEE_ReadObjectData(object, data, object_info.dataSize,
							 &read_bytes);

	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
			 res, read_bytes, object_info.dataSize);
		goto exit;
	}

	result.data = data;
	result.res = res;

	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize)
	{
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
			 res, read_bytes, object_info.dataSize);
		goto exit;
	}

	return result;

exit:
	TEE_CloseObject(object);
	TEE_Free(obj_id);
	TEE_Free(data);
	return result;
}

/**
 * Calculates the HMAC-SHA256 of a given message using a given key.
 *
 * @param state A pointer to the hmac_key struct containing the key information.
 * @param param_types The types of the input parameters.
 * @param params An array of TEE_Param structures containing the input and output parameters.
 *
 * @return A TEE_Result value indicating the success or failure of the operation.
 */
static TEE_Result get_hmac_sha256(struct hmac_key *state,
								  uint32_t param_types, TEE_Param params[4])
{
	IMSG("Entering get_hmac_sha256");
	TEE_Result res = TEE_SUCCESS;
	uint8_t mac[SHA256_HASH_SIZE];
	memset(mac, 0, SHA256_HASH_SIZE);

	uint32_t mac_len = sizeof(mac);
	struct HmacResult key_result;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_MEMREF_OUTPUT,
											   TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_NONE);

	IMSG("check param type get_hmac_sha256");
	if (param_types != exp_param_types)
	{
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	char *message_received = (char *)params[0].memref.buffer;

	DMSG(" message: %s", message_received);

	key_result = read_key_for_hmac(state, params);

	IMSG("key_result.data: %s", key_result.data);
	IMSG("key_result.res: %d", key_result.res);
	IMSG("key_result.data size: %zu", strlen(key_result.data));

	uint8_t *output_data = (uint8_t *)params[1].memref.buffer;

	size_t encoded_length = base64_enc_len(strlen(key_result.data));
	size_t decoded_length = base64_enc_len(encoded_length); 
    char decoded_buffer[decoded_length];

	// FIXME create a function or adapt the read_key_for_hmac function
    if (base64_dec((const char*)key_result.data, encoded_length, decoded_buffer, &decoded_length)) {
        DMSG("Base64 Decoded: %s\n", decoded_buffer);
    } else {
        EMSG("Decoding failed.\n");
    }

	IMSG("HMAC SHA256");

	res = hmac_sha256(decoded_buffer, decoded_length, (uint8_t *)message_received,
					  strlen(message_received), mac, &mac_len);

	IMSG("HMAC SHA256 exit function");

	memcpy(output_data, mac, sizeof(mac));

	return res;
}

/**
 * Generates a JSON Web Token (JWT) using HMAC-SHA256 algorithm.
 *
 * @param state The HMAC key state.
 * @param param_types The types of the input parameters.
 * @param params The input parameters.
 *
 * @return TEE_Result The result of the operation.
 */
static TEE_Result generate_jwt_hs256(struct hmac_key *state,
                                    uint32_t param_types, TEE_Param params[4]) {
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_VALUE_INPUT)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

	DMSG("Entering generate_jwt_hs256");	

	//string to be signed
    char *payload = (char *)params[0].memref.buffer;

	DMSG(" payload: %s", payload);

	size_t header_b64_len = base64_enc_len(strlen(JWT_HEADER));
	size_t claims_b64_len = base64_enc_len(strlen(payload) + 50);  // Extra space

    char jwt_header_b64[base64_enc_len(base64_enc_len(strlen(JWT_HEADER)))];
    base64_enc(JWT_HEADER, strlen(JWT_HEADER), jwt_header_b64, &header_b64_len);

	DMSG(" jwt_header_b64: %s", jwt_header_b64);

    char jwt_claims_b64[base64_enc_len(base64_enc_len(strlen(payload)))];
    base64_enc(payload, strlen(payload), jwt_claims_b64, &claims_b64_len);

	DMSG(" jwt_claims_b64: %s", jwt_claims_b64);
    // Create the message to sign by concatenating header and claims with a period separator
    char jwt_message[header_b64_len + 1 + claims_b64_len + 1];
    snprintf(jwt_message, sizeof(jwt_message), "%s.%s", jwt_header_b64, jwt_claims_b64);

	DMSG(" jwt_message: %s", jwt_message);

    unsigned int hmac_len = SHA256_HASH_SIZE;
    unsigned char hmac[SHA256_HASH_SIZE];

	struct HmacResult key_result;
	key_result = read_key_for_hmac(state, params);

	// FIXME create a function or adapt the read_key_for_hmac function
	size_t encoded_length = base64_enc_len(strlen(key_result.data));
	size_t decoded_length = base64_enc_len(encoded_length); 
    char decoded_buffer[decoded_length];

    if (base64_dec((const char*)key_result.data, encoded_length, decoded_buffer, &decoded_length)) {
        DMSG("Base64 Decoded: %s\n", decoded_buffer);
    } else {
        EMSG("Decoding failed.\n");
    }

    TEE_Result res = hmac_sha256_bytes(decoded_buffer, decoded_length, (uint8_t*)jwt_message, strlen(jwt_message), hmac, &hmac_len);
    if (res != TEE_SUCCESS) {
        return res;
    }	
	DMSG("state-> %s", state->K);
	DMSG("jwt_message: %s", jwt_message);
	
	DMSG("hmac values \n");
	for (uint32_t i = 0; i < hmac_len; i++)
	{
		DMSG(" %02x ", hmac[i]);
	}

    size_t jwt_signature_b64_len = base64_enc_len(base64_enc_len(SHA256_HASH_SIZE));
    char jwt_signature_b64[jwt_signature_b64_len];
    base64_enc(hmac, SHA256_HASH_SIZE, jwt_signature_b64, &jwt_signature_b64_len);

	DMSG(" jwt_signature_b64: %s", jwt_signature_b64);

    char jwt[header_b64_len + 1 + claims_b64_len + 1 + jwt_signature_b64_len + 1];
    snprintf(jwt, sizeof(jwt), "%s.%s.%s", jwt_header_b64, jwt_claims_b64, jwt_signature_b64);

    // Copy the resulting JWT to the output buffer
    size_t output_len = strlen(jwt);
    if (params[1].memref.size < output_len) {
        return TEE_ERROR_SHORT_BUFFER;
    }
    TEE_MemMove(params[1].memref.buffer, jwt, output_len);
    params[1].memref.size = output_len;

    return TEE_SUCCESS;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}


/**
 * TA_DestroyEntryPoint - Entry point for destroying the TA.
 */
void TA_DestroyEntryPoint(void)
{
}


/**
 * TA_OpenSessionEntryPoint - Entry point for opening a session with the TA.
 * @param_types: The types of the parameters passed to the TA.
 * @params: The parameters passed to the TA.
 * @sess_ctx: The context of the session.
 *
 * This function is called when a client opens a session with the TA. It allocates and initializes
 * the state for the session.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS if the parameter types are incorrect,
 *         or TEE_ERROR_OUT_OF_MEMORY if there is not enough memory to allocate the state.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
									TEE_Param __unused params[4],
									void **sess_ctx)
{
	struct hmac_key *state = NULL;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Allocate and init state for the session.
	 */
	state = TEE_Malloc(sizeof(*state), 0);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	*sess_ctx = state;

	return TEE_SUCCESS;
}

/**
 * @brief Closes the session and frees the session context.
 * 
 * @param sess_ctx The session context to be freed.
 */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	TEE_Free(sess_ctx);
	sess_ctx = NULL;
}


/**
 * This function is the entry point for the Trusted Application (TA) command invocation.
 * It receives the session context, command ID, parameter types, and parameters.
 * The function then switches on the command ID and calls the corresponding function.
 * 
 * @param sess_ctx The session context.
 * @param cmd_id The command ID.
 * @param param_types The parameter types.
 * @param params The parameters.
 * 
 * @return TEE_Result The result of the invoked command.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
									  uint32_t cmd_id,
									  uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id)
	{
	case TA_GET_HMAC_SHA256:
		return get_hmac_sha256(sess_ctx, param_types, params);
	case TA_SECURE_STORAGE_POC_CMD_READ_RAW:
		return read_raw_object(param_types, params);
	case TA_SECURE_STORAGE_POC_CMD_WRITE_RAW:
		return create_raw_object(param_types, params);
	case TA_GET_JWT_HS256:
		return generate_jwt_hs256(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}