// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __CRYPTO_POC_TA_H__
#define __CRYPTO_POC_TA_H__

/* UUID of the acipher example trusted application */
#define TA_CRYPTO_POC_UUID \
	{ 0xae9462ba, 0x04f1, 0x4ff2, { \
		0xaa, 0x96, 0xd8, 0xbc, 0x7d, 0x78, 0xf5, 0x09 } }

#define TA_SECURE_STORAGE_POC_CMD_READ_RAW	0

#define TA_SECURE_STORAGE_POC_CMD_WRITE_RAW 1

#define TA_GET_HMAC_SHA256 2

#define TA_GET_JWT_HS256 3



#endif /* __CRYPTO_POC_TA_H */
