// SPDX-License-Identifier: LGPL-3.0-or-later
#ifndef TRUENAS_PWENC_H
#define TRUENAS_PWENC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <limits.h>

#define PWENC_BLOCK_SIZE 32
#define PWENC_NONCE_SIZE 8
#define PWENC_MAX_PAYLOAD_SIZE (1024 * 1024)  /* 1 MiB */
#define PWENC_SUCCESS 0
#define PWENC_ERROR_INVALID_INPUT -1
#define PWENC_ERROR_MEMORY -2
#define PWENC_ERROR_CRYPTO -3
#define PWENC_ERROR_IO -4
#define PWENC_ERROR_SECRET_NOT_FOUND -5
#define PWENC_ERROR_PAYLOAD_TOO_LARGE -6

#define PWENC_OPEN_EXISTING 0
#define PWENC_OPEN_CREATE O_CREAT

#define PWENC_DEFAULT_SECRET_PATH "/data/pwenc_secret"

typedef int pwenc_resp_t;

typedef struct pwenc_ctx pwenc_ctx_t;

typedef struct {
	unsigned char *data;
	size_t size;
} pwenc_datum_t;

typedef struct {
	char message[1024];
} pwenc_error_t;

/*
 * @brief allocate and initialize a new pwenc context
 *
 * @param[in]	secret_path - path to secret file (if NULL, uses default)
 * @param[in]   flags - PWENC_OPEN_EXISTING or PWENC_OPEN_CREATE
 * @param[out]	ctx - pointer to receive allocated context
 * @param[out]  created - pointer to bool that will be set to true if secret file was created
 * @param[out]	error - pointer to error structure for error details
 *
 * @return	PWENC_SUCCESS on success, error code on failure
 */
pwenc_resp_t pwenc_init_context(const char *secret_path,
				int flags,
				pwenc_ctx_t **ctx,
				bool *created,
				pwenc_error_t *error);

/*
 * @brief free a pwenc context
 *
 * This function calls pwenc_close() on the specified context and then
 * frees the memory associated with the context itself.
 *
 * @param[in]	ctx - pointer to context to free (may be NULL)
 */
void pwenc_free_context(pwenc_ctx_t *ctx);

/*
 * @brief get the secret file path from a context
 *
 * @param[in]	ctx - pointer to context structure
 *
 * @return	pointer to secret file path string
 */
const char *pwenc_get_secret_path(pwenc_ctx_t *ctx);

/*
 * @brief free a pwenc_datum_t
 *
 * This function frees the data buffer and zeros the struct.
 * Optionally zeros the data buffer before freeing for secure cleanup.
 * It is safe to call this function with a NULL or already-freed datum.
 *
 * @param[in,out]	datum - pointer to datum to free
 * @param[in]		zero_data - if true, zero data buffer before freeing
 */
void pwenc_datum_free(pwenc_datum_t *datum, bool zero_data);

/*
 * @brief encrypt data using AES-256-CTR and encode as base64
 *
 * This function encrypts the input data using AES-256-CTR with a random
 * 8-byte nonce. The base64 string encodes the nonce and encrypted result.
 *
 * @param[in]	ctx - initialized context
 * @param[in]	data_in - input data to encrypt
 * @param[out]	data_out - datum to receive allocated base64 output string
 * @param[out]	error - error structure for error details
 *
 * @return	PWENC_SUCCESS on success, error code on failure
 */
pwenc_resp_t pwenc_encrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error);

/*
 * @brief decrypt base64-encoded data using AES-256-CTR
 *
 * This function decodes the base64 input, extracts the nonce, and
 * decrypts the data using AES-256-CTR.
 *
 * @param[in]	ctx - initialized context
 * @param[in]	data_in - base64-encoded input string datum
 * @param[out]	data_out - datum to receive allocated decrypted output
 * @param[out]	error - error structure for error details
 *
 * @return	PWENC_SUCCESS on success, error code on failure
 */
pwenc_resp_t pwenc_decrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error);

#endif
