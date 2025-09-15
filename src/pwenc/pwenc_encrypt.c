// SPDX-License-Identifier: LGPL-3.0-or-later
#define _GNU_SOURCE
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>
#include <endian.h>


static pwenc_resp_t pwenc_create_nonce(pwenc_datum_t *nonce, pwenc_error_t *error)
{
	nonce->data = malloc(PWENC_NONCE_SIZE);
	if (!nonce->data) {
		pwenc_set_error(error, "malloc() failed for nonce");
		return PWENC_ERROR_MEMORY;
	}

	if (RAND_bytes(nonce->data, PWENC_NONCE_SIZE) != 1) {
		pwenc_set_ssl_error(error, "RAND_bytes() failed");
		free(nonce->data);
		nonce->data = NULL;
		return PWENC_ERROR_CRYPTO;
	}

	nonce->size = PWENC_NONCE_SIZE;
	return PWENC_SUCCESS;
}

static pwenc_resp_t do_encrypt(const unsigned char *secret,
	const pwenc_datum_t *nonce, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error)
{
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	pwenc_datum_t nonce_encrypted = {0};
	unsigned char iv[16] = {0};
	pwenc_resp_t ret = PWENC_SUCCESS;
	int len, final_len;
	size_t encrypted_len;

	/* Allocate buffer for nonce + encrypted data (add extra space for potential final block) */
	nonce_encrypted.size = nonce->size + data_in->size + EVP_CIPHER_block_size(EVP_aes_256_ctr());
	nonce_encrypted.data = calloc(1, nonce_encrypted.size);
	if (!nonce_encrypted.data) {
		pwenc_set_error(error, "calloc() failed for nonce+encrypted");
		ret = PWENC_ERROR_MEMORY;
		goto cleanup;
	}

	/* Copy nonce to the beginning of the buffer */
	memcpy(nonce_encrypted.data, nonce->data, nonce->size);

	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!cipher_ctx) {
		pwenc_set_error(error, "EVP_CIPHER_CTX_new() failed");
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	/* Set counter to 1 (big-endian) for middleware compatibility */
	*(uint64_t *)(iv + 8) = htobe64(LEGACY_PWENC_INIT_CTR);
	/* Set nonce in initialization vector */
	memcpy(iv, nonce->data, nonce->size);

	if (!EVP_EncryptInit_ex2(cipher_ctx, EVP_aes_256_ctr(), secret, iv, NULL)) {
		pwenc_set_ssl_error(error, "EVP_EncryptInit_ex() failed");
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	/* Encrypt directly into the buffer after the nonce */
	if (!EVP_EncryptUpdate(cipher_ctx, nonce_encrypted.data + nonce->size, &len, data_in->data, data_in->size)) {
		pwenc_set_ssl_error(error, "EVP_EncryptUpdate() failed");
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}
	encrypted_len = len;

	if (EVP_EncryptFinal_ex(cipher_ctx, nonce_encrypted.data + nonce->size + len, &final_len) != 1) {
		pwenc_set_ssl_error(error, "EVP_EncryptFinal_ex() failed");
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}
	encrypted_len += final_len;

	/* Update the actual size with the real encrypted length */
	nonce_encrypted.size = nonce->size + encrypted_len;

	ret = base64_encode(error, &nonce_encrypted, data_out);
	if (ret != PWENC_SUCCESS) {
		goto cleanup;
	}

cleanup:
	EVP_CIPHER_CTX_free(cipher_ctx);
	pwenc_datum_free(&nonce_encrypted, true);

	return ret;
}

/* Encrypt the data_in and return a base64-encoded response */
pwenc_resp_t pwenc_encrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error)
{
	pwenc_datum_t nonce = {0};
	pwenc_resp_t ret = PWENC_SUCCESS;

	if (!ctx || ctx->secret_mem == NULL || !PWENC_DATUM_VALID(data_in) || !data_out) {
		pwenc_set_error(error, "invalid input parameters");
		return PWENC_ERROR_INVALID_INPUT;
	}

	if (data_in->size > PWENC_MAX_PAYLOAD_SIZE) {
		pwenc_set_error(error, "payload size %zu exceeds maximum of %d bytes",
			data_in->size, PWENC_MAX_PAYLOAD_SIZE);
		return PWENC_ERROR_PAYLOAD_TOO_LARGE;
	}

	ret = pwenc_create_nonce(&nonce, error);
	if (ret != PWENC_SUCCESS) {
		goto cleanup;
	}

	ret = do_encrypt(ctx->secret_mem, &nonce, data_in, data_out, error);

cleanup:
	pwenc_datum_free(&nonce, false);

	return ret;
}
