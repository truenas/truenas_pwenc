#define _GNU_SOURCE
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>

static int base64_decode(pwenc_error_t *error, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out)
{
	unsigned char *decoded;
	int decoded_len;

	if (!PWENC_DATUM_VALID(data_in) || !data_out) {
		pwenc_set_error(error, "invalid input parameters");
		return PWENC_ERROR_INVALID_INPUT;
	}

	decoded = calloc(1, data_in->size);
	if (!decoded) {
		pwenc_set_error(error, "calloc() failed");
		return PWENC_ERROR_MEMORY;
	}

	decoded_len = EVP_DecodeBlock(decoded, data_in->data, data_in->size);
	if (decoded_len < 0) {
		free(decoded);
		pwenc_set_error(error, "EVP_DecodeBlock() failed");
		return PWENC_ERROR_CRYPTO;
	}

	/* Adjust for base64 padding */
	if (data_in->size > 0 && data_in->data[data_in->size - 1] == '=') {
		decoded_len--;
		if (data_in->size > 1 && data_in->data[data_in->size - 2] == '=') {
			decoded_len--;
		}
	}

	data_out->data = decoded;
	data_out->size = decoded_len;
	return PWENC_SUCCESS;
}

static int do_decrypt(pwenc_ctx_t *ctx, const unsigned char *nonce,
	const unsigned char *ciphertext, size_t ciphertext_len,
	unsigned char **plaintext_out, size_t *plaintext_len_out,
	pwenc_error_t *error)
{
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	unsigned char *plaintext = NULL;
	unsigned char iv[16] = {0};
	int len, plaintext_len, ret = PWENC_SUCCESS;

	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!cipher_ctx) {
		pwenc_set_error(error, "EVP_CIPHER_CTX_new() failed");
		return PWENC_ERROR_CRYPTO;
	}

	memcpy(iv, nonce, PWENC_NONCE_SIZE);

	if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, ctx->secret_mem,
	    iv) != 1) {
		pwenc_set_error(error, "EVP_DecryptInit_ex() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	plaintext = calloc(1, ciphertext_len);
	if (!plaintext) {
		pwenc_set_error(error, "calloc() failed");
		ret = PWENC_ERROR_MEMORY;
		goto cleanup;
	}

	if (EVP_DecryptUpdate(cipher_ctx, plaintext, &len, ciphertext,
	    ciphertext_len) != 1) {
		pwenc_set_error(error, "EVP_DecryptUpdate() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	plaintext_len = len;

	if (EVP_DecryptFinal_ex(cipher_ctx, plaintext + len, &len) != 1) {
		pwenc_set_error(error, "EVP_DecryptFinal_ex() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	plaintext_len += len;

	*plaintext_out = plaintext;
	*plaintext_len_out = plaintext_len;

cleanup:
	EVP_CIPHER_CTX_free(cipher_ctx);
	if (ret != PWENC_SUCCESS) {
		free(plaintext);
	}
	return ret;
}

int pwenc_decrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error)
{
	unsigned char *plaintext;
	unsigned char nonce[PWENC_NONCE_SIZE];
	size_t plaintext_len;
	pwenc_datum_t decoded_datum = {0};
	int ret;

	if (!ctx || !PWENC_DATUM_VALID(data_in) || !data_out) {
		pwenc_set_error(error, "invalid input");
		return PWENC_ERROR_INVALID_INPUT;
	}

	if (ctx->secret_mem == NULL) {
		pwenc_set_error(error, "context not open");
		return PWENC_ERROR_INVALID_INPUT;
	}

	/* Check if base64-encoded data could exceed maximum payload size */
	if (data_in->size > PWENC_MAX_ENCODED_SIZE) {
		pwenc_set_error(error, "encoded data size %zu exceeds maximum for %d byte payload",
			data_in->size, PWENC_MAX_PAYLOAD_SIZE);
		return PWENC_ERROR_PAYLOAD_TOO_LARGE;
	}

	ret = base64_decode(error, data_in, &decoded_datum);
	if (ret != PWENC_SUCCESS) {
		return ret;
	}

	if (decoded_datum.size < PWENC_NONCE_SIZE) {
		pwenc_datum_free(&decoded_datum, false);
		pwenc_set_error(error, "decoded data too short");
		return PWENC_ERROR_INVALID_INPUT;
	}

	memcpy(nonce, decoded_datum.data, PWENC_NONCE_SIZE);

	ret = do_decrypt(ctx, nonce, decoded_datum.data + PWENC_NONCE_SIZE,
		decoded_datum.size - PWENC_NONCE_SIZE, &plaintext, &plaintext_len,
		error);

	pwenc_datum_free(&decoded_datum, false);

	if (ret != PWENC_SUCCESS) {
		return ret;
	}

	data_out->data = plaintext;
	data_out->size = plaintext_len;
	return PWENC_SUCCESS;
}
