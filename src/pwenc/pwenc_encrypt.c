#define _GNU_SOURCE
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>


static unsigned char *pwenc_create_nonce(pwenc_error_t *error)
{
	unsigned char *nonce;

	nonce = malloc(PWENC_NONCE_SIZE);
	if (!nonce) {
		pwenc_set_error(error, "malloc() failed for nonce");
		return NULL;
	}

	if (RAND_bytes(nonce, PWENC_NONCE_SIZE) != 1) {
		pwenc_set_error(error, "RAND_bytes() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		free(nonce);
		return NULL;
	}

	return nonce;
}

static int do_encrypt(const unsigned char *secret,
	const unsigned char *nonce, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error)
{
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	unsigned char *encrypted = NULL;
	unsigned char *nonce_encrypted = NULL;
	unsigned char iv[16] = {0};
	size_t encrypted_len, nonce_encrypted_len;
	int ret = PWENC_SUCCESS, len, final_len;

	encrypted = calloc(1, data_in->size);
	if (!encrypted) {
		pwenc_set_error(error, "calloc() failed for encryption");
		ret = PWENC_ERROR_MEMORY;
		goto cleanup;
	}

	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!cipher_ctx) {
		pwenc_set_error(error, "EVP_CIPHER_CTX_new() failed");
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	memcpy(iv, nonce, PWENC_NONCE_SIZE);

	if (!EVP_EncryptInit_ex2(cipher_ctx, EVP_aes_256_ctr(), secret, iv, NULL)) {
		pwenc_set_error(error, "EVP_EncryptInit_ex() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	if (!EVP_EncryptUpdate(cipher_ctx, encrypted, &len, data_in->data, data_in->size)) {
		pwenc_set_error(error, "EVP_EncryptUpdate() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}
	encrypted_len = len;

	if (EVP_EncryptFinal_ex(cipher_ctx, encrypted + len, &final_len) != 1) {
		pwenc_set_error(error, "EVP_EncryptFinal_ex() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}
	encrypted_len += final_len;

	nonce_encrypted_len = PWENC_NONCE_SIZE + encrypted_len;
	nonce_encrypted = calloc(1, nonce_encrypted_len);
	if (!nonce_encrypted) {
		pwenc_set_error(error, "calloc() failed for nonce+encrypted");
		ret = PWENC_ERROR_MEMORY;
		goto cleanup;
	}

	memcpy(nonce_encrypted, nonce, PWENC_NONCE_SIZE);
	memcpy(nonce_encrypted + PWENC_NONCE_SIZE, encrypted, encrypted_len);

	pwenc_datum_t nonce_encrypted_datum = {
		.data = nonce_encrypted,
		.size = nonce_encrypted_len
	};

	ret = base64_encode(error, &nonce_encrypted_datum, data_out);
	if (ret != PWENC_SUCCESS) {
		goto cleanup;
	}

cleanup:
	EVP_CIPHER_CTX_free(cipher_ctx);
	free(encrypted);
	free(nonce_encrypted);

	return ret;
}

int pwenc_encrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error)
{
	unsigned char *nonce = NULL;
	int ret = PWENC_SUCCESS;

	if (!ctx || ctx->secret_mem == NULL || !PWENC_DATUM_VALID(data_in) || !data_out) {
		pwenc_set_error(error, "invalid input parameters");
		return PWENC_ERROR_INVALID_INPUT;
	}

	if (data_in->size > PWENC_MAX_PAYLOAD_SIZE) {
		pwenc_set_error(error, "payload size %zu exceeds maximum of %d bytes",
			data_in->size, PWENC_MAX_PAYLOAD_SIZE);
		return PWENC_ERROR_PAYLOAD_TOO_LARGE;
	}

	nonce = pwenc_create_nonce(error);
	if (!nonce) {
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	ret = do_encrypt(ctx->secret_mem, nonce, data_in, data_out, error);

cleanup:
	free(nonce);

	return ret;
}
