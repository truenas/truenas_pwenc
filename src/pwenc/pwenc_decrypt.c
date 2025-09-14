#define _GNU_SOURCE
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>
#include <endian.h>


static pwenc_resp_t do_decrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *nonce,
	const pwenc_datum_t *ciphertext, pwenc_datum_t *plaintext_out,
	pwenc_error_t *error)
{
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	pwenc_datum_t plaintext = {0};
	unsigned char iv[16] = {0};
	pwenc_resp_t ret = PWENC_SUCCESS;
	int len;

	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!cipher_ctx) {
		pwenc_set_error(error, "EVP_CIPHER_CTX_new() failed");
		return PWENC_ERROR_CRYPTO;
	}

	/* Set counter to 1 (big-endian) for middleware compatibility */
	*(uint64_t *)(iv + 8) = htobe64(LEGACY_PWENC_INIT_CTR);
	/* Set nonce in initialization vector */
	memcpy(iv, nonce->data, nonce->size);

	if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, ctx->secret_mem,
	    iv) != 1) {
		pwenc_set_error(error, "EVP_DecryptInit_ex() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	plaintext.data = calloc(1, ciphertext->size + EVP_CIPHER_block_size(EVP_aes_256_ctr()));
	if (!plaintext.data) {
		pwenc_set_error(error, "calloc() failed");
		ret = PWENC_ERROR_MEMORY;
		goto cleanup;
	}

	if (EVP_DecryptUpdate(cipher_ctx, plaintext.data, &len, ciphertext->data,
	    ciphertext->size) != 1) {
		pwenc_set_error(error, "EVP_DecryptUpdate() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	plaintext.size = len;

	if (EVP_DecryptFinal_ex(cipher_ctx, plaintext.data + len, &len) != 1) {
		pwenc_set_error(error, "EVP_DecryptFinal_ex() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		ret = PWENC_ERROR_CRYPTO;
		goto cleanup;
	}

	plaintext.size += len;

	*plaintext_out = plaintext;
	plaintext.data = NULL;

cleanup:
	EVP_CIPHER_CTX_free(cipher_ctx);
	pwenc_datum_free(&plaintext, true);
	return ret;
}

pwenc_resp_t pwenc_decrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error)
{
	pwenc_datum_t nonce = {0};
	pwenc_datum_t decoded_datum = {0};
	pwenc_datum_t ciphertext = {0};
	pwenc_resp_t ret;

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

	/* Extract nonce from decoded data */
	nonce.size = PWENC_NONCE_SIZE;
	nonce.data = malloc(PWENC_NONCE_SIZE);
	if (!nonce.data) {
		pwenc_datum_free(&decoded_datum, false);
		pwenc_set_error(error, "malloc() failed for nonce");
		return PWENC_ERROR_MEMORY;
	}
	memcpy(nonce.data, decoded_datum.data, PWENC_NONCE_SIZE);

	/* Setup ciphertext datum pointing to encrypted portion */
	ciphertext.data = decoded_datum.data + PWENC_NONCE_SIZE;
	ciphertext.size = decoded_datum.size - PWENC_NONCE_SIZE;

	ret = do_decrypt(ctx, &nonce, &ciphertext, data_out, error);

	pwenc_datum_free(&decoded_datum, true);
	pwenc_datum_free(&nonce, false);

	return ret;
}
