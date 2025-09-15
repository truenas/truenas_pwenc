// SPDX-License-Identifier: LGPL-3.0-or-later
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>


void pwenc_datum_free(pwenc_datum_t *datum, bool zero_data)
{
	if (!datum) {
		return;
	}

	if (datum->data && datum->size > 0) {
		if (zero_data) {
			explicit_bzero(datum->data, datum->size);
		}
		free(datum->data);
	}

	explicit_bzero(datum, sizeof(*datum));
}

pwenc_resp_t base64_encode(pwenc_error_t *error, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out)
{
	char *encoded;
	size_t encoded_len;
	pwenc_resp_t ret;

	if (!PWENC_DATUM_VALID(data_in) || !data_out) {
		pwenc_set_error(error, "invalid input parameters");
		return PWENC_ERROR_INVALID_INPUT;
	}

	encoded_len = 4 * ((data_in->size + 2) / 3) + 1;
	encoded = calloc(1, encoded_len);
	if (!encoded) {
		pwenc_set_error(error, "calloc() failed");
		return PWENC_ERROR_MEMORY;
	}

	ret = EVP_EncodeBlock((unsigned char *)encoded, data_in->data, data_in->size);
	if (ret < 0) {
		pwenc_set_ssl_error(error, "EVP_EncodeBlock() failed to base64 encode data");
		free(encoded);
		return PWENC_ERROR_CRYPTO;
	}

	data_out->data = (unsigned char *)encoded;
	data_out->size = ret;

	return PWENC_SUCCESS;
}

pwenc_resp_t base64_decode(pwenc_error_t *error, const pwenc_datum_t *data_in,
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
		pwenc_set_ssl_error(error, "EVP_DecodeBlock() failed to base64 decode data");
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
