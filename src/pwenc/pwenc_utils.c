#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>


void pwenc_datum_free(pwenc_datum_t *datum)
{
	if (!datum) {
		return;
	}

	if (datum->data && datum->size > 0) {
		explicit_bzero(datum->data, datum->size);
		free(datum->data);
	}

	explicit_bzero(datum, sizeof(*datum));
}

int base64_encode(pwenc_error_t *error, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out)
{
	char *encoded;
	size_t encoded_len;
	int ret;

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
		pwenc_set_error(error, "EVP_EncodeBlock() failed");
		free(encoded);
		return PWENC_ERROR_CRYPTO;
	}

	data_out->data = (unsigned char *)encoded;
	data_out->size = ret;

	return PWENC_SUCCESS;
}