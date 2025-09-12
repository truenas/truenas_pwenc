#ifndef TRUENAS_PWENC_PRIVATE_H
#define TRUENAS_PWENC_PRIVATE_H

#include "truenas_pwenc.h"
#include <limits.h>
#include <sys/param.h>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

struct pwenc_ctx {
	int memfd;
	void *secret_mem;
	char secret_path[PATH_MAX];
};

/*
 * @brief set error message in error struct with location info
 *
 * @param[in]	error - error struct to set message in (may be NULL)
 * @param[in]	fmt - printf-style format string
 * @param[in]	... - format arguments
 */
void _pwenc_set_error(pwenc_error_t *error, const char *fmt,
	const char *location, ...);

#define __stringify(x) #x
#define __stringify2(x) __stringify(x)
#define __location__ __FILE__ ":" __stringify2(__LINE__)

#define pwenc_set_error(error, fmt, ...) \
	_pwenc_set_error(error, fmt, __location__, ##__VA_ARGS__)

/*
 * Macro for pwenc_datum_t validation
 */
#define PWENC_DATUM_VALID(datum) \
	((datum) != NULL && (datum)->data != NULL && (datum)->size > 0)

/*
 * Maximum base64-encoded size for PWENC_MAX_PAYLOAD_SIZE + nonce
 * Base64 encodes (PWENC_MAX_PAYLOAD_SIZE + PWENC_NONCE_SIZE) bytes to roughly 4/3 that size
 */
#define PWENC_MAX_ENCODED_SIZE \
	(((PWENC_MAX_PAYLOAD_SIZE + PWENC_NONCE_SIZE + 2) / 3) * 4)

/*
 * @brief encode data as base64
 *
 * @param[in]	error - error struct for error reporting (may be NULL)
 * @param[in]	data_in - input data to encode
 * @param[out]	data_out - datum to receive allocated base64 string
 *
 * @return	PWENC_SUCCESS on success, error code on failure
 *
 * @note	the output string is NOT null-terminated
 */
pwenc_resp_t base64_encode(pwenc_error_t *error, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out);

#endif
