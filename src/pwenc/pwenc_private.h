// SPDX-License-Identifier: LGPL-3.0-or-later
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
 * Initial counter value for AES-256-CTR mode (for middleware compatibility)
 */
#define LEGACY_PWENC_INIT_CTR 1

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

/*
 * @brief decode base64 data
 *
 * @param[in]	error - error struct for error reporting (may be NULL)
 * @param[in]	data_in - input base64 data to decode
 * @param[out]	data_out - datum to receive allocated decoded data
 *
 * @return	PWENC_SUCCESS on success, error code on failure
 */
pwenc_resp_t base64_decode(pwenc_error_t *error, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out);

/*
 * @brief open and initialize a pwenc context
 *
 * This function opens the secret file and loads it into a memfd_secret for
 * secure storage. If PWENC_OPEN_CREATE is specified and the secret file
 * doesn't exist, a new random secret will be generated.
 *
 * @param[in]   ctx - pointer to context structure to initialize
 * @param[in]   flags - PWENC_OPEN_EXISTING or PWENC_OPEN_CREATE
 * @param[out]  created - pointer to bool that will be set to true if secret file was created
 * @param[out]  error - pointer to error structure for error details
 *
 * @return      PWENC_SUCCESS on success, error code on failure
 */
pwenc_resp_t pwenc_open(pwenc_ctx_t *ctx, int flags, bool *created, pwenc_error_t *error);

/*
 * @brief close and cleanup a pwenc context
 *
 * This function closes the memfd_secret and cleans up all resources
 * associated with the context.
 *
 * @param[in]   ctx - pointer to context structure to cleanup
 */
void pwenc_close(pwenc_ctx_t *ctx);

#endif
