#ifndef TRUENAS_PWENC_H
#define TRUENAS_PWENC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <limits.h>

#define PWENC_BLOCK_SIZE 32
#define PWENC_NONCE_SIZE 8
#define PWENC_SUCCESS 0
#define PWENC_ERROR_INVALID_INPUT -1
#define PWENC_ERROR_MEMORY -2
#define PWENC_ERROR_CRYPTO -3
#define PWENC_ERROR_IO -4
#define PWENC_ERROR_SECRET_NOT_FOUND -5

#define PWENC_OPEN_EXISTING 0
#define PWENC_OPEN_CREATE O_CREAT

#define PWENC_DEFAULT_SECRET_PATH "/data/pwenc_secret"

typedef struct pwenc_ctx pwenc_ctx_t;

typedef struct {
	unsigned char *data;
	size_t size;
} pwenc_datum_t;

typedef struct {
	char message[1024];
} pwenc_error_t;

/*
 * @brief allocate and initialize a new password encryption context
 *
 * @return	pointer to new context on success, NULL on failure
 */
pwenc_ctx_t *pwenc_init_context(void);

/*
 * @brief free a password encryption context
 *
 * This function closes any open file descriptors and frees all memory
 * associated with the context.
 *
 * @param[in]	ctx - pointer to context to free (may be NULL)
 */
void pwenc_free_context(pwenc_ctx_t *ctx);


/*
 * @brief open and initialize a password encryption context
 *
 * This function opens the secret file and loads it into a memfd_secret for
 * secure storage. If PWENC_OPEN_CREATE is specified and the secret file
 * doesn't exist, a new random secret will be generated.
 *
 * @param[in]	ctx - pointer to context structure to initialize
 * @param[in]	flags - PWENC_OPEN_EXISTING or PWENC_OPEN_CREATE
 * @param[out]	created - pointer to bool that will be set to true if secret file was created
 * @param[out]	error - pointer to error structure for error details
 *
 * @return	PWENC_SUCCESS on success, error code on failure
 */
int pwenc_open(pwenc_ctx_t *ctx, int flags, bool *created, pwenc_error_t *error);

/*
 * @brief close and cleanup a password encryption context
 *
 * This function closes the memfd_secret and cleans up all resources
 * associated with the context.
 *
 * @param[in]	ctx - pointer to context structure to cleanup
 */
void pwenc_close(pwenc_ctx_t *ctx);

/*
 * @brief get the secret file path from a context
 *
 * @param[in]	ctx - pointer to context structure
 *
 * @return	pointer to secret file path string
 */
const char *pwenc_get_secret_path(pwenc_ctx_t *ctx);

/*
 * @brief securely free a pwenc_datum_t
 *
 * This function zeros the data buffer, frees it, and zeros the struct.
 * It is safe to call this function with a NULL or already-freed datum.
 *
 * @param[in,out]	datum - pointer to datum to free
 */
void pwenc_datum_free(pwenc_datum_t *datum);

/*
 * @brief encrypt data using AES-256-CTR and encode as base64
 *
 * This function encrypts the input data using AES-256-CTR with a random
 * 8-byte nonce, applies PKCS#7-style padding, and encodes the result
 * as a base64 string.
 *
 * @param[in]	ctx - initialized context
 * @param[in]	data_in - input data to encrypt
 * @param[out]	data_out - datum to receive allocated base64 output string
 * @param[out]	error - error structure for error details
 *
 * @return	PWENC_SUCCESS on success, error code on failure
 */
int pwenc_encrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error);

/*
 * @brief decrypt base64-encoded data using AES-256-CTR
 *
 * This function decodes the base64 input, extracts the nonce, and
 * decrypts the data using AES-256-CTR, removing padding.
 *
 * @param[in]	ctx - initialized context
 * @param[in]	data_in - base64-encoded input string datum
 * @param[out]	data_out - datum to receive allocated decrypted output
 * @param[out]	error - error structure for error details
 *
 * @return	PWENC_SUCCESS on success, error code on failure
 */
int pwenc_decrypt(pwenc_ctx_t *ctx, const pwenc_datum_t *data_in,
	pwenc_datum_t *data_out, pwenc_error_t *error);

#endif