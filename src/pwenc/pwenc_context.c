// SPDX-License-Identifier: LGPL-3.0-or-later
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <bsd/string.h>


pwenc_resp_t pwenc_init_context(const char *secret_path,
				int flags, pwenc_ctx_t **ctx,
				bool *created, pwenc_error_t *error)
{
	pwenc_ctx_t *new_ctx;
	pwenc_resp_t resp;
	const char *env_path;
	const char *path_to_use;

	if (!ctx) {
		pwenc_set_error(error, "Context pointer cannot be NULL");
		return PWENC_ERROR_INVALID_INPUT;
	}

	*ctx = NULL;

	new_ctx = calloc(1, sizeof(*new_ctx));
	if (!new_ctx) {
		pwenc_set_error(error, "Failed to allocate memory for context");
		return PWENC_ERROR_MEMORY;
	}

	new_ctx->memfd = -1;
	new_ctx->secret_mem = NULL;

	/*
	 * For compatiblity with legacy middleware behavior we allow overriding secret
	 * path with an environmental variable.
	 */
	if (secret_path) {
		path_to_use = secret_path;
	} else {
		env_path = getenv("FREENAS_PWENC_SECRET");
		path_to_use = env_path ? env_path : PWENC_DEFAULT_SECRET_PATH;
	}

	if (strlcpy(new_ctx->secret_path, path_to_use, PATH_MAX) >= PATH_MAX) {
		pwenc_set_error(error, "Secret path too long (max %d characters)", PATH_MAX - 1);
		free(new_ctx);
		return PWENC_ERROR_INVALID_INPUT;
	}

	resp = pwenc_open(new_ctx, flags, created, error);
	if (resp != PWENC_SUCCESS) {
		pwenc_free_context(new_ctx);
		return resp;
	}

	*ctx = new_ctx;
	return PWENC_SUCCESS;
}

void pwenc_free_context(pwenc_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}
	pwenc_close(ctx);
	free(ctx);
}

const char *pwenc_get_secret_path(pwenc_ctx_t *ctx)
{
	if (!ctx) {
		return NULL;
	}
	return ctx->secret_path;
}

void _pwenc_set_error(pwenc_error_t *error, unsigned long ssl_err_code,
	const char *fmt, const char *location, ...)
{
	va_list args;
	int offset;
	char ssl_err_buf[256];  // temporary buffer to hold SSL error string

	if (!error || !fmt) {
		return;
	}

	va_start(args, location);
	offset = vsnprintf(error->message, sizeof(error->message), fmt, args);
	va_end(args);

	/* Append SSL error string if ssl_err_code is non-zero */
	if (ssl_err_code != 0 && offset > 0 && (size_t)offset < sizeof(error->message) - 1) {
		ERR_error_string(ssl_err_code, ssl_err_buf);
		offset += snprintf(error->message + offset, sizeof(error->message) - offset,
			": %s", ssl_err_buf);
	}

	if (offset > 0 && (size_t)offset < sizeof(error->message) - 1) {
		snprintf(error->message + offset, sizeof(error->message) - offset,
			" [%s]", location);
	}
}
