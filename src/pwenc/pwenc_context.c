#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <bsd/string.h>


pwenc_ctx_t *pwenc_init_context(const char *secret_path)
{
	pwenc_ctx_t *ctx;
	const char *env_path;
	const char *path_to_use;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return NULL;
	}

	ctx->memfd = -1;
	ctx->secret_mem = NULL;

	/* Priority: provided path > environment > default */
	if (secret_path) {
		path_to_use = secret_path;
	} else {
		env_path = getenv("FREENAS_PWENC_SECRET");
		path_to_use = env_path ? env_path : PWENC_DEFAULT_SECRET_PATH;
	}

	if (strlcpy(ctx->secret_path, path_to_use, PATH_MAX) >= PATH_MAX) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

void pwenc_free_context(pwenc_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->secret_mem != NULL) {
		munmap(ctx->secret_mem, PWENC_BLOCK_SIZE);
	}

	if (ctx->memfd > 0) {
		close(ctx->memfd);
	}

	free(ctx);
}

const char *pwenc_get_secret_path(pwenc_ctx_t *ctx)
{
	if (!ctx) {
		return NULL;
	}
	return ctx->secret_path;
}

void _pwenc_set_error(pwenc_error_t *error, const char *fmt,
	const char *location, ...)
{
	va_list args;
	int offset;

	if (!error || !fmt) {
		return;
	}

	va_start(args, location);
	offset = vsnprintf(error->message, sizeof(error->message), fmt, args);
	va_end(args);

	if (offset > 0 && (size_t)offset < sizeof(error->message) - 1) {
		snprintf(error->message + offset, sizeof(error->message) - offset,
			" [%s]", location);
	}
}