// SPDX-License-Identifier: LGPL-3.0-or-later
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <unistd.h>
#include <sys/mman.h>

void pwenc_close(pwenc_ctx_t *ctx)
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
	ctx->secret_mem = NULL;
	ctx->memfd = -1;
}
