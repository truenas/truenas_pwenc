// SPDX-License-Identifier: LGPL-3.0-or-later
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <unistd.h>

void pwenc_close(pwenc_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->memfd > 0) {
		close(ctx->memfd);
		ctx->memfd = -1;
	}
}