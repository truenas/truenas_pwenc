// SPDX-License-Identifier: LGPL-3.0-or-later
#define _GNU_SOURCE
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <errno.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN 4096

/*
 * Check if an inotify event requires reloading the secret.
 * Returns true if the event indicates the secret file has changed.
 */
static bool event_needs_reload(pwenc_ctx_t *ctx, struct inotify_event *event)
{
	// File-level events (inode changes)
	if (event->wd == ctx->file_watch_wd) {
		if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_MODIFY)) {
			return true;
		}
	}

	// Directory-level events (rename-over case)
	if (event->wd == ctx->dir_watch_wd) {
		if ((event->mask & (IN_CREATE | IN_MOVED_TO)) &&
		    event->len > 0 &&
		    strcmp(event->name, ctx->filename) == 0) {
			return true;
		}
	}

	return false;
}

/*
 * Reload the secret from the file at secret_path into the context.
 * This closes the old secret and loads the new one.
 */
static pwenc_resp_t pwenc_reload_secret(pwenc_ctx_t *ctx, pwenc_error_t *error)
{
	pwenc_resp_t ret;
	bool created;

	// Clean up old secret
	pwenc_close(ctx);

	// Load new secret using existing open function
	ret = pwenc_open(ctx, PWENC_OPEN_EXISTING, &created, error);
	if (ret != PWENC_SUCCESS) {
		return PWENC_ERROR_SECRET_RELOAD_FAILED;
	}

	return PWENC_SUCCESS;
}

pwenc_resp_t pwenc_check_and_reload(pwenc_ctx_t *ctx, pwenc_error_t *error)
{
	char buf[EVENT_BUF_LEN];
	ssize_t len;
	struct inotify_event *event;
	bool needs_reload = false;

	// Keep reading events until queue is empty or we find a reload trigger
	while (!needs_reload) {
		// Non-blocking read of inotify events
		len = read(ctx->inotify_fd, buf, sizeof(buf));

		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;  // No more events
			}
			pwenc_set_error(error, "read() from inotify fd failed: %s", strerror(errno));
			return PWENC_ERROR_IO;
		}

		// Process events in this read
		for (char *ptr = buf; ptr < buf + len; ) {
			event = (struct inotify_event *)ptr;

			needs_reload = event_needs_reload(ctx, event);
			if (needs_reload) {
				break;
			}

			ptr += EVENT_SIZE + event->len;
		}
	}

	if (needs_reload) {
		return pwenc_reload_secret(ctx, error);
	}

	return PWENC_SUCCESS;
}

pwenc_resp_t pwenc_setup_watch(pwenc_ctx_t *ctx, pwenc_error_t *error)
{
	int fd, file_wd, dir_wd;

	// Create inotify instance
	fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0) {
		pwenc_set_error(error, "inotify_init1() failed: %s", strerror(errno));
		return PWENC_ERROR_WATCH_FAILED;
	}

	// Watch the file itself (inode-level)
	file_wd = inotify_add_watch(fd, ctx->secret_path,
		IN_DELETE_SELF | IN_MOVE_SELF | IN_MODIFY | IN_ATTRIB);
	if (file_wd < 0) {
		pwenc_set_error(error, "inotify_add_watch() on file failed: %s", strerror(errno));
		close(fd);
		return PWENC_ERROR_WATCH_FAILED;
	}

	// Watch the parent directory (path-level for rename-over)
	dir_wd = inotify_add_watch(fd, ctx->dir_path,
		IN_CREATE | IN_MOVED_TO);
	if (dir_wd < 0) {
		pwenc_set_error(error, "inotify_add_watch() on directory failed: %s", strerror(errno));
		inotify_rm_watch(fd, file_wd);
		close(fd);
		return PWENC_ERROR_WATCH_FAILED;
	}

	ctx->inotify_fd = fd;
	ctx->file_watch_wd = file_wd;
	ctx->dir_watch_wd = dir_wd;
	ctx->watching = true;

	return PWENC_SUCCESS;
}

void pwenc_cleanup_watch(pwenc_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->file_watch_wd >= 0 && ctx->inotify_fd >= 0) {
		inotify_rm_watch(ctx->inotify_fd, ctx->file_watch_wd);
		ctx->file_watch_wd = -1;
	}

	if (ctx->dir_watch_wd >= 0 && ctx->inotify_fd >= 0) {
		inotify_rm_watch(ctx->inotify_fd, ctx->dir_watch_wd);
		ctx->dir_watch_wd = -1;
	}

	if (ctx->inotify_fd >= 0) {
		close(ctx->inotify_fd);
		ctx->inotify_fd = -1;
	}
}

bool pwenc_is_watching(pwenc_ctx_t *ctx)
{
	return ctx && ctx->watching;
}
