#define _GNU_SOURCE
#include "truenas_pwenc.h"
#include "pwenc_private.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <bsd/string.h>



static int generate_secret_file(const char *path, pwenc_error_t *error)
{
	unsigned char secret[PWENC_BLOCK_SIZE];
	char temp_path[PATH_MAX];
	int fd, ret = PWENC_SUCCESS;

	if (RAND_bytes(secret, PWENC_BLOCK_SIZE) != 1) {
		pwenc_set_error(error, "RAND_bytes() failed: %s",
			ERR_error_string(ERR_get_error(), NULL));
		return PWENC_ERROR_CRYPTO;
	}

	if (snprintf(temp_path, PATH_MAX, "%s.XXXXXX", path) >= PATH_MAX) {
		pwenc_set_error(error, "secret path too long: %s", path);
		return PWENC_ERROR_INVALID_INPUT;
	}

	fd = mkstemp(temp_path);
	if (fd < 0) {
		pwenc_set_error(error, "mkstemp() failed: %s", strerror(errno));
		return PWENC_ERROR_IO;
	}

	if (pwrite(fd, secret, PWENC_BLOCK_SIZE, 0) != PWENC_BLOCK_SIZE) {
		pwenc_set_error(error, "pwrite() failed: %s", strerror(errno));
		ret = PWENC_ERROR_IO;
		goto cleanup;
	}

	if (fsync(fd) < 0) {
		pwenc_set_error(error, "fsync() failed: %s", strerror(errno));
		ret = PWENC_ERROR_IO;
		goto cleanup;
	}

	close(fd);

	if (ret == PWENC_SUCCESS) {
		if (rename(temp_path, path) < 0) {
			pwenc_set_error(error, "rename() failed: %s",
				strerror(errno));
			ret = PWENC_ERROR_IO;
			unlink(temp_path);
		}
	} else {
		unlink(temp_path);
	}

	explicit_bzero(secret, PWENC_BLOCK_SIZE);
	return ret;

cleanup:
	explicit_bzero(secret, PWENC_BLOCK_SIZE);
	close(fd);
	unlink(temp_path);
	return ret;
}

static int load_secret_to_memfd(pwenc_ctx_t *ctx, const char *path,
	int *memfd_out, pwenc_error_t *error)
{
	int fd, memfd, ret = PWENC_SUCCESS;
	unsigned char buffer[PWENC_BLOCK_SIZE];
	ssize_t bytes_read;
	struct stat st;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pwenc_set_error(error, "open() failed: %s", strerror(errno));
		return PWENC_ERROR_SECRET_NOT_FOUND;
	}

	if (fstat(fd, &st) < 0) {
		pwenc_set_error(error, "fstat() failed: %s", strerror(errno));
		close(fd);
		return PWENC_ERROR_IO;
	}

	if (st.st_size != PWENC_BLOCK_SIZE) {
		pwenc_set_error(error, "secret file has invalid size: %ld bytes",
			st.st_size);
		close(fd);
		return PWENC_ERROR_IO;
	}

	memfd = syscall(SYS_memfd_secret, 0);
	if (memfd < 0) {
		pwenc_set_error(error, "memfd_secret() failed: %s",
			strerror(errno));
		close(fd);
		return PWENC_ERROR_IO;
	}

	if (ftruncate(memfd, sizeof(buffer) + 1) < 0) {
		pwenc_set_error(error, "ftruncate() failed: %s", strerror(errno));
		close(fd);
		close(memfd);
		return PWENC_ERROR_IO;
	}

	/* Copy secret data using mmap for memfd_secret */
	bytes_read = pread(fd, buffer, sizeof(buffer), 0);
	if (bytes_read != PWENC_BLOCK_SIZE) {
		pwenc_set_error(error, "pread() failed: %s", strerror(errno));
		ret = PWENC_ERROR_IO;
	} else {
		void *mem = mmap(NULL, PWENC_BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
		if (mem == MAP_FAILED) {
			pwenc_set_error(error, "mmap() failed: %s", strerror(errno));
			ret = PWENC_ERROR_IO;
		} else {
			memcpy(mem, buffer, PWENC_BLOCK_SIZE);
			ctx->secret_mem = mem;
			/* Keep mapped - will be unmapped in pwenc_free_context */
		}
	}
	
	explicit_bzero(buffer, sizeof(buffer));

	close(fd);

	if (ret != PWENC_SUCCESS) {
		close(memfd);
		return ret;
	}

	*memfd_out = memfd;
	return PWENC_SUCCESS;
}

int pwenc_open(pwenc_ctx_t *ctx, int flags, bool *created, pwenc_error_t *error)
{
	int ret;

	if (!ctx || !created) {
		return PWENC_ERROR_INVALID_INPUT;
	}

	*created = false;
	ctx->memfd = -1;

	ret = load_secret_to_memfd(ctx, ctx->secret_path, &ctx->memfd, error);
	if (ret == PWENC_ERROR_SECRET_NOT_FOUND &&
	    (flags & PWENC_OPEN_CREATE)) {
		ret = generate_secret_file(ctx->secret_path, error);
		if (ret == PWENC_SUCCESS) {
			*created = true;
			ret = load_secret_to_memfd(ctx, ctx->secret_path,
				&ctx->memfd, error);
		}
	}

	return ret;
}
