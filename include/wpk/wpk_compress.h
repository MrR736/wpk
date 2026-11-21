
#ifndef WPK_COMPRESS_H
#define WPK_COMPRESS_H

#include <stdint.h>
#include <stddef.h>

#include "wpk_uuid.h"

enum {
	WPK_NO_COMPRESSION = 0,
	WPK_BEST_SPEED = 1,
	WPK_BEST_COMPRESSION = 9,
	WPK_UBER_COMPRESSION = 10,
	WPK_DEFAULT_LEVEL = 6,
	WPK_DEFAULT_COMPRESSION = -1
};

typedef struct WPK_COMPRESS_OPTIONS {
	int level;

	/* NULL means no encryption. */
	const char *password;

	/* 0 means use the default iteration count. */
	uint32_t pbkdf2_iterations;
} WPK_COMPRESS_OPTIONS;

/* A file whose contents are already in memory. */
typedef struct WPK_MEM_FILE {
	const char *path;   /* path inside the archive */
	const void *data;   /* may be NULL when size is 0 */
	size_t size;
	uint64_t timestamp; /* UTC Unix time */
} wpk_mem_file_t;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Compress a directory recursively.
 *
 * archive:  output archive path.
 * dir:      input directory.
 * options:  compression/encryption settings.
 * out_uuid: receives the generated UUID.
 *
 * Returns 1 on success, 0 on failure.
 */
int wpk_compress_dir(
	const char *archive,
	const char *dir,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
);

/* Compress one file. */
int wpk_compress_file(
	const char *archive,
	const char *file,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
);

/*
 * Compress multiple files.
 *
 * files must be a NULL-terminated array.
 */
int wpk_compress_files(
	const char *archive,
	const char **files,
	size_t count,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
);

/*
 * Compress files held in memory. The buffers are only read, never modified
 * or freed. Returns 1 on success, 0 on failure.
 */
int wpk_compress_mem(
	const char *archive,
	const wpk_mem_file_t *files,
	size_t count,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
);

int wpk_compress_files_ex(
	const char *archive,
	const char **source_files,
	const char **archive_paths,
	size_t count,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
);

#ifdef __cplusplus
}
#endif

#endif
