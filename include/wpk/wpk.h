#ifndef WPK_H
#define WPK_H

#include <stdint.h>
#include <stddef.h>

#include "miniz/miniz.h"

#include "wpk_uuid.h"
#include "wpk_compress.h"
#include "wpk_reader.h"
#include "wpk_extract.h"

#define WPK_VERSION 1
#define WPK_MAGIC "WPK100"
#define WPK_MAGIC_SIZE 6

#ifdef __cplusplus
extern "C" {
#endif

bool wpk_mem_convert_to_zip_mem(
	const void *wpk,
	size_t size,
	uint8_t **zip,
	size_t *out_size,
	const char *password
);

bool wpk_convert_to_zip_mem(
	const char *wpk_path,
	uint8_t **zip,
	size_t *out_size,
	const char *password
);

bool wpk_convert_to_zip_mem_uuid(
	const char *wpk_path,
	uint8_t **zip,
	size_t *out_size,
	const char *password,
	wpk_uuid_t uuid
);

bool wpk_convert_to_zip(
	const char *wpk_path,
	const char *zip_path,
	const char *password
);

/*
 * Convert a ZIP archive to a WPK archive.
 * password may be NULL for an unencrypted archive.
 * Directory entries are dropped; encrypted ZIP entries are rejected.
 */
bool zip_convert_to_wpk(
	const char *zip_path,
	const char *wpk_path,
	const char *password
);

bool wpk_reader_init_mem(
	mz_zip_archive *pZip,
	const void *wpk_mem,
	size_t size,
	mz_uint flags
);

bool wpk_reader_init_file(
	mz_zip_archive *pZip,
	const char *wpk_path,
	mz_uint32 flags
);

bool wpk_reader_end(mz_zip_archive *pZip);

#ifdef __cplusplus
}
#endif

#endif
