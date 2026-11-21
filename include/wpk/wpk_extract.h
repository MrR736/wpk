#ifndef WPK_EXTRACT_H
#define WPK_EXTRACT_H

#include <stdint.h>
#include <stddef.h>
#include "wpk_uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Extract all files from an unencrypted archive.
 * UUID verification is optional.
 */
int wpk_extract(const char *archive,const char *outdir);
int wpk_extract_uuid(const char *archive,const char *outdir,const wpk_uuid_t expected_uuid);

/*
 * Extract all files from an archive.
 * Supports encrypted and unencrypted archives.
 */
int wpk_extract_password(const char *archive,const char *outdir,const char *password);
int wpk_extract_password_uuid(const char *archive,const char *outdir,const wpk_uuid_t expected_uuid,const char *password);

/*
 * Extract one file from an unencrypted archive.
 */
int wpk_extract_file(const char *archive,uint32_t index,const char *outdir);
int wpk_extract_file_uuid(const char *archive,uint32_t index,const char *outdir,const wpk_uuid_t expected_uuid);

/*
 * Extract one file from an archive.
 * Supports encrypted and unencrypted archives.
 */
int wpk_extract_file_password(const char *archive,uint32_t index,const char *outdir,const char *password);
int wpk_extract_file_password_uuid(const char *archive,uint32_t index,const char *outdir,const wpk_uuid_t expected_uuid,const char *password);

/* --------------------------------------------------------- */
/* Buffer extraction API                                     */
/* --------------------------------------------------------- */

/*
 * Extract all files from an archive stored in memory.
 */
int wpk_extract_buffer(const void *buffer,size_t buffer_size,const char *outdir);

/*
 * Extract all files and verify the archive UUID.
 */
int wpk_extract_buffer_uuid(const void *buffer,size_t buffer_size,const char *outdir,const wpk_uuid_t expected_uuid);

/*
 * Extract all files from an encrypted archive.
 */
int wpk_extract_buffer_password(
	const void *buffer,
	size_t buffer_size,
	const char *outdir,
	const char *password
);

/*
 * Extract all files from an encrypted archive
 * and verify its UUID.
 */
int wpk_extract_buffer_password_uuid(
	const void *buffer,
	size_t buffer_size,
	const char *outdir,
	const wpk_uuid_t expected_uuid,
	const char *password
);

/*
 * Extract one file by its archive index.
 */
int wpk_extract_buffer_file(
	const void *buffer,
	size_t buffer_size,
	uint32_t index,
	const char *outdir
);

/*
 * Extract one file by index and verify the archive UUID.
 */
int wpk_extract_buffer_file_uuid(
	const void *buffer,
	size_t buffer_size,
	uint32_t index,
	const char *outdir,
	const wpk_uuid_t expected_uuid
);

/*
 * Extract one file from an encrypted archive.
 */
int wpk_extract_buffer_file_password(
	const void *buffer,
	size_t buffer_size,
	uint32_t index,
	const char *outdir,
	const char *password
);

/*
 * Extract one file from an encrypted archive
 * and verify its UUID.
 */
int wpk_extract_buffer_file_password_uuid(
	const void *buffer,
	size_t buffer_size,
	uint32_t index,
	const char *outdir,
	const wpk_uuid_t expected_uuid,
	const char *password
);

#ifdef __cplusplus
}
#endif

#endif
