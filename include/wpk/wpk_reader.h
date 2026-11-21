#ifndef WPK_READER_H
#define WPK_READER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "miniz/miniz.h"
#include "wpk_uuid.h"

#define WPK_ZIP_MAX_ARCHIVE_FILENAME_SIZE 512

typedef mz_zip_archive_file_stat wpk_stat;

typedef struct WPK_READER wpk_reader_t;

#ifdef __cplusplus
extern "C" {
#endif

int wpk_reader_open_mem(const void *wpk,size_t size,wpk_reader_t **reader);

int wpk_reader_open_password_mem(const void *wpk,size_t size,const char *password,wpk_reader_t **reader);

int wpk_reader_open(const char *archive_path,wpk_reader_t **reader);

int wpk_reader_open_password(const char *archive_path,const char *password,wpk_reader_t **reader);

void wpk_reader_close(wpk_reader_t *reader);

/* Get archive UUID. */
int wpk_reader_get_uuid(const wpk_reader_t *reader,wpk_uuid_t uuid);

int wpk_reader_equal_uuid(const wpk_reader_t *reader, wpk_uuid_t uuid);

/* Get number of entries. */
uint32_t wpk_reader_get_file_count(const wpk_reader_t *reader);

/* Get an entry path. */
int wpk_reader_get_file_path(const wpk_reader_t *reader,uint32_t index,char *buffer,size_t buffer_size);

/*
 * Returns:
 *   Number of files on success.
 *   UINT32_MAX if reader is NULL.
 */
uint32_t wpk_reader_get_locate_file(const wpk_reader_t *reader,const char* filename);

/*
 * Get the number of files in the archive.
 *
 * Returns:
 *   Number of files on success.
 *   UINT32_MAX if reader is NULL.
 */
uint32_t wpk_reader_get_num_files(const wpk_reader_t *reader);

/* Metadata of one entry, read straight from the archive table. */
typedef struct WPK_ENTRY_INFO {
	uint64_t original_size;
	uint64_t compressed_size;
	uint64_t timestamp;	/* UTC Unix time */
	int encrypted;
} wpk_entry_info_t;

/* Returns 1 on success, 0 on bad arguments/index. */
int wpk_reader_get_entry_info(const wpk_reader_t *reader,uint32_t index,wpk_entry_info_t *info);

/* Returns 1 if the archive is encrypted, 0 otherwise. */
int wpk_reader_is_encrypted(const wpk_reader_t *reader);

bool wpk_reader_file_stat(const wpk_reader_t *reader, uint32_t file_index, wpk_stat *stat);

#ifdef __cplusplus
}
#endif

#endif
