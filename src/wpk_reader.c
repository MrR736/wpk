#include "wpk.h"
#ifdef _WIN32
#include <io.h>
#define WPK_FSEEK _fseeki64
#define WPK_FTELL _ftelli64
#else
#include <unistd.h>
#include <sys/types.h>
#define WPK_FSEEK fseeko
#define WPK_FTELL ftello
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "wpk_reader.h"
#include "wpk_internal.h"

static int read_bytes(FILE *f, void *buffer, size_t size) {
	if (size == 0) return 1;
	return fread(buffer, 1, size, f) == size;
}

static int read_u16(FILE *f, uint16_t *value) {
	uint8_t b[2];
	if (!read_bytes(f, b, sizeof(b))) return 0;
	*value = (uint16_t)b[0] | ((uint16_t)b[1] << 8);
	return 1;
}

static int read_u32(FILE *f, uint32_t *value) {
	uint8_t b[4];
	if (!read_bytes(f, b, sizeof(b))) return 0;
	*value = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
	return 1;
}

static int read_u64(FILE *f, uint64_t *value) {
	uint8_t b[8];
	if (!read_bytes(f, b, sizeof(b))) return 0;
	*value = 0;
	for (unsigned i = 0; i < 8; ++i) *value |= (uint64_t)b[i] << (i * 8);
	return 1;
}

static int get_file_size(FILE *f, uint64_t *size) {
	if (WPK_FSEEK(f, 0, SEEK_END) != 0) return 0;

	{
		int64_t position = (int64_t)WPK_FTELL(f);
		if (position < 0) return 0;
		*size = (uint64_t)position;
	}

	return WPK_FSEEK(f, 0, SEEK_SET) == 0;
}

static int valid_path(const char *path, size_t length) {
	size_t i = 0;

	if (!path || length == 0) return 0;
	if (path[0] == '/' || path[0] == '\\') return 0;
	if (length >= 2 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':') return 0;

	while (i < length) {
		size_t start = i;

		while (i < length && path[i] != '/' && path[i] != '\\') ++i;

		size_t component = i - start;

		if (component == 0) return 0;

		if (component == 1 && path[start] == '.') return 0;

		if (component == 2 && path[start] == '.' && path[start + 1] == '.') return 0;

		if (i < length) ++i;
	}

	return 1;
}

static void free_entries(WPK_INTERNAL_ENTRY *entries,uint32_t count) {
	if (!entries) return;
	for (uint32_t i = 0; i < count; ++i) free(entries[i].path);
	free(entries);
}

static int read_header(wpk_reader_t *reader) {
	uint8_t magic[WPK_MAGIC_SIZE];
	wpk_uuid_t uuid;
	uint16_t reserved;

	FILE *f = reader->file;

	if (!read_bytes(f, magic, sizeof(magic))) return 0;

	if (memcmp(magic, WPK_MAGIC, WPK_MAGIC_SIZE) != 0) return 0;

	if (!read_bytes(f, uuid, sizeof(uuid))) return 0;

	memcpy(reader->uuid, uuid, WPK_UUID_SIZE);

	if (!read_u32(f, &reader->version)) return 0;

	if (reader->version != WPK_VERSION) return 0;

	if (!read_u32(f, &reader->file_count)) return 0;

	if (reader->file_count > WPK_MAX_FILES) return 0;

	if (!read_u64(f, &reader->table_offset)) return 0;

	if (!read_bytes(f, reader->salt, WPK_SALT_SIZE)) return 0;

	if (!read_u32(f, &reader->pbkdf2_iterations)) return 0;

	if (!read_u32(f, &reader->flags)) return 0;

	if (!read_u16(f, &reserved)) return 0;

	if (reserved != 0) return 0;

	if (reader->flags & ~WPK_FLAG_ENCRYPTED) return 0;

	if (reader->flags & WPK_FLAG_ENCRYPTED) {
		if (reader->pbkdf2_iterations < 100000 || reader->pbkdf2_iterations > 10000000) return 0;
	} else {
		if (reader->pbkdf2_iterations != 0) return 0;
	}

	return 1;
}

static int read_entries(wpk_reader_t *reader) {
	FILE *f = reader->file;

	if (reader->table_offset < WPK_HEADER_SIZE || reader->table_offset > reader->archive_size) return 0;

	if (reader->file_count == 0)
		return reader->table_offset == WPK_HEADER_SIZE && reader->archive_size == WPK_HEADER_SIZE;

	reader->entries = calloc(reader->file_count,sizeof(*reader->entries));

	if (!reader->entries) return 0;

	if (WPK_FSEEK(f, (int64_t)reader->table_offset, SEEK_SET) != 0) return 0;

	for (uint32_t i = 0; i < reader->file_count; ++i) {
		WPK_INTERNAL_ENTRY *e = &reader->entries[i];

		if (!read_u16(f, &e->path_len)) return 0;

		if (!read_u16(f, &e->flags)) return 0;

		if (!read_u64(f, &e->original_size)) return 0;

		if (!read_u64(f, &e->compressed_size)) return 0;

		if (!read_u64(f, &e->data_offset)) return 0;

		if (!read_bytes(f, e->nonce, WPK_NONCE_SIZE)) return 0;

		if (!read_bytes(f, e->tag, WPK_TAG_SIZE)) return 0;

		if (!read_u64(f, &e->timestamp)) return 0;

		if (e->path_len == 0 || e->path_len > WPK_MAX_PATH) return 0;

		if (e->flags & ~WPK_FLAG_ENCRYPTED) return 0;

		if (e->flags != (reader->flags & WPK_FLAG_ENCRYPTED)) return 0;

		if (e->original_size > ((uint64_t)1 << 40) || e->compressed_size > ((uint64_t)1 << 40)) return 0;

		if (e->data_offset < WPK_HEADER_SIZE) return 0;

		if (e->data_offset > reader->table_offset) return 0;

		if (e->compressed_size > reader->table_offset - e->data_offset) return 0;

		e->path = malloc((size_t)e->path_len + 1);

		if (!e->path) return 0;

		if (!read_bytes(f, e->path, e->path_len)) return 0;

		e->path[e->path_len] = '\0';

		if (memchr(e->path, '\0', e->path_len)) return 0;

		if (!valid_path(e->path, e->path_len)) return 0;

		/* Reject duplicate paths. */
		for (uint32_t j = 0; j < i; ++j) {
			if (strcmp(reader->entries[j].path,e->path) == 0) return 0;
		}
	}

	/* The table must end exactly at the archive end. */
	{
		int64_t position = (int64_t)WPK_FTELL(f);
		if (position < 0 || (uint64_t)position != reader->archive_size) return 0;
	}

	/* Reject overlapping payload ranges. */
	for (uint32_t i = 0; i < reader->file_count; ++i) {
		const WPK_INTERNAL_ENTRY *a = &reader->entries[i];

		for (uint32_t j = i + 1; j < reader->file_count; ++j) {
			const WPK_INTERNAL_ENTRY *b = &reader->entries[j];

			if (a->compressed_size == 0 || b->compressed_size == 0) continue;

			if (a->data_offset < b->data_offset + b->compressed_size &&
				b->data_offset < a->data_offset + a->compressed_size)
				return 0;
		}
	}

	return 1;
}

int wpk_reader_open(const char *archive_path,wpk_reader_t **reader) {
	wpk_reader_t *r;

	if (!archive_path || !reader) return 0;

	*reader = NULL;

	r = calloc(1, sizeof(*r));
	if (!r) return 0;

	r->path = archive_path;

	/* Strictly read-only. */
	r->file = fopen(archive_path, "rb");

	if (!r->file) goto fail;

	if (!get_file_size(r->file, &r->archive_size)) goto fail;

	if (r->archive_size < WPK_HEADER_SIZE) goto fail;

	if (!read_header(r)) goto fail;

	if (!read_entries(r)) goto fail;

	*reader = r;

	return 1;

fail:
	wpk_reader_close(r);
	return 0;
}

int wpk_reader_open_password(
	const char *archive_path,
	const char *password,
	wpk_reader_t **reader)
{
	wpk_reader_t *r = NULL;
	const mbedtls_md_info_t *md_info;
	size_t password_len;
	int status;
	int result = 0;

	if (!archive_path || !reader)
		return 0;

	*reader = NULL;

	/* Open and validate the archive first. */
	if (!wpk_reader_open(archive_path, &r))
		return 0;

	/* Unencrypted archives do not require a password. */
	if (!(r->flags & WPK_FLAG_ENCRYPTED)) {
		*reader = r;
		return 1;
	}

	if (!password)
		goto cleanup;

	password_len = strlen(password);

	/* Get SHA-256 digest information. */
	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	if (!md_info)
		goto cleanup;

	/* Derive the 256-bit AES key using PBKDF2-HMAC-SHA256. */
	status = mbedtls_pkcs5_pbkdf2_hmac_ext(
		MBEDTLS_MD_SHA256,
		(const unsigned char *)password,
		password_len,
		r->salt,
		WPK_SALT_SIZE,
		r->pbkdf2_iterations,
		WPK_KEY_SIZE,
		r->key
	);

	if (status != 0)
		goto cleanup;

	r->has_key = 1;

	*reader = r;
	r = NULL;

	result = 1;

cleanup:

	if (r) {
		memset(r->key, 0, sizeof(r->key));
		wpk_reader_close(r);
	}

	return result;
}

#include <stdlib.h>
#include <string.h>
#include <limits.h>

static uint16_t wpk_read_u16(const uint8_t *p)
{
	return (uint16_t)p[0] |
		   ((uint16_t)p[1] << 8);
}

static uint32_t wpk_read_u32(const uint8_t *p)
{
	return (uint32_t)p[0] |
		   ((uint32_t)p[1] << 8) |
		   ((uint32_t)p[2] << 16) |
		   ((uint32_t)p[3] << 24);
}

static uint64_t wpk_read_u64(const uint8_t *p)
{
	return (uint64_t)wpk_read_u32(p) |
		   ((uint64_t)wpk_read_u32(p + 4) << 32);
}

static int wpk_mem_range_valid(
	size_t size,
	uint64_t offset,
	uint64_t length
) {
	return offset <= size && length <= size - (size_t)offset;
}

static int wpk_reader_parse_mem(
	const uint8_t *wpk,
	size_t size,
	wpk_reader_t **reader
) {
	wpk_reader_t *r = NULL;

	const uint8_t *header;
	size_t offset;

	if (!wpk || !reader)
		return 0;

	*reader = NULL;

	if (size < WPK_HEADER_SIZE)
		return 0;

	header = wpk;

	/*
	 * IMPORTANT:
	 * Replace these offsets with the actual offsets
	 * used by your WPK writer.
	 */

	/* Validate archive magic. */
	if (memcmp(header,WPK_MAGIC,WPK_MAGIC_SIZE) != 0)
		return 0;

	r = (wpk_reader_t *)calloc(1, sizeof(*r));

	if (!r)
		return 0;

	/* Memory-backed reader. */
	r->memory = wpk;
	r->memory_size = size;
	r->memory_backed = 1;

	/*
	 * Header layout assumed:
	 *
	 * 0  - magic
	 * 4  - version
	 * 8  - flags
	 * 12 - file_count
	 * 16 - pbkdf2_iterations
	 * 20 - table_offset (8 bytes)
	 * 28 - archive_size (8 bytes)
	 * 36 - salt (16 bytes)
	 * 52 - UUID (12 bytes)
	 */

	r->version = wpk_read_u32(header + 4);
	r->flags = wpk_read_u32(header + 8);
	r->file_count = wpk_read_u32(header + 12);
	r->pbkdf2_iterations = wpk_read_u32(header + 16);
	r->table_offset = wpk_read_u64(header + 20);
	r->archive_size = wpk_read_u64(header + 28);

	memcpy(r->salt, header + 36, WPK_SALT_SIZE);

	/* Validate archive metadata. */
	if (r->archive_size != size)
		goto cleanup;

	if (r->file_count > WPK_MAX_FILES)
		goto cleanup;

	if (r->table_offset > size)
		goto cleanup;

	if (r->table_offset < WPK_HEADER_SIZE)
		goto cleanup;

	if (r->file_count) {
		r->entries = (WPK_INTERNAL_ENTRY *)calloc(
			r->file_count,
			sizeof(WPK_INTERNAL_ENTRY)
		);

		if (!r->entries)
			goto cleanup;
	}

	offset = (size_t)r->table_offset;

	for (uint32_t i = 0; i < r->file_count; ++i) {
		WPK_INTERNAL_ENTRY *entry = &r->entries[i];
		const uint8_t *fixed;

		if (!wpk_mem_range_valid(
				size,
				offset,
				WPK_ENTRY_FIXED_SIZE))
			goto cleanup;

		fixed = wpk + offset;

		/*
		 * ASSUMED entry layout:
		 *
		 * 0  - path_len (2)
		 * 2  - flags (2)
		 * 4  - original_size (8)
		 * 12 - compressed_size (8)
		 * 20 - data_offset (8)
		 * 28 - timestamp (8)
		 * 36 - nonce (12)
		 * 48 - tag (16)
		 */

		entry->path_len = wpk_read_u16(fixed);
		entry->flags = wpk_read_u16(fixed + 2);
		entry->original_size = wpk_read_u64(fixed + 4);
		entry->compressed_size = wpk_read_u64(fixed + 12);
		entry->data_offset = wpk_read_u64(fixed + 20);
		entry->timestamp = wpk_read_u64(fixed + 28);

		memcpy(entry->nonce, fixed + 36, WPK_NONCE_SIZE);
		memcpy(entry->tag, fixed + 48, WPK_TAG_SIZE);

		offset += WPK_ENTRY_FIXED_SIZE;

		if (!entry->path_len ||
			entry->path_len > WPK_MAX_PATH)
			goto cleanup;

		if (!wpk_mem_range_valid(
				size,
				offset,
				entry->path_len))
			goto cleanup;

		entry->path = (char *)malloc(
			(size_t)entry->path_len + 1
		);

		if (!entry->path)
			goto cleanup;

		memcpy(entry->path, wpk + offset, entry->path_len);
		entry->path[entry->path_len] = '\0';

		/* Reject embedded NUL bytes in filenames. */
		if (strlen(entry->path) != entry->path_len)
			goto cleanup;

		offset += entry->path_len;

		/* Validate entry data range. */
		if (!wpk_mem_range_valid(
				size,
				entry->data_offset,
				entry->compressed_size))
			goto cleanup;
	}

	*reader = r;
	return 1;

cleanup:

	if (r) {
		if (r->entries) {
			for (uint32_t i = 0; i < r->file_count; ++i)
				free(r->entries[i].path);

			free(r->entries);
		}

		secure_zero(r->key, sizeof(r->key));
		free(r);
	}

	return 0;
}

int wpk_reader_open_mem(
	const void *wpk,
	size_t size,
	wpk_reader_t **reader
) {
	if (!wpk || !size || !reader)
		return 0;

	*reader = NULL;

	return wpk_reader_parse_mem(
		(const uint8_t *)wpk,
		size,
		reader
	);
}

int wpk_reader_open_password_mem(
	const void *wpk,
	size_t size,
	const char *password,
	wpk_reader_t **reader
) {
	wpk_reader_t *r = NULL;
	int status;

	if (!wpk || !size || !reader)
		return 0;

	*reader = NULL;

	/* Open and validate the memory archive. */
	if (!wpk_reader_open_mem(wpk, size, &r))
		return 0;

	if (!r)
		return 0;

	/* Unencrypted archives do not require a password. */
	if (!(r->flags & WPK_FLAG_ENCRYPTED)) {
		*reader = r;
		return 1;
	}

	if (!password)
		goto cleanup;

	/* Derive AES-256 key using PBKDF2-HMAC-SHA256. */
	status = mbedtls_pkcs5_pbkdf2_hmac_ext(
		MBEDTLS_MD_SHA256,
		(const unsigned char *)password,
		strlen(password),
		r->salt,
		WPK_SALT_SIZE,
		r->pbkdf2_iterations,
		WPK_KEY_SIZE,
		r->key
	);

	if (status != 0)
		goto cleanup;

	r->has_key = 1;

	*reader = r;
	return 1;

cleanup:

	secure_zero(r->key, sizeof(r->key));
	wpk_reader_close(r);

	return 0;
}

void wpk_reader_close(wpk_reader_t *reader) {
	if (!reader) return;
	if (reader->file) fclose(reader->file);
	free_entries(reader->entries, reader->file_count);
	free(reader);
}

int wpk_reader_get_uuid(const wpk_reader_t *reader,wpk_uuid_t uuid) {
	if (!reader || !uuid) return 0;
	memcpy(uuid, reader->uuid, WPK_UUID_SIZE);
	return 1;
}

int wpk_reader_equal_uuid(const wpk_reader_t *reader, wpk_uuid_t uuid) {
	if (!reader || !uuid) return 0;
	return memcmp(reader->uuid, uuid, WPK_UUID_SIZE) == 0;
}

uint32_t wpk_reader_get_file_count(const wpk_reader_t *reader) {
	if (!reader) return 0;
	return reader->file_count;
}

int wpk_reader_get_file_path(
	const wpk_reader_t *reader,
	uint32_t index,
	char *buffer,
	size_t buffer_size
) {
	const WPK_INTERNAL_ENTRY *e;

	if (!reader || !buffer) return 0;

	if (index >= reader->file_count) return 0;

	e = &reader->entries[index];

	if (buffer_size <= e->path_len) return 0;

	memcpy(buffer, e->path, e->path_len);

	buffer[e->path_len] = '\0';

	return 1;
}

uint32_t wpk_reader_get_locate_file(const wpk_reader_t *reader,const char *filename) {
	if (!reader || !filename || !filename[0]) return UINT32_MAX;
	for (uint32_t i = 0; i < reader->file_count; ++i) {
		if (strcmp(reader->entries[i].path, filename) == 0) return i;
	}
	return UINT32_MAX;
}

uint32_t wpk_reader_get_num_files(const wpk_reader_t *reader) {
	if (!reader) return UINT32_MAX;
	return reader->file_count;
}

bool wpk_reader_file_stat(
	const wpk_reader_t *reader,
	uint32_t file_index,
	wpk_stat *stat
) {
	mz_zip_archive g_zip = {0};

	if (!reader || !stat)
		return false;

	if (file_index >= reader->file_count)
		return false;

	if (!wpk_reader_init_file(
		&g_zip,
		reader->path,
		0
	)) {
		return false;
	}

	bool success = mz_zip_reader_file_stat(
		&g_zip,
		file_index,
		(mz_zip_archive_file_stat *)stat
	);

	wpk_reader_end(&g_zip);

	return success;
}

int wpk_reader_get_entry_info(
	const wpk_reader_t *reader,
	uint32_t index,
	wpk_entry_info_t *info
) {
	if (!reader || !info || index >= reader->file_count || !reader->entries)
		return 0;
	info->original_size = reader->entries[index].original_size;
	info->compressed_size = reader->entries[index].compressed_size;
	info->timestamp = reader->entries[index].timestamp;
	info->encrypted = (reader->entries[index].flags & WPK_FLAG_ENCRYPTED) != 0;
	return 1;
}

int wpk_reader_is_encrypted(const wpk_reader_t *reader) {
	return reader && (reader->flags & WPK_FLAG_ENCRYPTED) != 0;
}
