
/*
 * WPK100 extraction implementation.
 *
 * Dependencies:
 *   - wpk_reader.c
 *   - wpk_crypto.c
 *   - wpk_uuid.c
 *   - miniz/miniz.h
 *
 * Uses PSA Crypto for:
 *   - PBKDF2-HMAC-SHA256
 *   - AES-256-GCM
 *
 * Uses miniz for DEFLATE decompression.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

#include <sys/stat.h>
#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
#include <direct.h>

#define WPK_MKDIR(path) _mkdir(path)
#define WPK_CLOSE(fd) _close(fd)
#define WPK_FDOPEN(fd, mode) _fdopen((fd), (mode))
#define WPK_OPEN(path, flags, mode) \
_open((path), (flags) | _O_BINARY, (mode))

#else
#include <unistd.h>
#include <sys/types.h>

#define WPK_MKDIR(path) mkdir((path), 0700)
#define WPK_CLOSE(fd) close(fd)
#define WPK_FDOPEN(fd, mode) fdopen((fd), (mode))
#define WPK_OPEN(path, flags, mode) open((path), (flags), (mode))

#endif

#include "miniz/miniz.h"

#include "wpk_extract.h"
#include "wpk_internal.h"
#include "wpk_reader.h"

/*
 * Extraction memory limit.
 *
 * The archive format allows larger files, but this implementation
 * loads compressed and decompressed data into memory.
 *
 * Override this definition at compile time if required.
 */
#define WPK_STREAM_CHUNK 65536u

#ifndef WPK_BUFFER_MAX_FILE_SIZE
#define WPK_BUFFER_MAX_FILE_SIZE (1024ULL * 1024ULL * 1024ULL)
#endif

#ifndef WPK_MAX_EXTRACT_FILE_SIZE
#define WPK_MAX_EXTRACT_FILE_SIZE WPK_BUFFER_MAX_FILE_SIZE
#endif

#define WPK_MIN_PBKDF2_ITERATIONS 100000u
#define WPK_MAX_PBKDF2_ITERATIONS 10000000u

/* --------------------------------------------------------- */
/* File positioning										   */
/* --------------------------------------------------------- */

static int seek_file(FILE *file, uint64_t offset)
{
	if (!file || offset > (uint64_t)INT64_MAX)
		return 0;

	#ifdef _WIN32
	return _fseeki64(file, (__int64)offset, SEEK_SET) == 0;
	#else
	return fseeko(file, (off_t)offset, SEEK_SET) == 0;
	#endif
}

/* --------------------------------------------------------- */
/* Read exact number of bytes								 */
/* --------------------------------------------------------- */

static int read_exact(FILE *file, void *buffer, size_t size)
{
	if (!file || (!buffer && size != 0))
		return 0;

	if (size == 0)
		return 1;

	return fread(buffer, 1, size, file) == size;
}

/* --------------------------------------------------------- */
/* Windows reserved filename check							*/
/* --------------------------------------------------------- */

static int is_reserved_windows_name(
	const char *component,
	size_t length)
{
	char base[16];
	size_t base_len = 0;

	/*
	 * Windows treats names such as CON.txt and AUX.log
	 * as reserved device names.
	 */
	while (base_len < length &&
		component[base_len] != '.')
	{
		if (base_len >= sizeof(base) - 1)
			return 0;

		base[base_len] =
		(char)toupper((unsigned char)component[base_len]);

		++base_len;
	}

	while (base_len > 0 &&
		(base[base_len - 1] == ' ' ||
		base[base_len - 1] == '.'))
	{
		--base_len;
	}

	base[base_len] = '\0';

	if (strcmp(base, "CON") == 0 ||
		strcmp(base, "PRN") == 0 ||
		strcmp(base, "AUX") == 0 ||
		strcmp(base, "NUL") == 0)
	{
		return 1;
	}

	if (base_len == 4 &&
		(memcmp(base, "COM", 3) == 0 ||
		memcmp(base, "LPT", 3) == 0) &&
		base[3] >= '1' &&
		base[3] <= '9')
	{
		return 1;
	}

	return 0;
}

/* --------------------------------------------------------- */
/* Validate archive-relative paths							*/
/* --------------------------------------------------------- */

static int valid_archive_path(
	const char *path,
	size_t length)
{
	size_t i = 0;

	if (!path || length == 0 ||
		length > WPK_MAX_PATH)
	{
		return 0;
	}

	/* Reject absolute paths. */
	if (path[0] == '/' || path[0] == '\\')
		return 0;

	/* Reject drive paths. */
	if (length >= 2 &&
		((path[0] >= 'A' && path[0] <= 'Z') ||
		(path[0] >= 'a' && path[0] <= 'z')) &&
		path[1] == ':')
	{
		return 0;
	}

	/* Reject paths ending in a separator. */
	if (path[length - 1] == '/' ||
		path[length - 1] == '\\')
	{
		return 0;
	}

	while (i < length)
	{
		size_t start = i;

		while (i < length &&
			path[i] != '/' &&
			path[i] != '\\')
		{
			unsigned char c = (unsigned char)path[i];

			/* Reject control characters and DEL. */
			if (c < 32 || c == 127)
				return 0;

			/*
			 * Reject characters invalid or dangerous
			 * in common Windows filenames.
			 */
			if (c == ':' || c == '*' || c == '?' ||
				c == '"' || c == '<' || c == '>' ||
				c == '|')
			{
				return 0;
			}

			++i;
		}

		size_t component_len = i - start;

		if (component_len == 0)
			return 0;

		/* Reject "." and "..". */
		if (component_len == 1 &&
			path[start] == '.')
		{
			return 0;
		}

		if (component_len == 2 &&
			path[start] == '.' &&
			path[start + 1] == '.')
		{
			return 0;
		}

		/* Reject Windows trailing spaces and dots. */
		if (path[start + component_len - 1] == ' ' ||
			path[start + component_len - 1] == '.')
		{
			return 0;
		}

		if (is_reserved_windows_name(
			path + start,
			component_len))
		{
			return 0;
		}

		if (i < length)
			++i;
	}

	return 1;
}

/* --------------------------------------------------------- */
/* Directory validation									   */
/* --------------------------------------------------------- */

static int directory_exists(const char *path)
{
	#ifdef _WIN32
	struct _stat st;

	if (_stat(path, &st) != 0)
		return 0;

	return (st.st_mode & _S_IFDIR) != 0;

	#else
	struct stat st;

	/*
	 * lstat rejects symbolic links to directories.
	 * This is safer than stat for extraction paths.
	 */
	if (lstat(path, &st) != 0)
		return 0;

	return S_ISDIR(st.st_mode);
	#endif
}

/* --------------------------------------------------------- */
/* Create directories recursively							 */
/* --------------------------------------------------------- */

static int make_directories(const char *path)
{
	char *copy;
	size_t len;

	if (!path || !*path)
		return 0;

	len = strlen(path);

	if (len > SIZE_MAX - 1)
		return 0;

	copy = (char *)malloc(len + 1);

	if (!copy)
		return 0;

	memcpy(copy, path, len + 1);

	for (size_t i = 1; i <= len; ++i)
	{
		if (copy[i] == '/' ||
			copy[i] == '\\' ||
			copy[i] == '\0')
		{
			char saved = copy[i];

			copy[i] = '\0';

			if (*copy)
			{
				#ifdef _WIN32
				/*
				 * Do not attempt to create "C:".
				 * It is a drive prefix, not a directory.
				 */
				if (!(i == 2 && copy[1] == ':'))
					#endif
				{
					if (WPK_MKDIR(copy) != 0)
					{
						if (errno != EEXIST ||
							!directory_exists(copy))
						{
							free(copy);
							return 0;
						}
					}
					else if (!directory_exists(copy))
					{
						free(copy);
						return 0;
					}
				}
			}

			copy[i] = saved;
		}
	}

	free(copy);
	return 1;
}

/* --------------------------------------------------------- */
/* Construct output filename								  */
/* --------------------------------------------------------- */

static char *make_output_path(
	const char *outdir,
	const char *archive_path,
	size_t archive_path_len)
{
	size_t root_len;
	size_t total;
	size_t offset;
	char *result;

	if (!outdir || !*outdir ||
		!valid_archive_path(
			archive_path,
			archive_path_len))
	{
		return NULL;
	}

	root_len = strlen(outdir);

	if (root_len > SIZE_MAX - archive_path_len - 2)
		return NULL;

	total = root_len + archive_path_len + 2;

	result = (char *)malloc(total);

	if (!result)
		return NULL;

	memcpy(result, outdir, root_len);

	offset = root_len;

	if (outdir[root_len - 1] != '/' &&
		outdir[root_len - 1] != '\\')
	{
		result[offset++] = '/';
	}

	memcpy(
		result + offset,
		archive_path,
		archive_path_len
	);

	result[offset + archive_path_len] = '\0';

	return result;
}

/* --------------------------------------------------------- */
/* Create parent directories for an output file			   */
/* --------------------------------------------------------- */

static int make_parent_directories(const char *file_path)
{
	char *copy;
	size_t len;

	if (!file_path)
		return 0;

	len = strlen(file_path);

	copy = (char *)malloc(len + 1);

	if (!copy)
		return 0;

	memcpy(copy, file_path, len + 1);

	for (size_t i = len; i > 0; --i)
	{
		if (copy[i - 1] == '/' ||
			copy[i - 1] == '\\')
		{
			copy[i - 1] = '\0';

			if (*copy && !make_directories(copy))
			{
				free(copy);
				return 0;
			}

			free(copy);
			return 1;
		}
	}

	free(copy);
	return 1;
}

/* --------------------------------------------------------- */
/* Create a new output file without overwriting existing data */
/* --------------------------------------------------------- */

static FILE *create_output_file_exclusive(const char *path)
{
	int fd;
	FILE *file;

	if (!path)
		return NULL;

	#ifdef _WIN32
	fd = WPK_OPEN(
		path,
		_O_WRONLY | _O_CREAT | _O_EXCL,
		_S_IREAD | _S_IWRITE
	);
	#else
	fd = WPK_OPEN(
		path,
		O_WRONLY | O_CREAT | O_EXCL,
		0600
	);
	#endif

	if (fd < 0)
		return NULL;

	file = WPK_FDOPEN(fd, "wb");

	if (!file)
	{
		WPK_CLOSE(fd);
		remove(path);
		return NULL;
	}

	return file;
}

/* --------------------------------------------------------- */
/* Build AES-GCM additional authenticated data				*/
/* --------------------------------------------------------- */

static int make_aad(
	const wpk_uuid_t uuid,
	uint32_t index,
	const WPK_INTERNAL_ENTRY *entry,
	uint8_t **out,
	size_t *out_size)
{
	size_t size;
	size_t offset = 0;
	uint8_t *buffer;

	if (!uuid || !entry || !entry->path ||
		!out || !out_size)
	{
		return 0;
	}

	*out = NULL;
	*out_size = 0;

	if (entry->path_len == 0 ||
		entry->path_len > WPK_MAX_PATH)
	{
		return 0;
	}

	if (strlen(entry->path) != entry->path_len)
		return 0;

	size = 48u + (size_t)entry->path_len;

	buffer = (uint8_t *)malloc(size);

	if (!buffer)
		return 0;

	/* UUID: 16 bytes. */
	memcpy(buffer + offset, uuid, 16);
	offset += 16;

	/* Index: little-endian uint32. */
	for (unsigned i = 0; i < 4; ++i)
		buffer[offset++] = (uint8_t)(index >> (i * 8));

	/* Flags: little-endian uint16. */
	buffer[offset++] = (uint8_t)entry->flags;
	buffer[offset++] = (uint8_t)(entry->flags >> 8);

	/* Original size: little-endian uint64. */
	for (unsigned i = 0; i < 8; ++i)
		buffer[offset++] =
		(uint8_t)(entry->original_size >> (i * 8));

	/* Compressed size: little-endian uint64. */
	for (unsigned i = 0; i < 8; ++i)
		buffer[offset++] =
		(uint8_t)(entry->compressed_size >> (i * 8));

	/* Data offset: little-endian uint64. */
	for (unsigned i = 0; i < 8; ++i)
		buffer[offset++] =
		(uint8_t)(entry->data_offset >> (i * 8));

	/* Path length: little-endian uint16. */
	buffer[offset++] = (uint8_t)entry->path_len;
	buffer[offset++] = (uint8_t)(entry->path_len >> 8);

	/* Path bytes. */
	memcpy(
		buffer + offset,
		entry->path,
		entry->path_len
	);

	offset += entry->path_len;

	*out = buffer;
	*out_size = offset;

	return 1;
}

/* --------------------------------------------------------- */
/* Extract one entry										  */
/* --------------------------------------------------------- */

static int extract_entry(
	wpk_reader_t *reader,
	uint32_t index,
	const char *outdir,
	const uint8_t key[WPK_KEY_SIZE])
{
	WPK_INTERNAL_ENTRY *entry;

	uint8_t *compressed = NULL;
	uint8_t *plain_compressed = NULL;
	uint8_t *decompressed = NULL;
	uint8_t *aad = NULL;

	size_t aad_size = 0;

	char *output_path = NULL;
	FILE *output = NULL;

	int output_created = 0;
	int result = 0;

	if (!reader ||
		index >= reader->file_count ||
		!outdir)
	{
		return 0;
	}

	entry = &reader->entries[index];

	/* Check archive flags and entry flags. */
	if (reader->flags & ~WPK_FLAG_ENCRYPTED)
		goto cleanup;

	if (entry->flags & ~(uint16_t)WPK_FLAG_ENCRYPTED)
		goto cleanup;

	if ((uint32_t)entry->flags !=
		(reader->flags & WPK_FLAG_ENCRYPTED))
	{
		goto cleanup;
	}

	/* Validate archive boundaries. */
	if (reader->table_offset > reader->archive_size)
		goto cleanup;

	if (entry->data_offset < WPK_HEADER_SIZE)
		goto cleanup;

	if (entry->data_offset > reader->table_offset)
		goto cleanup;

	/*
	 * Subtraction-based check avoids integer overflow.
	 */
	if (entry->compressed_size >
		reader->table_offset - entry->data_offset)
	{
		goto cleanup;
	}

	/* Enforce memory limits before allocation. */
	if (entry->original_size > WPK_MAX_EXTRACT_FILE_SIZE ||
		entry->compressed_size > WPK_MAX_EXTRACT_FILE_SIZE)
	{
		goto cleanup;
	}

	if (entry->original_size > SIZE_MAX ||
		entry->compressed_size > SIZE_MAX)
	{
		goto cleanup;
	}

	if (entry->original_size > (uint64_t)((mz_ulong)-1) ||
		entry->compressed_size > (uint64_t)((mz_ulong)-1))
	{
		goto cleanup;
	}

	/* Validate path metadata. */
	if (!entry->path ||
		strlen(entry->path) != entry->path_len ||
		!valid_archive_path(entry->path, entry->path_len))
	{
		goto cleanup;
	}

	/*
	 * Read compressed payload.
	 */
	compressed = (uint8_t *)malloc(
		entry->compressed_size
		? (size_t)entry->compressed_size
		: 1
	);

	if (!compressed)
		goto cleanup;

	if (!seek_file(reader->file, entry->data_offset))
		goto cleanup;

	if (!read_exact(
		reader->file,
		compressed,
		(size_t)entry->compressed_size))
	{
		goto cleanup;
	}

	/*
	 * Decrypt if encrypted.
	 */
	if (entry->flags & WPK_FLAG_ENCRYPTED)
	{
		if (!key)
			goto cleanup;

		plain_compressed = (uint8_t *)malloc(
			entry->compressed_size
			? (size_t)entry->compressed_size
			: 1
		);

		if (!plain_compressed)
			goto cleanup;

		if (!make_aad(
			reader->uuid,
			index,
			entry,
			&aad,
			&aad_size))
		{
			goto cleanup;
		}

		/*
		 * Decrypted bytes are not used unless GCM
		 * authentication succeeds.
		 */
		if (!wpk_aes_gcm_decrypt(
			key,
			entry->nonce,
			aad,
			aad_size,
			compressed,
			(size_t)entry->compressed_size,
								 entry->tag,
								 plain_compressed))
		{
			goto cleanup;
		}
	}
	else
	{
		plain_compressed = compressed;
		compressed = NULL;
	}

	/*
	 * Decompress using miniz.
	 */
	decompressed = (uint8_t *)malloc(
		entry->original_size
		? (size_t)entry->original_size
		: 1
	);

	if (!decompressed)
		goto cleanup;

	{
		mz_ulong decompressed_size =
		entry->original_size
		? (mz_ulong)entry->original_size
		: 1;

		int mz_result = mz_uncompress(
			decompressed,
			&decompressed_size,
			plain_compressed,
			(mz_ulong)entry->compressed_size
		);

		if (mz_result != MZ_OK)
			goto cleanup;

		if (decompressed_size !=
			(mz_ulong)entry->original_size)
		{
			goto cleanup;
		}
	}

	/*
	 * Construct output path.
	 */
	output_path = make_output_path(
		outdir,
		entry->path,
		entry->path_len
	);

	if (!output_path)
		goto cleanup;

	if (!make_parent_directories(output_path))
		goto cleanup;

	/*
	 * Exclusive creation prevents overwriting existing files.
	 */
	output = create_output_file_exclusive(output_path);

	if (!output)
		goto cleanup;

	output_created = 1;

	if (entry->original_size != 0)
	{
		if (fwrite(
			decompressed,
			1,
			(size_t)entry->original_size,
				   output) != (size_t)entry->original_size)
		{
			goto cleanup;
		}
	}

	if (fflush(output) != 0)
		goto cleanup;

	if (fclose(output) != 0)
	{
		output = NULL;
		goto cleanup;
	}

	output = NULL;
	result = 1;

	cleanup:

	if (output)
	{
		fclose(output);
		output = NULL;
	}

	/*
	 * Remove incomplete output files.
	 * Do not remove a file after successful extraction.
	 */
	if (!result && output_created && output_path)
		remove(output_path);

	free(output_path);

	if (compressed)
	{
		secure_zero(
			compressed,
			(size_t)entry->compressed_size
		);

		free(compressed);
	}

	if (plain_compressed &&
		plain_compressed != compressed)
	{
		secure_zero(
			plain_compressed,
			(size_t)entry->compressed_size
		);

		free(plain_compressed);
	}

	if (decompressed)
	{
		secure_zero(
			decompressed,
			(size_t)entry->original_size
		);

		free(decompressed);
	}

	free(aad);

	return result;
}

static uint16_t read_u16_le(const uint8_t *p)
{
	return (uint16_t)p[0] |
	((uint16_t)p[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *p)
{
	return (uint32_t)p[0] |
	((uint32_t)p[1] << 8) |
	((uint32_t)p[2] << 16) |
	((uint32_t)p[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *p)
{
	return (uint64_t)read_u32_le(p) |
	((uint64_t)read_u32_le(p + 4) << 32);
}

static int buffer_range_valid(
	size_t total,
	uint64_t offset,
	uint64_t length)
{
	if (offset > (uint64_t)total)
		return 0;

	if (length > (uint64_t)total - offset)
		return 0;

	return 1;
}

static uint16_t buffer_u16(const uint8_t *p)
{
	return (uint16_t)p[0] |
	((uint16_t)p[1] << 8);
}

static uint32_t buffer_u32(const uint8_t *p)
{
	return (uint32_t)p[0] |
	((uint32_t)p[1] << 8) |
	((uint32_t)p[2] << 16) |
	((uint32_t)p[3] << 24);
}

static uint64_t buffer_u64(const uint8_t *p)
{
	return (uint64_t)buffer_u32(p) |
	((uint64_t)buffer_u32(p + 4) << 32);
}

static int buffer_bounds(
	size_t total,
	uint64_t offset,
	uint64_t length)
{
	return offset <= (uint64_t)total &&
	length <= (uint64_t)total - offset;
}

/* --------------------------------------------------------- */
/* Common extraction implementation						   */
/* --------------------------------------------------------- */

static int extract_common(
	const char *archive,
	const char *outdir,
	const wpk_uuid_t expected_uuid,
	bool useMatchUUID,
	const char *password,
	int allow_encrypted,
	int single_file,
	uint32_t index)
{
	wpk_reader_t *reader = NULL;

	uint8_t key[WPK_KEY_SIZE] = {0};
	const uint8_t *key_ptr = NULL;

	int result = 0;

	if (!archive ||
		!outdir ||
		!*outdir ||
		(!expected_uuid && useMatchUUID))
	{
		return 0;
	}

	/*
	 * Open and validate archive.
	 */
	if (!wpk_reader_open(archive, &reader))
		goto cleanup;

	/*
	 * Verify UUID before creating output directories.
	 */
	if (useMatchUUID && (!expected_uuid || memcmp(reader->uuid, expected_uuid, WPK_UUID_SIZE) != 0)) {
		goto cleanup;
	}

	/* Check archive flags. */
	if (reader->flags & ~WPK_FLAG_ENCRYPTED)
		goto cleanup;

	/* Check single-file index. */
	if (single_file && index >= reader->file_count)
		goto cleanup;

	/*
	 * Check encryption requirements.
	 */
	if (reader->flags & WPK_FLAG_ENCRYPTED)
	{
		if (!allow_encrypted ||
			!password ||
			!*password)
		{
			goto cleanup;
		}

		if (reader->pbkdf2_iterations <
			WPK_MIN_PBKDF2_ITERATIONS ||
			reader->pbkdf2_iterations >
			WPK_MAX_PBKDF2_ITERATIONS)
		{
			goto cleanup;
		}

		/*
		 * Initialize PSA before using its cryptographic APIs.
		 */
		if (!wpk_crypto_init())
			goto cleanup;

		if (!wpk_derive_key(
			password,
			reader->salt,
			reader->pbkdf2_iterations,
			key))
		{
			goto cleanup;
		}

		key_ptr = key;
	}
	else
	{
		/* Unencrypted archives must not specify PBKDF2. */
		if (reader->pbkdf2_iterations != 0)
			goto cleanup;
	}

	/*
	 * Create extraction root.
	 */
	if (!make_directories(outdir))
		goto cleanup;

	/*
	 * Extract one file or all files.
	 */
	if (single_file)
	{
		if (!extract_entry(
			reader,
			index,
			outdir,
			key_ptr))
		{
			goto cleanup;
		}
	}
	else
	{
		for (uint32_t i = 0; i < reader->file_count; ++i)
		{
			if (!extract_entry(
				reader,
				i,
				outdir,
				key_ptr))
			{
				goto cleanup;
			}
		}
	}

	result = 1;

	cleanup:

	secure_zero(key, sizeof(key));

	if (reader)
		wpk_reader_close(reader);

	return result;
}


static int extract_buffer_common(
	const void *in,
	size_t inlen,
	const char *outdir,
	const wpk_uuid_t expected_uuid,
	bool useMatchUUID,
	const char *password,
	int allow_encrypted,
	int single_file,
	uint32_t index)
{
	const uint8_t *archive = (const uint8_t *)in;

	WPK_INTERNAL_ENTRY *entries = NULL;

	uint8_t key[WPK_KEY_SIZE] = {0};
	const uint8_t *key_ptr = NULL;

	uint8_t salt[WPK_SALT_SIZE] = {0};
	wpk_uuid_t uuid;

	uint32_t version;
	uint32_t file_count;
	uint32_t iterations;
	uint32_t flags;

	uint64_t table_offset;
	uint64_t table_pos;
	uint64_t previous_data_end;

	uint8_t *decrypt_buffer = NULL;
	uint8_t *output_buffer = NULL;

	int result = 0;

	/*
	 * Validate arguments.
	 */
	if (!archive ||
		inlen < WPK_HEADER_SIZE ||
		!outdir ||
		!*outdir ||
		(useMatchUUID && !expected_uuid))
	{
		return 0;
	}

	/*
	 * Validate archive magic.
	 */
	if (memcmp(
			archive,
			WPK_MAGIC,
			WPK_MAGIC_SIZE) != 0)
	{
		goto cleanup;
	}

	/*
	 * Parse header.
	 *
	 * 0  - 5  : Magic
	 * 6  - 21 : UUID
	 * 22 - 25 : Version
	 * 26 - 29 : File count
	 * 30 - 37 : Table offset
	 * 38 - 53 : Salt
	 * 54 - 57 : PBKDF2 iterations
	 * 58 - 61 : Flags
	 * 62 - 63 : Reserved
	 */
	memcpy(uuid, archive + 6, WPK_UUID_SIZE);

	version = buffer_u32(archive + 22);
	file_count = buffer_u32(archive + 26);
	table_offset = buffer_u64(archive + 30);

	memcpy(salt, archive + 38, WPK_SALT_SIZE);

	iterations = buffer_u32(archive + 54);
	flags = buffer_u32(archive + 58);

	if (version != WPK_VERSION)
		goto cleanup;

	if (file_count > WPK_MAX_FILES)
		goto cleanup;

	if (flags & ~WPK_FLAG_ENCRYPTED)
		goto cleanup;

	if (archive[62] != 0 || archive[63] != 0)
		goto cleanup;

	/*
	 * Table must begin after the header and inside the archive.
	 */
	if (table_offset < WPK_HEADER_SIZE ||
		!buffer_bounds(inlen, table_offset, 0))
	{
		goto cleanup;
	}

	/*
	 * Validate UUID before creating directories.
	 */
	if (useMatchUUID &&
		memcmp(uuid, expected_uuid, WPK_UUID_SIZE) != 0)
	{
		goto cleanup;
	}

	/*
	 * Validate encryption settings and derive key.
	 */
	if (flags & WPK_FLAG_ENCRYPTED)
	{
		if (!allow_encrypted ||
			!password ||
			!*password)
		{
			goto cleanup;
		}

		if (iterations < WPK_MIN_PBKDF2_ITERATIONS ||
			iterations > WPK_MAX_PBKDF2_ITERATIONS)
		{
			goto cleanup;
		}

		if (!wpk_crypto_init())
			goto cleanup;

		if (!wpk_derive_key(
				password,
				salt,
				iterations,
				key))
		{
			goto cleanup;
		}

		key_ptr = key;
	}
	else
	{
		if (iterations != 0)
			goto cleanup;
	}

	/*
	 * Validate single-file index.
	 */
	if (single_file && index >= file_count)
		goto cleanup;

	/*
	 * Allocate entry metadata.
	 */
	if (file_count != 0)
	{
		if ((size_t)file_count > SIZE_MAX / sizeof(WPK_INTERNAL_ENTRY)) {
			goto cleanup;
		}
		entries = calloc(
			file_count,
			sizeof(WPK_INTERNAL_ENTRY));

		if (!entries)
			goto cleanup;
	}

	/*
	 * Parse and validate the complete table.
	 */
	table_pos = table_offset;
	previous_data_end = WPK_HEADER_SIZE;

	for (uint32_t i = 0; i < file_count; ++i)
	{
		WPK_INTERNAL_ENTRY *entry = &entries[i];

		uint16_t path_len;
		uint16_t entry_flags;

		uint64_t path_offset;
		uint64_t original_size;
		uint64_t compressed_size;
		uint64_t data_offset;

		const uint8_t *fixed;

		if (!buffer_bounds(
				inlen,
				table_pos,
				WPK_ENTRY_FIXED_SIZE))
		{
			goto cleanup;
		}

		fixed = archive + (size_t)table_pos;

		path_len = buffer_u16(fixed);
		entry_flags = buffer_u16(fixed + 2);

		original_size = buffer_u64(fixed + 4);
		compressed_size = buffer_u64(fixed + 12);
		data_offset = buffer_u64(fixed + 20);

		if (path_len == 0 ||
			path_len > WPK_MAX_PATH)
		{
			goto cleanup;
		}

		/*
		 * Entry encryption flags must match archive flags.
		 */
		if ((uint32_t)entry_flags != flags)
			goto cleanup;

		/*
		 * Enforce extraction limits.
		 */
		if (original_size > WPK_MAX_EXTRACT_FILE_SIZE ||
			compressed_size > WPK_MAX_EXTRACT_FILE_SIZE)
		{
			goto cleanup;
		}

		if (original_size > SIZE_MAX ||
			compressed_size > SIZE_MAX)
		{
			goto cleanup;
		}

		/*
		 * A valid DEFLATE stream cannot have an empty
		 * compressed representation.
		 */
		if (compressed_size == 0)
			goto cleanup;

		/*
		 * Validate path position.
		 */
		path_offset = table_pos + WPK_ENTRY_FIXED_SIZE;

		if (!buffer_bounds(
				inlen,
				path_offset,
				path_len))
		{
			goto cleanup;
		}

		/*
		 * Validate payload bounds.
		 *
		 * All payloads must end before the table.
		 */
		if (data_offset < WPK_HEADER_SIZE ||
			data_offset > table_offset ||
			compressed_size > table_offset - data_offset)
		{
			goto cleanup;
		}

		/*
		 * Reject overlapping or out-of-order payloads.
		 */
		if (data_offset < previous_data_end)
			goto cleanup;

		previous_data_end = data_offset + compressed_size;

		/*
		 * Copy path and append NUL.
		 */
		if (memchr(
				archive + (size_t)path_offset,
				'\0',
				path_len) != NULL)
		{
			goto cleanup;
		}

		entry->path = malloc((size_t)path_len + 1);

		if (!entry->path)
			goto cleanup;

		memcpy(
			entry->path,
			archive + (size_t)path_offset,
			path_len);

		entry->path[path_len] = '\0';

		entry->path_len = path_len;
		entry->flags = entry_flags;

		entry->original_size = original_size;
		entry->compressed_size = compressed_size;
		entry->data_offset = data_offset;

		memcpy(entry->nonce, fixed + 28, WPK_NONCE_SIZE);
		memcpy(entry->tag, fixed + 40, WPK_TAG_SIZE);

		/*
		 * Validate archive-relative path.
		 */
		if (strlen(entry->path) != path_len ||
			!valid_archive_path(
				entry->path,
				entry->path_len))
		{
			goto cleanup;
		}

		/*
		 * Reject duplicate paths.
		 */
		for (uint32_t j = 0; j < i; ++j)
		{
			if (strcmp(
					entries[j].path,
					entry->path) == 0)
			{
				goto cleanup;
			}
		}

		/*
		 * Advance to next table entry.
		 */
		table_pos = path_offset + path_len;
	}

	/*
	 * Require the table to consume the rest of the archive.
	 */
	if (table_pos != (uint64_t)inlen)
		goto cleanup;

	/*
	 * Allocate bounded working buffers.
	 *
	 * The archive itself is never copied.
	 */
	output_buffer = malloc(WPK_STREAM_CHUNK);

	if (!output_buffer)
		goto cleanup;

	if (flags & WPK_FLAG_ENCRYPTED)
	{
		/*
		 * Extra capacity accommodates PSA AEAD update output.
		 */
		if (WPK_STREAM_CHUNK > SIZE_MAX - 16)
			goto cleanup;

		decrypt_buffer = malloc(WPK_STREAM_CHUNK + 16);

		if (!decrypt_buffer)
			goto cleanup;
	}

	/*
	 * Create extraction root only after archive validation.
	 */
	if (!make_directories(outdir))
		goto cleanup;

	/*
	 * Determine selected entries.
	 */
	{
		uint32_t first = single_file ? index : 0;
		uint32_t last = single_file ? index + 1 : file_count;

		for (uint32_t i = first; i < last; ++i)
		{
			WPK_INTERNAL_ENTRY *entry = &entries[i];

			char *output_path = NULL;

			FILE *temporary = NULL;
			FILE *output = NULL;

			mz_stream stream;

			WPK_GCM_DECRYPT_CTX crypto_ctx;

			uint8_t *aad = NULL;
			size_t aad_size = 0;

			uint64_t input_offset = 0;
			uint64_t total_output = 0;

			int stream_initialized = 0;
			int stream_finished = 0;
			int crypto_started = 0;
			int output_created = 0;
			int entry_success = 0;

			memset(&stream, 0, sizeof(stream));
			memset(&crypto_ctx, 0, sizeof(crypto_ctx));

			/*
			 * Construct output path.
			 */
			output_path = make_output_path(
				outdir,
				entry->path,
				entry->path_len);

			if (!output_path)
				goto entry_cleanup;

			/*
			 * Initialize streaming inflater.
			 */
			if (mz_inflateInit(&stream) != MZ_OK)
				goto entry_cleanup;

			stream_initialized = 1;

			/*
			 * Start multipart GCM decryption.
			 */
			if (flags & WPK_FLAG_ENCRYPTED)
			{
				if (!make_aad(
						uuid,
						i,
						entry,
						&aad,
						&aad_size))
				{
					goto entry_cleanup;
				}

				if (!wpk_aes_gcm_decrypt_start(
						&crypto_ctx,
						key_ptr,
						entry->nonce,
						aad,
						aad_size))
				{
					goto entry_cleanup;
				}

				crypto_started = 1;
			}

			/*
			 * Create an anonymous temporary file.
			 *
			 * No final output file is created until the
			 * complete DEFLATE stream and GCM tag are valid.
			 */
			temporary = tmpfile();

			if (!temporary)
				goto entry_cleanup;

			/*
			 * Stream compressed input.
			 */
			while (input_offset < entry->compressed_size)
			{
				size_t chunk_size =
					(entry->compressed_size - input_offset >
					 WPK_STREAM_CHUNK)
					? WPK_STREAM_CHUNK
					: (size_t)(
						entry->compressed_size - input_offset);

				const uint8_t *source =
					archive + (size_t)(
						entry->data_offset + input_offset);

				const uint8_t *compressed_data = source;
				size_t compressed_size = chunk_size;

				/*
				 * Decrypt this chunk if necessary.
				 */
				if (crypto_started)
				{
					if (!wpk_aes_gcm_decrypt_update(
							&crypto_ctx,
							source,
							chunk_size,
							decrypt_buffer,
							WPK_STREAM_CHUNK + 16,
							&compressed_size))
					{
						goto entry_cleanup;
					}

					if (compressed_size > WPK_STREAM_CHUNK + 16)
						goto entry_cleanup;

					compressed_data = decrypt_buffer;
				}

				/*
				 * Feed this chunk to miniz.
				 */
				stream.next_in =
					(const unsigned char *)compressed_data;

				stream.avail_in = (mz_uint)compressed_size;

				for (;;)
				{
					mz_uint previous_avail_in = stream.avail_in;

					size_t produced;

					stream.next_out = output_buffer;
					stream.avail_out = WPK_STREAM_CHUNK;

					int inflate_result = mz_inflate(
						&stream,
						MZ_NO_FLUSH);

					produced =
						WPK_STREAM_CHUNK - stream.avail_out;

					/*
					 * Enforce declared output size.
					 */
					if (produced != 0)
					{
						if (total_output > entry->original_size ||
							produced >
							entry->original_size - total_output)
						{
							goto entry_cleanup;
						}

						if (fwrite(
								output_buffer,
								1,
								produced,
								temporary) != produced)
						{
							goto entry_cleanup;
						}

						total_output += produced;
					}

					/*
					 * DEFLATE stream ended.
					 */
					if (inflate_result == MZ_STREAM_END)
					{
						stream_finished = 1;

						/*
						 * No unused input or trailing payload is allowed.
						 */
						if (stream.avail_in != 0 ||
							input_offset + chunk_size !=
							entry->compressed_size)
						{
							goto entry_cleanup;
						}

						break;
					}

					if (inflate_result != MZ_OK)
						goto entry_cleanup;

					/*
					 * Detect an inflater that makes no progress.
					 */
					if (previous_avail_in == stream.avail_in &&
						produced == 0)
					{
						goto entry_cleanup;
					}

					/*
					 * Continue draining output even when all
					 * input bytes have already been consumed.
					 */
					if (stream.avail_in == 0 &&
						produced < WPK_STREAM_CHUNK)
					{
						break;
					}
				}

				input_offset += chunk_size;

				if (stream_finished)
					break;

				secure_zero(output_buffer, WPK_STREAM_CHUNK);

				if (decrypt_buffer)
					secure_zero(
						decrypt_buffer,
						WPK_STREAM_CHUNK + 16);
			}

			/*
			 * Finish the DEFLATE stream.
			 */
			if (!stream_finished)
			{
				for (;;)
				{
					size_t produced;

					stream.next_in = NULL;
					stream.avail_in = 0;

					stream.next_out = output_buffer;
					stream.avail_out = WPK_STREAM_CHUNK;

					int inflate_result = mz_inflate(
						&stream,
						MZ_FINISH);

					produced =
						WPK_STREAM_CHUNK - stream.avail_out;

					if (produced != 0)
					{
						if (total_output > entry->original_size ||
							produced >
							entry->original_size - total_output)
						{
							goto entry_cleanup;
						}

						if (fwrite(
								output_buffer,
								1,
								produced,
								temporary) != produced)
						{
							goto entry_cleanup;
						}

						total_output += produced;
					}

					if (inflate_result == MZ_STREAM_END)
					{
						stream_finished = 1;
						break;
					}

					if (inflate_result != MZ_OK ||
						produced == 0)
					{
						goto entry_cleanup;
					}
				}
			}

			/*
			 * Verify decompressed size.
			 */
			if (!stream_finished ||
				input_offset != entry->compressed_size ||
				total_output != entry->original_size)
			{
				goto entry_cleanup;
			}

			/*
			 * Authenticate encrypted data.
			 *
			 * No final output file exists yet.
			 */
			if (crypto_started)
			{
				if (!wpk_aes_gcm_decrypt_finish(
						&crypto_ctx,
						entry->tag))
				{
					crypto_started = 0;
					goto entry_cleanup;
				}

				crypto_started = 0;
			}

			/*
			 * Decompression and authentication succeeded.
			 * Prepare to publish the temporary file.
			 */
			if (fflush(temporary) != 0 ||
				fseek(temporary, 0, SEEK_SET) != 0)
			{
				goto entry_cleanup;
			}

			/*
			 * Create parent directories.
			 */
			if (!make_parent_directories(output_path))
				goto entry_cleanup;

			/*
			 * Create final file exclusively.
			 */
			output = create_output_file_exclusive(output_path);

			if (!output)
				goto entry_cleanup;

			output_created = 1;

			/*
			 * Copy authenticated temporary contents to final file.
			 */
			for (;;)
			{
				size_t bytes_read = fread(
					output_buffer,
					1,
					WPK_STREAM_CHUNK,
					temporary);

				if (bytes_read != 0)
				{
					if (fwrite(
							output_buffer,
							1,
							bytes_read,
							output) != bytes_read)
					{
						goto entry_cleanup;
					}
				}

				if (bytes_read < WPK_STREAM_CHUNK)
				{
					if (ferror(temporary))
						goto entry_cleanup;

					break;
				}
			}

			if (fflush(output) != 0)
				goto entry_cleanup;

			if (fclose(output) != 0)
			{
				output = NULL;
				goto entry_cleanup;
			}

			output = NULL;
			output_created = 0;

			entry_success = 1;

entry_cleanup:

			if (crypto_started)
				wpk_aes_gcm_decrypt_abort(&crypto_ctx);

			if (stream_initialized)
				mz_inflateEnd(&stream);

			if (output)
			{
				fclose(output);
				output = NULL;
			}

			/*
			 * Remove incomplete final file.
			 */
			if (!entry_success &&
				output_created &&
				output_path)
			{
				remove(output_path);
			}

			if (temporary)
			{
				fclose(temporary);
				temporary = NULL;
			}

			if (aad)
			{
				secure_zero(aad, aad_size);
				free(aad);
			}

			if (output_path)
				free(output_path);

			secure_zero(
				&crypto_ctx,
				sizeof(crypto_ctx));

			secure_zero(
				output_buffer,
				WPK_STREAM_CHUNK);

			if (decrypt_buffer)
			{
				secure_zero(
					decrypt_buffer,
					WPK_STREAM_CHUNK + 16);
			}

			if (!entry_success)
				goto cleanup;
		}
	}

	result = 1;

cleanup:

	if (output_buffer)
	{
		secure_zero(output_buffer, WPK_STREAM_CHUNK);
		free(output_buffer);
	}

	if (decrypt_buffer)
	{
		secure_zero(
			decrypt_buffer,
			WPK_STREAM_CHUNK + 16);

		free(decrypt_buffer);
	}

	if (entries)
	{
		for (uint32_t i = 0; i < file_count; ++i)
		{
			if (entries[i].path)
			{
				secure_zero(
					entries[i].path,
					strlen(entries[i].path));

				free(entries[i].path);
			}
		}

		free(entries);
	}

	secure_zero(key, sizeof(key));
	secure_zero(salt, sizeof(salt));

	return result;
}

/* --------------------------------------------------------- */
/* Public API												  */
/* --------------------------------------------------------- */

int wpk_extract_uuid(
	const char *archive,
	const char *outdir,
	const wpk_uuid_t expected_uuid)
{
	return extract_common(
		archive,
		outdir,
		expected_uuid,
		true,
		NULL,
		0,
		0,
		0
	);
}

int wpk_extract(const char *archive,const char *outdir) {
	return extract_common(
		archive,
		outdir,
		NULL,
		false,
		NULL,
		0,
		0,
		0
	);
}

int wpk_extract_password(
	const char *archive,
	const char *outdir,
	const char *password)
{
	return extract_common(
		archive,
		outdir,
		NULL,
		false,
		password,
		1,
		0,
		0
	);
}

int wpk_extract_password_uuid(
	const char *archive,
	const char *outdir,
	const wpk_uuid_t expected_uuid,
	const char *password)
{
	return extract_common(
		archive,
		outdir,
		expected_uuid,
		true,
		password,
		1,
		0,
		0
	);
}

int wpk_extract_file(
	const char *archive,
	uint32_t index,
	const char *outdir
) {
	return extract_common(
		archive,
		outdir,
		NULL,
		false,
		NULL,
		0,
		1,
		index
	);
}

int wpk_extract_file_uuid(
	const char *archive,
	uint32_t index,
	const char *outdir,
	const wpk_uuid_t expected_uuid)
{
	return extract_common(
		archive,
		outdir,
		expected_uuid,
		true,
		NULL,
		0,
		1,
		index
	);
}

int wpk_extract_file_password(
	const char *archive,
	uint32_t index,
	const char *outdir,
	const char *password)
{
	return extract_common(
		archive,
		outdir,
		NULL,
		false,
		password,
		1,
		1,
		index
	);
}

int wpk_extract_file_password_uuid(
	const char *archive,
	uint32_t index,
	const char *outdir,
	const wpk_uuid_t expected_uuid,
	const char *password
) {
	return extract_common(
		archive,
		outdir,
		expected_uuid,
		true,
		password,
		1,
		1,
		index
	);
}

/* --------------------------------------------------------- */
/* Public Buffer Extraction API                              */
/* --------------------------------------------------------- */

int wpk_extract_buffer(
	const void *buffer,
	size_t buffer_size,
	const char *outdir)
{
	return extract_buffer_common(
		buffer,
		buffer_size,
		outdir,
		NULL,
		false,
		NULL,
		0,
		0,
		0
	);
}

int wpk_extract_buffer_uuid(
	const void *buffer,
	size_t buffer_size,
	const char *outdir,
	const wpk_uuid_t expected_uuid)
{
	return extract_buffer_common(
		buffer,
		buffer_size,
		outdir,
		expected_uuid,
		true,
		NULL,
		0,
		0,
		0
	);
}

int wpk_extract_buffer_password(
	const void *buffer,
	size_t buffer_size,
	const char *outdir,
	const char *password)
{
	return extract_buffer_common(
		buffer,
		buffer_size,
		outdir,
		NULL,
		false,
		password,
		1,
		0,
		0
	);
}

int wpk_extract_buffer_password_uuid(
	const void *buffer,
	size_t buffer_size,
	const char *outdir,
	const wpk_uuid_t expected_uuid,
	const char *password)
{
	return extract_buffer_common(
		buffer,
		buffer_size,
		outdir,
		expected_uuid,
		true,
		password,
		1,
		0,
		0
	);
}

int wpk_extract_buffer_file(
	const void *buffer,
	size_t buffer_size,
	uint32_t index,
	const char *outdir)
{
	return extract_buffer_common(
		buffer,
		buffer_size,
		outdir,
		NULL,
		false,
		NULL,
		0,
		1,
		index
	);
}

int wpk_extract_buffer_file_uuid(
	const void *buffer,
	size_t buffer_size,
	uint32_t index,
	const char *outdir,
	const wpk_uuid_t expected_uuid)
{
	return extract_buffer_common(
		buffer,
		buffer_size,
		outdir,
		expected_uuid,
		true,
		NULL,
		0,
		1,
		index
	);
}

int wpk_extract_buffer_file_password(
	const void *buffer,
	size_t buffer_size,
	uint32_t index,
	const char *outdir,
	const char *password)
{
	return extract_buffer_common(
		buffer,
		buffer_size,
		outdir,
		NULL,
		false,
		password,
		1,
		1,
		index
	);
}

int wpk_extract_buffer_file_password_uuid(
	const void *buffer,
	size_t buffer_size,
	uint32_t index,
	const char *outdir,
	const wpk_uuid_t expected_uuid,
	const char *password)
{
	return extract_buffer_common(
		buffer,
		buffer_size,
		outdir,
		expected_uuid,
		true,
		password,
		1,
		1,
		index
	);
}
