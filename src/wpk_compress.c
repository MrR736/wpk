#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

#include "miniz/miniz.h"

#include "wpk_compress.h"
#include "wpk_internal.h"
#include "wpk_uuid.h"

#define WPK_MAX_FILE_SIZE ((uint64_t)1 << 40)

static int put_u16(FILE *f, uint16_t v)
{
	return fputc((int)(v & 0xff), f) != EOF &&
	fputc((int)(v >> 8), f) != EOF;
}

static int put_u32(FILE *f, uint32_t v)
{
	for (unsigned i = 0; i < 4; ++i) {
		if (fputc((int)((v >> (i * 8)) & 0xff), f) == EOF)
			return 0;
	}

	return 1;
}

static int put_u64(FILE *f, uint64_t v)
{
	for (unsigned i = 0; i < 8; ++i) {
		if (fputc((int)((v >> (i * 8)) & 0xff), f) == EOF)
			return 0;
	}

	return 1;
}

static int write_bytes(FILE *f, const void *data, size_t size)
{
	return size == 0 || fwrite(data, 1, size, f) == size;
}

static char *wpk_strdup(const char *str)
{
	size_t len;
	char *copy;

	if (str == NULL)
		return NULL;

	len = strlen(str);

	if (len == SIZE_MAX)
		return NULL;

	copy = malloc(len + 1);

	if (copy == NULL)
		return NULL;

	memcpy(copy, str, len + 1);

	return copy;
}

static int get_file_timestamp(
	const char *path,
	uint64_t *timestamp
) {
	struct stat st;

	if (!path || !timestamp)
		return 0;

	if (stat(path, &st) != 0)
		return 0;

	if (st.st_mtime < 0)
		return 0;

	*timestamp = (uint64_t)st.st_mtime;

	return 1;
}

/*
 * AAD layout:
 * UUID, index[4], flags[2], original_size[8],
 * compressed_size[8], data_offset[8], path_length[2], path[]
 */
static int make_aad(
	const wpk_uuid_t uuid,
	uint32_t index,
	const WPK_INTERNAL_ENTRY *e,
	uint8_t **out,
	size_t *out_size)
{
	size_t n = 48u + e->path_len;
	uint8_t *p = (uint8_t *)malloc(n);

	if (!p)
		return 0;

	size_t o = 0;

	memcpy(p + o, uuid, 16);
	o += 16;

	for (unsigned i = 0; i < 4; ++i)
		p[o++] = (uint8_t)(index >> (i * 8));

	p[o++] = (uint8_t)e->flags;
	p[o++] = (uint8_t)(e->flags >> 8);

	for (unsigned i = 0; i < 8; ++i)
		p[o++] = (uint8_t)(e->original_size >> (i * 8));

	for (unsigned i = 0; i < 8; ++i)
		p[o++] = (uint8_t)(e->compressed_size >> (i * 8));

	for (unsigned i = 0; i < 8; ++i)
		p[o++] = (uint8_t)(e->data_offset >> (i * 8));

	p[o++] = (uint8_t)e->path_len;
	p[o++] = (uint8_t)(e->path_len >> 8);

	memcpy(p + o, e->path, e->path_len);
	o += e->path_len;

	*out = p;
	*out_size = o;

	return 1;
}

static int read_source(
	const char *path,
	uint8_t **data,
	mz_ulong *size)
{
	FILE *f = NULL;
	long length;
	uint8_t *buffer = NULL;

	if (!path || !data || !size)
		return 0;

	f = fopen(path, "rb");

	if (!f)
		return 0;

	if (fseek(f, 0, SEEK_END) != 0)
		goto fail;

	length = ftell(f);

	if (length < 0 ||
		(uint64_t)length > WPK_MAX_FILE_SIZE ||
		(uint64_t)length > SIZE_MAX)
		goto fail;

	if (fseek(f, 0, SEEK_SET) != 0)
		goto fail;

	buffer = (uint8_t *)malloc(length ? (size_t)length : 1);

	if (!buffer)
		goto fail;

	if (length &&
		fread(buffer, 1, (size_t)length, f) != (size_t)length)
		goto fail;

	fclose(f);

	*data = buffer;
	*size = (mz_ulong)length;

	return 1;

fail:
	free(buffer);
	fclose(f);
	return 0;
}

static void free_entries(
	WPK_INTERNAL_ENTRY *entries,
	size_t count)
{
	if (!entries)
		return;

	for (size_t i = 0; i < count; ++i) {
		free(entries[i].path);

		if (entries[i].data) {
			secure_zero(
				entries[i].data,
			   (size_t)entries[i].compressed_size
			);

			free(entries[i].data);
		}
	}

	free(entries);
}

static int valid_archive_path(const char *path)
{
	size_t len;

	if (!path || !*path)
		return 0;

	len = strlen(path);

	if (len > WPK_MAX_PATH)
		return 0;

	if (path[0] == '/' || path[0] == '\\')
		return 0;

	if (len >= 2 &&
		((path[0] >= 'A' && path[0] <= 'Z') ||
		 (path[0] >= 'a' && path[0] <= 'z')) &&
		path[1] == ':')
		return 0;

	for (size_t i = 0; i < len;) {
		size_t start = i;

		while (i < len && path[i] != '/' && path[i] != '\\')
			++i;

		size_t component_len = i - start;

		if (component_len == 0 ||
			(component_len == 1 && path[start] == '.') ||
			(component_len == 2 &&
			 path[start] == '.' && path[start + 1] == '.'))
			return 0;

		if (i < len)
			++i;
	}

	return 1;
}

/*
 * Entries are normally read from disk (files[i]). When `mem` is not NULL the
 * contents come from mem[i] instead and `files` is ignored (may be NULL).
 */
static int compress_entries(
	const char *archive,
	const char **files,
	const char **archive_paths,
	const wpk_mem_file_t *mem,
	size_t count,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid)
{
	WPK_INTERNAL_ENTRY *entries = NULL;
	FILE *out = NULL;

	uint8_t salt[WPK_SALT_SIZE] = {0};
	uint8_t key[WPK_KEY_SIZE] = {0};
	wpk_uuid_t uuid;

	uint32_t iterations = 0;
	uint32_t flags = 0;
	int level = 3;
	int encrypted = 0;
	int result = 0;

	uint64_t data_offset = WPK_HEADER_SIZE;
	uint64_t table_offset = 0;

	if (!archive || (!files && !mem) || !archive_paths ||
		!out_uuid || count == 0 || count > WPK_MAX_FILES)
		return 0;

	/* Every entry is zlib-compressed; the header only carries WPK_FLAG_ENCRYPTED. */

	if (options) {
		if (options->level)
			level = options->level;

		if (options->password) encrypted = 1;

		iterations = options->pbkdf2_iterations;
	}

	if (encrypted && !wpk_crypto_init()) return 0;


	if (encrypted) {
		if (iterations == 0)
			iterations = WPK_DEFAULT_ITER;

		if (iterations < 100000 || iterations > INT_MAX)
			return 0;
	}

	entries = (WPK_INTERNAL_ENTRY *)calloc(count, sizeof(*entries));

	if (!entries)
		return 0;

	if (!wpk_uuid_generate(uuid))
		goto cleanup;

	memcpy(out_uuid, uuid, WPK_UUID_SIZE);

	if (encrypted) {
		if (!wpk_random_bytes(salt, sizeof(salt)))
			goto cleanup;

		if (!wpk_derive_key(
			options->password, salt, iterations, key))
			goto cleanup;

		flags |= WPK_FLAG_ENCRYPTED;
	}

	/*
	 * Compress and optionally encrypt each input file.
	 */

	for (size_t i = 0; i < count; ++i) {
		uint8_t *raw = NULL;
		mz_ulong raw_size = 0;
		mz_ulong bound;
		mz_ulong actual_size;
		size_t compressed_size;
		size_t path_len;
		int ret;

		if ((!mem && !files[i]) ||
			!valid_archive_path(archive_paths[i]))
			goto cleanup;

		path_len = strlen(archive_paths[i]);

		if (path_len > WPK_MAX_PATH ||
			path_len > UINT16_MAX)
			goto cleanup;

		/* Reject duplicate archive paths. */
		for (size_t j = 0; j < i; ++j) {
			if (strcmp(entries[j].path, archive_paths[i]) == 0)
				goto cleanup;
		}

		entries[i].path = wpk_strdup(archive_paths[i]);

		if (!entries[i].path)
			goto cleanup;

		entries[i].path_len = (uint16_t)path_len;
		entries[i].flags = encrypted ? WPK_FLAG_ENCRYPTED : 0;

		/* Read source file. */
		if (mem) {
			/* Borrowed buffer: never freed or wiped here. */
			static const uint8_t empty = 0;

			if (mem[i].size > WPK_MAX_FILE_SIZE ||
				(uint64_t)mem[i].size > (uint64_t)(mz_ulong)-1)
				goto cleanup;

			raw = (uint8_t *)(mem[i].data ? mem[i].data : &empty);
			raw_size = (mz_ulong)mem[i].size;
		} else if (!read_source(files[i], &raw, &raw_size))
			goto cleanup;

		entries[i].original_size = (uint64_t)raw_size;

		/* Calculate compression buffer size. */
		bound = mz_compressBound(raw_size);

		if (bound == 0 || (uint64_t)bound > SIZE_MAX) {
			if (!mem) {
				secure_zero(raw, (size_t)raw_size);
				free(raw);
			}
			goto cleanup;
		}

		/* Allocate compression buffer exactly once. */
		entries[i].data = (uint8_t *)malloc((size_t)bound);

		if (!entries[i].data) {
			if (!mem) {
				secure_zero(raw, (size_t)raw_size);
				free(raw);
			}
			goto cleanup;
		}

		actual_size = bound;

		ret = mz_compress2(
			entries[i].data,
			&actual_size,
			raw,
			raw_size,
			level
		);

		/* Clear source data after compression. */
		if (!mem) {
			secure_zero(raw, (size_t)raw_size);
			free(raw);
		}
		raw = NULL;

		if (ret != MZ_OK || actual_size > bound)
			goto cleanup;

		/* IMPORTANT: Save the actual compressed size. */
		compressed_size = (size_t)actual_size;
		entries[i].compressed_size = (uint64_t)compressed_size;

		/* Set payload offset. */
		entries[i].data_offset = data_offset;

		/* Check archive offset overflow before encryption. */
		if (UINT64_MAX - data_offset < compressed_size)
			goto cleanup;

		if (mem)
			entries[i].timestamp = mem[i].timestamp;
		else if (!get_file_timestamp(files[i],&entries[i].timestamp))
			goto cleanup;

		if (encrypted) {
			uint8_t *ciphertext = NULL;
			uint8_t *aad = NULL;
			size_t aad_size = 0;

			if (!wpk_random_bytes(
				entries[i].nonce,
				WPK_NONCE_SIZE))
				goto cleanup;

			ciphertext = (uint8_t *)malloc(
				compressed_size ? compressed_size : 1);

			if (!ciphertext)
				goto cleanup;

			if (!make_aad(
				uuid,
				(uint32_t)i,
				&entries[i],
				&aad,
				&aad_size)) {
				free(ciphertext);
				goto cleanup;
			}

			ret = wpk_aes_gcm_encrypt(
				key,
				entries[i].nonce,
				aad,
				aad_size,
				entries[i].data,
				compressed_size,
				ciphertext,
				entries[i].tag
			);

			free(aad);

			if (!ret) {
				secure_zero(ciphertext, compressed_size);
				free(ciphertext);
				goto cleanup;
			}

			/*
			* The original compressed data is no longer needed.
			* Clear it because it contains compressed plaintext.
			*/
			secure_zero(entries[i].data, compressed_size);
			free(entries[i].data);

			entries[i].data = ciphertext;

			entries[i].original_size = (uint64_t)raw_size;
		}

		data_offset += (uint64_t)compressed_size;
	}


	table_offset = data_offset;

	/*
	 * Write to a new archive.
	 */
	out = fopen(archive, "wb");

	if (!out)
		goto cleanup;

	/* Header */
	if (!write_bytes(out, WPK_MAGIC, WPK_MAGIC_SIZE) ||
		!write_bytes(out, uuid, 16))
		goto cleanup;

	if (!put_u32(out, WPK_VERSION) ||
		!put_u32(out, (uint32_t)count) ||
		!put_u64(out, table_offset))
		goto cleanup;

	if (!write_bytes(out, salt, WPK_SALT_SIZE))
		goto cleanup;

	if (!put_u32(out, iterations) ||
		!put_u32(out, flags) ||
		!put_u16(out, 0))
		goto cleanup;

	/* Payloads */
	for (size_t i = 0; i < count; ++i) {
		if (!write_bytes(
			out, entries[i].data,
			(size_t)entries[i].compressed_size))
			goto cleanup;
	}

	/* File table */
	for (size_t i = 0; i < count; ++i) {
		WPK_INTERNAL_ENTRY *e = &entries[i];

		if(!put_u16(out, e->path_len) ||
		   !put_u16(out, e->flags) ||
		   !put_u64(out, e->original_size) ||
		   !put_u64(out, e->compressed_size) ||
		   !put_u64(out, e->data_offset))
			goto cleanup;

		if (!write_bytes(out, e->nonce, WPK_NONCE_SIZE) ||
			!write_bytes(out, e->tag, WPK_TAG_SIZE) ||
			!put_u64(out, e->timestamp) ||
			!write_bytes(out, e->path, e->path_len))
			goto cleanup;
	}

	if (fflush(out) != 0)
		goto cleanup;

	if (fclose(out) != 0) {
		out = NULL;
		goto cleanup;
	}

	out = NULL;
	result = 1;

cleanup:
	if (out) fclose(out);

	secure_zero(key, sizeof(key));
	secure_zero(salt, sizeof(salt));

	free_entries(entries, count);

	return result;
}

int wpk_compress_files(
	const char *archive,
	const char **files,
	size_t count,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
) {
	if (!archive || !files || !out_uuid || count == 0 || count > WPK_MAX_FILES) return 0;
	const char **paths = (const char **)calloc(count, sizeof(*paths));
	if (!paths) return 0;
	for (size_t i = 0; i < count; ++i) paths[i] = files[i];
	int result = compress_entries(archive,files,paths,NULL,count,options,out_uuid);
	free(paths);
	return result;
}

int wpk_compress_file(
	const char *archive,
	const char *file,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
) {
	const char *files[1] = { file };
	return wpk_compress_files(archive, files, 1, options, out_uuid);
}


int wpk_compress_files_ex(
	const char *archive,
	const char **source_files,
	const char **archive_paths,
	size_t count,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
) {
	if (!archive || !source_files || !archive_paths || !out_uuid || count == 0 || count > WPK_MAX_FILES) {
		return 0;
	}

	return compress_entries(
		archive,
		source_files,
		archive_paths,
		NULL,
		count,
		options,
		out_uuid
	);
}

int wpk_compress_mem(
	const char *archive,
	const wpk_mem_file_t *files,
	size_t count,
	const WPK_COMPRESS_OPTIONS *options,
	wpk_uuid_t out_uuid
) {
	const char **paths;
	int result;

	if (!archive || !files || !out_uuid || count == 0 || count > WPK_MAX_FILES)
		return 0;

	paths = (const char **)calloc(count, sizeof(*paths));

	if (!paths)
		return 0;

	for (size_t i = 0; i < count; ++i)
		paths[i] = files[i].path;

	result = compress_entries(archive, NULL, paths, files, count, options, out_uuid);

	free(paths);

	return result;
}



typedef struct WPK_FILE_LIST {
	char **files;
	char **paths;
	size_t count;
	size_t capacity;
} WPK_FILE_LIST;

static char *wpk_join_path(
	const char *a,
	const char *b,
	char separator)
{
	size_t alen = strlen(a);
	size_t blen = strlen(b);
	int add_separator =
	alen != 0 && a[alen - 1] != '/' && a[alen - 1] != '\\';

	if (alen > SIZE_MAX - blen - (size_t)add_separator - 1)
		return NULL;

	char *result = malloc(
		alen + (size_t)add_separator + blen + 1);

	if (!result)
		return NULL;

	memcpy(result, a, alen);

	size_t offset = alen;

	if (add_separator)
		result[offset++] = separator;

	memcpy(result + offset, b, blen + 1);

	return result;
}

static int wpk_file_list_add(
	WPK_FILE_LIST *list,
	const char *file,
	const char *path)
{
	if (list->count >= WPK_MAX_FILES)
		return 0;

	if (list->count == list->capacity) {
		size_t capacity = list->capacity ?
		list->capacity * 2 : 16;

		if (capacity > WPK_MAX_FILES)
			capacity = WPK_MAX_FILES;

		if (capacity > SIZE_MAX / sizeof(char *))
			return 0;

		char **new_files = realloc(
			list->files, capacity * sizeof(char *));

		if (!new_files)
			return 0;

		list->files = new_files;

		char **new_paths = realloc(
			list->paths, capacity * sizeof(char *));

		if (!new_paths)
			return 0;

		list->paths = new_paths;
		list->capacity = capacity;
	}

	char *file_copy = wpk_strdup(file);
	char *path_copy = wpk_strdup(path);

	if (!file_copy || !path_copy) {
		free(file_copy);
		free(path_copy);
		return 0;
	}

	list->files[list->count] = file_copy;
	list->paths[list->count] = path_copy;

	++list->count;

	return 1;
}

static void wpk_file_list_free(WPK_FILE_LIST *list)
{
	if (!list)
		return;

	for (size_t i = 0; i < list->count; ++i) {
		free(list->files[i]);
		free(list->paths[i]);
	}

	free(list->files);
	free(list->paths);

	memset(list, 0, sizeof(*list));
}


#ifndef _WIN32
#include <dirent.h>

static int wpk_collect_dir(WPK_FILE_LIST *list,const char *root,const char *relative,unsigned depth) {
	DIR *dir;
	struct dirent *entry;
	char *directory;

	if (depth > 256) return 0;

	directory = relative[0] ? wpk_join_path(root, relative, '/') : wpk_strdup(root);

	if (!directory) return 0;

	dir = opendir(directory);

	if (!dir) {
		free(directory);
		return 0;
	}

	int result = 1;

	while ((entry = readdir(dir)) != NULL) {
		struct stat st;
		char *rel_path;
		char *full_path;

		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

		rel_path = relative[0] ? wpk_join_path(relative, entry->d_name, '/') : wpk_strdup(entry->d_name);

		if (!rel_path) {
			result = 0;
			break;
		}

		full_path = wpk_join_path(root, rel_path, '/');

		if (!full_path) {
			free(rel_path);
			result = 0;
			break;
		}

		/*
		 * lstat() does not follow symbolic links.
		 * Symlinks are intentionally excluded to prevent
		 * directory cycles and unexpected external files.
		 */
		if (lstat(full_path, &st) != 0) {
			free(rel_path);
			free(full_path);
			result = 0;
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			if (!wpk_collect_dir(
				list, root, rel_path, depth + 1))
				result = 0;
		}
		else if (S_ISREG(st.st_mode)) {
			if (!wpk_file_list_add(
				list, full_path, rel_path))
				result = 0;
		}

		free(rel_path);
		free(full_path);

		if (!result)
			break;
	}

	closedir(dir);
	free(directory);

	return result;
}

#else

static int wpk_collect_dir(
	WPK_FILE_LIST *list,
	const char *root,
	const char *relative,
	unsigned depth)
{
	WIN32_FIND_DATAA data;
	HANDLE find;
	char *directory;
	char *pattern;

	if (depth > 256)
		return 0;

	directory = relative[0]
	? wpk_join_path(root, relative, '\\')
	: wpk_strdup(root);

	if (!directory)
		return 0;

	pattern = wpk_join_path(directory, "*", '\\');

	if (!pattern) {
		free(directory);
		return 0;
	}

	find = FindFirstFileA(pattern, &data);

	free(pattern);

	if (find == INVALID_HANDLE_VALUE) {
		free(directory);
		return 0;
	}

	int result = 1;

	do {
		char *rel_path;
		char *full_path;

		if (strcmp(data.cFileName, ".") == 0 ||
			strcmp(data.cFileName, "..") == 0)
			continue;

		/*
		 * Skip symbolic links, junctions and other
		 * reparse points.
		 */
		if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			continue;

		rel_path = relative[0]
		? wpk_join_path(relative, data.cFileName, '/')
		: wpk_strdup(data.cFileName);

		if (!rel_path) {
			result = 0;
			break;
		}

		full_path = wpk_join_path(root, rel_path, '\\');

		if (!full_path) {
			free(rel_path);
			result = 0;
			break;
		}

		if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (!wpk_collect_dir(
				list, root, rel_path, depth + 1))
				result = 0;
		}
		else {
			if (!wpk_file_list_add(
				list, full_path, rel_path))
				result = 0;
		}

		free(rel_path);
		free(full_path);

		if (!result)
			break;

	} while (FindNextFileA(find, &data));

	if (GetLastError() != ERROR_NO_MORE_FILES)
		result = 0;

	FindClose(find);
	free(directory);

	return result;
}

#endif

int wpk_compress_dir(
    const char *archive,
    const char *dir,
    const WPK_COMPRESS_OPTIONS *options,
    wpk_uuid_t out_uuid)
{
    WPK_FILE_LIST list = {0};
    int result = 0;

    if (!archive || !dir || !out_uuid)
        return 0;

    if (!wpk_collect_dir(&list, dir, "", 0))
        goto cleanup;

    /* Empty directories are not supported by compress_entries(). */
    if (list.count == 0)
        goto cleanup;

    result = wpk_compress_files_ex(
        archive,
        (const char **)list.files,
        (const char **)list.paths,
        list.count,
        options,
        out_uuid
    );

cleanup:
    wpk_file_list_free(&list);

    return result;
}
