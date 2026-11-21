#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "wpk_internal.h"

#ifdef _WIN32
#define WPK_FSEEK _fseeki64
#else
#include <sys/types.h>
#define WPK_FSEEK fseeko
#endif

/* Largest zlib expansion ratio is ~1032:1; anything beyond is corrupt. */
#define WPK_MAX_EXPANSION 1100u

/* --------------------------------------------------------- */
/* Helpers                                                   */
/* --------------------------------------------------------- */

/*
 * AES-GCM additional authenticated data. Must match the layout used by the
 * writer (wpk_compress.c) and the extractor (wpk_extract.c):
 *   UUID[16], index[4], flags[2], original_size[8], compressed_size[8],
 *   data_offset[8], path_len[2], path[]
 */
static int wpk_make_aad(
	const wpk_uuid_t uuid,
	uint32_t index,
	const WPK_INTERNAL_ENTRY *e,
	uint8_t **out,
	size_t *out_size
) {
	size_t n = 48u + (size_t)e->path_len;
	size_t o = 0;
	uint8_t *p = (uint8_t *)malloc(n);

	if (!p)
		return 0;

	memcpy(p + o, uuid, WPK_UUID_SIZE);
	o += WPK_UUID_SIZE;

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

/*
 * Convert every entry of an already opened (and, if needed, unlocked) reader
 * into one in-memory ZIP archive. Works for file-backed and memory-backed
 * readers. On success *zip is owned by the caller (release with mz_free()).
 */
static bool wpk_reader_to_zip_mem(
	wpk_reader_t *reader,
	uint8_t **zip,
	size_t *out_size
) {
	mz_zip_archive archive;
	void *zip_buffer = NULL;
	size_t zip_size = 0;
	bool zip_initialized = false;
	bool success = false;

	memset(&archive, 0, sizeof(archive));

	if (!reader || !zip || !out_size)
		return false;

	*zip = NULL;
	*out_size = 0;

	if (reader->file_count && !reader->entries)
		return false;

	/* The AES backend must be ready before the first decryption. */
	if ((reader->flags & WPK_FLAG_ENCRYPTED) && !wpk_crypto_init())
		return false;

	if (!mz_zip_writer_init_heap(&archive, 0, 0))
		return false;

	zip_initialized = true;

	for (uint32_t i = 0; i < reader->file_count; ++i) {
		WPK_INTERNAL_ENTRY *entry = &reader->entries[i];

		uint8_t *stored = NULL;     /* private copy of the payload */
		uint8_t *plain_z = NULL;    /* decrypted (still compressed) */
		uint8_t *file_data = NULL;  /* final file contents */
		uint8_t *aad = NULL;
		char *name = NULL;

		const uint8_t *compressed_data = NULL;
		size_t aad_size = 0;
		size_t compressed_size;
		size_t original_size;
		mz_ulong decompressed_size;
		MZ_TIME_T mtime;
		bool entry_success = false;

		if (entry->compressed_size > SIZE_MAX ||
			entry->original_size > SIZE_MAX)
			goto entry_cleanup;

		/* Single-volume (non-ZIP64) output and miniz's mz_ulong limits. */
		if (entry->compressed_size > MZ_UINT32_MAX ||
			entry->original_size > MZ_UINT32_MAX ||
			entry->compressed_size > (mz_ulong)-1 ||
			entry->original_size > (mz_ulong)-1)
			goto entry_cleanup;

		compressed_size = (size_t)entry->compressed_size;
		original_size = (size_t)entry->original_size;

		/* Reject absurd size claims before allocating for them. */
		if (entry->original_size >
			((uint64_t)compressed_size + 16u) * WPK_MAX_EXPANSION)
			goto entry_cleanup;

		/* Locate the payload. */
		if (reader->memory_backed) {
			if (!reader->memory ||
				entry->data_offset > reader->memory_size ||
				compressed_size >
				reader->memory_size - (size_t)entry->data_offset)
				goto entry_cleanup;

			compressed_data = reader->memory + (size_t)entry->data_offset;
		} else {
			if (!reader->file)
				goto entry_cleanup;

			stored = (uint8_t *)malloc(compressed_size ? compressed_size : 1);

			if (!stored)
				goto entry_cleanup;

			if (WPK_FSEEK(reader->file,
				(int64_t)entry->data_offset, SEEK_SET) != 0)
				goto entry_cleanup;

			if (compressed_size &&
				fread(stored, 1, compressed_size, reader->file)
				!= compressed_size)
				goto entry_cleanup;

			compressed_data = stored;
		}

		/* Authenticate and decrypt. */
		if (entry->flags & WPK_FLAG_ENCRYPTED) {
			if (!reader->has_key)
				goto entry_cleanup;

			plain_z = (uint8_t *)malloc(compressed_size ? compressed_size : 1);

			if (!plain_z)
				goto entry_cleanup;

			if (!wpk_make_aad(reader->uuid, i, entry, &aad, &aad_size))
				goto entry_cleanup;

			if (!wpk_aes_gcm_decrypt(
				reader->key,
				entry->nonce,
				aad,
				aad_size,
				compressed_data,
				compressed_size,
				entry->tag,
				plain_z))
				goto entry_cleanup;

			compressed_data = plain_z;
		}

		/* Every payload is a zlib stream. */
		file_data = (uint8_t *)malloc(original_size ? original_size : 1);

		if (!file_data)
			goto entry_cleanup;

		decompressed_size = (mz_ulong)original_size;

		if (mz_uncompress(
			file_data,
			&decompressed_size,
			compressed_data,
			(mz_ulong)compressed_size) != MZ_OK)
			goto entry_cleanup;

		if ((size_t)decompressed_size != original_size)
			goto entry_cleanup;

		/* ZIP names always use '/'. */
		name = (char *)malloc((size_t)entry->path_len + 1);

		if (!name)
			goto entry_cleanup;

		for (size_t k = 0; k < entry->path_len; ++k)
			name[k] = entry->path[k] == '\\' ? '/' : entry->path[k];

		name[entry->path_len] = '\0';

		mtime = (MZ_TIME_T)entry->timestamp;

		if (!mz_zip_writer_add_mem_ex_v2(
			&archive,
			name,
			file_data,
			original_size,
			NULL,
			0,
			MZ_DEFAULT_LEVEL,
			0,
			0,
			entry->timestamp ? &mtime : NULL,
			NULL,
			0,
			NULL,
			0))
			goto entry_cleanup;

		entry_success = true;

entry_cleanup:

		if (aad) {
			secure_zero(aad, aad_size);
			free(aad);
		}

		/* These can hold plaintext of an encrypted archive. */
		if (plain_z) {
			secure_zero(plain_z, compressed_size);
			free(plain_z);
		}

		if (file_data) {
			if (reader->flags & WPK_FLAG_ENCRYPTED)
				secure_zero(file_data, original_size);

			free(file_data);
		}

		free(stored);
		free(name);

		if (!entry_success)
			goto cleanup;
	}

	if (!mz_zip_writer_finalize_heap_archive(&archive, &zip_buffer, &zip_size))
		goto cleanup;

	*zip = (uint8_t *)zip_buffer;
	*out_size = zip_size;

	zip_buffer = NULL;
	success = true;

cleanup:

	if (zip_buffer)
		mz_free(zip_buffer);

	if (zip_initialized)
		mz_zip_writer_end(&archive);

	return success;
}

/* --------------------------------------------------------- */
/* WPK -> ZIP                                                */
/* --------------------------------------------------------- */

bool wpk_mem_convert_to_zip_mem(
	const void *wpk,
	size_t size,
	uint8_t **zip,
	size_t *out_size,
	const char *password
) {
	wpk_reader_t *reader = NULL;
	bool success;

	if (zip)
		*zip = NULL;

	if (out_size)
		*out_size = 0;

	if (!wpk || !size || !zip || !out_size)
		return false;

	if (!wpk_reader_open_password_mem(wpk, size, password, &reader) || !reader)
		return false;

	success = wpk_reader_to_zip_mem(reader, zip, out_size);

	wpk_reader_close(reader);

	return success;
}

bool wpk_mem_convert_to_zip_mem_uuid(
	const void *wpk,
	size_t size,
	uint8_t **zip,
	size_t *out_size,
	const char *password,
	wpk_uuid_t uuid
) {
	wpk_reader_t *reader = NULL;
	bool success = false;

	if (zip)
		*zip = NULL;

	if (out_size)
		*out_size = 0;

	if (!wpk || !size || !zip || !out_size || !uuid)
		return false;

	if (!wpk_reader_open_password_mem(wpk, size, password, &reader) || !reader)
		return false;

	/* Verify the UUID before any entry is decrypted or decompressed. */
	if (wpk_reader_equal_uuid(reader, uuid))
		success = wpk_reader_to_zip_mem(reader, zip, out_size);

	wpk_reader_close(reader);

	return success;
}

bool wpk_convert_to_zip_mem(
	const char *wpk_path,
	uint8_t **zip,
	size_t *out_size,
	const char *password
) {
	wpk_reader_t *reader = NULL;
	bool success;

	if (zip)
		*zip = NULL;

	if (out_size)
		*out_size = 0;

	if (!wpk_path || !wpk_path[0] || !zip || !out_size)
		return false;

	if (!wpk_reader_open_password(wpk_path, password, &reader) || !reader)
		return false;

	success = wpk_reader_to_zip_mem(reader, zip, out_size);

	wpk_reader_close(reader);

	return success;
}

bool wpk_convert_to_zip_mem_uuid(
	const char *wpk_path,
	uint8_t **zip,
	size_t *out_size,
	const char *password,
	wpk_uuid_t uuid
) {
	wpk_reader_t *reader = NULL;
	bool success = false;

	if (zip)
		*zip = NULL;

	if (out_size)
		*out_size = 0;

	if (!zip || !out_size)
		return false;

	if (!wpk_path || !wpk_path[0] || !uuid)
		return false;

	if (!wpk_reader_open_password(wpk_path, password, &reader) || !reader)
		return false;

	/*
	 * Verify the UUID before extracting any entries. The same reader is
	 * reused so the (expensive) key derivation runs only once.
	 */
	if (wpk_reader_equal_uuid(reader, uuid))
		success = wpk_reader_to_zip_mem(reader, zip, out_size);

	wpk_reader_close(reader);

	return success;
}

bool wpk_convert_to_zip(
	const char *wpk_path,
	const char *zip_path,
	const char *password
) {
	uint8_t *zip_data = NULL;
	size_t zip_size = 0;
	char *tmp_path = NULL;
	FILE *file = NULL;
	bool success = false;
	bool tmp_created = false;

	if (!wpk_path || !wpk_path[0] || !zip_path || !zip_path[0])
		return false;

	if (!wpk_convert_to_zip_mem(wpk_path, &zip_data, &zip_size, password))
		goto cleanup;

	/*
	 * Write to "<zip_path>.tmp" and rename, so a failure never destroys
	 * an existing file at zip_path or leaves a partial ZIP behind.
	 */
	{
		size_t len = strlen(zip_path);

		tmp_path = (char *)malloc(len + 5);

		if (!tmp_path)
			goto cleanup;

		memcpy(tmp_path, zip_path, len);
		memcpy(tmp_path + len, ".tmp", 5);
	}

	file = fopen(tmp_path, "wb");

	if (!file)
		goto cleanup;

	tmp_created = true;

	if (zip_size && fwrite(zip_data, 1, zip_size, file) != zip_size)
		goto cleanup;

	if (fflush(file) != 0)
		goto cleanup;

	if (fclose(file) != 0) {
		file = NULL;
		goto cleanup;
	}

	file = NULL;

	if (rename(tmp_path, zip_path) != 0) {
		/* Windows cannot rename over an existing file. */
		remove(zip_path);

		if (rename(tmp_path, zip_path) != 0)
			goto cleanup;
	}

	tmp_created = false;
	success = true;

cleanup:

	if (file)
		fclose(file);

	if (tmp_created)
		remove(tmp_path);

	free(tmp_path);

	if (zip_data)
		mz_free(zip_data);

	return success;
}

/* --------------------------------------------------------- */
/* WPK as a miniz ZIP reader                                 */
/* --------------------------------------------------------- */

/*
 * The WPK is converted to an in-memory ZIP that miniz then reads. That
 * buffer must outlive the mz_zip_archive, and miniz has no hook to free it,
 * so it is tied to the archive through the allocator "opaque" pointer and
 * released by wpk_reader_end(). Always close these archives with
 * wpk_reader_end(), not mz_zip_reader_end().
 */
typedef struct WPK_ZIP_OWNER {
	uint8_t *zip_mem;
} WPK_ZIP_OWNER;

static void *wpk_zip_alloc(void *opaque, size_t items, size_t size) {
	(void)opaque;
	return malloc(items * size);
}

static void wpk_zip_free(void *opaque, void *address) {
	(void)opaque;
	free(address);
}

static void *wpk_zip_realloc(void *opaque, void *address, size_t items, size_t size) {
	(void)opaque;
	return realloc(address, items * size);
}

/* Takes ownership of zip_mem in every case. */
static bool wpk_zip_reader_attach(
	mz_zip_archive *pZip,
	uint8_t *zip_mem,
	size_t zip_size,
	mz_uint flags
) {
	WPK_ZIP_OWNER *owner = (WPK_ZIP_OWNER *)malloc(sizeof(*owner));

	if (!owner) {
		mz_free(zip_mem);
		return false;
	}

	owner->zip_mem = zip_mem;

	memset(pZip, 0, sizeof(*pZip));
	pZip->m_pAlloc = wpk_zip_alloc;
	pZip->m_pFree = wpk_zip_free;
	pZip->m_pRealloc = wpk_zip_realloc;
	pZip->m_pAlloc_opaque = owner;

	if (!mz_zip_reader_init_mem(pZip, zip_mem, zip_size, flags)) {
		free(owner);
		mz_free(zip_mem);
		memset(pZip, 0, sizeof(*pZip));
		return false;
	}

	return true;
}

bool wpk_reader_init_mem_password(
	mz_zip_archive *pZip,
	const void *wpk_mem,
	size_t size,
	const char *password,
	mz_uint flags
) {
	uint8_t *zip_mem = NULL;
	size_t zip_size = 0;

	if (!pZip)
		return false;

	if (!wpk_mem || size == 0) {
		memset(pZip, 0, sizeof(*pZip));
		return false;
	}

	memset(pZip, 0, sizeof(*pZip));

	if (!wpk_mem_convert_to_zip_mem(wpk_mem, size, &zip_mem, &zip_size, password))
		return false;

	return wpk_zip_reader_attach(pZip, zip_mem, zip_size, flags);
}

bool wpk_reader_init_mem(
	mz_zip_archive *pZip,
	const void *wpk_mem,
	size_t size,
	mz_uint flags
) {
	return wpk_reader_init_mem_password(pZip, wpk_mem, size, NULL, flags);
}

bool wpk_reader_init_file_password(
	mz_zip_archive *pZip,
	const char *wpk_path,
	const char *password,
	mz_uint32 flags
) {
	uint8_t *zip_mem = NULL;
	size_t zip_size = 0;

	if (!pZip)
		return false;

	memset(pZip, 0, sizeof(*pZip));

	if (!wpk_path || wpk_path[0] == '\0')
		return false;

	if (!wpk_convert_to_zip_mem(wpk_path, &zip_mem, &zip_size, password))
		return false;

	return wpk_zip_reader_attach(pZip, zip_mem, zip_size, flags);
}

bool wpk_reader_init_file(
	mz_zip_archive *pZip,
	const char *wpk_path,
	mz_uint32 flags
) {
	return wpk_reader_init_file_password(pZip, wpk_path, NULL, flags);
}

bool wpk_reader_end(mz_zip_archive *pZip) {
	WPK_ZIP_OWNER *owner;
	bool ok;

	if (!pZip)
		return false;

	owner = (WPK_ZIP_OWNER *)pZip->m_pAlloc_opaque;

	/* Only archives created by wpk_reader_init_*() carry our allocator. */
	if (pZip->m_pAlloc != wpk_zip_alloc)
		return mz_zip_reader_end(pZip) == MZ_TRUE;

	ok = mz_zip_reader_end(pZip) == MZ_TRUE;

	if (owner) {
		mz_free(owner->zip_mem);
		free(owner);
	}

	pZip->m_pAlloc_opaque = NULL;

	return ok;
}

/*
 * Convert a ZIP archive to a WPK archive.
 *
 * password may be NULL (no encryption). Directory entries are dropped (WPK
 * stores files only). Encrypted ZIP entries are not supported. The WPK file
 * is written to "<wpk_path>.tmp" and renamed, so a failure never leaves a
 * partial archive behind.
 */
bool zip_convert_to_wpk(
	const char *zip_path,
	const char *wpk_path,
	const char *password
) {
	mz_zip_archive zip;
	wpk_mem_file_t *files = NULL;
	char **names = NULL;
	void **buffers = NULL;
	char *tmp_path = NULL;
	size_t total = 0;
	size_t count = 0;
	bool zip_open = false;
	bool success = false;

	if (!zip_path || !zip_path[0] || !wpk_path || !wpk_path[0])
		return false;

	memset(&zip, 0, sizeof(zip));

	if (!mz_zip_reader_init_file(&zip, zip_path, 0))
		return false;

	zip_open = true;

	total = (size_t)mz_zip_reader_get_num_files(&zip);

	if (total == 0)
		goto cleanup;

	files = (wpk_mem_file_t *)calloc(total, sizeof(*files));
	names = (char **)calloc(total, sizeof(*names));
	buffers = (void **)calloc(total, sizeof(*buffers));

	if (!files || !names || !buffers)
		goto cleanup;

	for (mz_uint i = 0; i < (mz_uint)total; ++i) {
		mz_zip_archive_file_stat st;
		size_t size = 0;
		size_t name_len;

		if (!mz_zip_reader_file_stat(&zip, i, &st))
			goto cleanup;

		if (st.m_is_directory)
			continue;

		/* Encrypted or otherwise unreadable entries cannot be converted. */
		if (st.m_is_encrypted || !st.m_is_supported)
			goto cleanup;

		name_len = strlen(st.m_filename);

		names[count] = (char *)malloc(name_len + 1);

		if (!names[count])
			goto cleanup;

		/* WPK paths always use '/'. */
		for (size_t j = 0; j <= name_len; ++j)
			names[count][j] = st.m_filename[j] == '\\' ? '/' : st.m_filename[j];

		if (st.m_uncomp_size > 0) {
			buffers[count] = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);

			if (!buffers[count] || size != (size_t)st.m_uncomp_size)
				goto cleanup;
		}

		files[count].path = names[count];
		files[count].data = buffers[count];
		files[count].size = size;
		files[count].timestamp = st.m_time > 0 ? (uint64_t)st.m_time : 0;

		++count;
	}

	if (count == 0)
		goto cleanup;

	{
		WPK_COMPRESS_OPTIONS options;
		wpk_uuid_t uuid;
		size_t path_len = strlen(wpk_path);

		memset(&options, 0, sizeof(options));
		options.level = WPK_DEFAULT_LEVEL;
		options.password = password;

		tmp_path = (char *)malloc(path_len + 5);

		if (!tmp_path)
			goto cleanup;

		memcpy(tmp_path, wpk_path, path_len);
		memcpy(tmp_path + path_len, ".tmp", 5);

		if (!wpk_compress_mem(tmp_path, files, count, &options, uuid)) {
			remove(tmp_path);
			goto cleanup;
		}

		if (rename(tmp_path, wpk_path) != 0) {
			/* Windows cannot rename over an existing file. */
			remove(wpk_path);

			if (rename(tmp_path, wpk_path) != 0) {
				remove(tmp_path);
				goto cleanup;
			}
		}
	}

	success = true;

cleanup:

	for (size_t i = 0; i < total; ++i) {
		if (buffers && buffers[i]) {
			/* Plaintext of the archive contents: wipe before releasing. */
			if (password && files)
				memset(buffers[i], 0, files[i].size);

			mz_free(buffers[i]);
		}

		if (names)
			free(names[i]);
	}

	free(buffers);
	free(names);
	free(files);
	free(tmp_path);

	if (zip_open)
		mz_zip_reader_end(&zip);

	return success;
}
