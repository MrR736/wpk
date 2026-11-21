#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#include <unistd.h>
#define MKDIR(p) mkdir((p), 0777)
#endif

#include "wpk.h"

/* -------------------------------------------------- */
/* Configuration									  */
/* -------------------------------------------------- */

#define TEST_ROOT		   "wpk_test_tmp"

#define SOURCE_DIR		  TEST_ROOT "/source"
#define PLAIN_DIR		   TEST_ROOT "/plain_output"
#define ENCRYPTED_DIR	   TEST_ROOT "/encrypted_output"
#define SINGLE_DIR		  TEST_ROOT "/single_output"
#define TAMPER_DIR		  TEST_ROOT "/tamper_output"
#define TRAVERSAL_DIR	   TEST_ROOT "/traversal_output"

#define BUFFER_PLAIN_DIR				 TEST_ROOT "/buffer_plain_output"
#define BUFFER_UUID_DIR				  TEST_ROOT "/buffer_uuid_output"
#define BUFFER_ENCRYPTED_DIR			 TEST_ROOT "/buffer_encrypted_output"
#define BUFFER_ENCRYPTED_UUID_DIR		TEST_ROOT "/buffer_encrypted_uuid_output"
#define BUFFER_SINGLE_DIR			   TEST_ROOT "/buffer_single_output"
#define BUFFER_SINGLE_UUID_DIR		  TEST_ROOT "/buffer_single_uuid_output"
#define BUFFER_SINGLE_ENCRYPTED_DIR	 TEST_ROOT "/buffer_single_encrypted_output"
#define BUFFER_SINGLE_ENCRYPTED_UUID_DIR TEST_ROOT "/buffer_single_encrypted_uuid_output"
#define BUFFER_TAMPER_DIR			   TEST_ROOT "/buffer_tamper_output"
#define BUFFER_TRAVERSAL_DIR			 TEST_ROOT "/buffer_traversal_output"

#define PLAIN_ARCHIVE	   TEST_ROOT "/plain.wpk"
#define ENCRYPTED_ARCHIVE   TEST_ROOT "/encrypted.wpk"
#define TAMPER_ARCHIVE	  TEST_ROOT "/tampered.wpk"
#define TRAVERSAL_ARCHIVE   TEST_ROOT "/traversal.wpk"

#define TRAVERSAL_OUTSIDE   TEST_ROOT "/ab.txt"

#define TEST_PASSWORD	   "WPK100-Test-Password-2026"

#define WPK_TEST_HEADER_SIZE 64
#define WPK_TEST_ENTRY_SIZE  56

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(condition, description)				 \
do {											  \
	++tests_run;								  \
	if (condition) {							  \
		++tests_passed;						   \
		printf("[PASS] %s\n", description);	   \
	} else {									  \
		printf("[FAIL] %s\n", description);	   \
	}											 \
} while (0)

/* -------------------------------------------------- */
/* Filesystem helpers								 */
/* -------------------------------------------------- */

static int file_exists(const char *path)
{
	FILE *f = fopen(path, "rb");

	if (!f)
		return 0;

	fclose(f);
	return 1;
}

static uint16_t read_le16(const unsigned char *p)
{
	return (uint16_t)(
		(uint16_t)p[0] |
		((uint16_t)p[1] << 8)
	);
}

static uint64_t read_le64(const unsigned char *p)
{
	uint64_t value = 0;

	for (unsigned int i = 0; i < 8; ++i)
		value |= (uint64_t)p[i] << (i * 8);

	return value;
}

static int make_dir(const char *path)
{
	if (MKDIR(path) == 0)
		return 1;

	return errno == EEXIST;
}

static int write_file(
	const char *path,
	const void *data,
	size_t size)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;

	int ok = size == 0 ||
	fwrite(data, 1, size, f) == size;

	if (fclose(f) != 0)
		ok = 0;

	return ok;
}

static int files_equal(
	const char *path_a,
	const char *path_b)
{
	FILE *a = NULL;
	FILE *b = NULL;

	unsigned char buffer_a[4096];
	unsigned char buffer_b[4096];

	int result = 0;

	a = fopen(path_a, "rb");
	b = fopen(path_b, "rb");

	if (!a || !b)
		goto cleanup;

	for (;;) {
		size_t na = fread(buffer_a, 1, sizeof(buffer_a), a);
		size_t nb = fread(buffer_b, 1, sizeof(buffer_b), b);

		if (na != nb)
			goto cleanup;

		if (na != 0 &&
			memcmp(buffer_a, buffer_b, na) != 0)
		{
			goto cleanup;
		}

		if (na < sizeof(buffer_a)) {
			if (ferror(a) || ferror(b))
				goto cleanup;

			result = feof(a) && feof(b);
			break;
		}
	}

	cleanup:
	if (a)
		fclose(a);

	if (b)
		fclose(b);

	return result;
}

static int copy_file(
	const char *source,
	const char *destination)
{
	FILE *in = NULL;
	FILE *out = NULL;

	unsigned char buffer[4096];
	int result = 0;

	in = fopen(source, "rb");

	if (!in)
		goto cleanup;

	out = fopen(destination, "wb");

	if (!out)
		goto cleanup;

	for (;;) {
		size_t n = fread(buffer, 1, sizeof(buffer), in);

		if (n && fwrite(buffer, 1, n, out) != n)
			goto cleanup;

		if (n < sizeof(buffer)) {
			if (ferror(in))
				goto cleanup;

			break;
		}
	}

	result = 1;

	cleanup:
	if (in && fclose(in) != 0)
		result = 0;

	if (out && fclose(out) != 0)
		result = 0;

	if (!result)
		remove(destination);

	return result;
}

/* -------------------------------------------------- */
/* Archive tampering helpers						  */
/* -------------------------------------------------- */

static int flip_archive_byte(
	const char *path,
	long offset)
{
	FILE *f = fopen(path, "r+b");

	if (!f)
		return 0;

	if (fseek(f, offset, SEEK_SET) != 0) {
		fclose(f);
		return 0;
	}

	int value = fgetc(f);

	if (value == EOF) {
		fclose(f);
		return 0;
	}

	if (fseek(f, offset, SEEK_SET) != 0) {
		fclose(f);
		return 0;
	}

	if (fputc(value ^ 0x01, f) == EOF) {
		fclose(f);
		return 0;
	}

	return fclose(f) == 0;
}

/*
 * Creates a malicious archive by modifying the first
 * entry path in a valid unencrypted archive.
 *
 * Original path:  hello.txt
 * Malicious path: ../ab.txt
 *
 * Both paths are exactly 9 bytes.
 */
static int create_traversal_archive(
	const char *valid_archive,
	const char *malicious_archive)
{
	FILE *f = NULL;

	unsigned char header[WPK_TEST_HEADER_SIZE];
	unsigned char entry_prefix[2];

	static const char expected_path[] = "hello.txt";
	static const char malicious_path[] = "../ab.txt";

	uint64_t table_offset;
	uint64_t path_offset;

	uint16_t path_length;

	long file_size;
	int result = 0;

	if (!copy_file(valid_archive, malicious_archive))
		return 0;

	f = fopen(malicious_archive, "r+b");

	if (!f)
		goto cleanup;

	if (fread(header, 1, sizeof(header), f) != sizeof(header))
		goto cleanup;

	if (memcmp(header, WPK_MAGIC, WPK_MAGIC_SIZE) != 0)
		goto cleanup;

	table_offset = read_le64(header + 30);

	if (table_offset == 0 ||
		table_offset < WPK_TEST_HEADER_SIZE)
	{
		goto cleanup;
	}

	if (table_offset > (uint64_t)LONG_MAX - WPK_TEST_ENTRY_SIZE)
		goto cleanup;

	path_offset = table_offset + WPK_TEST_ENTRY_SIZE;

	if (fseek(f, 0, SEEK_END) != 0)
		goto cleanup;

	file_size = ftell(f);

	if (file_size < 0)
		goto cleanup;

	if (path_offset > (uint64_t)file_size ||
		(uint64_t)file_size - path_offset <
		sizeof(expected_path) - 1)
	{
		goto cleanup;
	}

	if (fseek(f, (long)table_offset, SEEK_SET) != 0)
		goto cleanup;

	if (fread(entry_prefix, 1, sizeof(entry_prefix), f) !=
		sizeof(entry_prefix))
	{
		goto cleanup;
	}

	path_length = read_le16(entry_prefix);

	if (path_length != sizeof(expected_path) - 1)
		goto cleanup;

	char original_path[sizeof(expected_path)] = {0};

	if (fseek(f, (long)path_offset, SEEK_SET) != 0)
		goto cleanup;

	if (fread(
		original_path,
		1,
		sizeof(expected_path) - 1,
			  f) != sizeof(expected_path) - 1)
	{
		goto cleanup;
	}

	if (memcmp(
		original_path,
		expected_path,
		sizeof(expected_path) - 1) != 0)
	{
		goto cleanup;
	}

	if (fseek(f, (long)path_offset, SEEK_SET) != 0)
		goto cleanup;

	if (fwrite(
		malicious_path,
		1,
		sizeof(malicious_path) - 1,
			   f) != sizeof(malicious_path) - 1)
	{
		goto cleanup;
	}

	if (fflush(f) != 0)
		goto cleanup;

	result = 1;

	cleanup:
	if (f && fclose(f) != 0)
		result = 0;

	if (!result)
		remove(malicious_archive);

	return result;
}

/* -------------------------------------------------- */
/* Test data										  */
/* -------------------------------------------------- */

static const char text_data[] =
"WPK100 archive test\n"
"This file checks DEFLATE compression.\n"
"This file also checks extraction integrity.\n";

static const unsigned char binary_data[] = {
	0x00, 0x01, 0x02, 0x03,
	0x10, 0x20, 0x30, 0x40,
	0x7F, 0x80, 0xFE, 0xFF,
	0x00, 0xAA, 0x55, 0xCC
};

static const char config_data[] =
"{\n"
"	\"name\": \"WPK100\",\n"
"	\"version\": 1\n"
"}\n";

/* -------------------------------------------------- */
/* Test preparation								   */
/* -------------------------------------------------- */

static int prepare_test_files(void)
{
	if (!make_dir(TEST_ROOT))
		return 0;

	if (!make_dir(SOURCE_DIR))
		return 0;

	if (!make_dir(SOURCE_DIR "/nested"))
		return 0;

	if (!make_dir(PLAIN_DIR) ||
		!make_dir(ENCRYPTED_DIR) ||
		!make_dir(SINGLE_DIR) ||
		!make_dir(TAMPER_DIR) ||
		!make_dir(TRAVERSAL_DIR))
	{
		return 0;
	}

	if (!make_dir(BUFFER_PLAIN_DIR) ||
		!make_dir(BUFFER_UUID_DIR) ||
		!make_dir(BUFFER_ENCRYPTED_DIR) ||
		!make_dir(BUFFER_ENCRYPTED_UUID_DIR) ||
		!make_dir(BUFFER_SINGLE_DIR) ||
		!make_dir(BUFFER_SINGLE_UUID_DIR) ||
		!make_dir(BUFFER_SINGLE_ENCRYPTED_DIR) ||
		!make_dir(BUFFER_SINGLE_ENCRYPTED_UUID_DIR) ||
		!make_dir(BUFFER_TAMPER_DIR) ||
		!make_dir(BUFFER_TRAVERSAL_DIR))
	{
		return 0;
	}

	/* Remove stale archives. */
	remove(PLAIN_ARCHIVE);
	remove(ENCRYPTED_ARCHIVE);
	remove(TAMPER_ARCHIVE);
	remove(TRAVERSAL_ARCHIVE);

	remove(TRAVERSAL_OUTSIDE);

	remove(TEST_ROOT "/invalid_traversal.wpk");
	remove(TEST_ROOT "/expected_hello.txt");
	remove(TEST_ROOT "/expected_data.bin");

	/* Remove regular extraction outputs. */
	remove(PLAIN_DIR "/hello.txt");
	remove(PLAIN_DIR "/data.bin");
	remove(PLAIN_DIR "/nested/config.json");

	remove(ENCRYPTED_DIR "/hello.txt");
	remove(ENCRYPTED_DIR "/data.bin");
	remove(ENCRYPTED_DIR "/nested/config.json");

	remove(SINGLE_DIR "/data.bin");

	remove(TRAVERSAL_DIR "/hello.txt");
	remove(TRAVERSAL_DIR "/data.bin");
	remove(TRAVERSAL_DIR "/nested/config.json");

	/* Remove buffer extraction outputs. */
	remove(BUFFER_PLAIN_DIR "/hello.txt");
	remove(BUFFER_PLAIN_DIR "/data.bin");
	remove(BUFFER_PLAIN_DIR "/nested/config.json");

	remove(BUFFER_UUID_DIR "/hello.txt");
	remove(BUFFER_UUID_DIR "/data.bin");
	remove(BUFFER_UUID_DIR "/nested/config.json");

	remove(BUFFER_ENCRYPTED_DIR "/hello.txt");
	remove(BUFFER_ENCRYPTED_DIR "/data.bin");
	remove(BUFFER_ENCRYPTED_DIR "/nested/config.json");

	remove(BUFFER_ENCRYPTED_UUID_DIR "/hello.txt");
	remove(BUFFER_ENCRYPTED_UUID_DIR "/data.bin");
	remove(BUFFER_ENCRYPTED_UUID_DIR "/nested/config.json");

	remove(BUFFER_SINGLE_DIR "/data.bin");
	remove(BUFFER_SINGLE_UUID_DIR "/data.bin");

	remove(BUFFER_SINGLE_ENCRYPTED_DIR "/data.bin");
	remove(BUFFER_SINGLE_ENCRYPTED_UUID_DIR "/data.bin");

	/* Ensure nested output directories exist. */
	if (!make_dir(PLAIN_DIR "/nested") ||
		!make_dir(ENCRYPTED_DIR "/nested") ||
		!make_dir(TRAVERSAL_DIR "/nested") ||
		!make_dir(BUFFER_PLAIN_DIR "/nested") ||
		!make_dir(BUFFER_UUID_DIR "/nested") ||
		!make_dir(BUFFER_ENCRYPTED_DIR "/nested") ||
		!make_dir(BUFFER_ENCRYPTED_UUID_DIR "/nested"))
	{
		return 0;
	}

	if (!write_file(
		SOURCE_DIR "/hello.txt",
		text_data,
		sizeof(text_data) - 1))
	{
		return 0;
	}

	if (!write_file(
		SOURCE_DIR "/data.bin",
		binary_data,
		sizeof(binary_data)))
	{
		return 0;
	}

	if (!write_file(
		SOURCE_DIR "/nested/config.json",
		config_data,
		sizeof(config_data) - 1))
	{
		return 0;
	}

	return 1;
}

/* -------------------------------------------------- */
/* Memory buffer helpers							  */
/* -------------------------------------------------- */

static unsigned char *load_file_buffer(
	const char *path,
	size_t *buffer_size)
{
	FILE *f = NULL;
	unsigned char *buffer = NULL;

	long file_size;

	if (!path || !buffer_size)
		return NULL;

	*buffer_size = 0;

	f = fopen(path, "rb");

	if (!f)
		return NULL;

	if (fseek(f, 0, SEEK_END) != 0)
		goto cleanup;

	file_size = ftell(f);

	if (file_size < 0)
		goto cleanup;

	if ((uintmax_t)file_size > (uintmax_t)SIZE_MAX)
		goto cleanup;

	if (fseek(f, 0, SEEK_SET) != 0)
		goto cleanup;

	buffer = malloc(file_size == 0 ? 1 : (size_t)file_size);

	if (!buffer)
		goto cleanup;

	if (file_size != 0 &&
		fread(buffer, 1, (size_t)file_size, f) != (size_t)file_size)
	{
		free(buffer);
		buffer = NULL;
		goto cleanup;
	}

	*buffer_size = (size_t)file_size;

	cleanup:
	fclose(f);
	return buffer;
}

static void free_file_buffer(
	unsigned char *buffer,
	size_t buffer_size)
{
	if (!buffer)
		return;

	memset(buffer, 0, buffer_size);
	free(buffer);
}

/* -------------------------------------------------- */
/* Public Buffer Extraction API Tests				 */
/* -------------------------------------------------- */

static void test_buffer_extraction(
	const char *plain_archive,
	const char *encrypted_archive,
	const char *traversal_archive,
	const char *source_dir,
	const wpk_uuid_t plain_uuid,
	const wpk_uuid_t encrypted_uuid,
	const wpk_uuid_t wrong_uuid)
{
	size_t plain_size = 0;
	size_t encrypted_size = 0;
	size_t traversal_size = 0;

	unsigned char *plain_buffer = NULL;
	unsigned char *encrypted_buffer = NULL;
	unsigned char *traversal_buffer = NULL;

	char source_hello[512];
	char source_binary[512];
	char source_config[512];

	char plain_hello[512];
	char plain_binary[512];
	char plain_config[512];

	char uuid_hello[512];
	char uuid_binary[512];
	char uuid_config[512];

	char encrypted_hello[512];
	char encrypted_binary[512];
	char encrypted_config[512];

	char encrypted_uuid_hello[512];
	char encrypted_uuid_binary[512];
	char encrypted_uuid_config[512];

	char single_binary[512];
	char single_uuid_binary[512];

	char encrypted_single_binary[512];
	char encrypted_single_uuid_binary[512];

	snprintf(source_hello, sizeof(source_hello),
			 "%s/hello.txt", source_dir);

	snprintf(source_binary, sizeof(source_binary),
			 "%s/data.bin", source_dir);

	snprintf(source_config, sizeof(source_config),
			 "%s/nested/config.json", source_dir);

	snprintf(plain_hello, sizeof(plain_hello),
			 "%s/hello.txt", BUFFER_PLAIN_DIR);

	snprintf(plain_binary, sizeof(plain_binary),
			 "%s/data.bin", BUFFER_PLAIN_DIR);

	snprintf(plain_config, sizeof(plain_config),
			 "%s/nested/config.json", BUFFER_PLAIN_DIR);

	snprintf(uuid_hello, sizeof(uuid_hello),
			 "%s/hello.txt", BUFFER_UUID_DIR);

	snprintf(uuid_binary, sizeof(uuid_binary),
			 "%s/data.bin", BUFFER_UUID_DIR);

	snprintf(uuid_config, sizeof(uuid_config),
			 "%s/nested/config.json", BUFFER_UUID_DIR);

	snprintf(encrypted_hello, sizeof(encrypted_hello),
			 "%s/hello.txt", BUFFER_ENCRYPTED_DIR);

	snprintf(encrypted_binary, sizeof(encrypted_binary),
			 "%s/data.bin", BUFFER_ENCRYPTED_DIR);

	snprintf(encrypted_config, sizeof(encrypted_config),
			 "%s/nested/config.json", BUFFER_ENCRYPTED_DIR);

	snprintf(encrypted_uuid_hello, sizeof(encrypted_uuid_hello),
			 "%s/hello.txt", BUFFER_ENCRYPTED_UUID_DIR);

	snprintf(encrypted_uuid_binary, sizeof(encrypted_uuid_binary),
			 "%s/data.bin", BUFFER_ENCRYPTED_UUID_DIR);

	snprintf(encrypted_uuid_config, sizeof(encrypted_uuid_config),
			 "%s/nested/config.json", BUFFER_ENCRYPTED_UUID_DIR);

	snprintf(single_binary, sizeof(single_binary),
			 "%s/data.bin", BUFFER_SINGLE_DIR);

	snprintf(single_uuid_binary, sizeof(single_uuid_binary),
			 "%s/data.bin", BUFFER_SINGLE_UUID_DIR);

	snprintf(encrypted_single_binary,
			 sizeof(encrypted_single_binary),
			 "%s/data.bin", BUFFER_SINGLE_ENCRYPTED_DIR);

	snprintf(encrypted_single_uuid_binary,
			 sizeof(encrypted_single_uuid_binary),
			 "%s/data.bin", BUFFER_SINGLE_ENCRYPTED_UUID_DIR);

	printf("\n====================================\n");
	printf("   PUBLIC BUFFER EXTRACTION TESTS\n");
	printf("====================================\n\n");

	/* ------------------------------------------ */
	/* Load archives into memory				  */
	/* ------------------------------------------ */

	plain_buffer = load_file_buffer(plain_archive, &plain_size);
	encrypted_buffer = load_file_buffer(encrypted_archive, &encrypted_size);
	traversal_buffer = load_file_buffer(traversal_archive, &traversal_size);

	CHECK(plain_buffer != NULL,
		  "Load unencrypted archive into memory");

	CHECK(encrypted_buffer != NULL,
		  "Load encrypted archive into memory");

	CHECK(traversal_buffer != NULL,
		  "Load traversal archive into memory");

	if (!plain_buffer || !encrypted_buffer || !traversal_buffer)
		goto cleanup;

	/* ------------------------------------------ */
	/* wpk_extract_buffer						 */
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer(
			plain_buffer,
			plain_size,
			BUFFER_PLAIN_DIR),
		  "Extract unencrypted archive from memory");

	CHECK(
		files_equal(source_hello, plain_hello),
		  "Verify buffer-extracted text file");

	CHECK(
		files_equal(source_binary, plain_binary),
		  "Verify buffer-extracted binary file");

	CHECK(
		files_equal(source_config, plain_config),
		  "Verify buffer-extracted nested file");

	CHECK(
		wpk_extract_buffer(
			plain_buffer,
			plain_size,
			BUFFER_PLAIN_DIR) == 0,
		  "Reject overwrite using buffer extraction");

	/* ------------------------------------------ */
	/* wpk_extract_buffer_uuid					*/
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer_uuid(
			plain_buffer,
			plain_size,
			BUFFER_TAMPER_DIR,
			wrong_uuid) == 0,
		  "Reject incorrect UUID in buffer extraction");

	CHECK(
		wpk_extract_buffer_uuid(
			plain_buffer,
			plain_size,
			BUFFER_UUID_DIR,
			plain_uuid),
		  "Extract unencrypted buffer using UUID");

	CHECK(
		files_equal(source_hello, uuid_hello) &&
		files_equal(source_binary, uuid_binary) &&
		files_equal(source_config, uuid_config),
		  "Verify UUID buffer extraction");

	CHECK(
		wpk_extract_buffer_uuid(
			plain_buffer,
			plain_size,
			BUFFER_UUID_DIR,
			plain_uuid) == 0,
		  "Reject overwrite using UUID buffer extraction");

	/* ------------------------------------------ */
	/* wpk_extract_buffer_file					*/
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer_file(
			plain_buffer,
			plain_size,
			1,
			BUFFER_SINGLE_DIR),
		  "Extract one unencrypted file from memory");

	CHECK(
		files_equal(source_binary, single_binary),
		  "Verify single-file buffer extraction");

	CHECK(
		wpk_extract_buffer_file(
			plain_buffer,
			plain_size,
			1,
			BUFFER_SINGLE_DIR) == 0,
		  "Reject overwrite during single-file buffer extraction");

	CHECK(
		wpk_extract_buffer_file(
			plain_buffer,
			plain_size,
			100,
			BUFFER_TAMPER_DIR) == 0,
		  "Reject invalid buffer file index");

	/* ------------------------------------------ */
	/* wpk_extract_buffer_file_uuid			   */
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer_file_uuid(
			plain_buffer,
			plain_size,
			1,
			BUFFER_SINGLE_UUID_DIR,
			plain_uuid),
		  "Extract one unencrypted file using UUID");

	CHECK(
		files_equal(source_binary, single_uuid_binary),
		  "Verify single-file UUID buffer extraction");

	CHECK(
		wpk_extract_buffer_file_uuid(
			plain_buffer,
			plain_size,
			1,
			BUFFER_SINGLE_UUID_DIR,
			plain_uuid) == 0,
		  "Reject overwrite during UUID single-file extraction");

	CHECK(
		wpk_extract_buffer_file_uuid(
			plain_buffer,
			plain_size,
			100,
			BUFFER_TAMPER_DIR,
			plain_uuid) == 0,
		  "Reject invalid UUID buffer file index");

	/* ------------------------------------------ */
	/* Encrypted archive: no password			 */
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer(
			encrypted_buffer,
			encrypted_size,
			BUFFER_TAMPER_DIR) == 0,
		  "Reject encrypted buffer without password");

	/* ------------------------------------------ */
	/* wpk_extract_buffer_password				*/
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer_password(
			encrypted_buffer,
			encrypted_size,
			BUFFER_TAMPER_DIR,
			"WrongPassword") == 0,
		  "Reject incorrect buffer password");

	CHECK(
		wpk_extract_buffer_password(
			encrypted_buffer,
			encrypted_size,
			BUFFER_ENCRYPTED_DIR,
			TEST_PASSWORD),
		  "Extract encrypted archive from memory");

	CHECK(
		files_equal(source_hello, encrypted_hello) &&
		files_equal(source_binary, encrypted_binary) &&
		files_equal(source_config, encrypted_config),
		  "Verify decrypted buffer extraction");

	CHECK(
		wpk_extract_buffer_password(
			encrypted_buffer,
			encrypted_size,
			BUFFER_ENCRYPTED_DIR,
			TEST_PASSWORD) == 0,
		  "Reject overwrite during encrypted buffer extraction");

	/* ------------------------------------------ */
	/* wpk_extract_buffer_password_uuid		   */
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer_password_uuid(
			encrypted_buffer,
			encrypted_size,
			BUFFER_TAMPER_DIR,
			wrong_uuid,
			TEST_PASSWORD) == 0,
		  "Reject incorrect UUID for encrypted buffer");

	CHECK(
		wpk_extract_buffer_password_uuid(
			encrypted_buffer,
			encrypted_size,
			BUFFER_ENCRYPTED_UUID_DIR,
			encrypted_uuid,
			TEST_PASSWORD),
		  "Extract encrypted buffer using password and UUID");

	CHECK(
		files_equal(source_hello, encrypted_uuid_hello) &&
		files_equal(source_binary, encrypted_uuid_binary) &&
		files_equal(source_config, encrypted_uuid_config),
		  "Verify encrypted password-and-UUID extraction");

	CHECK(
		wpk_extract_buffer_password_uuid(
			encrypted_buffer,
			encrypted_size,
			BUFFER_ENCRYPTED_UUID_DIR,
			encrypted_uuid,
			TEST_PASSWORD) == 0,
		  "Reject overwrite during encrypted UUID extraction");

	/* ------------------------------------------ */
	/* wpk_extract_buffer_file_password		   */
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer_file_password(
			encrypted_buffer,
			encrypted_size,
			1,
			BUFFER_SINGLE_ENCRYPTED_DIR,
			TEST_PASSWORD),
		  "Extract one encrypted file from memory");

	CHECK(
		files_equal(source_binary, encrypted_single_binary),
		  "Verify encrypted single-file buffer extraction");

	CHECK(
		wpk_extract_buffer_file_password(
			encrypted_buffer,
			encrypted_size,
			1,
			BUFFER_SINGLE_ENCRYPTED_DIR,
			TEST_PASSWORD) == 0,
		  "Reject overwrite during encrypted single-file extraction");

	CHECK(
		wpk_extract_buffer_file_password(
			encrypted_buffer,
			encrypted_size,
			100,
			BUFFER_TAMPER_DIR,
			TEST_PASSWORD) == 0,
		  "Reject invalid encrypted buffer file index");

	/* ------------------------------------------ */
	/* wpk_extract_buffer_file_password_uuid	  */
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer_file_password_uuid(
			encrypted_buffer,
			encrypted_size,
			1,
			BUFFER_SINGLE_ENCRYPTED_UUID_DIR,
			encrypted_uuid,
			TEST_PASSWORD),
		  "Extract encrypted single file using password and UUID");

	CHECK(
		files_equal(source_binary, encrypted_single_uuid_binary),
		  "Verify encrypted single-file UUID extraction");

	CHECK(
		wpk_extract_buffer_file_password_uuid(
			encrypted_buffer,
			encrypted_size,
			1,
			BUFFER_SINGLE_ENCRYPTED_UUID_DIR,
			encrypted_uuid,
			TEST_PASSWORD) == 0,
			"Reject overwrite during encrypted UUID single-file extraction");

	CHECK(
		wpk_extract_buffer_file_password_uuid(
			encrypted_buffer,
			encrypted_size,
			100,
			BUFFER_TAMPER_DIR,
			encrypted_uuid,
			TEST_PASSWORD) == 0,
			"Reject invalid encrypted UUID buffer file index");

	/* ------------------------------------------ */
	/* Invalid arguments						  */
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer(
			NULL,
			plain_size,
			BUFFER_TAMPER_DIR) == 0,
			"Reject NULL input buffer");

	CHECK(
		wpk_extract_buffer(
			plain_buffer,
			plain_size,
			NULL) == 0,
			"Reject NULL output directory");

	CHECK(
		wpk_extract_buffer_uuid(
			plain_buffer,
			plain_size,
			BUFFER_TAMPER_DIR,
			NULL) == 0,
			"Reject NULL expected UUID");

	CHECK(
		wpk_extract_buffer_password(
			encrypted_buffer,
			encrypted_size,
			BUFFER_TAMPER_DIR,
			NULL) == 0,
			"Reject NULL password");

	/* ------------------------------------------ */
	/* Truncated buffers						  */
	/* ------------------------------------------ */

	CHECK(
		plain_size >= WPK_TEST_HEADER_SIZE &&
		wpk_extract_buffer(
			plain_buffer,
			WPK_TEST_HEADER_SIZE - 1,
			BUFFER_TAMPER_DIR) == 0,
			"Reject truncated archive header");

	CHECK(
		plain_size > 0 &&
		wpk_extract_buffer(
			plain_buffer,
			plain_size - 1,
			BUFFER_TAMPER_DIR) == 0,
			"Reject truncated unencrypted archive");

	CHECK(
		encrypted_size > 0 &&
		wpk_extract_buffer_password(
			encrypted_buffer,
			encrypted_size - 1,
			BUFFER_TAMPER_DIR,
			TEST_PASSWORD) == 0,
			"Reject truncated encrypted archive");

	/* ------------------------------------------ */
	/* Path traversal							 */
	/* ------------------------------------------ */

	CHECK(
		wpk_extract_buffer_uuid(
			traversal_buffer,
			traversal_size,
			BUFFER_TRAVERSAL_DIR,
			plain_uuid) == 0,
			"Reject path traversal in buffer archive");

	CHECK(
		!file_exists(TRAVERSAL_OUTSIDE),
		  "Verify buffer extraction did not create outside file");

	cleanup:
	free_file_buffer(plain_buffer, plain_size);
	free_file_buffer(encrypted_buffer, encrypted_size);
	free_file_buffer(traversal_buffer, traversal_size);
}

/* -------------------------------------------------- */
/* Main test suite									*/
/* -------------------------------------------------- */

int main(void)
{
	const char *source_files[] = {
		SOURCE_DIR "/hello.txt",
		SOURCE_DIR "/data.bin",
		SOURCE_DIR "/nested/config.json"
	};

	const char *archive_paths[] = {
		"hello.txt",
		"data.bin",
		"nested/config.json"
	};

	const size_t file_count =
	sizeof(source_files) / sizeof(source_files[0]);

	wpk_uuid_t plain_uuid = {0};
	wpk_uuid_t encrypted_uuid = {0};
	wpk_uuid_t wrong_uuid = {0};
	wpk_uuid_t traversal_uuid = {0};

	WPK_COMPRESS_OPTIONS plain_options = {
		.level = WPK_DEFAULT_LEVEL,
		.password = NULL,
		.pbkdf2_iterations = 0
	};

	WPK_COMPRESS_OPTIONS encrypted_options = {
		.level = WPK_DEFAULT_LEVEL,
		.password = TEST_PASSWORD,
		.pbkdf2_iterations = 600000
	};

	printf("\n====================================\n");
	printf("	   %s TEST SUITE\n", WPK_MAGIC);
	printf("====================================\n\n");

	CHECK(
		prepare_test_files(),
		  "Prepare test directories and source files");

	if (tests_passed != tests_run)
		goto finish;

	/* ---------------------------------------------- */
	/* UUID tests									 */
	/* ---------------------------------------------- */

	CHECK(
		wpk_uuid_generate(wrong_uuid),
		  "Generate UUID");

	/* ---------------------------------------------- */
	/* Unencrypted archive tests					  */
	/* ---------------------------------------------- */

	CHECK(
		wpk_compress_files_ex(
			PLAIN_ARCHIVE,
			source_files,
			archive_paths,
			file_count,
			&plain_options,
			plain_uuid),
		  "Create unencrypted archive");

	if (!file_exists(PLAIN_ARCHIVE))
		goto finish;

	CHECK(
		wpk_uuid_generate(wrong_uuid) &&
		!wpk_uuid_equal(plain_uuid, wrong_uuid),
		  "Generate a UUID different from archive UUID");

	CHECK(
		wpk_extract_uuid(
			PLAIN_ARCHIVE,
			PLAIN_DIR,
			plain_uuid),
		  "Extract unencrypted archive using UUID");

	CHECK(
		files_equal(
			SOURCE_DIR "/hello.txt",
			PLAIN_DIR "/hello.txt"),
		  "Verify extracted text file");

	CHECK(
		files_equal(
			SOURCE_DIR "/data.bin",
			PLAIN_DIR "/data.bin"),
		  "Verify extracted binary file");

	CHECK(
		files_equal(
			SOURCE_DIR "/nested/config.json",
			PLAIN_DIR "/nested/config.json"),
		  "Verify extracted nested file");

	CHECK(
		!wpk_extract_uuid(
			PLAIN_ARCHIVE,
			TAMPER_DIR,
			wrong_uuid),
		  "Reject incorrect UUID");

	CHECK(
		!wpk_extract_file_uuid(
			PLAIN_ARCHIVE,
			(uint32_t)file_count,
							   TAMPER_DIR,
							   plain_uuid),
		  "Reject invalid file index");

	CHECK(
		wpk_extract_file_uuid(
			PLAIN_ARCHIVE,
			1,
			SINGLE_DIR,
			plain_uuid),
		  "Extract one unencrypted file");

	CHECK(
		files_equal(
			SOURCE_DIR "/data.bin",
			SINGLE_DIR "/data.bin"),
		  "Verify single-file extraction");

	CHECK(
		!wpk_extract_uuid(
			PLAIN_ARCHIVE,
			PLAIN_DIR,
			plain_uuid),
		  "Refuse to overwrite existing extracted files");

	/* ---------------------------------------------- */
	/* Path traversal tests						   */
	/* ---------------------------------------------- */

	const char *bad_archive_paths[] = {
		"../ab.txt"
	};

	CHECK(
		!wpk_compress_files_ex(
			TEST_ROOT "/invalid_traversal.wpk",
			source_files,
			bad_archive_paths,
			1,
			&plain_options,
			traversal_uuid),
		  "Reject path traversal during compression");

	CHECK(
		create_traversal_archive(
			PLAIN_ARCHIVE,
			TRAVERSAL_ARCHIVE),
		  "Construct malicious archive with traversal path");

	CHECK(
		!wpk_extract_uuid(
			TRAVERSAL_ARCHIVE,
			TRAVERSAL_DIR,
			plain_uuid),
		  "Reject malicious archive containing traversal path");

	CHECK(
		!file_exists(TRAVERSAL_OUTSIDE),
		  "Verify extraction did not create file outside output directory");

	/* ---------------------------------------------- */
	/* Encrypted archive tests						*/
	/* ---------------------------------------------- */

	CHECK(
		wpk_compress_files_ex(
			ENCRYPTED_ARCHIVE,
			source_files,
			archive_paths,
			file_count,
			&encrypted_options,
			encrypted_uuid),
		  "Create encrypted archive");

	if (!file_exists(ENCRYPTED_ARCHIVE))
		goto finish;

	CHECK(
		!wpk_uuid_equal(plain_uuid, encrypted_uuid),
		  "Generate distinct UUIDs for separate archives");

	CHECK(
		!wpk_extract_uuid(
			ENCRYPTED_ARCHIVE,
			TAMPER_DIR,
			encrypted_uuid),
		  "Reject encrypted archive without password");

	CHECK(
		!wpk_extract_password_uuid(
			ENCRYPTED_ARCHIVE,
			TAMPER_DIR,
			wrong_uuid,
			TEST_PASSWORD),
		  "Reject encrypted archive with incorrect UUID");

	CHECK(
		!wpk_extract_password_uuid(
			ENCRYPTED_ARCHIVE,
			TAMPER_DIR,
			encrypted_uuid,
			"WrongPassword"),
		  "Reject incorrect password");

	CHECK(
		wpk_extract_password_uuid(
			ENCRYPTED_ARCHIVE,
			ENCRYPTED_DIR,
			encrypted_uuid,
			TEST_PASSWORD),
		  "Extract encrypted archive using password");

	CHECK(
		files_equal(
			SOURCE_DIR "/hello.txt",
			ENCRYPTED_DIR "/hello.txt"),
		  "Verify decrypted text file");

	CHECK(
		files_equal(
			SOURCE_DIR "/data.bin",
			ENCRYPTED_DIR "/data.bin"),
		  "Verify decrypted binary file");

	CHECK(
		files_equal(
			SOURCE_DIR "/nested/config.json",
			ENCRYPTED_DIR "/nested/config.json"),
		  "Verify decrypted nested file");

	CHECK(
		wpk_extract_file_password_uuid(
			ENCRYPTED_ARCHIVE,
			1,
			SINGLE_DIR,
			encrypted_uuid,
			TEST_PASSWORD) == 0,
		  "Refuse to overwrite existing single-file output");

	/* ---------------------------------------------- */
	/* Buffer extraction tests						*/
	/* ---------------------------------------------- */

	test_buffer_extraction(
		PLAIN_ARCHIVE,
		ENCRYPTED_ARCHIVE,
		TRAVERSAL_ARCHIVE,
		SOURCE_DIR,
		plain_uuid,
		encrypted_uuid,
		wrong_uuid);

	/* ---------------------------------------------- */
	/* Tampering tests								*/
	/* ---------------------------------------------- */

	CHECK(
		copy_file(
			ENCRYPTED_ARCHIVE,
			TAMPER_ARCHIVE),
		  "Copy encrypted archive for tampering test");

	CHECK(
		flip_archive_byte(
			TAMPER_ARCHIVE,
			WPK_TEST_HEADER_SIZE),
		  "Modify encrypted payload");

	CHECK(
		!wpk_extract_password_uuid(
			TAMPER_ARCHIVE,
			TAMPER_DIR,
			encrypted_uuid,
			TEST_PASSWORD),
		  "Reject modified encrypted payload");

	/* ---------------------------------------------- */
	/* Source integrity							   */
	/* ---------------------------------------------- */

	CHECK(
		write_file(
			TEST_ROOT "/expected_hello.txt",
			text_data,
			sizeof(text_data) - 1) &&
			files_equal(
				SOURCE_DIR "/hello.txt",
				TEST_ROOT "/expected_hello.txt"),
		  "Verify original source text was not modified");

	CHECK(
		write_file(
			TEST_ROOT "/expected_data.bin",
			binary_data,
			sizeof(binary_data)) &&
			files_equal(
				SOURCE_DIR "/data.bin",
				TEST_ROOT "/expected_data.bin"),
		  "Verify original source binary was not modified");

	finish:

	printf("\n====================================\n");
	printf("			 RESULTS\n");
	printf("====================================\n");

	printf("Tests passed: %d\n", tests_passed);
	printf("Tests failed: %d\n", tests_run - tests_passed);
	printf("Total tests:  %d\n", tests_run);

	printf("====================================\n");

	return tests_passed == tests_run ? 0 : 1;
}
