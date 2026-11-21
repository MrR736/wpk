#include <string.h>

#include "wpk_uuid.h"

#ifdef _WIN32
#include <windows.h>
#include <objbase.h>

int wpk_uuid_generate(wpk_uuid_t uuid) {
	if (!uuid) return 0;

	GUID guid;
	if (CoCreateGuid(&guid) != S_OK) return 0;

	uuid[0] = (uint8_t)(guid.Data1 >> 24);
	uuid[1] = (uint8_t)(guid.Data1 >> 16);
	uuid[2] = (uint8_t)(guid.Data1 >> 8);
	uuid[3] = (uint8_t)(guid.Data1);
	uuid[4] = (uint8_t)(guid.Data2 >> 8);
	uuid[5] = (uint8_t)(guid.Data2);
	uuid[6] = (uint8_t)(guid.Data3 >> 8);
	uuid[7] = (uint8_t)(guid.Data3);
	memcpy(uuid + 8, guid.Data4, 8);
	return 1;
}
#else
#ifndef __has_include
#define __has_include(x) 0
#endif

#ifdef __ANDROID__
#include <stddef.h>
#if defined(__ANDROID_API__) && __ANDROID_API__ >= 28
#include <sys/random.h>
#include <errno.h>
#else
#include <stdio.h>
#endif
#elif __has_include(<uuid/uuid.h>)
#include <uuid/uuid.h>
#else
#include <stdio.h>
#endif

int wpk_uuid_generate(wpk_uuid_t uuid) {
	if (uuid == NULL) return 0;
#ifdef __ANDROID__
# if defined(__ANDROID_API__) && __ANDROID_API__ >= 28
	size_t offset = 0;

	while (offset < WPK_UUID_SIZE) {
		ssize_t result = getrandom(uuid + offset,WPK_UUID_SIZE - offset,0);
		if (result > 0) {
			offset += (size_t)result;
			continue;
		}
		if (result < 0 && errno == EINTR) continue;
		return 0;
	}
# else
	FILE *file = fopen("/dev/urandom", "rb");
	if (file == NULL) return 0;
	size_t count = fread(uuid, 1, WPK_UUID_SIZE, file);
	int failed = (count != WPK_UUID_SIZE || ferror(file));
	if (fclose(file) != 0) failed = 1;
	if (failed) return 0;
# endif

	/* UUID version 4 */
	uuid[6] = (uint8_t)((uuid[6] & 0x0F) | 0x40);

	/* RFC-compatible variant */
	uuid[8] = (uint8_t)((uuid[8] & 0x3F) | 0x80);

	return 1;
#elif __has_include(<uuid/uuid.h>)
	uuid_t generated;
	uuid_generate_random(generated);
	memcpy(uuid, generated, WPK_UUID_SIZE);
	return 1;
#else
	FILE *file = fopen("/dev/urandom", "rb");
	if (file == NULL) return 0;
	size_t count = fread(uuid, 1, WPK_UUID_SIZE, file);
	int failed = (count != WPK_UUID_SIZE || ferror(file));
	if (fclose(file) != 0) failed = 1;
	if (failed) return 0;

	/* UUID version 4 */
	uuid[6] = (uint8_t)((uuid[6] & 0x0F) | 0x40);

	/* RFC-compatible variant */
	uuid[8] = (uint8_t)((uuid[8] & 0x3F) | 0x80);

	return 1;
#endif
}
#endif

int wpk_uuid_equal(const wpk_uuid_t a,const wpk_uuid_t b) {
	if (!a || !b) return 0;
	return memcmp(a, b, WPK_UUID_SIZE) == 0;
}

static int wpk_uuid_hex_value(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int wpk_uuid_parse(const char *str,wpk_uuid_t uuid) {
	static const unsigned char hyphen_positions[] = {8, 13, 18, 23};
	size_t i;
	size_t j;
	int high;
	int low;

	if (str == NULL) return 0;

	/* Canonical UUID string: 36 characters + null terminator. */
	if (strlen(str) != 36) return 0;

	/* Validate hyphen positions. */
	for (i = 0; i < sizeof(hyphen_positions); ++i) {
		if (str[hyphen_positions[i]] != '-') return 0;
	}

	j = 0;

	for (i = 0; i < 36;) {
		if (str[i] == '-') {
			++i;
			continue;
		}

		high = wpk_uuid_hex_value(str[i]);
		low  = wpk_uuid_hex_value(str[i + 1]);

		if (high < 0 || low < 0) return 0;

		uuid[j++] = (uint8_t)((high << 4) | low);

		i += 2;
	}

	return j == WPK_UUID_SIZE;
}

int wpk_uuid_to_string(const wpk_uuid_t uuid,char *output) {
	static const char hex[] = "0123456789abcdef";
	static const unsigned char hyphen_positions[] = {8, 13, 18, 23};

	size_t i;
	size_t j;
	size_t k;

	if (output == NULL) return 0;

	j = 0;
	k = 0;

	for (i = 0; i < 36; ++i) {
		if (k < sizeof(hyphen_positions) &&
			i == hyphen_positions[k]) {
			output[i] = '-';
			++k;
			continue;
		}

		output[i] = hex[uuid[j] >> 4];
		output[i + 1] = hex[uuid[j] & 0x0F];

		++j;
		++i;
	}

	output[36] = '\0';

	return j == WPK_UUID_SIZE;
}
