#ifndef WPK_UUID_H
#define WPK_UUID_H

#include <stdint.h>

#define WPK_UUID_SIZE 16
#define WPK_UUID_STRING_SIZE 37

#ifdef __cplusplus
using wpk_uuid_t = uint8_t[WPK_UUID_SIZE];
#else
typedef uint8_t wpk_uuid_t[WPK_UUID_SIZE];
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generate a random UUID v4.
 *
 * Returns:
 *   1 = success
 *   0 = failure
 */
int wpk_uuid_generate(wpk_uuid_t uuid);

/*
 * Compare two UUIDs.
 *
 * Returns:
 *   1 = equal
 *   0 = different or invalid arguments
 */
int wpk_uuid_equal(const wpk_uuid_t a,const wpk_uuid_t b);

/*
 * Parse a UUID string.
 *
 * Expected format:
 *   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 *
 * Returns:
 *   1 = success
 *   0 = invalid input
 */
int wpk_uuid_parse(const char *str,wpk_uuid_t uuid);

/*
 * Convert UUID to a lowercase string.
 *
 * output must contain at least 37 bytes.
 *
 * Returns:
 *   1 = success
 *   0 = invalid input
 */
int wpk_uuid_to_string(const wpk_uuid_t uuid,char *output);

#ifdef __cplusplus
}
#endif

#endif
