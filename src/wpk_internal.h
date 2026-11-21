#ifndef WPK_INTERNAL_H
#define WPK_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <mbedtls/pkcs5.h>
#include <psa/crypto.h>

#include "miniz/miniz.h"
#include "wpk.h"

#define WPK_HEADER_SIZE 64
#define WPK_ENTRY_FIXED_SIZE 64

#define WPK_FLAG_ENCRYPTED 0x00000001u
#define WPK_FLAG_COMPRESSED 0x00000002u

#define WPK_KEY_SIZE 32
#define WPK_SALT_SIZE 16
#define WPK_NONCE_SIZE 12
#define WPK_TAG_SIZE 16

#define WPK_DEFAULT_ITER 600000
#define WPK_MAX_PATH 4096
#define WPK_MAX_FILES 100000

typedef struct WPK_INTERNAL_ENTRY {
	char *path;
    uint8_t *data;

	uint16_t path_len;
	uint16_t flags;

	uint64_t original_size;
	uint64_t compressed_size;
	uint64_t data_offset;

	uint64_t timestamp; /* UTC Unix timestamp */

	uint8_t nonce[WPK_NONCE_SIZE];
	uint8_t tag[WPK_TAG_SIZE];
} WPK_INTERNAL_ENTRY;

struct WPK_READER {
	const char *path;
	FILE *file;

	const uint8_t *memory;
	size_t memory_size;
	int memory_backed;

	wpk_uuid_t uuid;

	uint32_t version;
	uint32_t file_count;
	uint32_t flags;
	uint32_t pbkdf2_iterations;

	uint64_t table_offset;
	uint64_t archive_size;

	uint8_t salt[WPK_SALT_SIZE];

	uint8_t key[WPK_KEY_SIZE];
	int has_key;

	WPK_INTERNAL_ENTRY *entries;
};

typedef struct WPK_GCM_DECRYPT_CTX {
	psa_aead_operation_t operation;
	psa_key_id_t key_id;
	int active;
} WPK_GCM_DECRYPT_CTX;

#ifdef __cplusplus
extern "C" {
#endif

void secure_zero(void *ptr, size_t size);

int wpk_random_bytes(uint8_t *buffer, size_t size);

int wpk_crypto_init(void);

int wpk_derive_key(
	const char *password,
	const uint8_t salt[WPK_SALT_SIZE],
	uint32_t iterations,
	uint8_t key[WPK_KEY_SIZE]
);

int wpk_aes_gcm_encrypt(
	const uint8_t key[WPK_KEY_SIZE],
	const uint8_t nonce[WPK_NONCE_SIZE],
	const uint8_t *aad,
	size_t aad_size,
	const uint8_t *plaintext,
	size_t plaintext_size,
	uint8_t *ciphertext,
	uint8_t tag[WPK_TAG_SIZE]
);

int wpk_aes_gcm_decrypt(
	const uint8_t key[WPK_KEY_SIZE],
	const uint8_t nonce[WPK_NONCE_SIZE],
	const uint8_t *aad,
	size_t aad_size,
	const uint8_t *input,
	size_t input_size,
	const uint8_t tag[WPK_TAG_SIZE],
	uint8_t *output
);

int wpk_aes_gcm_decrypt_start(
	WPK_GCM_DECRYPT_CTX *ctx,
	const uint8_t key[WPK_KEY_SIZE],
	const uint8_t nonce[WPK_NONCE_SIZE],
	const uint8_t *aad,
	size_t aad_size);

int wpk_aes_gcm_decrypt_update(
	WPK_GCM_DECRYPT_CTX *ctx,
	const uint8_t *input,
	size_t input_size,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_size);

int wpk_aes_gcm_decrypt_finish(
	WPK_GCM_DECRYPT_CTX *ctx,
	const uint8_t tag[WPK_TAG_SIZE]);

void wpk_aes_gcm_decrypt_abort(WPK_GCM_DECRYPT_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif
