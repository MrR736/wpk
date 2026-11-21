#include <psa/crypto.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include "wpk_internal.h"

void secure_zero(void *ptr, size_t size) {
	volatile unsigned char *p =
	(volatile unsigned char *)ptr;
	if (!p) return;
	while (size--) *p++ = 0;
}

int wpk_random_bytes(uint8_t *output, size_t size) {
	if (!output && size != 0) return 0;
	return psa_generate_random(output, size) == PSA_SUCCESS;
}

int wpk_crypto_init(void) {
	return psa_crypto_init() == PSA_SUCCESS;
}

int wpk_derive_key(
	const char *password,
	const uint8_t salt[WPK_SALT_SIZE],
	uint32_t iterations,
	uint8_t key[WPK_KEY_SIZE]
) {
	size_t password_len;
	int ret;

	if (!password || !salt || !key || iterations == 0) return 0;

	password_len = strlen(password);

	if (password_len == 0) return 0;

	ret = mbedtls_pkcs5_pbkdf2_hmac_ext(
		MBEDTLS_MD_SHA256,
		(const unsigned char *)password,
		password_len,
		salt,
		WPK_SALT_SIZE,
		iterations,
		WPK_KEY_SIZE,
		key
	);

	if (ret != 0) {
		secure_zero(key, WPK_KEY_SIZE);
		return 0;
	}

	return 1;
}

int wpk_aes_gcm_encrypt(
	const uint8_t key[WPK_KEY_SIZE],
	const uint8_t nonce[WPK_NONCE_SIZE],
	const uint8_t *aad,
	size_t aad_size,
	const uint8_t *plaintext,
	size_t plaintext_size,
	uint8_t *ciphertext,
	uint8_t tag[WPK_TAG_SIZE]
) {
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_key_id_t key_id = 0;
	psa_status_t status;

	uint8_t *combined = NULL;
	size_t combined_size;
	size_t output_size = 0;

	int success = 0;

	if (!key || !nonce || !ciphertext || !tag) return 0;

	if ((!aad && aad_size) || (!plaintext && plaintext_size)) return 0;

	if (plaintext_size > SIZE_MAX - WPK_TAG_SIZE) return 0;

	combined_size = plaintext_size + WPK_TAG_SIZE;

	combined = malloc(combined_size ? combined_size : 1);

	if (!combined) return 0;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 256);
	psa_set_key_usage_flags(&attributes,PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

	status = psa_import_key(&attributes,key,WPK_KEY_SIZE,&key_id);
	if (status != PSA_SUCCESS) goto cleanup;

	status = psa_aead_encrypt(
		key_id,
		PSA_ALG_GCM,
		nonce,
		WPK_NONCE_SIZE,
		aad,
		aad_size,
		plaintext,
		plaintext_size,
		combined,
		combined_size,
		&output_size
	);

	if (status != PSA_SUCCESS) goto cleanup;

	if (output_size != combined_size) goto cleanup;

	if (plaintext_size) memcpy(ciphertext, combined, plaintext_size);

	memcpy(tag,combined + plaintext_size,WPK_TAG_SIZE);

	success = 1;

cleanup:
	if (key_id != 0) psa_destroy_key(key_id);

	psa_reset_key_attributes(&attributes);

	secure_zero(combined, combined_size);
	free(combined);

	if (!success) {
		if (plaintext_size) secure_zero(ciphertext, plaintext_size);
		secure_zero(tag, WPK_TAG_SIZE);
	}

	return success;
}

int wpk_aes_gcm_decrypt(
	const uint8_t key[WPK_KEY_SIZE],
	const uint8_t nonce[WPK_NONCE_SIZE],
	const uint8_t *aad,
	size_t aad_size,
	const uint8_t *input,
	size_t input_size,
	const uint8_t tag[WPK_TAG_SIZE],
	uint8_t *output
) {
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_key_id_t key_id = 0;
	psa_status_t status;

	uint8_t *combined = NULL;
	size_t combined_size;
	size_t output_size = 0;

	int success = 0;

	if (!key || !nonce || !tag || !output) return 0;

	if ((!aad && aad_size) || (!input && input_size)) return 0;

	if (input_size > SIZE_MAX - WPK_TAG_SIZE) return 0;

	combined_size = input_size + WPK_TAG_SIZE;

	combined = malloc(combined_size);

	if (!combined) return 0;

	if (input_size) memcpy(combined, input, input_size);

	memcpy(combined + input_size,tag,WPK_TAG_SIZE);

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 256);
	psa_set_key_usage_flags(&attributes,PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

	status = psa_import_key(&attributes,key,WPK_KEY_SIZE,&key_id);

	if (status != PSA_SUCCESS) goto cleanup;

	status = psa_aead_decrypt(
		key_id,
		PSA_ALG_GCM,
		nonce,
		WPK_NONCE_SIZE,
		aad,
		aad_size,
		combined,
		combined_size,
		output,
		input_size,
		&output_size
	);

	if (status != PSA_SUCCESS || output_size != input_size) goto cleanup;

	success = 1;

cleanup:
    if (key_id != 0) psa_destroy_key(key_id);

	psa_reset_key_attributes(&attributes);

	secure_zero(combined, combined_size);
	free(combined);

	if (!success && input_size) secure_zero(output, input_size);

	return success;
}

void wpk_aes_gcm_decrypt_abort(WPK_GCM_DECRYPT_CTX *ctx) {
	if (!ctx) return;

	if (ctx->active) {
		psa_aead_abort(&ctx->operation);
		ctx->active = 0;
	}

	if (ctx->key_id != 0) {
		psa_destroy_key(ctx->key_id);
		ctx->key_id = 0;
	}

	secure_zero(ctx, sizeof(*ctx));
}

int wpk_aes_gcm_decrypt_start(
	WPK_GCM_DECRYPT_CTX *ctx,
	const uint8_t key[WPK_KEY_SIZE],
	const uint8_t nonce[WPK_NONCE_SIZE],
	const uint8_t *aad,
	size_t aad_size
) {
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	if (!ctx || !key || !nonce || (!aad && aad_size)) return 0;

	memset(ctx, 0, sizeof(*ctx));
	ctx->operation = psa_aead_operation_init();

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 256);
	psa_set_key_usage_flags(&attributes,PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

	status = psa_import_key(&attributes,key,WPK_KEY_SIZE,&ctx->key_id);

	psa_reset_key_attributes(&attributes);

	if (status != PSA_SUCCESS) goto failure;

	status = psa_aead_decrypt_setup(&ctx->operation,ctx->key_id,PSA_ALG_GCM);

	if (status != PSA_SUCCESS) goto failure;

	ctx->active = 1;

	status = psa_aead_set_nonce(&ctx->operation,nonce,WPK_NONCE_SIZE);

	if (status != PSA_SUCCESS) goto failure;

	if (aad_size != 0) {
		status = psa_aead_update_ad(&ctx->operation,aad,aad_size);
		if (status != PSA_SUCCESS) goto failure;
	}

	return 1;

failure:
	wpk_aes_gcm_decrypt_abort(ctx);
	return 0;
}

int wpk_aes_gcm_decrypt_update(
	WPK_GCM_DECRYPT_CTX *ctx,
	const uint8_t *input,
	size_t input_size,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_size
) {
	psa_status_t status;

	if (output_size) *output_size = 0;

	if (!ctx || !ctx->active || !output_size) return 0;

	if ((!input && input_size) || (!output && output_capacity)) return 0;

	if (output_capacity < input_size) return 0;

	if (input_size == 0) return 1;

	status = psa_aead_update(&ctx->operation,input,input_size,output,output_capacity,output_size);

	if (status != PSA_SUCCESS) {
		if (output && output_capacity) secure_zero(output, output_capacity);
		*output_size = 0;
		return 0;
	}

	return 1;
}

int wpk_aes_gcm_decrypt_finish(
	WPK_GCM_DECRYPT_CTX *ctx,
	const uint8_t tag[WPK_TAG_SIZE]
) {
	psa_status_t status;
	uint8_t final_output[16];
	size_t final_output_size = 0;

	if (!ctx || !ctx->active || !tag) return 0;

	memset(final_output, 0, sizeof(final_output));

	status = psa_aead_verify(&ctx->operation,final_output,sizeof(final_output),&final_output_size,tag,WPK_TAG_SIZE);
	secure_zero(final_output, sizeof(final_output));

	if (status != PSA_SUCCESS) {
		wpk_aes_gcm_decrypt_abort(ctx);
		return 0;
	}

	wpk_aes_gcm_decrypt_abort(ctx);
	return 1;
}
