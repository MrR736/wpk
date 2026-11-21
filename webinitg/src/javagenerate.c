#include "javagenerate.h"
#include "libxc/xlog.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define AES_KEY_SIZE   32
#define AES_NONCE_SIZE 12
#define AES_TAG_SIZE   16

/* Write a C byte array. */
static int write_c_array(
	FILE* fp,
	const char* name,
	const uint8_t* data,
	size_t size
) {
	if (fprintf(fp, "static const uint8_t %s[%zu] = {\n\t", name, size) < 0)
		return 0;

	for (size_t i = 0; i < size; ++i) {
		if (fprintf(fp, "0x%02X%s",(unsigned)data[i],i + 1 == size ? "" : ",") < 0)
			return 0;

		if ((i + 1) == size) continue;

		if ((i + 1) % 8 == 0 && fprintf(fp, "\n\t") < 0)
			return 0;
	}

	return fprintf(fp, "\r};\n\n") >= 0;
}

/* Write a Java byte array. */
static int write_java_array(
	FILE* fp,
	const char* name,
	const uint8_t* data,
	size_t size
) {
	if (fprintf(fp,
		"\tprivate static final byte[] %s = new byte[] {\n\t\t",
		name) < 0)
		return 0;

	for (size_t i = 0; i < size; ++i) {
		if (fprintf(fp, "(byte)0x%02X%s",(unsigned)data[i],i + 1 == size ? "" : ",") < 0)
			return 0;

		if ((i + 1) == size) continue;

		if ((i + 1) % 8 == 0 && fprintf(fp, "\n\t\t") < 0)
			return 0;
	}

	return fprintf(fp, "\r\t};\n\n") >= 0;
}

/* Convert package name into JNI package notation. */
static char* jni_mangle_package(const char* package_name)
{
	if (!package_name)
		return NULL;

	size_t len = strlen(package_name);

	if (len > (SIZE_MAX - 1) / 2)
		return NULL;

	char* result = (char*)malloc(len * 2 + 1);
	if (!result)
		return NULL;

	size_t j = 0;

	for (size_t i = 0; i < len; ++i) {
		unsigned char c = (unsigned char)package_name[i];

		if (c == '.') {
			result[j++] = '_';
		}
		else if (c == '_') {
			result[j++] = '_';
			result[j++] = '1';
		}
		else if ((c >= 'a' && c <= 'z') ||
				 (c >= 'A' && c <= 'Z') ||
				 (c >= '0' && c <= '9')) {
			result[j++] = (char)c;
		}
		else {
			free(result);
			return NULL;
		}
	}

	result[j] = '\0';
	return result;
}

/* AES-256-GCM encryption. */
static int aes_encrypt(
	const uint8_t* plaintext,
	size_t plaintext_size,
	const uint8_t key[AES_KEY_SIZE],
	const uint8_t nonce[AES_NONCE_SIZE],
	uint8_t* ciphertext,
	uint8_t tag[AES_TAG_SIZE]
) {
	if (plaintext_size > INT_MAX)
		return 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	int len = 0;
	int total = 0;
	int ok = 0;

	if (EVP_EncryptInit_ex(
			ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto cleanup;

	if (EVP_CIPHER_CTX_ctrl(
			ctx, EVP_CTRL_GCM_SET_IVLEN,
			AES_NONCE_SIZE, NULL) != 1)
		goto cleanup;

	if (EVP_EncryptInit_ex(
			ctx, NULL, NULL, key, nonce) != 1)
		goto cleanup;

	if (EVP_EncryptUpdate(
			ctx, ciphertext, &len,
			plaintext, (int)plaintext_size) != 1)
		goto cleanup;

	total = len;

	if (EVP_EncryptFinal_ex(
			ctx, ciphertext + total, &len) != 1)
		goto cleanup;

	total += len;

	if ((size_t)total != plaintext_size)
		goto cleanup;

	if (EVP_CIPHER_CTX_ctrl(
			ctx, EVP_CTRL_GCM_GET_TAG,
			AES_TAG_SIZE, tag) != 1)
		goto cleanup;

	ok = 1;

cleanup:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

int JavaGenerate(
	const WebinitConfig* config,
	const char* file_java,
	const char* file_c,
	const char* password,
	const wpk_uuid_t uuid
) {
	if (!config || !config->BuildDir ||
		!config->App || !file_java || !file_c ||
		!password || !uuid) {
		XLOGE("JavaGenerate", "Invalid arguments.\n");
		return 0;
	}

	int success = 0;

	FILE* fp = NULL;
	char uuid_string[WPK_UUID_STRING_SIZE];

	char* RApp = NULL;

	uint8_t key[AES_KEY_SIZE] = { 0 };
	uint8_t mask[AES_KEY_SIZE] = { 0 };
	uint8_t key_a[AES_KEY_SIZE] = { 0 };

	uint8_t nonce[AES_NONCE_SIZE] = { 0 };
	uint8_t tag[AES_TAG_SIZE] = { 0 };

	uint8_t* plaintext = NULL;
	uint8_t* ciphertext = NULL;
	uint8_t* encrypted_payload = NULL;

	size_t password_size = strlen(password);
	size_t uuid_string_size;

	size_t payload_size;
	size_t encrypted_payload_size;

	if (!wpk_uuid_to_string(uuid, uuid_string)) {
		XLOGE("JavaGenerate", "Invalid UUID.\n");
		goto cleanup;
	}

	uuid_string_size = strlen(uuid_string);

	if (password_size > SIZE_MAX - uuid_string_size - WPK_UUID_SIZE) {
		XLOGE("JavaGenerate", "Payload too large.\n");
		goto cleanup;
	}

	payload_size = password_size + uuid_string_size + WPK_UUID_SIZE;

	if (payload_size > INT_MAX ||
		payload_size > SIZE_MAX - AES_NONCE_SIZE - AES_TAG_SIZE) {
		XLOGE("JavaGenerate", "Payload too large.\n");
		goto cleanup;
	}

	encrypted_payload_size =
		AES_NONCE_SIZE + payload_size + AES_TAG_SIZE;

	RApp = jni_mangle_package(config->App);

	if (!RApp) {
		XLOGE("JavaGenerate", "Invalid Java package.\n");
		goto cleanup;
	}

	plaintext = (uint8_t*)malloc(payload_size ? payload_size : 1);
	ciphertext = (uint8_t*)malloc(payload_size ? payload_size : 1);
	encrypted_payload = (uint8_t*)malloc(encrypted_payload_size);

	if (!plaintext || !ciphertext || !encrypted_payload) {
		XLOGE("JavaGenerate", "Memory allocation failed.\n");
		goto cleanup;
	}

	/*
	 * Plaintext layout:
	 *
	 * [ password UTF-8 bytes ]
	 * [ UUID ASCII string ]
	 * [ UUID binary: 16 bytes ]
	 */

	size_t uuid_string_offset = password_size;
	size_t uuid_bytes_offset = password_size + uuid_string_size;

	memcpy(plaintext, password, password_size);

	memcpy(
		plaintext + uuid_string_offset,
		uuid_string,
		uuid_string_size
	);

	memcpy(
		plaintext + uuid_bytes_offset,
		uuid,
		WPK_UUID_SIZE
	);

	/* Generate random AES key and nonce. */
	if (RAND_bytes(key, sizeof(key)) != 1 ||
		RAND_bytes(mask, sizeof(mask)) != 1 ||
		RAND_bytes(nonce, sizeof(nonce)) != 1) {
		XLOGE("JavaGenerate", "Random generation failed.\n");
		goto cleanup;
	}

	/*
	 * Split AES key:
	 *
	 * key = key_a XOR mask
	 */
	for (size_t i = 0; i < AES_KEY_SIZE; ++i)
		key_a[i] = key[i] ^ mask[i];

	if (!aes_encrypt(
			plaintext,
			payload_size,
			key,
			nonce,
			ciphertext,
			tag)) {
		XLOGE("JavaGenerate", "AES encryption failed.\n");
		goto cleanup;
	}

	/*
	 * Encrypted payload layout:
	 *
	 * [ 12-byte nonce ]
	 * [ ciphertext ]
	 * [ 16-byte GCM authentication tag ]
	 */
	memcpy(encrypted_payload, nonce, AES_NONCE_SIZE);

	memcpy(
		encrypted_payload + AES_NONCE_SIZE,
		ciphertext,
		payload_size
	);

	memcpy(
		encrypted_payload + AES_NONCE_SIZE + payload_size,
		tag,
		AES_TAG_SIZE
	);

	/* Generate Java source. */
	fp = fopen(file_java, "w");

	if (!fp) {
		XLOGE("JavaGenerate", "Cannot open Java file.\n");
		goto cleanup;
	}

	if (fprintf(fp,
		"package %s;\n"
		"\n"
		"import javax.crypto.Cipher;\n"
		"import javax.crypto.spec.GCMParameterSpec;\n"
		"import javax.crypto.spec.SecretKeySpec;\n"
		"import java.nio.charset.StandardCharsets;\n"
		"import java.util.Arrays;\n"
		"\n"
		"public final class WebInitCrypto {\n"
		"\tstatic { System.loadLibrary(\"%s-crypto\"); }\n"
		"\n"
		"\tprivate static final int PASSWORD_LENGTH = %zu;\n"
		"\tprivate static final int UUID_LENGTH = %zu;\n"
		"\n",
		config->App,config->Name,
		password_size,
		uuid_string_size) < 0)
		goto cleanup;

	if (!write_java_array(fp, "KEY_A", key_a, sizeof(key_a)) ||
		!write_java_array(fp, "KEY_B", mask, sizeof(mask)))
		goto cleanup;

	if (fprintf(fp,
		"\tprivate static volatile boolean initialized;\n"
		"\tprivate static String password;\n"
		"\tprivate static String uuid;\n"
		"\tprivate static byte[] byteUUID;\n"
		"\n"
		"\tprivate static native byte[] getEncryptedData();\n"
		"\n"
		"\tprivate static synchronized void initialize() {\n"
		"\t\tif (initialized) return;\n"
		"\n"
		"\t\tbyte[] encrypted = null;\n"
		"\t\tbyte[] key = new byte[32];\n"
		"\t\tbyte[] plain = null;\n"
		"\n"
		"\t\ttry {\n"
		"\t\t\tencrypted = getEncryptedData();\n"
		"\t\t\tif (encrypted == null || encrypted.length < 28)\n"
		"\t\t\t\tthrow new IllegalStateException(\"Invalid encrypted data\");\n"
		"\n"
		"\t\t\tfor (int i = 0; i < 32; ++i)\n"
		"\t\t\t\tkey[i] = (byte)(KEY_A[i] ^ KEY_B[i]);\n"
		"\n"
		"\t\t\tbyte[] nonce = Arrays.copyOfRange(encrypted, 0, 12);\n"
		"\t\t\tbyte[] cipherText = Arrays.copyOfRange(encrypted, 12, encrypted.length);\n"
		"\n"
		"\t\t\tCipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
		"\t\t\tSecretKeySpec secretKey = new SecretKeySpec(key, \"AES\");\n"
		"\t\t\tGCMParameterSpec parameters = new GCMParameterSpec(128, nonce);\n"
		"\n"
		"\t\t\tcipher.init(Cipher.DECRYPT_MODE, secretKey, parameters);\n"
		"\t\t\tplain = cipher.doFinal(cipherText);\n"
		"\n"
		"\t\t\tint uuidOffset = PASSWORD_LENGTH;\n"
		"\t\t\tint bytesOffset = uuidOffset + UUID_LENGTH;\n"
		"\n"
		"\t\t\tif (plain.length != bytesOffset + 16)\n"
		"\t\t\t\tthrow new IllegalStateException(\"Invalid plaintext size\");\n"
		"\n"
		"\t\t\tpassword = new String(plain, 0, PASSWORD_LENGTH,StandardCharsets.UTF_8);\n"
		"\n"
		"\t\t\tuuid = new String(plain, uuidOffset, UUID_LENGTH,StandardCharsets.US_ASCII);\n"
		"\n"
		"\t\t\tbyteUUID = Arrays.copyOfRange(plain, bytesOffset, bytesOffset + 16);\n"
		"\t\t\tinitialized = true;\n"
		"\n"
		"\t\t} catch (Exception e) {\n"
		"\t\t\tthrow new IllegalStateException(\"Crypto initialization failed\", e);\n"
		"\t\t} finally {\n"
		"\t\t\tArrays.fill(key, (byte)0);\n"
		"\t\t\tif (encrypted != null) Arrays.fill(encrypted, (byte)0);\n"
		"\t\t\tif (plain != null) Arrays.fill(plain, (byte)0);\n"
		"\t\t}\n"
		"\t}\n"
		"\n"
		"\tpublic static String getPassword() {\n"
		"\t\tinitialize();\n"
		"\t\treturn password;\n"
		"\t}\n"
		"\n"
		"\tpublic static String getUUID() {\n"
		"\t\tinitialize();\n"
		"\t\treturn uuid;\n"
		"\t}\n"
		"\n"
		"\tpublic static byte[] getByteUUID() {\n"
		"\t\tinitialize();\n"
		"\t\treturn byteUUID.clone();\n"
		"\t}\n"
		"}\n") < 0)
		goto cleanup;

	if (fclose(fp) != 0) {
		fp = NULL;
		goto cleanup;
	}

	fp = NULL;

	/* Generate JNI C source. No OpenSSL dependency here. */
	fp = fopen(file_c, "w");

	if (!fp) {
		XLOGE("JavaGenerate", "Cannot open C file.\n");
		goto cleanup;
	}

	if (fprintf(fp,
		"#include <jni.h>\n"
		"#include <stdint.h>\n"
		"\n") < 0)
		goto cleanup;

	if (!write_c_array(
			fp,
			"encrypted_payload",
			encrypted_payload,
			encrypted_payload_size))
		goto cleanup;

	if (fprintf(fp,
		"JNIEXPORT jbyteArray JNICALL\n"
		"Java_%s_WebInitCrypto_getEncryptedData(JNIEnv* env, jclass clazz) {\n"
		"\t(void)clazz;\n"
		"\n"
		"\tjbyteArray result = (*env)->NewByteArray(env, (jsize)sizeof(encrypted_payload));\n"
		"\tif (!result) return NULL;\n"
		"\n"
		"\t(*env)->SetByteArrayRegion(env,result,0,(jsize)sizeof(encrypted_payload),(const jbyte*)encrypted_payload);\n"
		"\n"
		"\tif ((*env)->ExceptionCheck(env)) return NULL;\n"
		"\n"
		"\treturn result;\n"
		"}\n",
		RApp) < 0) goto cleanup;

	if (fflush(fp) != 0)
		goto cleanup;

	if (fclose(fp) != 0) {
		fp = NULL;
		goto cleanup;
	}

	fp = NULL;
	success = 1;

cleanup:
	if (fp)
		fclose(fp);

	if (plaintext) {
		OPENSSL_cleanse(plaintext, payload_size);
		free(plaintext);
	}

	if (ciphertext) {
		OPENSSL_cleanse(ciphertext, payload_size);
		free(ciphertext);
	}

	if (encrypted_payload) {
		OPENSSL_cleanse(encrypted_payload, encrypted_payload_size);
		free(encrypted_payload);
	}

	OPENSSL_cleanse(key, sizeof(key));
	OPENSSL_cleanse(mask, sizeof(mask));
	OPENSSL_cleanse(key_a, sizeof(key_a));
	OPENSSL_cleanse(nonce, sizeof(nonce));
	OPENSSL_cleanse(tag, sizeof(tag));

	free(RApp);

	if (!success)
		XLOGE("JavaGenerate", "Source generation failed.\n");

	return success;
}
