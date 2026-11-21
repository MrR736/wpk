#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "cJSON/cJSON.h"

#include "cjsonconfig.h"
#define WEBINIT_CONFIG_MAX_SIZE (16u * 1024u * 1024u)

static char* json_strdup(const char *s) {
	if (!s) return NULL;
	size_t len = strlen(s);
	char *d = (char*)cJSON_malloc(len + 1);
	if (!d) return NULL;
	memcpy(d, s, len + 1);
	return d;
}

static char *json_get_string(cJSON *object, const char *name) {
	cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
	if (!cJSON_IsString(item)) return NULL;
	return json_strdup(item->valuestring);
}

static bool json_get_string_array(cJSON *object,const char *name,char ***output,size_t *count) {
	size_t i;
	cJSON *array = cJSON_GetObjectItemCaseSensitive(object, name);

	*output = NULL;
	*count = 0;

	if (cJSON_IsNull(array)) return true;
	if (!cJSON_IsArray(array)) return false;

	size_t size = (size_t)cJSON_GetArraySize(array);

	char **result = cJSON_malloc((size ? size : 1) * sizeof(*result));
	if (!result) return false;

	memset(result, 0, (size ? size : 1) * sizeof(*result));

	for (i = 0; i < size; i++) {
		cJSON *item = cJSON_GetArrayItem(array, (int)i);
		if (!cJSON_IsString(item) || !item->valuestring) goto error;
		size_t len = strlen(item->valuestring) + 1;
		result[i] = cJSON_malloc(len);
		if (!result[i]) goto error;
		memcpy(result[i], item->valuestring, len);
	}

	*output = result;
	*count = size;

	return true;

error:
	for (i = 0; i < size; i++) cJSON_free(result[i]);
	cJSON_free(result);
	return false;
}

void cJSONConfig_Free(WebinitConfig *config) {
	if (!config) return;

	cJSON_free(config->Name);
	cJSON_free(config->App);
	cJSON_free(config->BuildDir);
	cJSON_free(config->Password);

	char **arrays[] = {
		config->CommandsBefore,
		config->CommandsAfter,
		config->Assets,
		config->Removes
	};

	size_t counts[] = {
		config->CommandsBeforeCount,
		config->CommandsAfterCount,
		config->AssetsCount,
		config->RemovesCount
	};

	for (size_t i = 0; i < 4; i++) {
		if (!arrays[i]) continue;
		for (size_t j = 0; j < counts[i]; j++) cJSON_free(arrays[i][j]);
		cJSON_free(arrays[i]);
	}

	memset(config, 0, sizeof(*config));
}

bool cJSONConfig_Load(const char *filename, WebinitConfig *config) {
	if (!filename || !config) return false;

	memset(config, 0, sizeof(*config));

	FILE *file = fopen(filename, "rb");
	if (!file) return false;

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return false;
	}

	long file_size = ftell(file);

	if (file_size < 0 || fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return false;
	}

	if ((unsigned long)file_size > WEBINIT_CONFIG_MAX_SIZE) {
		fclose(file);
		return false;
	}

	char *buffer = cJSON_malloc((size_t)file_size + 1);

	if (!buffer) {
		fclose(file);
		return false;
	}

	size_t bytes_read = fread(buffer, 1, (size_t)file_size, file);
	fclose(file);

	if (bytes_read != (size_t)file_size) {
		cJSON_free(buffer);
		return false;
	}

	buffer[bytes_read] = '\0';

	cJSON *root = cJSON_Parse(buffer);
	cJSON_free(buffer);

	if (!cJSON_IsObject(root)) goto error;

	config->Name = json_get_string(root, "Name");
	config->App = json_get_string(root, "App");
	config->BuildDir = json_get_string(root, "BuildDir");
	config->Password = json_get_string(root, "Password");
	cJSON *encryption = cJSON_GetObjectItemCaseSensitive(root, "Encryption");

	if (!config->Name || !config->App || !config->BuildDir || !cJSON_IsBool(encryption))
		goto error;
	config->Encryption = cJSON_IsTrue(encryption);
	if (!json_get_string_array(root, "CommandsBefore",&config->CommandsBefore,&config->CommandsBeforeCount)) goto error;
	if (!json_get_string_array(root, "CommandsAfter",&config->CommandsAfter,&config->CommandsAfterCount)) goto error;
	if (!json_get_string_array(root, "Assets",&config->Assets,&config->AssetsCount)) goto error;
	if (!json_get_string_array(root, "Removes",&config->Removes,&config->RemovesCount)) goto error;

	cJSON_Delete(root);
	return true;

error:
	cJSON_Delete(root);
	cJSONConfig_Free(config);
	return false;
}