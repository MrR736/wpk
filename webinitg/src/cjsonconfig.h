#ifndef CJSONCONFIG_H
#define CJSONCONFIG_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
	char *Name;
	char *App;
	char *BuildDir;
	char *Password;

	char **CommandsBefore;
	size_t CommandsBeforeCount;

	char **CommandsAfter;
	size_t CommandsAfterCount;

	char **Assets;
	size_t AssetsCount;

	char **Removes;
	size_t RemovesCount;

	bool Encryption;
} WebinitConfig;

#ifdef __cplusplus
extern "C" {
#endif

bool cJSONConfig_Load(const char *filename, WebinitConfig *config);
void cJSONConfig_Free(WebinitConfig *config);

#ifdef __cplusplus
}
#endif

#endif