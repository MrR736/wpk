#define _POSIX_C_SOURCE 200809L

#include "runcjson.h"

#include "wpk.h"
#include "javagenerate.h"
#include "libxc/xstdlib.h"
#include "libxc/xlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <glob.h>

/* ---------------------------------------------------------
 * Path utilities
 * --------------------------------------------------------- */

static char *join_path(const char *a, const char *b)
{
	size_t na, nb;
	char *result;

	if (!a || !b)
		return NULL;

	na = strlen(a);
	nb = strlen(b);

	result = malloc(na + nb + 2);
	if (!result)
		return NULL;

	snprintf(result, na + nb + 2, "%s%s%s",
			 a,
			 (na && a[na - 1] != '/') ? "/" : "",
			 b);

	return result;
}

static char *absolute_path(const char *path)
{
	char cwd[PATH_MAX];

	if (!path)
		return NULL;

	if (path[0] == '/')
		return strdup(path);

	if (!getcwd(cwd, sizeof(cwd)))
		return NULL;

	return join_path(cwd, path);
}

static int make_dirs(const char *path)
{
	char *copy;
	char *p;
	struct stat st;

	if (!path || !*path)
		return 0;

	copy = strdup(path);
	if (!copy)
		return 0;

	for (p = copy + 1; *p; ++p) {
		if (*p != '/')
			continue;

		*p = '\0';

		if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
			free(copy);
			return 0;
		}

		*p = '/';
	}

	if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
		free(copy);
		return 0;
	}

	if (stat(copy, &st) != 0 || !S_ISDIR(st.st_mode)) {
		free(copy);
		return 0;
	}

	free(copy);
	return 1;
}

static int safe_relative_path(const char *path)
{
	const char *p;

	if (!path || !*path || path[0] == '/')
		return 0;

	p = path;

	while (*p) {
		const char *start = p;

		while (*p && *p != '/')
			++p;

		if ((p - start) == 2 &&
			start[0] == '.' && start[1] == '.')
			return 0;

		if (*p)
			++p;
	}

	return 1;
}

/* ---------------------------------------------------------
 * File copying
 * --------------------------------------------------------- */

static int copy_file(const char *src, const char *dst)
{
	FILE *in = NULL;
	FILE *out = NULL;

	unsigned char buffer[16384];
	size_t n;
	int ok = 1;

	struct stat st;
	char *parent;
	char *slash;

	parent = strdup(dst);
	if (!parent)
		return 0;

	slash = strrchr(parent, '/');

	if (slash) {
		*slash = '\0';

		if (*parent && !make_dirs(parent)) {
			free(parent);
			return 0;
		}
	}

	free(parent);

	in = fopen(src, "rb");
	if (!in)
		return 0;

	out = fopen(dst, "wb");
	if (!out) {
		fclose(in);
		return 0;
	}

	while ((n = fread(buffer, 1, sizeof(buffer), in)) > 0) {
		if (fwrite(buffer, 1, n, out) != n) {
			ok = 0;
			break;
		}
	}

	if (ferror(in))
		ok = 0;

	if (fclose(in) != 0)
		ok = 0;

	if (fclose(out) != 0)
		ok = 0;

	if (ok && stat(src, &st) == 0)
		chmod(dst, st.st_mode & 0777);

	return ok;
}

static int copy_recursive(const char *src, const char *dst)
{
	struct stat st;

	if (lstat(src, &st) != 0)
		return 0;

	if (S_ISREG(st.st_mode))
		return copy_file(src, dst);

	if (S_ISLNK(st.st_mode)) {
		char target[PATH_MAX];
		ssize_t n = readlink(src, target, sizeof(target) - 1);

		if (n < 0 || n >= (ssize_t)sizeof(target))
			return 0;

		target[n] = '\0';

		return symlink(target, dst) == 0;
	}

	if (!S_ISDIR(st.st_mode))
		return 0;

	if (!make_dirs(dst))
		return 0;

	{
		DIR *dir = opendir(src);
		struct dirent *entry;

		if (!dir)
			return 0;

		while ((entry = readdir(dir)) != NULL) {
			char *child_src;
			char *child_dst;
			int ok;

			if (!strcmp(entry->d_name, ".") ||
				!strcmp(entry->d_name, ".."))
				continue;

			child_src = join_path(src, entry->d_name);
			child_dst = join_path(dst, entry->d_name);

			if (!child_src || !child_dst) {
				free(child_src);
				free(child_dst);
				closedir(dir);
				return 0;
			}

			ok = copy_recursive(child_src, child_dst);

			free(child_src);
			free(child_dst);

			if (!ok) {
				closedir(dir);
				return 0;
			}
		}

		closedir(dir);
	}

	chmod(dst, st.st_mode & 0777);
	return 1;
}

/* ---------------------------------------------------------
 * Asset handling
 * --------------------------------------------------------- */

static int copy_asset(const char *asset, const char *build_dir)
{
	glob_t matches;
	size_t i;
	int result = 1;
	int g;

	if (!safe_relative_path(asset)) {
		XLOGE("RunCJson", "Invalid asset path: %s\n", asset);
		return 0;
	}

	memset(&matches, 0, sizeof(matches));

	g = glob(asset, GLOB_NOSORT, NULL, &matches);

	if (g != 0) {
		globfree(&matches);
		XLOGE("RunCJson", "Asset not found: %s\n", asset);
		return 0;
	}

	for (i = 0; i < matches.gl_pathc; ++i) {
		const char *src = matches.gl_pathv[i];
		char *dst;

		if (!safe_relative_path(src)) {
			result = 0;
			break;
		}

		dst = join_path(build_dir, src);

		if (!dst) {
			result = 0;
			break;
		}

		printf("[ASSET] %s\n", src);

		if (!copy_recursive(src, dst))
			result = 0;

		free(dst);

		if (!result)
			break;
	}

	globfree(&matches);
	return result;
}

/* ---------------------------------------------------------
 * Remove files/directories recursively
 * --------------------------------------------------------- */

static int remove_recursive(const char *path)
{
	struct stat st;

	if (lstat(path, &st) != 0)
		return errno == ENOENT;

	if (S_ISDIR(st.st_mode)) {
		DIR *dir = opendir(path);
		struct dirent *entry;

		if (!dir)
			return 0;

		while ((entry = readdir(dir)) != NULL) {
			char *child;
			int ok;

			if (!strcmp(entry->d_name, ".") ||
				!strcmp(entry->d_name, ".."))
				continue;

			child = join_path(path, entry->d_name);

			if (!child) {
				closedir(dir);
				return 0;
			}

			ok = remove_recursive(child);
			free(child);

			if (!ok) {
				closedir(dir);
				return 0;
			}
		}

		closedir(dir);
		return rmdir(path) == 0;
	}

	return unlink(path) == 0;
}

static int remove_asset(const char *pattern, const char *build_dir)
{
	glob_t matches;
	size_t i;
	int result = 1;

	memset(&matches, 0, sizeof(matches));

	if (!safe_relative_path(pattern))
		return 0;

	if (glob(pattern, GLOB_NOSORT, NULL, &matches) != 0) {
		globfree(&matches);
		XLOGE("RunCJson", "[REMOVE] Not found: %s\n", pattern);
		return 0;
	}

	for (i = 0; i < matches.gl_pathc; ++i) {
		char *path;

		if (!safe_relative_path(matches.gl_pathv[i])) {
			result = 0;
			break;
		}

		path = join_path(build_dir, matches.gl_pathv[i]);

		if (!path) {
			result = 0;
			break;
		}

		printf("[REMOVE] %s\n", matches.gl_pathv[i]);

		if (!remove_recursive(path))
			result = 0;

		free(path);

		if (!result)
			break;
	}

	globfree(&matches);
	return result;
}

/* Command execution */
static int run_command(const char *command) {
	int status;
	if (!command || !*command) return 1;
	printf("[COMMAND] %s\n", command);
	status = csystem(command);
	if (status == -1) return 0;
	if (!WIFEXITED(status)) return 0;
	return WEXITSTATUS(status) == 0;
}

static int run_commands(char **commands,size_t count) {
	size_t i;

	if (!commands)
		return 1;

	for (i = 0; i < count; ++i) {
		if (!commands[i])
			continue;

		if (!run_command(commands[i])) {
			XLOGE("RunCJson","Command failed: %s\n",commands[i]);
			return 0;
		}
	}

	return 1;
}

/* Password generation */
static int generate_password(char **password) {
	wpk_uuid_t random;
	char *result;
	size_t i;

	static const char hex[] = "0123456789abcdef";

	if (!password)
		return 0;

	if (!wpk_uuid_generate(random))
		return 0;

	result = malloc(33);
	if (!result)
		return 0;

	for (i = 0; i < WPK_UUID_SIZE; ++i) {
		result[i * 2] = hex[random[i] >> 4];
		result[i * 2 + 1] = hex[random[i] & 0x0F];
	}

	result[32] = '\0';

	*password = result;
	return 1;
}

/* ---------------------------------------------------------
 * Metadata file
 * --------------------------------------------------------- */

static int write_metadata(
    const char *password,
    const wpk_uuid_t uuid)
{
    char uuid_string[WPK_UUID_STRING_SIZE];
    FILE *fp;

    if (!wpk_uuid_to_string(uuid, uuid_string))
        return 0;

    fp = fopen("file.txt", "w+");

    if (!fp)
        return 0;

    if (fprintf(fp,
                "Password: %s\n"
                "UUID: %s\n",
                password ? password : "",
                uuid_string) < 0) {
        fclose(fp);
        return 0;
    }

    if (fflush(fp) != 0) {
        fclose(fp);
        return 0;
    }

    if (fclose(fp) != 0)
        return 0;

    return 1;
}


/* ---------------------------------------------------------
 * Main build function
 * --------------------------------------------------------- */

int RunCJson(const WebinitConfig *config,const char *out_file) {
	char cwd[PATH_MAX];

	char *build_dir = NULL;
	char *archive = NULL;
	char *password = NULL;

	const char *effective_password = "";

	WPK_COMPRESS_OPTIONS options;
	wpk_uuid_t uuid;

	size_t i;
	int success = 0;

	if (!config || !config->BuildDir) {
		XLOGE("RunCJson","Invalid configuration.\n");
		return 0;
	}

	if (!getcwd(cwd, sizeof(cwd))) return 0;

	/* -------------------------------------------------
	 * 1. CommandsBefore
	 * ------------------------------------------------- */

	printf("\n=== CommandsBefore ===\n");

	if (!run_commands(config->CommandsBefore,config->CommandsBeforeCount)) goto cleanup;

	/* -------------------------------------------------
	 * 2. Create BuildDir
	 * ------------------------------------------------- */

	printf("\n=== Create BuildDir ===\n");

	if (!make_dirs(config->BuildDir)) {
		XLOGE("RunCJson","Cannot create BuildDir.\n");
		goto cleanup;
	}

	build_dir = absolute_path(config->BuildDir);
	if (!build_dir) goto cleanup;

	/* -------------------------------------------------
	 * 3. Copy Assets
	 * ------------------------------------------------- */

	printf("\n=== Copy Assets ===\n");

	for (i = 0; i < config->AssetsCount; ++i) {
		if (!config->Assets || !config->Assets[i]) continue;
		if (!copy_asset(config->Assets[i], config->BuildDir)) goto cleanup;
	}

	/* -------------------------------------------------
	 * 4. Removes
	 * ------------------------------------------------- */

	printf("\n=== Removes ===\n");

	for (i = 0; i < config->RemovesCount; ++i) {
		if (!config->Removes || !config->Removes[i]) continue;
		if (!remove_asset(config->Removes[i], config->BuildDir)) goto cleanup;
	}

	/* -------------------------------------------------
	 * 5. CommandsAfter
	 * ------------------------------------------------- */

	printf("\n=== CommandsAfter ===\n");

	if (config->CommandsAfter) {
		if (chdir(build_dir) != 0)
			goto cleanup;

		if (!run_commands(
				config->CommandsAfter,
				config->CommandsAfterCount)) {
			chdir(cwd);
			goto cleanup;
		}

		if (chdir(cwd) != 0)
			goto cleanup;
	}

	/* -------------------------------------------------
	 * 6. Password and Encryption
	 * ------------------------------------------------- */

	printf("\n=== Encryption ===\n");

	if (config->Encryption) {
		if (config->Password && config->Password[0]) {
			effective_password = config->Password;
		} else {
			if (!generate_password(&password)) goto cleanup;
			effective_password = password;
		}
	} else {
		effective_password = "";
	}

	options.level = WPK_DEFAULT_COMPRESSION;
	options.password = config->Encryption ? effective_password : NULL;

	options.pbkdf2_iterations = 0;

	/* -------------------------------------------------
	 * 7. Compress BuildDir
	 * ------------------------------------------------- */

	printf("\n=== Compress ===\n");

	if (out_file && *out_file) {
		archive = absolute_path(out_file);
	} else if (config->Name && *config->Name) {
		char *name = malloc(strlen(config->Name) + 5);

		if (!name) goto cleanup;

		sprintf(name, "%s.wpk", config->Name);
		archive = absolute_path(name);

		free(name);
	}

	if (!archive)
		goto cleanup;

	printf("[WPK] Archive: %s\n", archive);

	if (!wpk_compress_dir(archive,build_dir,&options,uuid)) {
		XLOGE("RunCJson","WPK compression failed.\n");
		goto cleanup;
	}

	/* -------------------------------------------------
	 * 8. UUID and Password
	 * ------------------------------------------------- */

	printf("\n=== Archive Information ===\n");

	{
		char uuid_string[WPK_UUID_STRING_SIZE];

		if (!wpk_uuid_to_string(uuid, uuid_string))
			goto cleanup;

		printf("[WPK] UUID: %s\n", uuid_string);
		printf("[WPK] Password: %s\n", effective_password);
	}

	/* -------------------------------------------------
	 * 9. Create file.txt
	 * ------------------------------------------------- */

	printf("\n=== Write file.txt ===\n");

	if (!JavaGenerate(config,"WebInitCrypto.java","WebInitCrypto.c",effective_password, uuid)) {
		XLOGE("RunCJson","Cannot write file.txt.\n");
		goto cleanup;
	}

	printf("\nBuild completed successfully.\n");

	success = 1;

cleanup:

	free(password);
	free(build_dir);
	free(archive);

	return success;
}
