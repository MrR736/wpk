#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libxc/xlog.h"
#include "cjsonconfig.h"
#include "runcjson.h"

#define APP_NAME	"webinitg"
#define APP_VERSION	"1.0.0"

static void print_help(const char *program) {
	printf(
		"Usage: %s [OPTIONS]\n"
		"\n"
		"Options:\n"
		"  -c, --config FILE	Configuration JSON file\n"
		"  -o, --output FILE	Output WPK archive\n"
		"  -h, --help		   Show this help message\n"
		"  -v, --version		Show version information\n"
		"\n"
		"Examples:\n"
		"  %s -c webinit.json\n"
		"  %s -c webinit.json -o blockbench.wpk\n"
		"\n",
		program, program, program
	);
}

static void print_version(void) {
	printf("%s %s\n", APP_NAME, APP_VERSION);
}

int main(int argc, char **argv) {
	const char *config_file = NULL;
	const char *output_file = NULL;

	WebinitConfig config = {0};

	int i;
	int result = EXIT_FAILURE;

	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_help(argv[0]);
			return EXIT_SUCCESS;
		}

		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			print_version();
			return EXIT_SUCCESS;
		}

		if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) {
			if (++i >= argc) {
				XLOGE(APP_NAME,"Missing configuration file.");
				goto cleanup;
			}
			config_file = argv[i];
			continue;
		}

		if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
			if (++i >= argc) {
				XLOGE(APP_NAME,"Missing output filename.");
				goto cleanup;
			}

			output_file = argv[i];
			continue;
		}

		XLOGE(APP_NAME,"Unknown argument: %s", argv[i]);
		XLOGE(APP_NAME,"Use --help for usage.");
		goto cleanup;
	}

	if (!config_file) {
		XLOGE(APP_NAME,"Configuration file is required.\n");
		print_help(argv[0]);
		goto cleanup;
	}

	printf("%s %s\n", APP_NAME, APP_VERSION);
	printf("[INFO] Loading configuration: %s\n", config_file);

	if (!cJSONConfig_Load(config_file, &config)) {
		XLOGE(APP_NAME,"Failed to load configuration.");
		goto cleanup;
	}

	printf("[INFO] Configuration loaded successfully.");

	if (!output_file) {
		printf("[INFO] Output: %s.wpk\n",config.Name ? config.Name : "output");
	} else {
		printf("[INFO] Output: %s\n", output_file);
	}

	printf("[INFO] Starting build...\n");

	if (!RunCJson(&config, output_file)) {
		XLOGE(APP_NAME,"Build failed.");
		goto cleanup;
	}

	XLOGI(APP_NAME,"Build completed.");

	result = EXIT_SUCCESS;

cleanup:
	cJSONConfig_Free(&config);
	return result;
}
