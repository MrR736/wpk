// wpkc - command line tool for WPK archives.
//
//   wpkc list     <archive.wpk> [-p password]
//   wpkc compress <archive.wpk> <file|dir>... [-l level] [-p password] [-i iterations] [-f]
//   wpkc extract  <archive.wpk> [-o outdir] [-p password] [file...]
//
// Commands can be abbreviated to l / c / x.

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#define WPKC_ISATTY _isatty
#define WPKC_FILENO _fileno
#else
#include <termios.h>
#include <unistd.h>
#define WPKC_ISATTY isatty
#define WPKC_FILENO fileno
#endif

#include "wpk/wpk.h"

#ifdef USE_GHC_FILESYSTEM_HPP
#include "ghc/filesystem.hpp"
namespace fs = ghc::filesystem;
using cifstream = ghc::filesystem::ifstream;
#else
#include <fstream>
#include <filesystem>
namespace fs = std::filesystem;
using cifstream = std::ifstream;
#endif

#define VERSION "1.0.0"

static void usage(FILE *out) {
	fputs(
		"wpkc " VERSION " - WPK archive tool\n"
		"\n"
		"Usage:\n"
		"  wpkc list     <archive.wpk> [-p password]\n"
		"  wpkc compress <archive.wpk> <file|dir>... [options]\n"
		"  wpkc extract  <archive.wpk> [file...] [-o outdir] [-p password]\n"
		"  wpkc convert  <in.zip> <out.wpk> [-p password] [-f]\n"
		"  wpkc convert  <in.wpk> <out.zip> [-p password] [-f]\n"
		"\n"
		"Commands (short forms in brackets):\n"
		"  list (l)       show the archive contents\n"
		"  compress (c)   create an archive from files and directories\n"
		"  extract (x)    extract everything, or only the named files\n"
		"  convert        turn a ZIP archive into a WPK archive (directories are dropped)\n"
		"\n"
		"Options:\n"
		"  -p <password>  encrypt (compress) or decrypt (extract). The WPKC_PASSWORD\n"
		"                 environment variable is used when -p is absent. If an\n"
		"                 encrypted archive needs a password and none was given, it\n"
		"                 is asked for on the terminal.\n"
		"  -l <1-10>      compression level, default 6 (compress)\n"
		"  -i <count>     PBKDF2 iterations, default 600000 (compress, with -p)\n"
		"  -f             overwrite an existing archive (compress)\n"
		"  -o <dir>       output directory, default \".\" (extract)\n"
		"  -h, --help     show this help\n"
		"  --version      show the version\n"
		"\n"
		"Notes:\n"
		"  * A directory argument is stored with its contents at the archive root\n"
		"    (dir/index.html -> index.html). A file argument is stored by file name.\n"
		"  * Extraction never overwrites existing files.\n"
		"\n"
		"Exit status: 0 success, 1 failure, 2 bad usage.\n",
		out);
}

static int die_usage(const char *msg) {
	fprintf(stderr, "wpkc: %s\n", msg);
	fputs("Try 'wpkc --help' for usage.\n", stderr);
	return 2;
}

static std::string read_password_tty(const char *prompt) {
	fputs(prompt, stderr);
	fflush(stderr);
	std::string pw;
#ifdef _WIN32
	int c;
	while ((c = _getch()) != '\r' && c != '\n' && c != EOF) {
		if (c == '\b') {
			if (!pw.empty()) pw.pop_back();
		} else {
			pw.push_back((char)c);
		}
	}
#else
	termios oldt{}, newt{};
	bool changed = tcgetattr(STDIN_FILENO, &oldt) == 0;
	if (changed) {
		newt = oldt;
		newt.c_lflag &= ~(tcflag_t)ECHO;
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt);
	}
	int c;
	while ((c = getchar()) != '\n' && c != EOF) pw.push_back((char)c);
	if (changed) tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
#endif
	fputc('\n', stderr);
	return pw;
}

struct Options {
	std::string password;
	bool havePassword = false;
	int level = 6;
	uint32_t iterations = 0;
	bool force = false;
	std::string outdir = ".";
	std::vector<std::string> positional;
};

static bool parse_uint(const char *s, unsigned long max, unsigned long &out) {
	if (!s || !*s) return false;
	char *end = nullptr;
	errno = 0;
	unsigned long v = strtoul(s, &end, 10);
	if (errno || *end || v > max || *s == '-') return false;
	out = v;
	return true;
}

// Returns 0 on success, otherwise an exit code.
static int parse_args(int argc, char **argv, int first, Options &o) {
	for (int i = first; i < argc; ++i) {
		const char *a = argv[i];
		if (!strcmp(a, "--")) {
			for (++i; i < argc; ++i) o.positional.push_back(argv[i]);
			break;
		}
		if (a[0] == '-' && a[1] != '\0') {
			auto need = [&](const char *name) -> const char * {
				if (i + 1 >= argc) {
					fprintf(stderr, "wpkc: option %s needs a value\n", name);
					return nullptr;
				}
				return argv[++i];
			};
			if (!strcmp(a, "-p")) {
				const char *v = need("-p");
				if (!v) return 2;
				o.password = v;
				o.havePassword = true;
			} else if (!strcmp(a, "-l")) {
				const char *v = need("-l");
				unsigned long n;
				if (!v) return 2;
				if (!parse_uint(v, 10, n) || n < 1) return die_usage("level must be 1-10");
				o.level = (int)n;
			} else if (!strcmp(a, "-i")) {
				const char *v = need("-i");
				unsigned long n;
				if (!v) return 2;
				if (!parse_uint(v, 2147483647ul, n) || n < 100000)
					return die_usage("iterations must be between 100000 and 2147483647");
				o.iterations = (uint32_t)n;
			} else if (!strcmp(a, "-o")) {
				const char *v = need("-o");
				if (!v) return 2;
				o.outdir = v;
			} else if (!strcmp(a, "-f")) {
				o.force = true;
			} else {
				fprintf(stderr, "wpkc: unknown option %s\n", a);
				return die_usage("invalid option");
			}
		} else {
			o.positional.push_back(a);
		}
	}
	if (!o.havePassword) {
		const char *env = getenv("WPKC_PASSWORD");
		if (env && *env) {
			o.password = env;
			o.havePassword = true;
		}
	}
	return 0;
}

static std::string format_time(uint64_t t) {
	if (t == 0) return "-";
	time_t tt = (time_t)t;
	struct tm tmv;
#ifdef _WIN32
	if (gmtime_s(&tmv, &tt) != 0) return "-";
#else
	if (!gmtime_r(&tt, &tmv)) return "-";
#endif
	char buf[32];
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tmv);
	return buf;
}

static std::string human(uint64_t n) {
	char buf[32];
	if (n < 1024) snprintf(buf, sizeof(buf), "%llu", (unsigned long long)n);
	else if (n < 1024ull * 1024) snprintf(buf, sizeof(buf), "%.1fK", n / 1024.0);
	else if (n < 1024ull * 1024 * 1024) snprintf(buf, sizeof(buf), "%.1fM", n / 1048576.0);
	else snprintf(buf, sizeof(buf), "%.1fG", n / 1073741824.0);
	return buf;
}

// list

static int cmd_list(const Options &o) {
	if (o.positional.size() != 1) return die_usage("list needs exactly one archive");
	const char *archive = o.positional[0].c_str();

	wpk_reader_t *r = nullptr;
	if (!wpk_reader_open(archive, &r) || !r) {
		fprintf(stderr, "wpkc: cannot open '%s' (missing or not a valid WPK archive)\n", archive);
		return 1;
	}

	uint32_t count = wpk_reader_get_file_count(r);
	char uuid[WPK_UUID_STRING_SIZE] = "";
	wpk_uuid_t u;
	if (wpk_reader_get_uuid(r, u)) wpk_uuid_to_string(u, uuid);

	printf("Archive : %s\n", archive);
	printf("UUID    : %s\n", uuid);
	printf("Files   : %u%s\n\n", (unsigned)count, wpk_reader_is_encrypted(r) ? "  (encrypted)" : "");
	printf("%10s %10s  %-16s  %s\n", "Size", "Packed", "Modified (UTC)", "Name");
	printf("%10s %10s  %-16s  %s\n", "----------", "----------", "----------------", "----");

	uint64_t totalOrig = 0, totalPacked = 0;
	char path[WPK_ZIP_MAX_ARCHIVE_FILENAME_SIZE * 9];
	for (uint32_t i = 0; i < count; ++i) {
		wpk_entry_info_t info{};
		if (!wpk_reader_get_entry_info(r, i, &info) ||
			!wpk_reader_get_file_path(r, i, path, sizeof(path))) {
			fprintf(stderr, "wpkc: failed reading entry %u\n", (unsigned)i);
			wpk_reader_close(r);
			return 1;
		}
		totalOrig += info.original_size;
		totalPacked += info.compressed_size;
		printf("%10s %10s  %-16s  %s\n", human(info.original_size).c_str(),
			human(info.compressed_size).c_str(), format_time(info.timestamp).c_str(), path);
	}
	printf("%10s %10s  %-16s  %u file%s\n", "----------", "----------", "----------------",
		(unsigned)count, count == 1 ? "" : "s");
	printf("%10s %10s\n", human(totalOrig).c_str(), human(totalPacked).c_str());
	wpk_reader_close(r);
	return 0;
}

// compress

struct InputFile {
	std::string source;  // path on disk
	std::string name;    // path inside the archive
};

static std::string to_archive_name(const fs::path &rel) {
	std::string s = rel.generic_string(); // always '/'
	return s;
}

static bool collect_inputs(const std::vector<std::string> &inputs, const fs::path &archivePath,
	std::vector<InputFile> &out) {
	std::error_code ec;
	fs::path archiveAbs = fs::weakly_canonical(archivePath, ec);

	auto add = [&](const fs::path &file, const std::string &name) {
		std::error_code e2;
		fs::path abs = fs::weakly_canonical(file, e2);
		if (!e2 && !archiveAbs.empty() && abs == archiveAbs) return; // never pack the archive itself
		out.push_back({file.string(), name});
	};

	for (const std::string &in : inputs) {
		fs::path p(in);
		fs::file_status st = fs::status(p, ec);
		if (ec || !fs::exists(st)) {
			fprintf(stderr, "wpkc: '%s': no such file or directory\n", in.c_str());
			return false;
		}
		if (fs::is_directory(st)) {
			std::vector<InputFile> found;
			for (fs::recursive_directory_iterator it(p, fs::directory_options::skip_permission_denied, ec), end;
				 it != end; it.increment(ec)) {
				if (ec) {
					fprintf(stderr, "wpkc: cannot read '%s': %s\n", in.c_str(), ec.message().c_str());
					return false;
				}
				if (!it->is_regular_file(ec)) continue; // skips dirs, symlink loops, devices
				found.push_back({it->path().string(), to_archive_name(fs::relative(it->path(), p, ec))});
			}
			std::sort(found.begin(), found.end(),
				[](const InputFile &a, const InputFile &b) { return a.name < b.name; });
			for (auto &f : found) add(f.source, f.name);
		} else if (fs::is_regular_file(st)) {
			add(p, p.filename().generic_string());
		} else {
			fprintf(stderr, "wpkc: '%s': not a regular file or directory\n", in.c_str());
			return false;
		}
	}
	return true;
}

static int cmd_compress(Options &o) {
	if (o.positional.size() < 2) return die_usage("compress needs an archive and at least one input");
	const std::string archive = o.positional[0];
	std::vector<std::string> inputs(o.positional.begin() + 1, o.positional.end());

	std::error_code ec;
	if (!o.force && fs::exists(archive, ec)) {
		fprintf(stderr, "wpkc: '%s' already exists (use -f to overwrite)\n", archive.c_str());
		return 1;
	}

	std::vector<InputFile> files;
	if (!collect_inputs(inputs, archive, files)) return 1;
	if (files.empty()) {
		fprintf(stderr, "wpkc: nothing to compress\n");
		return 1;
	}
	for (size_t i = 0; i < files.size(); ++i)
		for (size_t j = 0; j < i; ++j)
			if (files[i].name == files[j].name) {
				fprintf(stderr, "wpkc: duplicate archive path '%s' (from '%s' and '%s')\n",
					files[i].name.c_str(), files[j].source.c_str(), files[i].source.c_str());
				return 1;
			}
	if (files.size() > 100000) {
		fprintf(stderr, "wpkc: too many files (limit is 100000)\n");
		return 1;
	}

	std::vector<const char *> src, names;
	for (auto &f : files) {
		src.push_back(f.source.c_str());
		names.push_back(f.name.c_str());
	}

	WPK_COMPRESS_OPTIONS opt{};
	opt.level = o.level;
	opt.password = o.havePassword ? o.password.c_str() : nullptr;
	opt.pbkdf2_iterations = o.iterations;

	// Write to a temporary name first so a failure never leaves a broken archive
	// (or destroys the previous one when -f is used).
	std::string tmp = archive + ".tmp";
	wpk_uuid_t uuid;
	if (!wpk_compress_files_ex(tmp.c_str(), src.data(), names.data(), files.size(), &opt, uuid)) {
		fprintf(stderr, "wpkc: failed to create archive (unreadable input, invalid path or bad parameters)\n");
		fs::remove(tmp, ec);
		return 1;
	}
	fs::rename(tmp, archive, ec);
	if (ec) { // Windows cannot rename over an existing file
		fs::remove(archive, ec);
		fs::rename(tmp, archive, ec);
	}
	if (ec) {
		fprintf(stderr, "wpkc: cannot write '%s': %s\n", archive.c_str(), ec.message().c_str());
		fs::remove(tmp, ec);
		return 1;
	}

	char u[WPK_UUID_STRING_SIZE] = "";
	wpk_uuid_to_string(uuid, u);
	uintmax_t size = fs::file_size(archive, ec);
	printf("Created %s: %zu file%s, %s%s, uuid %s\n", archive.c_str(), files.size(),
		files.size() == 1 ? "" : "s", human(ec ? 0 : size).c_str(),
		o.havePassword ? ", encrypted" : "", u);
	return 0;
}

// extract

static int cmd_extract(Options &o) {
	if (o.positional.empty()) return die_usage("extract needs an archive");
	const std::string archive = o.positional[0];
	std::vector<std::string> names(o.positional.begin() + 1, o.positional.end());

	wpk_reader_t *r = nullptr;
	if (!wpk_reader_open(archive.c_str(), &r) || !r) {
		fprintf(stderr, "wpkc: cannot open '%s' (missing or not a valid WPK archive)\n", archive.c_str());
		return 1;
	}
	bool encrypted = wpk_reader_is_encrypted(r) != 0;

	// Resolve requested names before touching the disk.
	std::vector<uint32_t> indexes;
	for (const std::string &n : names) {
		uint32_t idx = wpk_reader_get_locate_file(r, n.c_str());
		if (idx == UINT32_MAX) {
			fprintf(stderr, "wpkc: '%s' not found in archive\n", n.c_str());
			wpk_reader_close(r);
			return 1;
		}
		indexes.push_back(idx);
	}
	uint32_t total = wpk_reader_get_file_count(r);
	wpk_reader_close(r);

	if (encrypted && !o.havePassword) {
		if (WPKC_ISATTY(WPKC_FILENO(stdin))) {
			o.password = read_password_tty("Password: ");
			o.havePassword = true;
		} else {
			fprintf(stderr, "wpkc: archive is encrypted; supply a password with -p or WPKC_PASSWORD\n");
			return 1;
		}
	}
	const char *pw = (encrypted && o.havePassword) ? o.password.c_str() : nullptr;

	std::error_code ec;
	fs::create_directories(o.outdir, ec);
	if (ec) {
		fprintf(stderr, "wpkc: cannot create '%s': %s\n", o.outdir.c_str(), ec.message().c_str());
		return 1;
	}

	size_t extracted = 0;
	if (names.empty()) {
		if (!wpk_extract_password(archive.c_str(), o.outdir.c_str(), pw)) {
			fprintf(stderr, "wpkc: extraction failed (wrong password, corrupt archive, or a file already exists)\n");
			return 1;
		}
		extracted = total;
	} else {
		for (size_t i = 0; i < indexes.size(); ++i) {
			if (!wpk_extract_file_password(archive.c_str(), indexes[i], o.outdir.c_str(), pw)) {
				fprintf(stderr, "wpkc: failed extracting '%s' (wrong password, corrupt archive, or file already exists)\n",
					names[i].c_str());
				return 1;
			}
			++extracted;
		}
	}
	printf("Extracted %zu file%s to %s\n", extracted, extracted == 1 ? "" : "s", o.outdir.c_str());
	return 0;
}

// convert
static int cmd_convert_z2w(const Options &o) {
	if (o.positional.size() != 2) return die_usage("convert needs <in.zip> <out.wpk>");
	const std::string &zip = o.positional[0];
	const std::string &wpk = o.positional[1];
	std::error_code ec;
	if (!fs::is_regular_file(zip, ec)) {
		fprintf(stderr, "wpkc: '%s': no such file\n", zip.c_str());
		return 1;
	}
	if (!o.force && fs::exists(wpk, ec)) {
		fprintf(stderr, "wpkc: '%s' already exists (use -f to overwrite)\n", wpk.c_str());
		return 1;
	}
	if (!zip_convert_to_wpk(zip.c_str(), wpk.c_str(), o.havePassword ? o.password.c_str() : nullptr)) {
		fprintf(stderr, "wpkc: conversion failed (not a valid ZIP, encrypted ZIP entries, empty archive or unwritable output)\n");
		return 1;
	}
	uintmax_t size = fs::file_size(wpk, ec);
	printf("Converted %s -> %s (%s%s)\n", zip.c_str(), wpk.c_str(), human(ec ? 0 : size).c_str(),
		o.havePassword ? ", encrypted" : "");
	return 0;
}

static int cmd_convert_w2z(const Options &o) {
	if (o.positional.size() != 2)
		return die_usage("convert needs <in.wpk> <out.zip>");

	const std::string &wpk = o.positional[0];
	const std::string &zip = o.positional[1];

	std::error_code ec;

	if (!fs::is_regular_file(wpk, ec)) {
		fprintf(stderr, "wpkc: '%s': no such file\n", wpk.c_str());
		return 1;
	}

	if (!o.force && fs::exists(zip, ec)) {
		fprintf(stderr,"wpkc: '%s' already exists (use -f to overwrite)\n",zip.c_str());
		return 1;
	}

	if (!wpk_convert_to_zip(wpk.c_str(),zip.c_str(),o.havePassword ? o.password.c_str() : nullptr)) {
		fprintf(stderr,"wpkc: WPK to ZIP conversion failed (invalid WPK, wrong password or unwritable output)\n");
		return 1;
	}

	uintmax_t size = fs::file_size(zip, ec);
	printf("Converted %s -> %s (%s)\n",wpk.c_str(),zip.c_str(),human(ec ? 0 : size).c_str());
	return 0;
}

static bool IsZipMagic(const std::uint8_t* d, size_t n) {
	return n >= 4 && d[0] == 'P' && d[1] == 'K' &&
	((d[2] == 0x03 && d[3] == 0x04) ||   // local file header
	(d[2] == 0x05 && d[3] == 0x06));    // empty archive (end of central directory)
}

static bool IsWpkMagic(const std::uint8_t* d, size_t n) {
	return n >= WPK_MAGIC_SIZE && memcmp(d, WPK_MAGIC, WPK_MAGIC_SIZE) == 0;
}

static int cmd_convert(const Options &o) {
	if (o.positional.size() != 2)
		return die_usage("convert needs <in.zip|in.wpk> <out.wpk|out.zip>");

	const std::string &input = o.positional[0];
	const std::string &output = o.positional[1];

	cifstream file(input, std::ios::binary);
	if (!file) {
		fprintf(stderr, "wpkc: cannot open '%s'\n", input.c_str());
		return 1;
	}

	std::uint8_t magic[WPK_MAGIC_SIZE > 4 ? WPK_MAGIC_SIZE : 4]{};
	file.read(reinterpret_cast<char *>(magic), sizeof(magic));
	const size_t n = static_cast<size_t>(file.gcount());
	file.close();

	if (IsZipMagic(magic, n)) {
		return cmd_convert_z2w(o);
	}

	if (IsWpkMagic(magic, n)) {
		return cmd_convert_w2z(o);
	}

	fprintf(stderr,"wpkc: '%s' is neither a recognized ZIP nor WPK archive\n",input.c_str());

	return 1;
}

// main

int main(int argc, char **argv) {
	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	std::string cmd = argv[1];
	if (cmd == "-h" || cmd == "--help" || cmd == "help") {
		usage(stdout);
		return 0;
	}
	if (cmd == "--version" || cmd == "-V") {
		printf("wpkc %s (WPK format v%d)\n", VERSION, WPK_VERSION);
		return 0;
	}

	Options o;
	if (int rc = parse_args(argc, argv, 2, o)) return rc;

	if (cmd == "list" || cmd == "l" || cmd == "ls") return cmd_list(o);
	if (cmd == "compress" || cmd == "c" || cmd == "create") return cmd_compress(o);
	if (cmd == "extract" || cmd == "x") return cmd_extract(o);
	if (cmd == "z2w") return cmd_convert_z2w(o);
	if (cmd == "w2z") return cmd_convert_w2z(o);
	if (cmd == "convert") return cmd_convert(o);

	fprintf(stderr, "wpkc: unknown command '%s'\n", cmd.c_str());
	return die_usage("expected list, compress, extract or convert");
}
